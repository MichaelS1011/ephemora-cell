# Ephemora Cell — Product VM supervisor (local integration path)
# SPDX-License-Identifier: BUSL-1.1
# Copyright 2026 Michael Soppa

"""Host-side lifecycle and capacity book for one VM per run.

This module is the product path, not the audit prototype: it admits a VM
against a host capacity book (instances, guest RAM and a fixed per-instance
virtualization overhead), enforces a boot deadline and a run deadline, and
always kills, reaps and releases the instance on every exit route. The
backend is injected; :class:`VZProbeBackend` starts the VZ probe used by the
local hvc1 qualification, and tests use a deterministic fake.

Two books stay separate and must not be conflated:

* :class:`VMBudget` — host capacity for the *live* VM instances.
* :class:`~ephemora_cell.tenant.TenantStore` — fuel, raw output bytes and
  wall time for the guest executions (wired by the IPC layer, D2).

The module makes no A7 or release claim. A booted probe is a lifecycle fact,
not proof that the guest worker's authority is constrained.
"""

from __future__ import annotations

import os
import signal
import subprocess
import threading
import time
from collections import deque
from dataclasses import dataclass
from enum import Enum
from pathlib import Path
from typing import Protocol, runtime_checkable

__all__ = [
    "HostCapacitySnapshot",
    "SupervisorResult",
    "VMBudget",
    "VMHandle",
    "VMLimits",
    "VMOutcome",
    "VMStartRequest",
    "VMState",
    "VMSupervisor",
    "VZProbeBackend",
]


class VMState(str, Enum):
    REFUSED = "refused"
    ADMITTED = "admitted"
    STARTING = "starting"
    BOOTING = "booting"
    RUNNING = "running"
    STOPPING = "stopping"
    RESTARTING = "restarting"
    STOPPED = "stopped"
    FAILED = "failed"


@dataclass(frozen=True)
class VMLimits:
    """Host capacity and lifecycle ceilings for the supervisor.

    ``guest_overhead_mib`` is a fixed per-instance reservation for the VZ
    helper, pipe buffers and probe bookkeeping. It is deliberately not
    measured from RSS: RSS is lazy and would under-book a VM that has not
    touched its pages yet. The 2 GiB Python VM remains the qualified shape;
    1 GiB is a light-workload shape, not a Python guarantee.
    """

    max_instances: int = 8
    max_guest_ram_mib: int = 8_192
    max_host_overhead_mib: int = 4_096
    guest_overhead_mib: int = 256
    boot_deadline_s: float = 30.0
    run_deadline_s: float = 120.0
    shutdown_grace_s: float = 5.0
    max_restarts: int = 1

    def __post_init__(self) -> None:
        for name, value in (
            ("max_instances", self.max_instances),
            ("max_guest_ram_mib", self.max_guest_ram_mib),
        ):
            if isinstance(value, bool) or not isinstance(value, int) or value <= 0:
                raise ValueError(f"{name} must be a positive integer")
        for name, value in (
            ("max_host_overhead_mib", self.max_host_overhead_mib),
            ("guest_overhead_mib", self.guest_overhead_mib),
        ):
            if isinstance(value, bool) or not isinstance(value, int) or value < 0:
                raise ValueError(f"{name} must be a non-negative integer")
        for field, seconds in (
            ("boot_deadline_s", self.boot_deadline_s),
            ("run_deadline_s", self.run_deadline_s),
            ("shutdown_grace_s", self.shutdown_grace_s),
        ):
            if not isinstance(seconds, (int, float)) or isinstance(seconds, bool):
                raise ValueError(f"{field} must be a number")
            if seconds <= 0:
                raise ValueError(f"{field} must be positive")
        if (
            isinstance(self.max_restarts, bool)
            or not isinstance(self.max_restarts, int)
            or self.max_restarts < 0
        ):
            raise ValueError("max_restarts must be a non-negative integer")


@dataclass(frozen=True)
class HostCapacitySnapshot:
    active_instances: int
    active_guest_ram_mib: int
    active_overhead_mib: int
    max_instances: int
    max_guest_ram_mib: int
    max_host_overhead_mib: int

    @property
    def active_total_mib(self) -> int:
        return self.active_guest_ram_mib + self.active_overhead_mib


class VMBudget:
    """Host capacity book for live VM instances.

    Admission is a single critical section, so two threads cannot both read
    "there is room" and spend the same instance or RAM slot. Release is
    idempotent; a supervisor may call it in a ``finally`` after a failed
    start. This is an in-process book: it bounds one supervisor, not every
    host process. A cross-process host book needs a persistent lease and is
    explicitly not claimed here.
    """

    def __init__(self, limits: VMLimits) -> None:
        self._limits = limits
        self._active: dict[int, tuple[str, int, int]] = {}
        self._next = 1
        self._lock = threading.Lock()

    @property
    def limits(self) -> VMLimits:
        return self._limits

    def _totals_locked(self) -> tuple[int, int]:
        guest = sum(item[1] for item in self._active.values())
        overhead = sum(item[2] for item in self._active.values())
        return guest, overhead

    def admit(self, tenant: str, guest_ram_mib: int) -> tuple[int | None, str | None]:
        if not tenant:
            return None, "tenant_missing"
        if (
            isinstance(guest_ram_mib, bool)
            or not isinstance(guest_ram_mib, int)
            or guest_ram_mib <= 0
        ):
            return None, "ram_invalid"
        with self._lock:
            if len(self._active) >= self._limits.max_instances:
                return None, "instance_limit"
            guest, overhead = self._totals_locked()
            if guest + guest_ram_mib > self._limits.max_guest_ram_mib:
                return None, "guest_ram_limit"
            if (
                overhead + self._limits.guest_overhead_mib
                > self._limits.max_host_overhead_mib
            ):
                return None, "host_overhead_limit"
            token = self._next
            self._next += 1
            self._active[token] = (
                tenant,
                guest_ram_mib,
                self._limits.guest_overhead_mib,
            )
            return token, None

    def release(self, token: int) -> None:
        with self._lock:
            self._active.pop(token, None)

    def snapshot(self) -> HostCapacitySnapshot:
        with self._lock:
            guest, overhead = self._totals_locked()
            active = len(self._active)
        return HostCapacitySnapshot(
            active_instances=active,
            active_guest_ram_mib=guest,
            active_overhead_mib=overhead,
            max_instances=self._limits.max_instances,
            max_guest_ram_mib=self._limits.max_guest_ram_mib,
            max_host_overhead_mib=self._limits.max_host_overhead_mib,
        )


@dataclass(frozen=True)
class VMStartRequest:
    run_id: str
    tenant: str
    guest_ram_mib: int
    vcpus: int = 2
    boot_deadline_s: float = 30.0
    run_deadline_s: float = 120.0
    ipc_socket_path: str | None = None

    def __post_init__(self) -> None:
        if not self.run_id:
            raise ValueError("run_id must not be empty")
        if not self.tenant:
            raise ValueError("tenant must not be empty")
        if (
            isinstance(self.guest_ram_mib, bool)
            or not isinstance(self.guest_ram_mib, int)
            or self.guest_ram_mib <= 0
        ):
            raise ValueError("guest_ram_mib must be a positive integer")
        if isinstance(self.vcpus, bool) or not isinstance(self.vcpus, int):
            raise ValueError("vcpus must be an integer")
        if self.vcpus <= 0:
            raise ValueError("vcpus must be positive")
        if self.boot_deadline_s <= 0 or self.run_deadline_s <= 0:
            raise ValueError("deadlines must be positive")


@dataclass(frozen=True)
class VMOutcome:
    ok: bool
    booted: bool
    marker: bool
    returncode: int | None
    output_tail: str = ""
    error: str = ""
    ipc_aborted: bool = False
    #: Whether a HOST-side fact, not a guest report, established the result.
    #: The hvc1 path reports success from the guest's JSON and sets this False.
    host_verified: bool = False
    #: The guest worker report, if the transport received and validated one.
    #: It is guest data, not a host measurement; billing must not treat it as
    #: authoritative without an explicit trust decision.
    report: dict | None = None


@dataclass(frozen=True)
class SupervisorResult:
    status: str
    state: str
    token: int | None
    attempts: int = 0
    crashes: int = 0
    reason: str | None = None
    boot_ms: int | None = None
    wall_ms: int = 0
    output_tail: str = ""
    transitions: tuple[str, ...] = ()
    cleanup_ok: bool = True
    ipc_aborted: bool = False
    host_verified: bool = False
    report: dict | None = None
    started: bool = False


@runtime_checkable
class VMHandle(Protocol):
    def wait_boot(self, deadline_s: float) -> bool: ...

    def wait_run(
        self, deadline_s: float, abort_event: threading.Event | None = None
    ) -> VMOutcome: ...

    def abort_ipc(self, reason: str) -> None: ...

    def kill(self) -> None: ...

    def cleanup(self) -> bool: ...


class VMBackend(Protocol):
    def start(self, request: VMStartRequest) -> VMHandle: ...

    def reap_xpc(self) -> int: ...


class VMSupervisor:
    """Admission, boot deadline, restart, abort and cleanup for one backend."""

    def __init__(
        self,
        backend: VMBackend,
        limits: VMLimits,
        *,
        budget: VMBudget | None = None,
    ) -> None:
        self._backend = backend
        self._limits = limits
        self._budget = budget or VMBudget(limits)
        self._active: dict[int, VMHandle] = {}
        self._abort_events: dict[int, threading.Event] = {}
        self._lock = threading.RLock()
        self._results: list[SupervisorResult] = []

    @property
    def budget(self) -> VMBudget:
        return self._budget

    @property
    def max_attempts(self) -> int:
        """The most attempts this supervisor can make for one run."""
        return self._limits.max_restarts + 1

    @property
    def results(self) -> tuple[SupervisorResult, ...]:
        with self._lock:
            return tuple(self._results)

    def active_tokens(self) -> tuple[int, ...]:
        with self._lock:
            return tuple(self._active)

    def _register(self, token: int, handle: VMHandle) -> threading.Event:
        event = threading.Event()
        with self._lock:
            self._active[token] = handle
            self._abort_events[token] = event
        return event

    def _unregister(self, token: int) -> None:
        with self._lock:
            self._active.pop(token, None)
            self._abort_events.pop(token, None)

    def abort(self, token: int, reason: str = "operator_abort") -> bool:
        """Abort a live run. The run loop still owns cleanup and release."""
        with self._lock:
            event = self._abort_events.get(token)
            handle = self._active.get(token)
        if event is not None:
            event.set()
        if handle is not None:
            handle.abort_ipc(reason)
            return True
        return False

    def kill(self, token: int, reason: str = "operator_sigkill") -> bool:
        """SIGKILL the backend process for a live run; the loop cleans up."""
        with self._lock:
            event = self._abort_events.get(token)
            handle = self._active.get(token)
        if event is not None:
            event.set()
        if handle is not None:
            handle.abort_ipc(reason)
            handle.kill()
            return True
        return False

    def run(
        self,
        request: VMStartRequest,
        *,
        abort_event: threading.Event | None = None,
    ) -> SupervisorResult:
        started = time.monotonic()
        transitions: list[str] = []

        def transition(state: VMState) -> None:
            transitions.append(state.value)

        token, refusal = self._budget.admit(request.tenant, request.guest_ram_mib)
        if token is None:
            transition(VMState.REFUSED)
            result = SupervisorResult(
                status="refused",
                state=VMState.REFUSED.value,
                token=None,
                reason=refusal,
                wall_ms=round((time.monotonic() - started) * 1000),
                transitions=tuple(transitions),
            )
            with self._lock:
                self._results.append(result)
            return result
        transition(VMState.ADMITTED)

        attempts = 0
        crashes = 0
        boot_ms: int | None = None
        output_tail = ""
        report: dict | None = None
        host_verified = False
        cleanup_ok = True
        ipc_aborted = False
        reason: str | None = None
        status = "failed"
        started_any = False
        handle: VMHandle | None = None
        try:
            max_attempts = self._limits.max_restarts + 1
            for attempt in range(max_attempts):
                attempts = attempt + 1
                if attempt:
                    transition(VMState.RESTARTING)
                transition(VMState.STARTING)
                try:
                    handle = self._backend.start(request)
                except Exception as exc:  # backend is a boundary
                    status = "backend_error"
                    reason = f"backend start failed: {exc}"
                    transition(VMState.FAILED)
                    break
                run_abort = self._register(token, handle)
                if abort_event is not None:
                    target = handle

                    def _bridge(run_abort=run_abort, target=target) -> None:
                        abort_event.wait()
                        run_abort.set()
                        target.abort_ipc("operator_abort")

                    threading.Thread(target=_bridge, daemon=True).start()
                transition(VMState.BOOTING)
                boot_started = time.monotonic()
                booted = handle.wait_boot(request.boot_deadline_s)
                boot_ms = round((time.monotonic() - boot_started) * 1000)
                if not booted:
                    crashes += 1
                    reason = "boot_timeout"
                    transition(VMState.STOPPING)
                    handle.abort_ipc("boot_timeout")
                    handle.kill()
                    cleanup_ok = handle.cleanup() and cleanup_ok
                    self._unregister(token)
                    handle = None
                    status = "boot_timeout"
                    if attempt + 1 < max_attempts:
                        continue
                    transition(VMState.FAILED)
                    break
                # Only a guest that reached its boot marker counts as started;
                # a probe that never connected must release the reservation.
                started_any = True
                transition(VMState.RUNNING)
                outcome = handle.wait_run(request.run_deadline_s, run_abort)
                output_tail = outcome.output_tail
                report = outcome.report
                host_verified = outcome.host_verified
                transition(VMState.STOPPING)
                cleanup_ok = handle.cleanup() and cleanup_ok
                self._unregister(token)
                handle = None
                if outcome.ipc_aborted or run_abort.is_set():
                    ipc_aborted = True
                    status = "ipc_aborted"
                    reason = "ipc_aborted"
                    transition(VMState.FAILED)
                    break
                if outcome.ok:
                    status = "success"
                    reason = None
                    transition(VMState.STOPPED)
                    break
                crashes += 1
                reason = outcome.error or "worker_crashed"
                if attempt + 1 < max_attempts:
                    continue
                status = "worker_crashed"
                transition(VMState.FAILED)
                break
        finally:
            if handle is not None:
                cleanup_ok = handle.cleanup() and cleanup_ok
                self._unregister(token)
            self._budget.release(token)
            result = SupervisorResult(
                status=status,
                state=transitions[-1] if transitions else VMState.FAILED.value,
                token=token,
                attempts=attempts,
                crashes=crashes,
                reason=reason,
                boot_ms=boot_ms,
                wall_ms=round((time.monotonic() - started) * 1000),
                output_tail=output_tail,
                transitions=tuple(transitions),
                cleanup_ok=cleanup_ok,
                ipc_aborted=ipc_aborted,
                host_verified=host_verified,
                report=report,
                started=started_any,
            )
            with self._lock:
                self._results.append(result)
        return result

    def shutdown(self) -> int:
        """Abort live runs, reap their backends, then sweep orphaned VZ XPCs."""
        with self._lock:
            events = list(self._abort_events.values())
            handles = list(self._active.values())
        for event in events:
            event.set()
        for handle in handles:
            handle.abort_ipc("shutdown")
            handle.kill()
            handle.cleanup()
        deadline = time.monotonic() + self._limits.shutdown_grace_s
        while time.monotonic() < deadline:
            with self._lock:
                if not self._active:
                    break
            time.sleep(0.02)
        return self._backend.reap_xpc()


class VZProbeHandle:
    """Line-oriented handle for the VZ probe used by the local path."""

    def __init__(
        self,
        proc: subprocess.Popen,
        *,
        success_marker: str,
        boot_marker: str,
    ) -> None:
        self._proc = proc
        self._success_marker = success_marker
        self._boot_marker = boot_marker
        self._lines: deque[str] = deque(maxlen=50)
        self._boot = threading.Event()
        self._booted = False
        self._success = False
        self._ipc_aborted = False
        self._lock = threading.Lock()
        self._reader = threading.Thread(target=self._read, daemon=True)
        self._reader.start()

    @property
    def pid(self) -> int:
        return self._proc.pid

    @property
    def output_tail(self) -> str:
        return self._tail()

    @property
    def lines(self) -> tuple[str, ...]:
        with self._lock:
            return tuple(self._lines)

    def _read(self) -> None:
        assert self._proc.stdout is not None
        for line in self._proc.stdout:
            text = line.rstrip("\n")
            with self._lock:
                self._lines.append(text)
                if self._boot_marker in text:
                    self._booted = True
                    self._boot.set()
                if self._success_marker in text:
                    self._success = True
        self._boot.set()

    def wait_boot(self, deadline_s: float) -> bool:
        return self._boot.wait(deadline_s) and self._booted

    def wait_run(
        self, deadline_s: float, abort_event: threading.Event | None = None
    ) -> VMOutcome:
        deadline = time.monotonic() + deadline_s
        while time.monotonic() < deadline:
            if abort_event is not None and abort_event.is_set():
                self.abort_ipc("operator_abort")
                return VMOutcome(
                    ok=False,
                    booted=True,
                    marker=False,
                    returncode=self._proc.poll(),
                    output_tail=self._tail(),
                    error="ipc_aborted",
                    ipc_aborted=True,
                )
            if self._proc.poll() is not None:
                break
            if abort_event is not None:
                abort_event.wait(0.02)
            else:
                time.sleep(0.02)
        if self._proc.poll() is None:
            self.kill()
            return VMOutcome(
                ok=False,
                booted=True,
                marker=False,
                returncode=self._proc.poll(),
                output_tail=self._tail(),
                error="run_timeout",
            )
        returncode = self._proc.poll()
        with self._lock:
            marker = self._success
            ipc_aborted = self._ipc_aborted
        ok = returncode == 0 and marker and not ipc_aborted
        error = ""
        if not marker:
            error = "guest completion marker missing"
        elif returncode != 0:
            error = f"probe exited {returncode}"
        return VMOutcome(
            ok=ok,
            booted=True,
            marker=marker,
            returncode=returncode,
            output_tail=self._tail(),
            error=error,
            ipc_aborted=ipc_aborted,
        )

    def _tail(self) -> str:
        with self._lock:
            return " | ".join(list(self._lines)[-8:])

    def abort_ipc(self, reason: str) -> None:
        with self._lock:
            self._ipc_aborted = True
            self._lines.append(f"IPC_ABORT {reason}")

    def kill(self) -> None:
        if self._proc.poll() is None:
            try:
                os.killpg(os.getpgid(self._proc.pid), signal.SIGKILL)
            except OSError:
                try:
                    self._proc.kill()
                except OSError:
                    pass
        try:
            self._proc.wait(timeout=10)
        except subprocess.TimeoutExpired:
            pass

    def cleanup(self) -> bool:
        self.kill()
        self._reader.join(5.0)
        if self._proc.stdout is not None:
            try:
                self._proc.stdout.close()
            except OSError:
                pass
        return self._proc.poll() is not None


class VZProbeBackend:
    """Local VZ probe backend. Paths and the success marker are injected.

    The probe is a development/qualification launcher, not a signed
    distribution artifact. The production hvc1 backend implements the same
    :class:`VMHandle` contract and adds the host mediator; this class is the
    lifecycle proof, not an A7 claim.
    """

    def __init__(
        self,
        probe: str | Path,
        kernel: str | Path,
        initrd: str | Path,
        *,
        boot_marker: str = "VZ_RUNNING",
        success_marker: str = "GUEST_DONE",
        allow_session_wide_xpc_reap: bool = False,
    ) -> None:
        self._probe = Path(probe)
        self._kernel = Path(kernel)
        self._initrd = Path(initrd)
        self._boot_marker = boot_marker
        self._success_marker = success_marker
        self._allow_session_wide_reap = allow_session_wide_xpc_reap
        self._baseline = self._xpc_pids()

    def start(self, request: VMStartRequest) -> VZProbeHandle:
        for label, path in (
            ("probe", self._probe),
            ("kernel", self._kernel),
            ("initrd", self._initrd),
        ):
            if not path.is_file():
                raise FileNotFoundError(f"{label} not found: {path}")
        env = os.environ.copy()
        if request.ipc_socket_path:
            env["EPHEMORA_IPC_SOCKET"] = request.ipc_socket_path
        cmd = [
            str(self._probe),
            str(self._kernel),
            str(self._initrd),
            str(request.vcpus),
            str(request.guest_ram_mib),
            str(int(request.run_deadline_s + 10)),
        ]
        proc = subprocess.Popen(
            cmd,
            stdin=subprocess.DEVNULL,
            stdout=subprocess.PIPE,
            stderr=subprocess.STDOUT,
            text=True,
            errors="replace",
            bufsize=1,
            start_new_session=True,
            env=env,
        )
        return VZProbeHandle(
            proc,
            success_marker=self._success_marker,
            boot_marker=self._boot_marker,
        )

    @staticmethod
    def _xpc_pids() -> set[int]:
        try:
            completed = subprocess.run(
                ["ps", "-axo", "pid=,command="],
                capture_output=True,
                text=True,
                timeout=10,
            )
        except (OSError, subprocess.TimeoutExpired):
            return set()
        pids: set[int] = set()
        for line in completed.stdout.splitlines():
            parts = line.strip().split(None, 1)
            if len(parts) != 2 or "Virtualization.VirtualMachine" not in parts[1]:
                continue
            try:
                pids.add(int(parts[0]))
            except ValueError:
                continue
        return pids

    def residual_xpc(self) -> int:
        return max(0, len(self._xpc_pids() - self._baseline))

    def reap_xpc(self) -> int:
        """Kill VZ XPC services only when the caller opted into a session sweep.

        ``ps`` cannot prove which VM a Virtualization.VirtualMachine helper
        belongs to. Killing every new one would hit unrelated VMs on a shared
        host, so the product default only reports the residual (see
        :meth:`residual_xpc`). The qualification harness opts in explicitly.
        """
        if not self._allow_session_wide_reap:
            return 0
        killed = 0
        for pid in self._xpc_pids() - self._baseline:
            try:
                os.kill(pid, signal.SIGKILL)
                killed += 1
            except OSError:
                continue
        return killed
