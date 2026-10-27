# SPDX-License-Identifier: BUSL-1.1
# Copyright 2026 Michael Soppa

"""Product VM supervisor: capacity, state machine and cleanup controls."""

from __future__ import annotations

import os
import sys
import threading
import time

import pytest

sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))

from ephemora_cell.vm_supervisor import (
    SupervisorResult,
    VMLimits,
    VMOutcome,
    VMStartRequest,
    VMState,
    VMSupervisor,
    VZProbeBackend,
)


class FakeHandle:
    def __init__(self, mode: str) -> None:
        self.mode = mode
        self.boot_event = threading.Event()
        self.abort_event = threading.Event()
        self.abort_reason: str | None = None
        self.killed = False
        self.cleaned = False
        if mode != "no_boot":
            self.boot_event.set()

    def wait_boot(self, deadline_s: float) -> bool:
        return self.boot_event.wait(deadline_s)

    def wait_run(
        self, deadline_s: float, abort_event: threading.Event | None = None
    ) -> VMOutcome:
        if self.mode == "success":
            return VMOutcome(True, True, True, 0, output_tail="GUEST_DONE")
        if self.mode == "slow_success":
            time.sleep(0.2)
            return VMOutcome(True, True, True, 0, output_tail="GUEST_DONE")
        if self.mode == "crash":
            return VMOutcome(False, True, False, 1, error="worker_crashed")
        deadline = time.monotonic() + deadline_s
        while time.monotonic() < deadline:
            if self.abort_event.is_set() or (
                abort_event is not None and abort_event.is_set()
            ):
                return VMOutcome(
                    False,
                    True,
                    False,
                    None,
                    error="ipc_aborted",
                    ipc_aborted=True,
                )
            self.abort_event.wait(0.01)
        return VMOutcome(False, True, False, None, error="run_timeout")

    def abort_ipc(self, reason: str) -> None:
        self.abort_reason = reason
        self.abort_event.set()

    def kill(self) -> None:
        self.killed = True
        self.abort_event.set()

    def cleanup(self) -> bool:
        self.cleaned = True
        return True


class FakeBackend:
    def __init__(self, modes: list[str] | None = None) -> None:
        self.modes = list(modes or [])
        self.starts: list[VMStartRequest] = []
        self.handles: list[FakeHandle] = []
        self.reaped = 0

    def start(self, request: VMStartRequest) -> FakeHandle:
        self.starts.append(request)
        mode = self.modes.pop(0) if self.modes else "success"
        handle = FakeHandle(mode)
        self.handles.append(handle)
        return handle

    def reap_xpc(self) -> int:
        self.reaped += 1
        return 0


def _request(ram: int = 1024) -> VMStartRequest:
    return VMStartRequest(
        run_id="run-1",
        tenant="tenant:a",
        guest_ram_mib=ram,
        boot_deadline_s=0.2,
        run_deadline_s=2.0,
    )


def _limits(**overrides) -> VMLimits:
    values = dict(
        max_instances=8,
        max_guest_ram_mib=8192,
        max_host_overhead_mib=4096,
        guest_overhead_mib=256,
        boot_deadline_s=0.2,
        run_deadline_s=2.0,
        shutdown_grace_s=1.0,
        max_restarts=1,
    )
    values.update(overrides)
    return VMLimits(**values)


def test_budget_admits_eight_light_instances_and_refuses_the_ninth():
    supervisor = VMSupervisor(FakeBackend(), _limits())
    tokens = []
    for index in range(8):
        token, reason = supervisor.budget.admit(f"tenant:{index}", 1024)
        assert reason is None
        tokens.append(token)
    ninth, reason = supervisor.budget.admit("tenant:9", 1024)
    assert ninth is None
    assert reason == "instance_limit"
    snapshot = supervisor.budget.snapshot()
    assert snapshot.active_instances == 8
    assert snapshot.active_guest_ram_mib == 8192
    assert snapshot.active_overhead_mib == 8 * 256
    supervisor.budget.release(tokens[0])
    assert supervisor.budget.snapshot().active_instances == 7


def test_python_two_gib_instances_are_capped_by_guest_ram():
    supervisor = VMSupervisor(FakeBackend(), _limits())
    for index in range(4):
        token, reason = supervisor.budget.admit(f"tenant:{index}", 2048)
        assert reason is None
        assert token is not None
    fifth, reason = supervisor.budget.admit("tenant:5", 2048)
    assert fifth is None
    assert reason == "guest_ram_limit"


def test_virtualization_overhead_has_its_own_host_cap():
    supervisor = VMSupervisor(FakeBackend(), _limits(max_host_overhead_mib=512))
    assert supervisor.budget.admit("a", 1024)[1] is None
    assert supervisor.budget.admit("b", 1024)[1] is None
    token, reason = supervisor.budget.admit("c", 1024)
    assert token is None
    assert reason == "host_overhead_limit"


def test_success_releases_capacity_and_cleans_the_handle():
    backend = FakeBackend(["success"])
    supervisor = VMSupervisor(backend, _limits())
    result = supervisor.run(_request())
    assert result.status == "success"
    assert result.state == VMState.STOPPED.value
    assert result.transitions == (
        "admitted",
        "starting",
        "booting",
        "running",
        "stopping",
        "stopped",
    )
    assert backend.handles[0].cleaned is True
    assert supervisor.budget.snapshot().active_instances == 0


def test_boot_timeout_is_retried_then_reported_without_leaking_capacity():
    backend = FakeBackend(["no_boot", "no_boot"])
    supervisor = VMSupervisor(backend, _limits(max_restarts=1))
    result = supervisor.run(_request())
    assert result.status == "boot_timeout"
    assert result.started is False
    assert result.attempts == 2
    assert result.crashes == 2
    assert all(handle.cleaned and handle.killed for handle in backend.handles)
    assert all(handle.abort_reason == "boot_timeout" for handle in backend.handles)
    assert supervisor.budget.snapshot().active_instances == 0


def test_crash_then_restart_succeeds_with_two_attempts():
    backend = FakeBackend(["crash", "success"])
    supervisor = VMSupervisor(backend, _limits(max_restarts=1))
    result = supervisor.run(_request())
    assert result.status == "success"
    assert result.started is True
    assert result.attempts == 2
    assert result.crashes == 1
    assert len(backend.starts) == 2
    assert supervisor.budget.snapshot().active_instances == 0


def test_repeated_crash_reports_worker_crashed():
    backend = FakeBackend(["crash", "crash"])
    supervisor = VMSupervisor(backend, _limits(max_restarts=1))
    result = supervisor.run(_request())
    assert result.status == "worker_crashed"
    assert result.attempts == 2
    assert result.crashes == 2
    assert supervisor.budget.snapshot().active_instances == 0


def test_operator_abort_interrupts_a_running_vm_and_still_cleans():
    backend = FakeBackend(["hang"])
    supervisor = VMSupervisor(backend, _limits())
    results: list[SupervisorResult] = []
    thread = threading.Thread(
        target=lambda: results.append(supervisor.run(_request())), daemon=True
    )
    thread.start()
    deadline = time.monotonic() + 2
    while time.monotonic() < deadline and not supervisor.active_tokens():
        time.sleep(0.01)
    token = supervisor.active_tokens()[0]
    assert supervisor.abort(token, "test_abort") is True
    thread.join(5)
    assert results and results[0].status == "ipc_aborted"
    assert results[0].ipc_aborted is True
    assert backend.handles[0].abort_reason == "test_abort"
    assert backend.handles[0].cleaned is True
    assert supervisor.budget.snapshot().active_instances == 0


def test_shutdown_kills_active_handles_and_sweeps_the_backend():
    backend = FakeBackend(["hang"])
    supervisor = VMSupervisor(backend, _limits())
    results: list[SupervisorResult] = []
    thread = threading.Thread(
        target=lambda: results.append(supervisor.run(_request())), daemon=True
    )
    thread.start()
    deadline = time.monotonic() + 2
    while time.monotonic() < deadline and not supervisor.active_tokens():
        time.sleep(0.01)
    assert supervisor.shutdown() == 0
    thread.join(5)
    assert backend.reaped == 1
    assert backend.handles[0].killed is True
    assert backend.handles[0].cleaned is True
    assert results and results[0].status == "ipc_aborted"


def test_refused_admission_starts_no_backend():
    backend = FakeBackend(["hang"])
    supervisor = VMSupervisor(backend, _limits(max_instances=1))
    first: list[SupervisorResult] = []
    thread = threading.Thread(
        target=lambda: first.append(supervisor.run(_request())), daemon=True
    )
    thread.start()
    deadline = time.monotonic() + 2
    while time.monotonic() < deadline and not supervisor.active_tokens():
        time.sleep(0.01)
    second = supervisor.run(_request())
    assert second.status == "refused"
    assert second.reason == "instance_limit"
    assert len(backend.starts) == 1
    supervisor.abort(supervisor.active_tokens()[0])
    thread.join(5)


def test_eight_parallel_instances_run_and_the_ninth_is_refused():
    backend = FakeBackend(["slow_success"] * 8)
    supervisor = VMSupervisor(backend, _limits())
    barrier = threading.Barrier(9)
    results: list[SupervisorResult] = []
    lock = threading.Lock()

    def run(index: int) -> None:
        barrier.wait()
        result = supervisor.run(_request(1024))
        with lock:
            results.append(result)

    threads = [
        threading.Thread(target=run, args=(index,), daemon=True) for index in range(9)
    ]
    for thread in threads:
        thread.start()
    for thread in threads:
        thread.join(10)
    statuses = sorted(result.status for result in results)
    assert statuses.count("success") == 8
    assert statuses.count("refused") == 1
    refused = next(result for result in results if result.status == "refused")
    assert refused.reason == "instance_limit"
    assert len(backend.starts) == 8
    assert supervisor.budget.snapshot().active_instances == 0


def test_request_rejects_an_empty_identity_and_invalid_ram():
    with pytest.raises(ValueError, match="run_id"):
        VMStartRequest(run_id="", tenant="a", guest_ram_mib=1024)
    with pytest.raises(ValueError, match="guest_ram_mib"):
        VMStartRequest(run_id="r", tenant="a", guest_ram_mib=0)


@pytest.mark.skipif(
    os.environ.get("EPHEMORA_VZ_REAL") != "1"
    or not os.environ.get("EPHEMORA_VZ_GUEST_ROOT"),
    reason="real VZ boot is an explicit qualification run",
)
def test_real_vz_probe_reaches_boot_and_stops_cleanly():
    root = os.environ["EPHEMORA_VZ_GUEST_ROOT"]
    backend = VZProbeBackend(
        f"{root}/vzprobe_glibc_lts",
        f"{root}/Image",
        f"{root}/build_i/initramfs-glibc.cpio.gz",
        success_marker="GUEST_DONE",
    )
    supervisor = VMSupervisor(
        backend,
        _limits(
            max_instances=1,
            max_guest_ram_mib=1024,
            max_host_overhead_mib=1024,
            boot_deadline_s=20,
            run_deadline_s=60,
        ),
    )
    result = supervisor.run(
        VMStartRequest(
            run_id="real-boot",
            tenant="tenant:real",
            guest_ram_mib=1024,
            boot_deadline_s=20,
            run_deadline_s=60,
        )
    )
    assert result.token is not None
    assert result.status == "success"
    assert result.attempts == 1
    assert result.crashes == 0
    assert result.boot_ms is not None
    assert supervisor.budget.snapshot().active_instances == 0


def test_a_socket_binding_failure_leaves_no_socket_directory(tmp_path):
    import glob

    from ephemora_cell.vm_hvc1 import HVC1Backend, VMJob

    before = set(glob.glob("/tmp/eh_*"))
    run_id = "r" * 300
    job = VMJob(
        run_id=run_id,
        subject="tenant:a",
        policy_digest="p" * 64,
        module_digest="a" * 64,
        module_path="/opt/ephemora/hello.wasm",
    )
    backend = HVC1Backend(
        job=job,
        probe=str(tmp_path / "probe"),
        kernel=str(tmp_path / "kernel"),
        initrd=str(tmp_path / "initrd"),
    )
    request = VMStartRequest(run_id=run_id, tenant="tenant:a", guest_ram_mib=1024)
    with pytest.raises(OSError):
        backend.start(request)
    assert set(glob.glob("/tmp/eh_*")) == before
