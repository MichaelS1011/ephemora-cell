# Ephemora Cell WASM Runtime
# SPDX-License-Identifier: BUSL-1.1
# Copyright 2026 Michael Soppa
"""
Ephemora Cell — Isolated WASM sandbox with resource limits.

Decoupled WASMtime Runtime — Pure WASM execution with fuel metering,
memory limits, timeouts, and preopened directories.

This is a standalone wasmtime wrapper for public distribution.
"""

from __future__ import annotations

import hashlib
import math
import os
import re
import tempfile
import threading
import time
import traceback
from dataclasses import dataclass, replace
from enum import Enum
from pathlib import Path

from ephemora_cell._engine_config import build_engine_config
from ephemora_cell._sandbox_common import (
    _MAX_OUTPUT_BYTES,
    STDIN_MAX_BYTES,
)
from ephemora_cell._sandbox_common import (
    DANGEROUS_DIRS as _DANGEROUS_DIRS_POLICY,
)
from ephemora_cell._sandbox_common import (
    FORBIDDEN_CANONICAL as _FORBIDDEN_CANONICAL_POLICY,
)
from ephemora_cell._sandbox_common import (
    canonicalize_dir as _canonicalize_dir,
)
from ephemora_cell._sandbox_common import (
    check_dangerous_dirs as _check_dangerous_dirs_impl,
)
from ephemora_cell._sandbox_common import (
    filter_dangerous_dirs as _filter_dangerous_dirs_impl,
)
from ephemora_cell._sandbox_common import (
    forbidden_canonical_match as _forbidden_canonical_match_impl,
)
from ephemora_cell._sandbox_common import (
    fuel_consumed as _fuel_consumed_impl,
)
from ephemora_cell._sandbox_common import (
    grant_preopens as _grant_preopens_impl,
)
from ephemora_cell._sandbox_common import (
    is_memory_fault_trap as _is_memory_fault_trap,
)
from ephemora_cell._sandbox_common import (
    make_output_sink as _make_output_sink,
)
from ephemora_cell._sandbox_common import (
    read_capped_output as _read_capped_output,
)
from ephemora_cell._sandbox_common import (
    split_dir_mapping as _split_dir_mapping_impl,
)
from ephemora_cell._sandbox_common import (
    start_epoch_timer as _start_epoch_timer,
)
from ephemora_cell._sandbox_common import (
    start_interrupt_watch as _start_interrupt_watch,
)
from ephemora_cell._sandbox_common import (
    under_canonical_exception as _under_canonical_exception,
)
from ephemora_cell._sandbox_common import (
    validate_allow_dirs as _validate_allow_dirs_impl,
)
from ephemora_cell.state import StateStore
from ephemora_cell.tenant import Charge, CumulativeBudget, TenantId, TenantStore

try:
    import wasmtime
    from wasmtime import (
        Engine,
        Linker,
        Module,
        Store,
        Trap,
    )
    from wasmtime import (
        WasiConfig as WasmtimeWasiConfig,
    )

    HAS_WASMTIME = True
except ImportError:
    HAS_WASMTIME = False


# --- Shared output budget / stdin cap (single source: _sandbox_common) ---
# One budget, byte-based everywhere: the guest-side fd_write sink,
# the host-side capture-file read-back, and in-memory string truncation
# all measure encoded bytes, so the cap means the same thing at every
# layer. (Previously the in-memory truncation counted characters while
# the sink counted bytes — a two-byte-per-char discrepancy.) The budget,
# the wasmtime host stdin cap and the shared output helpers live in
# _sandbox_common; this module re-exports them (package __init__ and
# tests import them from here).
# Backwards-compatible alias (the budget used to be char-based).
_MAX_OUTPUT_CHARS = _MAX_OUTPUT_BYTES

# macOS temp-root exception + canonical denylist policy: the single source
# of truth lives in ephemora_cell._sandbox_common (shared by the preview1
# and component paths); the names are imported above so this module keeps
# referencing/exposing them as before.


# Trap classification, output capture and the interrupt-watcher loop are
# shared with the component path (single implementations in
# _sandbox_common; the names above re-export them for this module's own
# code and any external references).

# Process-wide engine pool. Created lazily on first use because
# engine_pool imports this module (circular import guard).
_ENGINE_POOL = None


def _get_engine_pool():
    """Return the process-wide EnginePool, creating it on first use."""
    global _ENGINE_POOL
    if _ENGINE_POOL is None:
        from .engine_pool import EnginePool

        _ENGINE_POOL = EnginePool()
    return _ENGINE_POOL


# --- Module size cap (single source: this module) -------------------------
# Cap on the .wasm file a run may load. Enforced on EVERY execution path
# (in-process preview1, in-process component, and both sides of the
# subprocess path) before the bytes are handed to the compiler, so the
# configured value never silently applies to only one path. The MCP tool
# registry uses the same default as its load guard.
DEFAULT_MAX_WASM_BYTES = 32 * 1024 * 1024
# Sentinel: 0 disables the cap. Interpreter guests are BYO binaries an order
# of magnitude larger than application modules (a CPython-WASI build is
# ~150 MB — docs/languages.md), so the caller who opts into one says so
# explicitly instead of passing a large number and hoping it is enough.
UNLIMITED_WASM_BYTES = 0


def module_size_cap_error(path: Path, max_wasm_bytes: int) -> str | None:
    """Return the rejection message when a module exceeds the cap.

    ``UNLIMITED_WASM_BYTES`` (0) disables the check. Negative caps are
    rejected by WASISandbox rather than interpreted here.
    """
    if max_wasm_bytes == UNLIMITED_WASM_BYTES:
        return None
    size = path.stat().st_size
    if size > max_wasm_bytes:
        return (
            f"WASM module exceeds size limit of {max_wasm_bytes} bytes: "
            f"{size} (set max_wasm_bytes higher, or "
            f"{UNLIMITED_WASM_BYTES} to disable the cap)"
        )
    return None


#: Sync entry points the P1 #12 blockade traps at the LINK layer. All three
#: carry ``(i32) -> (i32)`` and all three reach real host work: ``fd_sync`` is
#: Preview1's own sync call — the one a guest reaches through ``os.fsync``,
#: which ``define_wasi`` wires to a real ``fsync(2)`` — ``fd_datasync`` is its
#: sibling, and ``fd_psync`` does not exist in Preview1, so the Cell defines a
#: shim for it.
#:
#: Refusing these at the MODULE layer was the original design and it is wrong:
#: every wasm32-wasi Zig binary imports ``fd_sync`` and every CPython-WASI
#: guest imports ``fd_datasync``, in both cases without ever calling it
#: (measured: ``benchmarks/interpreter_guest/probe_datasync.py`` boots the
#: guest on a cold and a warm stdlib tree behind a full trap). An import
#: refusal therefore rejects toolchains instead of the harm. Interposing on
#: the call is what the published attack needs: a sync storm offloads work
#: into the host kernel and its own flushers, keeping the guest under 5 % CPU
#: while host I/O throughput collapses, so it cannot be metered — only
#: refused. (arXiv 2509.11242, USENIX Security '25.)
SYNC_CALL_TRAPS = ("fd_sync", "fd_datasync", "fd_psync")


def _limit_output(text: str, max_bytes: int = _MAX_OUTPUT_BYTES) -> str:
    """Truncate output to a UTF-8 byte budget.

    Called after every read() to bound stdout/stderr. Truncation happens
    on encoded bytes and re-decodes with errors='ignore' so a multi-byte
    sequence is never cut in half.
    """
    raw = text.encode("utf-8")
    if len(raw) > max_bytes:
        return raw[:max_bytes].decode("utf-8", errors="ignore") + "\n[... truncated]"
    return text


class ExecutionStatus(Enum):
    """Execution result status."""

    SUCCESS = "success"
    ERROR = "error"
    TIMEOUT = "timeout"
    FUEL_EXHAUSTED = "fuel_exhausted"
    MEMORY_EXCEEDED = "memory_exceeded"


@dataclass(frozen=True)
class WASIConfig:
    """Immutable configuration for the WASM sandbox.

    Attributes:
        max_memory_mb: Maximum memory in MB (default: 128).
        max_fuel: Maximum CPU fuel units (default: 1_000_000).
            WARNING: Setting to None allows unbounded compute — use only
            for trusted workloads.
        timeout_seconds: Maximum wall-clock execution time in seconds (default: 30).
        allow_dirs: Host directories pre-opened for the WASM guest (default: none).
            WARNING: Each entry grants full read/write access.
        allow_env: Environment variables forwarded to the guest (default: none).
        sandbox_base_dir: Base directory for the ephemeral sandbox temp dir.
            Set to "/dev/shm" on Linux for tmpfs execution.
        max_threads: Maximum threads (default: 1). Set to 1 for single-thread only.
        memory64: Enable 64-bit address-space memories (Wasm 3.0 memory64,
            default: False). Off by default for a deterministic security
            baseline; turn on per-config for workloads that must address
            more than 4 GiB in one memory. Store.set_limits still binds the
            actual committed size.
        max_gc_heap_mb: Declared cap for the Wasm GC heap in MB (default:
            None = unbounded by this knob). NOTE: wasmtime-py 47 exposes no
            GC-heap limiter binding (Store.set_limits covers linear memory
            only; upstream Rust has a ResourceLimiter GC hook that is not in
            the Python API), so this knob is recorded for observability and
            future enforcement — today the effective GC bound is max_fuel
            (see benchmarks/pocs/README.md).
        disk_quota_bytes: Hard per-file write cap for guest writes into
            preopened directories and the sandbox dir (default: 256 MiB,
            None = unlimited, for trusted workloads). Enforced in the
            subprocess isolation path via RLIMIT_FSIZE: a guest exceeding
            the quota gets a controlled write error (EFBIG) instead of
            filling host disk. In-process runs (use_subprocess=False)
            cannot enforce this without capping the host process itself —
            preopens there remain an explicitly granted, trusted
            capability.
        io_cpu_seconds: Wall for ALL host-side work a run induces
            (default: 2.0, None = unbounded for trusted workloads).
            Enforced in the subprocess isolation path: a worker watchdog
            reads getrusage CPU of the worker process — every unmetered
            host syscall (file writes, stat/open churn) shows up there —
            and interrupts the guest via epoch when exceeded (ADR-002).
            Fuel measures guest compute, not host work; this knob closes
            that gap. In-process runs are documented-trusted (S4
            precedent: rusage there would measure the host process).
        io_budget_bytes: Aggregate byte wall for guest writes into the
            sandbox dir (default: 64 MiB, None = unlimited). Enforced in
            BOTH paths by a watcher scanning the sandbox dir while the
            guest runs; breach interrupts the guest via epoch. The
            sandbox dir is the guest's scratch space — preopen trees are
            covered by io_cpu_seconds (their write() cost is CPU); a
            du-delta over preopens is the documented v2 option (ADR-002).
        max_wasm_bytes: Size cap for the module a run may load, in bytes
            (default: DEFAULT_MAX_WASM_BYTES = 32 MiB, 0 = no cap). Checked
            on every execution path before compilation, and in the
            isolation path by parent AND worker. The cap exists to bound
            compiler input per run; interpreter guests are BYO binaries an
            order of magnitude larger (~150 MB for CPython-WASI), so a run
            that wants one raises this value or sets it to 0 — see the
            interpreter profile.
        allow_fsync: Permit WASI sync calls instead of trapping them
            (default: False). Off keeps the P1 #12 disk-DoS posture on:
            ``fd_sync``, ``fd_datasync`` and ``fd_psync`` are shadowed with a
            trap at the link layer, so a guest that calls one is refused. On
            restores ``define_wasi``'s real implementation for callers that
            genuinely need durability — note that this is host work the guest
            does not pay for in fuel, so it is a posture change, not a free
            knob, and it is attested in the signed baseline. Interpreter
            guests do NOT need it: CPython imports ``fd_datasync`` but never
            calls it (measured).
            ``fd_psync`` stays trapped either way — Preview1 has no such call,
            so the Cell cannot serve it. One warning that matters: turning this
            on is NOT covered by ``io_cpu_seconds``. A sync storm is kernel
            and device work that the guest does not spend CPU on (arXiv
            2509.11242 measures it under 5 % guest CPU while host throughput
            collapses), so the rusage watchdog does not bound it — and an
            in-process run has no watchdog at all. Treat the knob as a
            capability grant, not a tuning dial.
    """

    max_memory_mb: int = 128
    max_fuel: int | None = 1_000_000
    timeout_seconds: int = 30
    allow_dirs: tuple[str, ...] = ()
    allow_env: tuple[tuple[str, str], ...] = ()
    sandbox_base_dir: str | None = None
    max_threads: int = 1  # 1 = single-thread only (default)
    memory64: bool = False  # Wasm 3.0 memory64 opt-in (default: off)
    max_gc_heap_mb: int | None = None
    disk_quota_bytes: int | None = 256 * 1024 * 1024
    io_cpu_seconds: float | None = 2.0
    io_budget_bytes: int | None = 64 * 1024 * 1024
    max_wasm_bytes: int = DEFAULT_MAX_WASM_BYTES
    allow_fsync: bool = False

    @property
    def memory_capacity_bytes(self) -> int:
        """Memory limit in bytes for wasmtime engine config.

        Returns:
            max_memory_mb * 1024 * 1024 (0 if max_memory_mb is 0).
        """
        if self.max_memory_mb <= 0:
            return 0
        return self.max_memory_mb * 1024 * 1024


@dataclass
class ExecutionResult:
    """Result of a WASM sandbox execution.

    Attributes:
        status: Execution status
        exit_code: WASM guest exit code (0 = success)
        stdout: Captured standard output
        stderr: Captured standard error
        elapsed_ms: Execution time in milliseconds
        fuel_consumed: CPU fuel units consumed
        sandbox_dir: Path to ephemeral sandbox directory
    """

    status: ExecutionStatus
    exit_code: int = 0
    stdout: str = ""
    stderr: str = ""
    elapsed_ms: float = 0.0
    fuel_consumed: int | None = None
    sandbox_dir: str | None = None
    # Host-side traceback for a run that died inside the HOST (an engine bug,
    # bad import wiring). Never surfaced to a client — `stderr` is, this is not.
    host_traceback: str | None = None
    # S2: directories ACTUALLY preopened for this run (post-filter, per
    # ABI) — the attestation input for ExecutionReport.security_baseline.
    effective_preopens: tuple[str, ...] = ()
    # ADR-002: I/O-budget observability. io_bytes_written = bytes the
    # guest wrote into the sandbox dir (watcher sample); io_budget_exceeded
    # = True when a run was interrupted for breaching io_budget_bytes.
    io_bytes_written: int | None = None
    io_budget_exceeded: bool = False
    # ADR-004: footprint of the StateStore at run end (None = no state).
    state_bytes: int | None = None
    # ADR-012: attribution the HOST decided, never the guest. Set by
    # WASISandbox.run when a tenant was attached — including on a refused
    # admission, whose receipt is evidence that the account was denied.
    # Subprocess workers never see either value.
    tenant: str | None = None
    tenant_budget_ref: str | None = None


class WASISandbox:
    """Minimal WASM sandbox for isolated code execution.

    Uses wasmtime with strict resource limits and capability-based I/O.
    No ambient authority — deny-all by default.

    Example:
        config = WASIConfig(max_memory_mb=128, max_fuel=1_000_000)
        sandbox = WASISandbox(config=config)
        result = sandbox.run("module.wasm")
        print(result.stdout)
    """

    # Dangerous directories that are NEVER preopened (P0 #2)
    # These are system-critical directories that could expose host state.
    # NOTE: "/private" is on the STRING denylist, but macOS temp roots
    # (/private/tmp, /private/var/folders) are explicitly ALLOWED via the
    # canonical exception list _CANONICAL_EXCEPTIONS. The STRING check is
    # only a pre-filter; the authority is the canonical realpath check in
    # _forbidden_canonical_match() which allows those two prefixes. This
    # two-layer design (string denylist + canonical allowlist) is intentional:
    # string matching is fast and catches obvious mistakes, canonical matching
    # closes symlink bypasses (e.g. /tmp -> /private/tmp on macOS).
    # The policy itself lives in _sandbox_common (shared with the component
    # path); the class attributes stay as aliases for compatibility.
    _DANGEROUS_DIRS: frozenset[str] = _DANGEROUS_DIRS_POLICY

    # Canonical (realpath) locations that are NEVER allowed in allow_dirs.
    # "/" is handled explicitly in _forbidden_canonical_match.
    _FORBIDDEN_CANONICAL: tuple[str, ...] = _FORBIDDEN_CANONICAL_POLICY

    def __init__(self, config: WASIConfig | None = None) -> None:
        """Initialize the sandbox with the given configuration.

        Args:
            config: WASIConfig instance. Uses defaults if None.

        Raises:
            ValueError: if any allow_dirs entry resolves into a forbidden
                host location (canonical path check).
        """
        if not HAS_WASMTIME:
            raise RuntimeError(
                "wasmtime is not installed. " "Install with: pip install wasmtime"
            )
        self._config = config or WASIConfig()
        self._sandbox_dir: str | None = None
        self._host_dir: str | None = None
        self._validate_allow_dirs(self._config.allow_dirs)
        self._check_dangerous_dirs(self._config.allow_dirs)
        if self._config.max_gc_heap_mb is not None and self._config.max_gc_heap_mb <= 0:
            raise ValueError(
                "max_gc_heap_mb must be a positive int (or None for unbounded)"
            )
        if (
            self._config.disk_quota_bytes is not None
            and self._config.disk_quota_bytes <= 0
        ):
            raise ValueError(
                "disk_quota_bytes must be a positive int (or None for unlimited)"
            )
        if self._config.io_cpu_seconds is not None and self._config.io_cpu_seconds <= 0:
            raise ValueError(
                "io_cpu_seconds must be a positive float (or None for unbounded)"
            )
        if (
            self._config.io_budget_bytes is not None
            and self._config.io_budget_bytes <= 0
        ):
            raise ValueError(
                "io_budget_bytes must be a positive int (or None for unlimited)"
            )
        if self._config.max_wasm_bytes < 0:
            raise ValueError(
                "max_wasm_bytes must be a non-negative int "
                f"(0 = {UNLIMITED_WASM_BYTES} disables the cap)"
            )

    def run(
        self,
        wasm_path: str,
        *,
        args: list[str] | None = None,
        stdin_data: str | None = None,
        use_subprocess: bool = False,
        use_engine_pool: bool = True,
        abi: str = "preview1",
        interrupt_event: threading.Event | None = None,
        state_store: StateStore | None = None,
        expected_sha256: str | None = None,
        tenant: TenantId | str | None = None,
        tenant_budget: CumulativeBudget | None = None,
        tenant_store: TenantStore | None = None,
    ) -> ExecutionResult:
        """Execute a WASM module in the sandbox.

        Args:
            wasm_path: Path to the .wasm file
            args: Command-line arguments for the WASM guest
            stdin_data: Data to provide on stdin
            use_subprocess: Run the sandbox in a disposable worker subprocess
                (process-level isolation: RLIMIT_NOFILE, address-space
                limits, module size cap, hard process timeout).
            use_engine_pool: Reuse pooled wasmtime engines and compiled
                module caches across runs instead of building a per-run
                engine. Ignored when use_subprocess is True.
            abi: "preview1" (default), "component" (WASI 0.2) or "auto"
                (detect by binary format magic bytes).
            interrupt_event: Optional event an EXTERNAL watchdog sets to
                interrupt the guest via epoch (ADR-002 io_cpu_seconds:
                the subprocess worker watches its own rusage CPU and
                signals here). When set, the run ends with an ERROR
                carrying the I/O-budget message.
            state_store: Optional :class:`ephemora_cell.state.StateStore`
                (ADR-004). Passing it IS the capability grant: the guest
                may import ``ephemora_state.get/set/del`` to carry named
                state across consecutive runs. Session-scoped and bounded;
                None (default) defines no state imports. In-process path
                only — subprocess runs cannot share host-side state.
            expected_sha256: Optional lowercase hex digest. When set, the
                module bytes are read once and verified BEFORE compiling
                (per-call module binding): executed bytes cannot drift
                from the registered digest. Applies to all three paths
                (preview1, component, subprocess worker).
            tenant: ADR-012 billing/attribution identity (operator-chosen,
                never guest-visible). None (default) = no accounting at all,
                which is the byte-identical pre-1.1 code path. Setting it
                requires ``tenant_store``.
            tenant_budget: Optional cross-run caps checked BEFORE the run
                starts. Needs ``tenant``; useless without one.
            tenant_store: The append-only book this tenant's runs are billed
                to. Admission and settlement happen here, around every
                execution path — including ``use_subprocess`` and
                ``abi="component"`` — because the choke point is this method.

        Returns:
            ExecutionResult with status, stdout, stderr, and timing. A refused
            admission is an ERROR whose stderr names the exhausted cap; nothing
            is started, no subprocess is spawned and no module is compiled.
        """
        if tenant is None:
            if tenant_budget is not None or tenant_store is not None:
                raise ValueError(
                    "tenant_budget/tenant_store without a tenant would record "
                    "nothing — pass tenant"
                )
            return self._execute(
                wasm_path,
                args=args,
                stdin_data=stdin_data,
                use_subprocess=use_subprocess,
                use_engine_pool=use_engine_pool,
                abi=abi,
                interrupt_event=interrupt_event,
                state_store=state_store,
                expected_sha256=expected_sha256,
            )
        if tenant_store is None:
            raise ValueError(
                f"tenant {tenant!r} has no tenant_store: an id without a book "
                "silently bills nothing"
            )
        admission = tenant_store.admit(
            tenant,
            reserve=self.reservation(),
            budget=tenant_budget,
        )
        if not admission.allowed or admission.admit_id is None:
            return ExecutionResult(
                status=ExecutionStatus.ERROR,
                stderr=(
                    f"tenant budget exhausted: {admission.limit} "
                    f"(tenant {tenant}, {admission.reason})"
                ),
                tenant=str(tenant),
                tenant_budget_ref=tenant_budget.ref() if tenant_budget else None,
            )
        started = time.monotonic()
        try:
            result = self._execute(
                wasm_path,
                args=args,
                stdin_data=stdin_data,
                use_subprocess=use_subprocess,
                use_engine_pool=use_engine_pool,
                abi=abi,
                interrupt_event=interrupt_event,
                state_store=state_store,
                expected_sha256=expected_sha256,
            )
        except BaseException:
            try:
                # The run never produced anything: hand the reservation back.
                # Leaving it open would let a crashing caller lock its own
                # tenant out until the TTL expires. Swallowing book errors here
                # is deliberate — they must not replace the run's own traceback.
                tenant_store.expire(tenant, admission.admit_id)
            except Exception:  # pragma: no cover - book unreadable mid-crash
                pass
            raise
        breach = result.io_budget_exceeded or result.status in (
            ExecutionStatus.TIMEOUT,
            ExecutionStatus.FUEL_EXHAUSTED,
            ExecutionStatus.MEMORY_EXCEEDED,
        )
        charge = Charge(
            fuel=result.fuel_consumed or 0,
            output_bytes=len(result.stdout.encode("utf-8"))
            + len(result.stderr.encode("utf-8"))
            + (result.io_bytes_written or 0),
            wall_ms=round((time.monotonic() - started) * 1000),
        )
        tenant_store.settle(
            tenant,
            admission.admit_id,
            charge=charge,
            violation=breach,
            # No fuel figure means the worker died before reporting one: the
            # run is billed in wall time and flagged, never as free.
            unknown=result.fuel_consumed is None,
        )
        result.tenant = str(tenant)
        result.tenant_budget_ref = tenant_budget.ref() if tenant_budget else None
        return result

    def reservation(self) -> Charge:
        """The most a run under THIS config could take, per dimension.

        Deliberately derived from the config rather than passed in: the
        reservation is the same ceiling the sandbox stops at, so a caller
        cannot bill a rival tenant full budgets by reserving loudly. A knob
        set to None (unbounded by design) contributes 0, which is exactly why
        :class:`~ephemora_cell.tenant.CumulativeBudget` also compares what
        previous runs ACTUALLY consumed — see ADR-012.
        """
        return Charge(
            fuel=self._config.max_fuel or 0,
            output_bytes=2 * _MAX_OUTPUT_BYTES + (self._config.io_budget_bytes or 0),
            wall_ms=int(self._config.timeout_seconds * 1000),
        )

    def _execute(
        self,
        wasm_path: str,
        *,
        args: list[str] | None = None,
        stdin_data: str | None = None,
        use_subprocess: bool = False,
        use_engine_pool: bool = True,
        abi: str = "preview1",
        interrupt_event: threading.Event | None = None,
        state_store: StateStore | None = None,
        expected_sha256: str | None = None,
    ) -> ExecutionResult:
        """The three execution paths, unbilled. Call through :meth:`run`."""
        if use_subprocess:
            from .process_executor import run_isolated

            report = run_isolated(
                wasm_path,
                self._config,
                args=args,
                stdin_data=stdin_data,
                abi=abi,
                expected_sha256=expected_sha256,
            )
            return self._result_from_report(report)

        if abi in ("auto", "component"):
            from .wasi_02 import ComponentSandbox, is_component_binary

            if abi == "component" or is_component_binary(wasm_path):
                return ComponentSandbox(self._config).run(
                    wasm_path,
                    args=args,
                    stdin_data=stdin_data,
                    expected_sha256=expected_sha256,
                )

        wasm_path_resolved = Path(wasm_path).resolve()
        if not wasm_path_resolved.exists():
            return ExecutionResult(
                status=ExecutionStatus.ERROR,
                stderr=f"WASM module not found: {wasm_path}",
            )

        cap_error = module_size_cap_error(
            wasm_path_resolved, self._config.max_wasm_bytes
        )
        if cap_error is not None:
            return ExecutionResult(status=ExecutionStatus.ERROR, stderr=cap_error)

        # Create ephemeral sandbox directory. A previous run() on the same
        # instance left its dirs behind (leak) — clean them now; the
        # caller was expected to call cleanup() but repeat-run must not
        # accumulate one dir pair per run. Skip the cleanup when the module
        # to run lives inside one of those dirs (caller-managed placement).
        wasm_resolved = Path(wasm_path).resolve()
        previous = (self._sandbox_dir, self._host_dir)
        self._sandbox_dir = None
        self._host_dir = None
        for prev in previous:
            if prev and wasm_resolved.is_relative_to(Path(prev).resolve()):
                continue
            if prev:
                import shutil as _shutil

                _shutil.rmtree(prev, ignore_errors=True)
        base = self._config.sandbox_base_dir or tempfile.gettempdir()
        sandbox_dir = tempfile.mkdtemp(prefix="ephemora_cell_", dir=base)
        self._sandbox_dir = sandbox_dir
        # Host-owned output directory — NEVER preopened or visible to the guest.
        # Guest output is captured here so the guest cannot tamper with the
        # files the host later reads back (CWE-59 host-read closure).
        host_dir = tempfile.mkdtemp(prefix="ephemora_host_", dir=base)
        self._host_dir = host_dir

        stdout_path: str | None = None
        stderr_path: str | None = None
        effective_preopens: tuple[str, ...] = ()

        start_time = time.monotonic()

        try:
            # Per-run engine for epoch isolation, or a pooled engine under a
            # refcount lease: the pool's shared ticker advances the
            # epoch, the per-store deadline below enforces THIS run's
            # timeout — the old per-run increment timer tripped every other
            # store sharing the engine (epoch crossfire).
            #
            # ADR-002: I/O-budget interruption relies on the deadline=1 +
            # single-increment semantics (immediate trap). Pooled stores
            # carry far-future deadlines (timeout/tick ticks), and
            # set_epoch_deadline from a watcher thread does not affect a
            # running guest — so budget-guarded runs use a per-run engine.
            # The worker process is single-run anyway (no crossfire).
            io_budget_active = (
                interrupt_event is not None or self._config.io_budget_bytes is not None
            )
            if io_budget_active:
                use_engine_pool = False
            pool = None
            engine = None
            epoch_deadline = 1
            pool_retained = False
            if use_engine_pool:
                pool = _get_engine_pool()
                engine = pool.engine_for(self._config)
                pool.retain(engine)
                pool_retained = True
                if self._config.timeout_seconds and self._config.timeout_seconds > 0:
                    epoch_deadline = max(
                        1,
                        math.ceil(self._config.timeout_seconds / pool.TICK_SECONDS),
                    )
            else:
                # Hardened proposal-policy engine — ONE shared builder
                # (ephemora_cell._engine_config) serves the inline preview1
                # path, the engine pool and the component path, so the
                # freeze cannot drift between construction sites again.
                engine_config = build_engine_config(
                    max_fuel=self._config.max_fuel,
                    memory64=self._config.memory64,
                )
                engine = Engine(engine_config)

            if expected_sha256 is not None:
                # Per-call module binding: read once, hash THOSE bytes,
                # compile those bytes — no re-read between verify and
                # compile, so the executed module cannot drift from the
                # registered digest (a swapped on-disk file is refused).
                try:
                    wasm_bytes = wasm_path_resolved.read_bytes()
                except OSError as e:
                    return ExecutionResult(
                        status=ExecutionStatus.ERROR,
                        stderr=f"WASM module unreadable: {e}",
                    )
                if hashlib.sha256(wasm_bytes).hexdigest() != expected_sha256:
                    return ExecutionResult(
                        status=ExecutionStatus.ERROR,
                        stderr=(
                            "module hash mismatch — executed bytes do not "
                            "match the registered module digest"
                        ),
                    )
                if pool is not None:
                    module = pool.cached_module_data(engine, wasm_bytes)
                else:
                    module = Module(engine, wasm_bytes)
            elif pool is not None:
                module = pool.cached_module(engine, str(wasm_path_resolved))
            else:
                module = Module.from_file(engine, str(wasm_path_resolved))

            store = Store(engine)
            if self._config.max_fuel is not None:
                store.set_fuel(self._config.max_fuel)
            # Real memory limit: Store.set_limits (Config.memory_max_bytes is a
            # no-op in wasmtime-py 47). Must be set on the Store, not the engine.
            if self._config.memory_capacity_bytes > 0:
                store.set_limits(memory_size=self._config.memory_capacity_bytes)
            store.set_epoch_deadline(epoch_deadline)

            # Configure WASI
            wasi_cfg = WasmtimeWasiConfig()
            # Neutral argv[0] — never leak the host module path to the guest.
            wasi_cfg.argv = ["wasm-module"] + (args or [])

            stdout_path = os.path.join(host_dir, "stdout.txt")
            stderr_path = os.path.join(host_dir, "stderr.txt")
            # Byte-budgeted output: once the shared budget is exhausted the
            # guest's fd_write fails with ENOSPC, bounding on-disk growth.
            budget: list[int] = [_MAX_OUTPUT_BYTES]
            wasi_cfg.stdout_custom = self._make_output_sink(stdout_path, budget)
            wasi_cfg.stderr_custom = self._make_output_sink(stderr_path, budget)

            if stdin_data:
                if len(stdin_data.encode("utf-8")) > STDIN_MAX_BYTES:
                    return ExecutionResult(
                        status=ExecutionStatus.ERROR,
                        stderr=(
                            f"stdin_data exceeds the wasmtime host cap of "
                            f"{STDIN_MAX_BYTES} bytes; wasmtime silently truncates "
                            "larger stdin on fd 0 — pass input via a preopened file "
                            "instead"
                        ),
                        sandbox_dir=sandbox_dir,
                    )
                stdin_path = os.path.join(host_dir, "stdin.txt")
                with open(stdin_path, "w") as f:
                    f.write(stdin_data)
                wasi_cfg.stdin_file = stdin_path

            # P0 #2: Filter dangerous dirs, then revalidate each entry at
            # grant time (TOCTOU) and record what was ACTUALLY preopened
            # (S2 attestation input).
            safe_dirs = self._filter_dangerous_dirs(self._config.allow_dirs)
            effective_preopens = self._grant_preopens(wasi_cfg, safe_dirs, sandbox_dir)

            if self._config.allow_env:
                wasi_cfg.env = list(self._config.allow_env)

            store.set_wasi(wasi_cfg)

            linker = Linker(engine)
            linker.define_wasi()

            # ADR-004: named state — the passed StateStore is the grant.
            if state_store is not None:
                from .state import make_state_imports

                for name, (params, results, cb) in make_state_imports(
                    state_store
                ).items():
                    linker.define(
                        store,
                        "ephemora_state",
                        name,
                        wasmtime.Func(
                            store,
                            wasmtime.FuncType(params, results),
                            cb,
                            access_caller=True,
                        ),
                    )

            # P1 #12, call layer: shadow the sync entry points with a trap, so
            # a guest that actually syncs cannot hammer the host disk.
            # Importing them stays legal for every guest — which is the whole
            # point: the harm is the call, not the symbol. fd_psync is
            # registered unconditionally, because Preview1 defines no such call
            # and a shim is the only answer the Cell can give. fd_sync and
            # fd_datasync ARE defined by define_wasi and wired to real host
            # syncs, so they are shadowed here unless the run opted into sync.
            def _fsync_trap(ctx: wasmtime.Caller) -> None:
                """Trap fsync/fdatasync calls — blocked by sandbox."""
                raise wasmtime.Trap("fsync/fdatasync blocked by sandbox")

            sync_traps = [
                name
                for name in SYNC_CALL_TRAPS
                if name == "fd_psync" or not self._config.allow_fsync
            ]
            linker.allow_shadowing = True
            for sync_name in sync_traps:
                try:
                    linker.define(
                        store,
                        "wasi_snapshot_preview1",
                        sync_name,
                        wasmtime.Func(
                            store,
                            wasmtime.FuncType(
                                [wasmtime.ValType.i32()],
                                [wasmtime.ValType.i32()],
                            ),
                            _fsync_trap,
                        ),
                    )
                except Exception:
                    # Not definable in this wasmtime version — skip
                    pass

            # Cached modules must only be instantiated under the pool's
            # per-engine lock — wasmtime Module instances are not thread-safe.
            if pool is not None:
                with pool.locked(engine):
                    instance = linker.instantiate(store, module)
            else:
                instance = linker.instantiate(store, module)

            start_func = instance.exports(store).get("_start")
            if not isinstance(start_func, wasmtime.Func):
                return ExecutionResult(
                    status=ExecutionStatus.ERROR,
                    stderr="WASM module has no _start export",
                    sandbox_dir=sandbox_dir,
                    effective_preopens=effective_preopens,
                )

            # Timeout daemon — only for per-run engines. Pooled engines have
            # a shared ticker; per-run incrementing would trip sibling runs'
            # deadlines (S3 epoch crossfire).
            timeout_event = threading.Event()

            if pool is None:
                _start_epoch_timer(engine, timeout_event, self._config.timeout_seconds)

            # ADR-002 I/O budgets. Both watchers interrupt the guest via
            # epoch — for pooled engines one extra increment can pull a
            # sibling store's deadline one tick (50 ms) earlier, accepted.
            io_budget_exceeded = False
            io_bytes_written = 0

            def _sandbox_dir_size() -> int:
                total = 0
                for root, _, files in os.walk(sandbox_dir):
                    for name in files:
                        try:
                            total += os.path.getsize(os.path.join(root, name))
                        except OSError:
                            pass
                return total

            def _bytes_watch() -> None:
                # Precise byte wall for the guest scratch dir (ADR-002).
                limit = self._config.io_budget_bytes
                nonlocal io_bytes_written, io_budget_exceeded
                while not timeout_event.is_set():
                    io_bytes_written = _sandbox_dir_size()
                    if limit is not None and io_bytes_written > limit:
                        io_budget_exceeded = True
                        engine.increment_epoch()
                        return
                    timeout_event.wait(0.1)

            if interrupt_event is not None:
                _start_interrupt_watch(engine, interrupt_event, timeout_event)
            if self._config.io_budget_bytes is not None:
                threading.Thread(target=_bytes_watch, daemon=True).start()

            try:
                start_func(store)
                exit_code = 0
            except Trap as trap:
                timeout_event.set()
                trap_msg = str(trap)

                if "epoch" in trap_msg.lower() or "interrupt" in trap_msg.lower():
                    # ADR-002: an I/O-budget watcher fired this epoch —
                    # report as budget breach, not as a plain timeout.
                    if io_budget_exceeded:
                        return ExecutionResult(
                            status=ExecutionStatus.ERROR,
                            stderr=(
                                f"I/O budget exceeded: guest wrote "
                                f"{io_bytes_written} bytes to the sandbox dir "
                                f"(io_budget_bytes={self._config.io_budget_bytes})"
                            ),
                            stdout=_read_capped_output(stdout_path),
                            sandbox_dir=sandbox_dir,
                            elapsed_ms=(time.monotonic() - start_time) * 1000,
                            io_bytes_written=io_bytes_written,
                            io_budget_exceeded=True,
                            effective_preopens=effective_preopens,
                        )
                    return ExecutionResult(
                        status=ExecutionStatus.TIMEOUT,
                        stderr=f"Timeout after {self._config.timeout_seconds}s: {trap_msg}",
                        sandbox_dir=sandbox_dir,
                        elapsed_ms=(time.monotonic() - start_time) * 1000,
                        io_bytes_written=io_bytes_written,
                        effective_preopens=effective_preopens,
                    )
                if "fuel" in trap_msg.lower():
                    stderr_captured = _read_capped_output(stderr_path)
                    return ExecutionResult(
                        status=ExecutionStatus.FUEL_EXHAUSTED,
                        stderr=_limit_output(
                            f"Fuel exhausted: {trap_msg}"
                            + (("\n" + stderr_captured) if stderr_captured else "")
                        ),
                        stdout=_read_capped_output(stdout_path),
                        elapsed_ms=(time.monotonic() - start_time) * 1000,
                        fuel_consumed=self._fuel_consumed(store),
                        sandbox_dir=sandbox_dir,
                        effective_preopens=effective_preopens,
                    )
                if _is_memory_fault_trap(trap_msg):
                    return ExecutionResult(
                        status=ExecutionStatus.MEMORY_EXCEEDED,
                        stderr=(
                            f"Memory limit exceeded (max {self._config.max_memory_mb} "
                            f"MiB): {trap_msg}"
                        ),
                        stdout=_read_capped_output(stdout_path),
                        sandbox_dir=sandbox_dir,
                        elapsed_ms=(time.monotonic() - start_time) * 1000,
                        effective_preopens=effective_preopens,
                    )

                # Handle WASI proc_exit
                exit_code = 1
                exit_match = re.search(r"exit status (\d+)", trap_msg)
                if exit_match:
                    exit_code = int(exit_match.group(1))

                # proc_exit with code 0 = clean exit (SUCCESS)
                if exit_code == 0:
                    stdout_raw = _read_capped_output(stdout_path)
                    stderr_raw = _read_capped_output(stderr_path)
                    fuel_consumed = None
                    if self._config.max_fuel is not None:
                        try:
                            remaining = store.get_fuel()
                            fuel_consumed = self._config.max_fuel - remaining
                        except Exception:
                            pass
                    return ExecutionResult(
                        status=ExecutionStatus.SUCCESS,
                        exit_code=0,
                        stdout=stdout_raw,
                        stderr=stderr_raw,
                        elapsed_ms=(time.monotonic() - start_time) * 1000,
                        fuel_consumed=fuel_consumed,
                        sandbox_dir=sandbox_dir,
                        io_bytes_written=io_bytes_written,
                        state_bytes=(
                            state_store.total_bytes if state_store is not None else None
                        ),
                        effective_preopens=effective_preopens,
                    )

                # Read captured output even on Trap (non-zero exit)
                stdout = _read_capped_output(stdout_path)
                stderr_from_file = _read_capped_output(stderr_path)

                # Limit output to prevent buffer bloat
                stderr_combined = _limit_output(
                    trap_msg + ("\n" + stderr_from_file if stderr_from_file else "")
                )

                return ExecutionResult(
                    status=ExecutionStatus.ERROR,
                    exit_code=exit_code,
                    stdout=stdout,
                    stderr=stderr_combined,
                    sandbox_dir=sandbox_dir,
                    elapsed_ms=(time.monotonic() - start_time) * 1000,
                    effective_preopens=effective_preopens,
                )
            finally:
                timeout_event.set()

            elapsed_ms = (time.monotonic() - start_time) * 1000

            # Read captured output and limit to prevent buffer bloat
            stdout_raw = _read_capped_output(stdout_path)
            stderr_raw = _read_capped_output(stderr_path)
            stdout = stdout_raw
            stderr = stderr_raw

            # Get fuel consumed
            fuel_consumed = None
            if self._config.max_fuel is not None:
                try:
                    remaining = store.get_fuel()
                    fuel_consumed = self._config.max_fuel - remaining
                except Exception:
                    pass

            return ExecutionResult(
                status=ExecutionStatus.SUCCESS,
                exit_code=exit_code,
                stdout=stdout,
                stderr=stderr,
                elapsed_ms=elapsed_ms,
                fuel_consumed=fuel_consumed,
                sandbox_dir=sandbox_dir,
                io_bytes_written=io_bytes_written,
                state_bytes=(
                    state_store.total_bytes if state_store is not None else None
                ),
                effective_preopens=effective_preopens,
            )

        except Exception as e:
            if os.environ.get("CELL_DEBUG_TB_FILE"):  # debug branch only
                with open(os.environ["CELL_DEBUG_TB_FILE"], "a") as _tbh:
                    _tbh.write(
                        f"TEST: {os.environ.get('PYTEST_CURRENT_TEST', '?')}\n"
                        + traceback.format_exc()
                        + "\n"
                    )
            elapsed_ms = (time.monotonic() - start_time) * 1000
            exit_code = 1
            exit_match = re.search(r"exit status (\d+)", str(e))
            if exit_match:
                exit_code = int(exit_match.group(1))

            stdout = _read_capped_output(stdout_path) if stdout_path else ""
            stderr_from_file = _read_capped_output(stderr_path) if stderr_path else ""

            # Out-of-fuel can surface as a generic exception when the trap
            # fires inside a host function (e.g. fd_write) instead of a
            # guest instruction — classify it as FUEL_EXHAUSTED, not ERROR.
            if "all fuel consumed" in str(e).lower():
                return ExecutionResult(
                    status=ExecutionStatus.FUEL_EXHAUSTED,
                    exit_code=1,
                    stdout=stdout,
                    stderr=_limit_output(str(e) + stderr_from_file),
                    elapsed_ms=elapsed_ms,
                    fuel_consumed=self._fuel_consumed(store),
                    sandbox_dir=sandbox_dir,
                    state_bytes=(
                        state_store.total_bytes if state_store is not None else None
                    ),
                    effective_preopens=effective_preopens,
                )

            # proc_exit with code 0 = clean exit (even if it raised as Exception)
            if exit_code == 0:
                fuel_consumed = None
                if self._config.max_fuel is not None:
                    try:
                        remaining = store.get_fuel()
                        fuel_consumed = self._config.max_fuel - remaining
                    except Exception:
                        pass
                return ExecutionResult(
                    status=ExecutionStatus.SUCCESS,
                    exit_code=0,
                    stdout=stdout,
                    stderr=_limit_output(str(e) + stderr_from_file),
                    elapsed_ms=elapsed_ms,
                    fuel_consumed=fuel_consumed,
                    sandbox_dir=sandbox_dir,
                    state_bytes=(
                        state_store.total_bytes if state_store is not None else None
                    ),
                    effective_preopens=effective_preopens,
                )

            return ExecutionResult(
                status=ExecutionStatus.ERROR,
                exit_code=exit_code,
                stdout=stdout,
                # N-1 kept, with the exposure fixed: the host traceback stays
                # diagnosable, but in its OWN field. `stderr` is what the MCP
                # layer hands the client, and a host traceback names absolute
                # paths, the interpreter version and the site-packages layout of
                # the machine running the sandbox.
                stderr=_limit_output(str(e) + "\n" + stderr_from_file),
                host_traceback=_limit_output(traceback.format_exc(), 20000),
                elapsed_ms=elapsed_ms,
                sandbox_dir=sandbox_dir,
                state_bytes=(
                    state_store.total_bytes if state_store is not None else None
                ),
                effective_preopens=effective_preopens,
            )
        finally:
            if pool is not None and pool_retained:
                pool.release(engine)

    # --- Helper methods for testing (P0 #1) ---

    def _fuel_consumed(self, store) -> int | None:
        """Fuel units consumed at call time (None = unmetered run).

        An out-of-fuel trap proves the budget was spent; if the store
        refuses a fuel read past the trap, report the full budget instead
        of an unaccounted None.
        """
        return _fuel_consumed_impl(
            self._config.max_fuel, store, on_read_error="full_budget"
        )

    def _create_test_wasm(self, wat_bytes: bytes, filename: str) -> Path:
        """Write raw WASM bytes to the sandbox dir for testing.

        Only used in test code and examples to create test WASM modules.
        """
        sandbox_path = Path(self._sandbox_dir or tempfile.gettempdir())
        path = sandbox_path / filename
        path.write_bytes(wat_bytes)
        return path

    # --- Security helpers (Preopen-Default-Deny + canonical allowlist) ---

    def _get_dangerous_dirs(self) -> frozenset[str]:
        """Return the set of directories that are NEVER preopened."""
        return self._DANGEROUS_DIRS

    @classmethod
    def _forbidden_canonical_match(cls, canon: str) -> str | None:
        """Return the forbidden canonical location that ``canon`` resolves into.

        Delegates to the shared policy in ``_sandbox_common`` (one
        implementation for the preview1 and component paths). ``canon`` is
        expected to already be realpath-normalized. "/" is always forbidden;
        every other forbidden location is checked as a realpath prefix,
        closing symlink-based bypasses such as /private/etc on macOS. The
        macOS temp roots (``_CANONICAL_EXCEPTIONS``) are allowed explicitly.
        """
        return _forbidden_canonical_match_impl(canon)

    @staticmethod
    def _canonicalize(dir_path: str) -> str:
        return _canonicalize_dir(dir_path)

    @staticmethod
    def _split_dir_mapping(entry: str) -> tuple[str, str]:
        """Split an allow_dirs entry into (host_path, guest_name).

        Entries may use the wasmtime-style ``host::guest`` mapping (needed
        when the guest expects the preopen under a specific name, e.g. "/"
        for wasi-libc relative-path resolution); a plain entry preopens the
        host path under its own name. Validation always applies to the
        HOST side; the guest name is only a label inside the sandbox.
        """
        return _split_dir_mapping_impl(entry)

    @staticmethod
    def _validate_allow_dirs(allow_dirs: tuple[str, ...]) -> None:
        """Fail fast if any allow_dirs entry is canonically forbidden.

        Delegates to the shared policy in ``_sandbox_common``.

        Raises:
            ValueError: with the offending entry and its canonical path.
        """
        _validate_allow_dirs_impl(
            allow_dirs,
            split_dir_mapping=WASISandbox._split_dir_mapping,
            canonicalize=WASISandbox._canonicalize,
            forbidden_canonical_match=WASISandbox._forbidden_canonical_match,
        )

    @staticmethod
    def _check_dangerous_dirs(allow_dirs: tuple[str, ...]) -> None:
        """Warn if allow_dirs entries match the denylist by string.

        Delegates to the shared policy in ``_sandbox_common``. The canonical
        realpath check already rejects true forbidden paths; this remains as
        an additional visibility layer for suspicious strings.
        """
        _check_dangerous_dirs_impl(
            allow_dirs,
            dangerous_dirs=WASISandbox._DANGEROUS_DIRS,
            split_dir_mapping=WASISandbox._split_dir_mapping,
            under_canonical_exception=_under_canonical_exception,
            # One extra delegation frame vs the historical inline
            # implementation — keep the warning attributed to the
            # WASISandbox(...) call site.
            stacklevel=4,
        )

    @staticmethod
    def _dangerous_prefix_match(dir_path: str) -> str:
        """Return which dangerous prefix a directory path matches, or empty string."""
        for dd in sorted(WASISandbox._DANGEROUS_DIRS, key=len, reverse=True):
            if dd == "/":
                continue  # Skip root — everything starts with /
            if dd and (dir_path == dd or dir_path.startswith(dd + "/")):
                return dd
        return ""

    @staticmethod
    def _grant_preopens(
        wasi_cfg: WasmtimeWasiConfig,
        safe_dirs: tuple[str, ...],
        sandbox_dir: str | None,
    ) -> tuple[str, ...]:
        """Preopen the filtered dirs (plus the sandbox dir) and record what
        was ACTUALLY granted (S2 attestation input).

        Delegates to the shared implementation in ``_sandbox_common`` (the
        component path calls the same one — no /sandbox mount there).
        """
        return _grant_preopens_impl(
            wasi_cfg,
            safe_dirs,
            sandbox_dir,
            split_dir_mapping=WASISandbox._split_dir_mapping,
            canonicalize=WASISandbox._canonicalize,
            forbidden_canonical_match=WASISandbox._forbidden_canonical_match,
            # One extra delegation frame vs the historical inline
            # implementation — keep the warnings attributed to the run()
            # grant line.
            stacklevel=3,
        )

    def _filter_dangerous_dirs(self, allow_dirs: tuple[str, ...]) -> tuple[str, ...]:
        """Filter allow_dirs down to entries that pass the canonical allowlist.

        ONE shared implementation (``_sandbox_common.filter_dangerous_dirs``)
        serves the Preview1 AND the component path: mapping-style
        ``host::guest`` entries are split FIRST and the HOST part is checked
        against the canonical allowlist and the string denylist (except the
        macOS temp roots, which the canonical check decides).
        """
        return _filter_dangerous_dirs_impl(
            allow_dirs,
            split_dir_mapping=self._split_dir_mapping,
            canonicalize=self._canonicalize,
            forbidden_canonical_match=self._forbidden_canonical_match,
            dangerous_dirs=self._DANGEROUS_DIRS,
            under_canonical_exception=_under_canonical_exception,
        )

    @staticmethod
    def _make_output_sink(file_path: str, budget: list[int]):
        """Build a WASI stdout/stderr sink that enforces the byte budget.

        Thin delegate to the shared implementation in ``_sandbox_common``
        (the component path uses the same sink).
        """
        return _make_output_sink(file_path, budget)

    # --- P0 #3: Sandbox dir cleanup ---

    def cleanup(self) -> list[str]:
        """Remove the ephemeral sandbox and host-owned capture directories.

        Returns the paths that SURVIVED removal — empty means the run really was
        ephemeral. ``shutil.rmtree(..., ignore_errors=True)`` used to swallow
        every failure here, so a directory that could not be deleted (permissions
        after an abrupt kill, an immutable flag, a read-only mount) was reported
        as cleaned. The product promise is "no execution state survives into the
        next execution", so a residue is a fact callers and logs must be able to
        see, not something to hide.
        """
        import logging
        import shutil

        leftovers: list[str] = []
        for attr in ("_sandbox_dir", "_host_dir"):
            dir_path = getattr(self, attr, None)
            if dir_path is None:
                continue
            try:
                shutil.rmtree(dir_path)
            except FileNotFoundError:
                pass
            except OSError as e:
                logging.getLogger(__name__).warning(
                    "sandbox cleanup failed, residue survives at %s: %s", dir_path, e
                )
                if os.path.exists(dir_path):
                    leftovers.append(str(dir_path))
            setattr(self, attr, None)
        return leftovers

    @property
    def sandbox_dir(self) -> str | None:
        """Current sandbox directory path (for external access)."""
        return self._sandbox_dir

    @staticmethod
    def _result_from_report(report: dict) -> ExecutionResult:
        """Convert a process_executor report dict into an ExecutionResult."""
        return ExecutionResult(
            status=ExecutionStatus(report["status"]),
            exit_code=int(report.get("exit_code", 1)),
            stdout=str(report.get("stdout", "")),
            stderr=str(report.get("stderr", "")),
            elapsed_ms=float(report.get("elapsed_ms", 0.0)),
            fuel_consumed=report.get("fuel_consumed"),
            sandbox_dir=report.get("sandbox_dir"),
            effective_preopens=tuple(report.get("effective_preopens", ())),
            io_bytes_written=report.get("io_bytes_written"),
            io_budget_exceeded=bool(report.get("io_budget_exceeded", False)),
        )


def run_wasm(
    module_path: str,
    *,
    config: WASIConfig | None = None,
    max_memory_mb: int | None = None,
    max_fuel: int | None = None,
    timeout_seconds: int | None = None,
    allow_dirs: tuple[str, ...] | None = None,
    allow_env: tuple[tuple[str, str], ...] | None = None,
    args: list[str] | None = None,
    stdin_data: str | None = None,
    use_subprocess: bool = False,
    abi: str = "auto",
    memory64: bool | None = None,
    max_wasm_bytes: int | None = None,
) -> ExecutionResult:
    """Convenience wrapper for single-shot WASM execution.

    Args:
        config: Full :class:`WASIConfig` — carries every knob the flat
            parameters don't reach (io budgets, disk quota, GC-heap knob,
            sandbox base dir, thread/memory64 baseline). Flat keyword
            arguments, when given, override the matching ``config``
            fields; with neither, WASIConfig defaults apply. For state
            stores, engine-pool control, external interrupts and tenant
            accounting (ADR-012) use :meth:`WASISandbox.run` directly.
        stdin_data: Data to provide on stdin (subject to STDIN_MAX_BYTES).
        abi: "auto" (default — detects components by magic bytes),
            "preview1" or "component".
        memory64: Enable Wasm 3.0 memory64 (64-bit address space) for this
            run. Off by default.
        max_wasm_bytes: Module size cap for this run, overriding the
            config's value (0 = no cap — the opt-in for BYO interpreter
            binaries). Unset keeps the config/profile cap.
    """
    if config is None:
        config = WASIConfig()
    if max_memory_mb is not None:
        config = replace(config, max_memory_mb=max_memory_mb)
    if max_fuel is not None:
        config = replace(config, max_fuel=max_fuel)
    if timeout_seconds is not None:
        config = replace(config, timeout_seconds=timeout_seconds)
    if allow_dirs is not None:
        config = replace(config, allow_dirs=allow_dirs)
    if allow_env is not None:
        config = replace(config, allow_env=allow_env)
    if memory64 is not None:
        config = replace(config, memory64=memory64)
    if max_wasm_bytes is not None:
        config = replace(config, max_wasm_bytes=max_wasm_bytes)
    sandbox = WASISandbox(config=config)
    result = sandbox.run(
        module_path,
        args=args or [],
        stdin_data=stdin_data,
        use_subprocess=use_subprocess,
        abi=abi,
    )
    sandbox.cleanup()
    # The sandbox dir no longer exists — do not hand the caller a dangling
    # path (correctness fix).
    result.sandbox_dir = None
    return result
