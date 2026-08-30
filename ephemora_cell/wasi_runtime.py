# Ephemora Cell WASM Runtime
# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 Michael Soppa
"""
Ephemora Cell — Isolated WASM sandbox with resource limits.

Decoupled WASMtime Runtime — Pure WASM execution with fuel metering,
memory limits, timeouts, and preopened directories.

This is a standalone wasmtime wrapper for public distribution.
"""

from __future__ import annotations

import math
import os
import re
import tempfile
import threading
import time
from dataclasses import dataclass
from enum import Enum
from pathlib import Path

from ephemora_cell.state import StateStore

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


# --- Output Budget (max 10 KB of UTF-8 bytes per execution) ---
# One budget, byte-based everywhere: the guest-side fd_write sink,
# the host-side capture-file read-back, and in-memory string truncation
# all measure encoded bytes, so the cap means the same thing at every
# layer. (Previously the in-memory truncation counted characters while
# the sink counted bytes — a two-byte-per-char discrepancy.)
_MAX_OUTPUT_BYTES = 10_000
# Backwards-compatible alias (the budget used to be char-based).
_MAX_OUTPUT_CHARS = _MAX_OUTPUT_BYTES
# Host-side stdin cap: wasmtime's WASI preview1 host feeds fd 0 from a fixed
# worker-thread buffer (crates/wasi/src/cli/worker_thread_stdin.rs), silently
# truncating anything larger. Ephemora Cell never passes more than this to a
# guest — larger input must be read from a preopened file instead.
STDIN_MAX_BYTES = 9_216
# WASI errno returned to the guest once the output budget is exhausted.
_WASI_ERRNO_NOSPC = 51

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


def _is_memory_fault_trap(message: str) -> bool:
    """True when a wasmtime trap is a memory violation (OOB access, fault, or
    failed memory growth) — mapped to MEMORY_EXCEEDED instead of ERROR."""
    lowered = message.lower()
    return (
        "out of bounds memory access" in lowered
        or "memory fault" in lowered
        or "memory allocation failed" in lowered
        or "failed to grow memory" in lowered
    )


def _read_capped_output(path: str, limit: int = _MAX_OUTPUT_BYTES) -> str:
    """Read a host-owned capture file, bounding it at ``limit`` chars.

    Defense-in-depth: reads at most ``limit + 1`` bytes and truncates the
    file on disk if it somehow grew past the budget.
    """
    if not os.path.exists(path):
        return ""
    try:
        with open(path, "rb") as f:
            raw = f.read(limit + 1)
    except OSError:
        return ""
    if len(raw) > limit:
        try:
            with open(path, "r+b") as f:
                f.truncate(limit)
        except OSError:
            pass
        return raw[:limit].decode("utf-8", errors="replace") + "\n[... truncated]"
    return raw.decode("utf-8", errors="replace")


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
    # These are system-critical directories that could expose host state
    _DANGEROUS_DIRS: frozenset[str] = frozenset(
        [
            "/dev",
            "/proc",
            "/sys",
            "/etc",
            "/root",
            "/usr",
            "/bin",
            "/sbin",
            "/lib",
            "/lib64",
            "/boot",
            "/snap",
            "/kernel",
            "/private",
        ]
    )

    # Canonical (realpath) locations that are NEVER allowed in allow_dirs.
    # "/" is handled explicitly in _forbidden_canonical_match.
    _FORBIDDEN_CANONICAL: tuple[str, ...] = (
        "/etc",
        "/usr",
        "/bin",
        "/sbin",
        "/lib",
        "/lib64",
        "/dev",
        "/proc",
        "/sys",
        "/boot",
        "/snap",
        "/kernel",
        "/root",
        "/private",
    )

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
    ) -> ExecutionResult:
        """Execute a WASM module in the sandbox.

        Args:
            wasm_path: Path to the .wasm file
            args: Command-line arguments for the WASM guest
            stdin_data: Data to provide on stdin
            use_subprocess: Run the sandbox in a disposable worker subprocess
                (process-level isolation: RLIMIT_NOFILE, address-space
                limits, 32 MiB module size cap, hard process timeout).
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

        Returns:
            ExecutionResult with status, stdout, stderr, and timing
        """
        if use_subprocess:
            from .process_executor import run_isolated

            report = run_isolated(
                wasm_path, self._config, args=args, stdin_data=stdin_data, abi=abi
            )
            return self._result_from_report(report)

        if abi in ("auto", "component"):
            from .wasi_02 import ComponentSandbox, is_component_binary

            if abi == "component" or is_component_binary(wasm_path):
                return ComponentSandbox(self._config).run(
                    wasm_path, args=args, stdin_data=stdin_data
                )

        wasm_path_resolved = Path(wasm_path).resolve()
        if not wasm_path_resolved.exists():
            return ExecutionResult(
                status=ExecutionStatus.ERROR,
                stderr=f"WASM module not found: {wasm_path}",
            )

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
                engine_config = wasmtime.Config()
                if self._config.max_fuel is not None:
                    engine_config.consume_fuel = True
                engine_config.epoch_interruption = True
                # P1 #11: Disable threads (single-thread only for security)
                engine_config.wasm_threads = False
                # P1/K2: Freeze the baseline — multi-memory stays off; memory64
                # is a per-config opt-in (WASIConfig.memory64).
                engine_config.wasm_memory64 = self._config.memory64
                engine_config.wasm_multi_memory = False
                engine = Engine(engine_config)

            if pool is not None:
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

            # P1 #12: Block fsync/psync/datasync imports before linking
            for imp in module.imports:
                imp_name = imp.name or ""
                if "fsync" in imp_name or "psync" in imp_name or "datasync" in imp_name:
                    return ExecutionResult(
                        status=ExecutionStatus.ERROR,
                        stderr=(
                            f"Blocked WASI import: {imp.module}::{imp_name} — "
                            "fsync/sync operations are not allowed in sandbox"
                        ),
                        sandbox_dir=sandbox_dir,
                        effective_preopens=effective_preopens,
                    )

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

            # P1 #12: Register fd_psync trap — prevents disk DoS via fd_psync.
            # WASI Preview1 doesn't define fd_psync, but we register it
            # proactively for Preview2 / future wasmtime compatibility.
            def _fsync_trap(ctx: wasmtime.Caller) -> None:
                """Trap fsync/fdatasync calls — blocked by sandbox."""
                raise wasmtime.Trap("fsync/fdatasync blocked by sandbox")

            try:
                linker.define(
                    store,
                    "wasi_snapshot_preview1",
                    "fd_psync",
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
                # fd_psync not available in this wasmtime version — skip
                pass

            # Cached modules must only be instantiated under the pool's
            # per-engine lock — wasmtime Module instances are not thread-safe.
            if pool is not None:
                with pool.locked(engine):
                    instance = linker.instantiate(store, module)
            else:
                instance = linker.instantiate(store, module)

            start_func = instance.exports(store).get("_start")
            if start_func is None:
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

                def _epoch_timer() -> None:
                    """Increment WASM epoch on timeout — triggers epoch_interruption trap."""
                    if not timeout_event.wait(self._config.timeout_seconds):
                        engine.increment_epoch()

                timer = threading.Thread(target=_epoch_timer, daemon=True)
                timer.start()

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

            def _interrupt_watch() -> None:
                # External watchdog (worker io_cpu_seconds): one increment
                # fires the per-run engine's deadline=1 immediately.
                while not timeout_event.is_set():
                    if interrupt_event.is_set():
                        engine.increment_epoch()
                        return
                    timeout_event.wait(0.02)

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
                threading.Thread(target=_interrupt_watch, daemon=True).start()
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
                        sandbox_dir=sandbox_dir,
                        elapsed_ms=(time.monotonic() - start_time) * 1000,
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
            elapsed_ms = (time.monotonic() - start_time) * 1000
            exit_code = 1
            exit_match = re.search(r"exit status (\d+)", str(e))
            if exit_match:
                exit_code = int(exit_match.group(1))

            stdout = _read_capped_output(stdout_path) if stdout_path else ""
            stderr_from_file = _read_capped_output(stderr_path) if stderr_path else ""

            # proc_exit with code 0 = clean exit (even if it raised as Exception)
            if exit_code == 0:
                fuel_consumed = None
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
                stderr=_limit_output(str(e) + stderr_from_file),
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

        ``canon`` is expected to already be realpath-normalized. "/" is always
        forbidden; every other forbidden location is checked as a realpath
        prefix, closing symlink-based bypasses such as /private/etc on macOS.
        """
        if canon == "/":
            return "/"
        for f in cls._FORBIDDEN_CANONICAL:
            if canon == f or canon.startswith(f + "/"):
                return f
        return None

    def _canonicalize(self, dir_path: str) -> str:
        return os.path.realpath(os.path.expanduser(dir_path))

    def _validate_allow_dirs(self, allow_dirs: tuple[str, ...]) -> None:
        """Fail fast if any allow_dirs entry is canonically forbidden.

        Raises:
            ValueError: with the offending entry and its canonical path.
        """
        for d in allow_dirs:
            canon = self._canonicalize(d)
            match = self._forbidden_canonical_match(canon)
            if match is not None:
                raise ValueError(
                    f"allow_dirs entry {d!r} is forbidden: canonical path "
                    f"{canon!r} resolves into blocked location {match!r}"
                )

    def _check_dangerous_dirs(self, allow_dirs: tuple[str, ...]) -> None:
        """Warn if allow_dirs entries match the denylist by string.

        The canonical realpath check already rejects true forbidden paths;
        this remains as an additional visibility layer for suspicious strings.
        """
        if not allow_dirs:
            return
        for d in allow_dirs:
            if d in self._DANGEROUS_DIRS or any(
                d == dd or d.startswith(dd + "/") for dd in self._DANGEROUS_DIRS
            ):
                import warnings

                warnings.warn(
                    f"Preopen directory '{d}' matches the dangerous dirs denylist. "
                    "It will be filtered out at runtime.",
                    RuntimeWarning,
                    stacklevel=3,
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

    def _grant_preopens(
        self,
        wasi_cfg: WasmtimeWasiConfig,
        safe_dirs: tuple[str, ...],
        sandbox_dir: str | None,
    ) -> tuple[str, ...]:
        """Preopen the filtered dirs (plus the sandbox dir) and record what
        was ACTUALLY granted (S2 attestation input).

        TOCTOU: an entry validated at config time can be swapped before the
        grant happens (e.g. replaced with a symlink into a forbidden
        location). Every entry is therefore re-realpath'd immediately
        before ``preopen_dir`` and skipped with a warning when it now
        resolves into a forbidden canonical location. The guest-visible
        name stays the configured string; the host path is the canonical
        one. ``sandbox_dir=None`` grants no /sandbox mount (component ABI).
        """
        granted: list[str] = []
        for dir_path in safe_dirs:
            canon = self._canonicalize(dir_path)
            if self._forbidden_canonical_match(canon) is not None:
                import warnings

                warnings.warn(
                    "Preopen skipped at grant time (TOCTOU revalidation): "
                    f"{dir_path!r} now resolves to forbidden canonical path "
                    f"{canon!r}",
                    RuntimeWarning,
                    stacklevel=2,
                )
                continue
            if not os.path.isdir(canon):
                continue
            wasi_cfg.preopen_dir(canon, dir_path)
            granted.append(canon)
        if sandbox_dir is not None:
            wasi_cfg.preopen_dir(sandbox_dir, "/sandbox")
            granted.append("/sandbox")
        return tuple(granted)

    def _filter_dangerous_dirs(self, allow_dirs: tuple[str, ...]) -> tuple[str, ...]:
        """Filter allow_dirs down to entries that pass the canonical allowlist.

        Entries whose realpath lands in a forbidden location are dropped, as
        are plain string matches against the denylist.
        """
        if not allow_dirs:
            return ()
        safe: list[str] = []
        for d in allow_dirs:
            canon = self._canonicalize(d)
            if self._forbidden_canonical_match(canon) is not None:
                continue
            if d in self._DANGEROUS_DIRS or any(
                d == dd or d.startswith(dd + "/") for dd in self._DANGEROUS_DIRS
            ):
                continue
            safe.append(d)
        return tuple(safe)

    @staticmethod
    def _make_output_sink(file_path: str, budget: list[int]):
        """Build a WASI stdout/stderr sink that enforces the byte budget.

        Returns None to accept a write. Once the shared budget is exhausted
        the sink returns a NEGATIVE errno so the guest's fd_write fails
        without further output being appended to the host-owned capture file.

        NOTE: positive errno returns are NOT usable here — wasmtime-py 47
        misinterprets them as byte counts and panics ("cannot advance past
        remaining"). Negative returns take the C error path (guest sees EIO).
        """

        def _sink(data: bytes) -> int | None:
            if len(data) > budget[0]:
                return -_WASI_ERRNO_NOSPC
            budget[0] -= len(data)
            try:
                with open(file_path, "ab") as f:
                    f.write(data)
            except OSError:
                return -_WASI_ERRNO_NOSPC
            return None

        return _sink

    # --- P0 #3: Sandbox dir cleanup ---

    def cleanup(self) -> None:
        """Remove the ephemeral sandbox and host-owned capture directories.

        Call this after run() to clean up temporary files.
        If a directory is None or doesn't exist, silently pass.
        """
        import shutil

        for attr in ("_sandbox_dir", "_host_dir"):
            dir_path = getattr(self, attr, None)
            if dir_path is None:
                continue
            try:
                shutil.rmtree(dir_path, ignore_errors=True)
            except OSError:
                pass  # Best effort — dir may already be gone
            setattr(self, attr, None)

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
    max_memory_mb: int = 128,
    max_fuel: int = 1_000_000,
    timeout_seconds: int = 30,
    allow_dirs: tuple[str, ...] = (),
    allow_env: tuple[tuple[str, str], ...] = (),
    args: list[str] | None = None,
    stdin_data: str | None = None,
    use_subprocess: bool = False,
    abi: str = "auto",
    memory64: bool = False,
) -> ExecutionResult:
    """Convenience wrapper for single-shot WASM execution.

    Args:
        stdin_data: Data to provide on stdin (subject to STDIN_MAX_BYTES).
        abi: "auto" (default — detects components by magic bytes),
            "preview1" or "component".
        memory64: Enable Wasm 3.0 memory64 (64-bit address space) for this
            run. Off by default.
    """
    config = WASIConfig(
        max_memory_mb=max_memory_mb,
        max_fuel=max_fuel,
        timeout_seconds=timeout_seconds,
        allow_dirs=allow_dirs,
        allow_env=allow_env,
        memory64=memory64,
    )
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
