# Ephemora Cell — WASI 0.2 (Component Model) runtime
# SPDX-License-Identifier: BUSL-1.1
# Copyright 2026 Michael Soppa
"""
WASI 0.2 component execution (dual-ABI opt-in).

``ComponentSandbox`` mirrors the ``WASISandbox`` API but runs WebAssembly
*components* (binary format version 0x000d0000) against the stable WASI 0.2
host implementation exposed by wasmtime-py 47 (``wasmtime.component`` +
``Linker.add_wasip2``).

Why 0.2 and not 0.3: WASI 0.3 (ratified 2026-06-11) depends on the Component
Model 1.0 specification, which is not yet final; its toolchains are nightly
only (Rust ``wasm32-wasip3`` is Tier 3, WIT tools must be pinned to an
rc-snapshot) and its host API is completion/async-based. WASI 0.2 is the
first stable component-based WASI (ratified 2025-01) with mature toolchains
(Rust ``wasm32-wasip2``, ``cargo component``, jco).

Supported entry point: the ``wasi:cli/command`` world's ``run`` function.
Reactor-style components (no ``run`` export) are rejected with an ERROR.

Security posture matches the Preview1 sandbox: same engine baseline
(memory64/multi-memory/threads off), same canonical allowlist for preopens,
same byte-budgeted output capture, fuel + epoch timeout. Unknown imports
(e.g. ``wasi:http``) are NOT defined as traps — they fail at instantiate
time with "unknown import" (see the linker note in ``run``); the WASI 0.2
world links ``wasi:sockets`` and connect is denied at call time by the
host context (measured: benchmarks/mcp_cve_replay.py, component branch).

Limitations (documented): fuel consumption *rates* differ from Preview1
calibration (the command adapter burns fuel on every wasi hop); preopen
guest paths are not virtualized (guest sees the host path); output capture
happens through the same custom-sink mechanism. `fuel_consumed` is reported
like the Preview1 sandbox (`max_fuel - store.get_fuel()`).
"""

from __future__ import annotations

import hashlib
import os
import re
import tempfile
import threading
import time
from pathlib import Path

try:
    import wasmtime
    from wasmtime import Engine, Store, Trap
    from wasmtime import WasiConfig as WasmtimeWasiConfig
    from wasmtime import component as _component

    HAS_WASMTIME = True
except ImportError:
    HAS_WASMTIME = False

from ._engine_config import build_engine_config
from ._sandbox_common import (
    _MAX_OUTPUT_BYTES,
    STDIN_MAX_BYTES,
)
from ._sandbox_common import (
    DANGEROUS_DIRS as _DANGEROUS_DIRS_POLICY,
)
from ._sandbox_common import (
    OUTPUT_FILE_HARD_LIMIT as _OUTPUT_FILE_HARD_LIMIT,
)
from ._sandbox_common import (
    canonicalize_dir as _canonicalize_dir,
)
from ._sandbox_common import (
    check_dangerous_dirs as _check_dangerous_dirs_impl,
)
from ._sandbox_common import (
    filter_dangerous_dirs as _filter_dangerous_dirs_impl,
)
from ._sandbox_common import (
    forbidden_canonical_match as _forbidden_canonical_match_impl,
)
from ._sandbox_common import (
    fuel_consumed as _fuel_consumed_impl,
)
from ._sandbox_common import (
    grant_preopens as _grant_preopens_impl,
)
from ._sandbox_common import (
    is_memory_fault_trap as _is_memory_fault_trap,
)
from ._sandbox_common import (
    limit_output_text as _limit_output_text,
)
from ._sandbox_common import (
    make_output_fifo as _make_output_fifo,
)
from ._sandbox_common import (
    make_output_sink as _make_output_sink,
)
from ._sandbox_common import (
    open_private as _open_private,
)
from ._sandbox_common import (
    read_capped_output as _read_capped_output,
)
from ._sandbox_common import (
    split_dir_mapping as _split_dir_mapping_impl,
)
from ._sandbox_common import (
    start_epoch_timer as _start_epoch_timer,
)
from ._sandbox_common import (
    start_interrupt_watch as _start_interrupt_watch,
)
from ._sandbox_common import (
    start_output_cap_reader as _start_output_cap_reader,
)
from ._sandbox_common import (
    under_canonical_exception as _under_canonical_exception,
)
from ._sandbox_common import (
    validate_allow_dirs as _validate_allow_dirs_impl,
)
from .component_guard import ComponentGuardError as _ComponentGuardError
from .component_guard import guard_component_bytes as _guard_component_bytes
from .runtime_qualification import (
    runtime_qualification as _runtime_qualification,
)
from .runtime_qualification import (
    unqualified_runtime_allowed as _unqualified_runtime_allowed,
)
from .wasi_runtime import (
    ExecutionResult,
    ExecutionStatus,
    WASIConfig,
    _GuestWriteBudget,
    module_size_cap_error,
)

__all__ = ["ComponentSandbox", "is_component_binary", "is_component_bytes"]

# Component binary format: magic \0asm + version u32 whose low byte is 0x0d
# (0.2-era: 0x0000000d; post-Component-Model-1.0: 0x0001000d). Core modules
# use version 0x00000001.
_COMPONENT_VERSION_MARKER = 0x0D


def is_component_bytes(data: bytes) -> bool:
    """True if these BYTES are a component (vs. a core module) by magic bytes.

    The byte-level form of the format decision, so a caller that has already
    read the module (e.g. to hash the exact bytes it will bind execution to)
    can test the SAME magic without a second file read. :func:`is_component_binary`
    is the path-level wrapper, keeping one source of truth for the marker.
    """
    return (
        len(data) >= 8
        and data[:4] == b"\x00asm"
        and data[4] == _COMPONENT_VERSION_MARKER
    )


def is_component_binary(path: str) -> bool:
    """True if the file is a component (vs. a core module) by magic bytes."""
    try:
        with open(path, "rb") as f:
            header = f.read(8)
    except OSError:
        return False
    return is_component_bytes(header)


class ComponentSandbox:
    """WASI 0.2 component sandbox with the same resource limits as WASISandbox.

    LOW-LEVEL PRIMITIVE — not a guaranteed execution path (ADR-015,
    security-review case B).
    This class runs a component guest DIRECTLY in the calling process. It does
    NOT enforce the process-isolation mandate: that gate lives at the public
    facade :meth:`WASISandbox.run` (and everything routed through it —
    ``run_wasm``, ``run_isolated`` and the MCP ``CellToolEngine.execute``),
    which is where an untrusted/unknown ``component`` is forced into the
    disposable worker. The runtime resource walls (fuel, epoch, memory, the
    per-call ``expected_sha256`` module binding) DO apply here, because those
    are the engine's, but process isolation is a decision of the facade, not
    of this primitive. Reach for :meth:`WASISandbox.run` unless you ARE the
    host authorising a low-level in-process run; this class is what the gate
    and the isolated worker themselves call to actually execute a component.
    What this primitive DOES enforce on its own is the engine boundary: the
    qualified runtime line is checked before a single byte is read, compiled or
    billed, because a low-level route must not be a way around the runtime
    gate. What it does not enforce is process isolation — that stays the
    facade's decision, exactly as above.

    Example:
        config = WASIConfig(max_memory_mb=128, max_fuel=1_000_000)
        sandbox = ComponentSandbox(config=config)
        result = sandbox.run("module.component.wasm")
    """

    def __init__(self, config: WASIConfig | None = None) -> None:
        """Initialize the component sandbox.

        Raises:
            RuntimeError: if wasmtime is not installed.
            ValueError: if any allow_dirs entry resolves into a forbidden
                host location (same canonical check as WASISandbox).
        """
        if not HAS_WASMTIME:
            raise RuntimeError(
                "wasmtime is not installed. Install with: pip install wasmtime"
            )
        self._config = config or WASIConfig()
        self._host_dir: str | None = None
        # Same canonical allowlist validation as the Preview1 sandbox —
        # the ONE shared policy in _sandbox_common.
        _validate_allow_dirs_impl(
            self._config.allow_dirs,
            split_dir_mapping=_split_dir_mapping_impl,
            canonicalize=self._canonicalize,
            forbidden_canonical_match=self._forbidden_canonical_match,
        )
        _check_dangerous_dirs_impl(
            self._config.allow_dirs,
            dangerous_dirs=self._DANGEROUS_DIRS,
            split_dir_mapping=_split_dir_mapping_impl,
            under_canonical_exception=_under_canonical_exception,
        )

    def run(
        self,
        wasm_path: str,
        *,
        args: list[str] | None = None,
        stdin_data: str | None = None,
        interrupt_event: threading.Event | None = None,
        expected_sha256: str | None = None,
    ) -> ExecutionResult:
        """Execute a WASI 0.2 command component.

        Args:
            wasm_path: Path to the .wasm component file
            args: Command-line arguments for the guest
            stdin_data: Data to provide on stdin
            interrupt_event: External watchdog signal (ADR-002
                io_cpu_seconds in the subprocess worker) — when set, the
                guest is interrupted via epoch immediately (deadline=1
                engine, same semantics as the preview1 timer).
            expected_sha256: Optional lowercase hex digest — per-call
                module binding (see WASISandbox.run): the component bytes
                are read once and verified before compiling.

        Returns:
            ExecutionResult with status, stdout, stderr, and timing
        """
        # The runtime line is enforced HERE too, not only at the facade: this
        # primitive is reachable from the package surface, so a caller that
        # skipped WASISandbox.run would otherwise compile and execute a guest on
        # an engine this release does not qualify. Nothing is read, compiled or
        # billed before this decision, and the same documented hatch governs it.
        self._output_files_exceeded = False
        qualified, why = _runtime_qualification()
        if not qualified and not _unqualified_runtime_allowed():
            return ExecutionResult(
                status=ExecutionStatus.ERROR,
                exit_code=1,
                stderr=f"refused: unqualified runtime — {why}",
                execution_started=False,
            )
        resolved = Path(wasm_path).resolve()
        if not resolved.exists():
            return ExecutionResult(
                status=ExecutionStatus.ERROR,
                stderr=f"WASM component not found: {wasm_path}",
                execution_started=False,
            )
        cap_error = module_size_cap_error(resolved, self._config.max_wasm_bytes)
        if cap_error is not None:
            return ExecutionResult(
                status=ExecutionStatus.ERROR,
                stderr=cap_error,
                execution_started=False,
            )
        if not is_component_binary(str(resolved)):
            return ExecutionResult(
                status=ExecutionStatus.ERROR,
                stderr=(
                    f"Not a component binary: {wasm_path} "
                    "(use WASISandbox for preview1 modules)"
                ),
                execution_started=False,
            )

        base = self._config.sandbox_base_dir or tempfile.gettempdir()
        # Repeat-run leak: drop the previous run's capture dir before
        # creating a new one.
        self.cleanup()
        host_dir = tempfile.mkdtemp(prefix="ephemora_host_", dir=base)
        self._host_dir = host_dir
        stdout_path = os.path.join(host_dir, "stdout.txt")
        stderr_path = os.path.join(host_dir, "stderr.txt")
        effective_preopens: tuple[str, ...] = ()
        start_time = time.monotonic()
        # Bound variables for the exception handlers: a Trap/WasmtimeError
        # before Store construction (e.g. component parse failure) must not
        # turn into an UnboundLocalError while building the error result.
        store: Store | None = None
        timeout_event: threading.Event | None = None
        # ADR-002 byte wall over the directories this run preopens (a component
        # has no sandbox dir). Pre-bound for the same reason as the two above:
        # an exception before the watcher exists must not raise NameError.
        byte_watcher: _GuestWriteBudget | None = None

        try:
            # Hardened proposal-policy engine — ONE shared builder
            # (ephemora_cell._engine_config) serves the component path, the
            # engine pool and the inline preview1 path (component linking
            # verified against these knobs).
            engine_config = build_engine_config(
                max_fuel=self._config.max_fuel,
                memory64=self._config.memory64,
            )
            engine = Engine(engine_config)

            component_bytes = resolved.read_bytes()
            if (
                expected_sha256 is not None
                and hashlib.sha256(component_bytes).hexdigest() != expected_sha256
            ):
                return ExecutionResult(
                    status=ExecutionStatus.ERROR,
                    stderr=(
                        "module hash mismatch — executed bytes do not "
                        "match the registered module digest"
                    ),
                    execution_started=False,
                )
            # GHSA-32h6-97mm-8q3c enforced path exclusion: the bytes are walked
            # by an INDEPENDENT component-binary reader BEFORE they ever reach
            # the native ``Component()`` parser (the code the advisory is in).
            # Any component-model async construct (async-lift / future / stream)
            # — the surface the unvalidated async callback result count
            # overruns — is refused here, fail-closed, on every path (in-process
            # trusted runs and the protected worker alike, since this is the
            # single Component() construction site). This is loader-boundary
            # avoidance, not a claim the upstream overflow is patched; the
            # definitive fix remains a corrected wasmtime wheel (SECURITY.md).
            try:
                _guard_component_bytes(component_bytes)
            except _ComponentGuardError as guard_err:
                return ExecutionResult(
                    status=ExecutionStatus.ERROR,
                    stderr=str(guard_err),
                    execution_started=False,
                )
            component = _component.Component(engine, component_bytes)

            store = Store(engine)
            if self._config.max_fuel is not None:
                store.set_fuel(self._config.max_fuel)
            if self._config.memory_capacity_bytes > 0:
                store.set_limits(memory_size=self._config.memory_capacity_bytes)
            # Deadline MUST be set even without a timer: with epoch
            # interruption enabled an unset deadline traps immediately.
            store.set_epoch_deadline(1)

            wasi_cfg = WasmtimeWasiConfig()
            wasi_cfg.argv = ["wasm-module"] + (args or [])
            output_files_exceeded = threading.Event()
            output_reader_stop = threading.Event()
            output_reader_threads: list[threading.Thread] = []

            def _stop_output_readers() -> None:
                output_reader_stop.set()
                for thread in output_reader_threads:
                    thread.join(2.0)

            if os.environ.get("EPHEMORA_WORKER_OUTPUT_SINK"):
                # Untrusted worker path: the guest writes into a FIFO, and a
                # host reader drains it into the capture file with a hard byte
                # bound; no Python callback on Wasmtime's tokio worker.
                stdout_fifo = os.path.join(host_dir, "stdout.fifo")
                stderr_fifo = os.path.join(host_dir, "stderr.fifo")
                reader_errors: list[BaseException] = []
                try:
                    _make_output_fifo(stdout_fifo)
                    _make_output_fifo(stderr_fifo)
                except OSError as fifo_error:
                    reader_errors.append(fifo_error)
                with _open_private(stdout_path, "wb"):
                    pass
                with _open_private(stderr_path, "wb"):
                    pass
                ready = [threading.Event(), threading.Event()]
                if not reader_errors:
                    for fifo, capture, ready_event in (
                        (stdout_fifo, stdout_path, ready[0]),
                        (stderr_fifo, stderr_path, ready[1]),
                    ):
                        output_reader_threads.append(
                            _start_output_cap_reader(
                                fifo,
                                capture,
                                _OUTPUT_FILE_HARD_LIMIT,
                                output_files_exceeded,
                                output_reader_stop,
                                ready_event,
                                reader_errors,
                            )
                        )
                    for ready_event in ready:
                        ready_event.wait(5.0)
                else:
                    ready[0].set()
                    ready[1].set()
                if reader_errors:
                    _stop_output_readers()
                    return ExecutionResult(
                        status=ExecutionStatus.ERROR,
                        stderr=(
                            "worker output sink could not be established: "
                            f"{reader_errors[0]!r}"
                        ),
                        sandbox_dir=None,
                        elapsed_ms=(time.monotonic() - start_time) * 1000,
                        execution_started=False,
                    )
                wasi_cfg.stdout_file = stdout_fifo
                wasi_cfg.stderr_file = stderr_fifo
            else:
                # Trusted in-process path keeps the synchronous callback cap.
                budget: list[int] = [_MAX_OUTPUT_BYTES]
                wasi_cfg.stdout_custom = _make_output_sink(stdout_path, budget)
                wasi_cfg.stderr_custom = _make_output_sink(stderr_path, budget)

            if stdin_data:
                if len(stdin_data.encode("utf-8")) > STDIN_MAX_BYTES:
                    _stop_output_readers()
                    return ExecutionResult(
                        status=ExecutionStatus.ERROR,
                        stderr=(
                            f"stdin_data exceeds the wasmtime host cap of "
                            f"{STDIN_MAX_BYTES} bytes; wasmtime silently truncates "
                            "larger stdin on fd 0 — pass input via a preopened file "
                            "instead"
                        ),
                        sandbox_dir=None,
                        elapsed_ms=(time.monotonic() - start_time) * 1000,
                    )
                stdin_path = os.path.join(host_dir, "stdin.txt")
                with _open_private(stdin_path, "w") as f:
                    f.write(stdin_data)
                wasi_cfg.stdin_file = stdin_path

            safe_dirs = self._filter_dangerous_dirs(self._config.allow_dirs)
            # Component ABI: no /sandbox mount — the component gets no
            # sandbox dir at all (host_dir is host-owned, never preopened).
            effective_preopens = _grant_preopens_impl(
                wasi_cfg,
                safe_dirs,
                None,
                split_dir_mapping=_split_dir_mapping_impl,
                canonicalize=self._canonicalize,
                forbidden_canonical_match=self._forbidden_canonical_match,
            )

            if self._config.allow_env:
                wasi_cfg.env = list(self._config.allow_env)

            store.set_wasi(wasi_cfg)

            linker = _component.Linker(engine)
            linker.add_wasip2()
            # NOTE: define_unknown_imports_as_traps is NOT used — in wasmtime
            # 47 it defines traps for WASI interface imports whose version
            # differs from the linker's (e.g. wasi:cli/stdout@0.2.6 vs the
            # linker's 0.2.x), breaking version-range matching and trapping
            # every guest write. Unknown non-WASI imports (e.g. wasi:http)
            # already fail at instantiate time with "unknown import".

            instance = linker.instantiate(store, component)
            run_func = self._find_run_func(instance, store, component)

            if run_func is None:
                _stop_output_readers()
                return ExecutionResult(
                    status=ExecutionStatus.ERROR,
                    stderr=(
                        "Component has no wasi:cli/run export — only command "
                        "world components are supported"
                    ),
                    sandbox_dir=None,
                    elapsed_ms=(time.monotonic() - start_time) * 1000,
                    effective_preopens=effective_preopens,
                )

            timeout_event = threading.Event()

            _start_epoch_timer(engine, timeout_event, self._config.timeout_seconds)

            # ADR-002 I/O byte wall on the component path. The component has no
            # /sandbox mount, so the wall covers the directories this run
            # ACTUALLY preopened — its only writable scope. The enforcement
            # mechanics (poll interval, epoch interrupt, breach result) are the
            # shared ones from ``_GuestWriteBudget``.
            if self._config.io_budget_bytes is not None:
                byte_watcher = _GuestWriteBudget(
                    engine,
                    effective_preopens,
                    self._config.io_budget_bytes,
                    timeout_event,
                )
                byte_watcher.start()

            if interrupt_event is not None:
                # ADR-002: external CPU watchdog — one increment fires
                # the deadline=1 engine immediately.
                _start_interrupt_watch(engine, interrupt_event, timeout_event)

            try:
                result = run_func(store)
            finally:
                if timeout_event is not None:
                    timeout_event.set()
                _stop_output_readers()

            stdout = _read_capped_output(stdout_path)
            stderr = _read_capped_output(stderr_path)
            elapsed_ms = (time.monotonic() - start_time) * 1000
            self._output_files_exceeded = output_files_exceeded.is_set()

            # ADR-002 end-of-run measurement: the poller cannot see a write that
            # begins and finishes inside one 100 ms interval (the same sampling
            # bound the preview1 path has), so the delta is re-read here and an
            # overrun is reported as a breach instead of a silent success.
            # ``finish()`` stops and joins the poller before reading, so the
            # count published here cannot be a poller value that landed late.
            written: int | None = None
            if byte_watcher is not None:
                written = byte_watcher.finish()
                if written > byte_watcher.limit:
                    return self._iobudget_error(
                        written, elapsed_ms, effective_preopens, stderr
                    )

            if isinstance(result, _component.Variant):
                if result.tag == "err":
                    return ExecutionResult(
                        status=ExecutionStatus.ERROR,
                        exit_code=1,
                        # the guest's own `result` channel reported the failure
                        guest_exit_observed=True,
                        stdout=stdout,
                        stderr=_limit_output_text(
                            f"component run returned error: {result.payload!r}"
                            + (("\n" + stderr) if stderr else "")
                        ),
                        elapsed_ms=elapsed_ms,
                        output_files_exceeded=self._output_files_exceeded,
                        effective_preopens=effective_preopens,
                    )
                return ExecutionResult(
                    status=ExecutionStatus.SUCCESS,
                    exit_code=0,
                    output_files_exceeded=self._output_files_exceeded,
                    # the run export returned: the guest reached its own end
                    guest_exit_observed=True,
                    stdout=stdout,
                    stderr=stderr,
                    elapsed_ms=elapsed_ms,
                    fuel_consumed=self._fuel_consumed(store),
                    io_bytes_written=written,
                    effective_preopens=effective_preopens,
                )

            exit_code = int(result) if result is not None else 0
            status = (
                ExecutionStatus.SUCCESS if exit_code == 0 else ExecutionStatus.ERROR
            )
            return ExecutionResult(
                status=status,
                exit_code=exit_code,
                output_files_exceeded=self._output_files_exceeded,
                # the adapter returned the guest's exit value to the host
                guest_exit_observed=True,
                stdout=stdout,
                stderr=stderr,
                elapsed_ms=elapsed_ms,
                fuel_consumed=self._fuel_consumed(store),
                io_bytes_written=written,
                effective_preopens=effective_preopens,
            )

        except (Trap, wasmtime.WasmtimeError) as exc:
            # Stop the epoch timer if it is running (the run ended — no
            # need to keep the thread waiting out its timeout).
            if timeout_event is not None:
                timeout_event.set()
            stop_readers = locals().get("_stop_output_readers")
            if callable(stop_readers):
                stop_readers()
            trap_msg = str(exc)
            elapsed_ms = (time.monotonic() - start_time) * 1000
            stdout = _read_capped_output(stdout_path)
            stderr = _read_capped_output(stderr_path)
            if "output_files_exceeded" in locals():
                self._output_files_exceeded = output_files_exceeded.is_set()

            # ADR-002: an epoch trap raised by the BYTE watcher is a budget
            # breach, not a wall-clock timeout — same precedence as preview1.
            if byte_watcher is not None and byte_watcher.exceeded:
                return self._iobudget_error(
                    byte_watcher.bytes_written,
                    elapsed_ms,
                    effective_preopens,
                    stderr,
                )

            if "all fuel consumed" in trap_msg:
                return ExecutionResult(
                    status=ExecutionStatus.FUEL_EXHAUSTED,
                    stderr=_limit_output_text(
                        f"Fuel exhausted: {trap_msg}"
                        + (("\n" + stderr) if stderr else "")
                    ),
                    stdout=stdout,
                    elapsed_ms=elapsed_ms,
                    fuel_consumed=self._fuel_consumed(store),
                    output_files_exceeded=self._output_files_exceeded,
                    effective_preopens=effective_preopens,
                )
            if _is_memory_fault_trap(trap_msg):
                return ExecutionResult(
                    status=ExecutionStatus.MEMORY_EXCEEDED,
                    stderr=_limit_output_text(
                        f"Memory limit exceeded (max {self._config.max_memory_mb} "
                        f"MiB): {trap_msg}" + (("\n" + stderr) if stderr else "")
                    ),
                    stdout=stdout,
                    elapsed_ms=elapsed_ms,
                    output_files_exceeded=self._output_files_exceeded,
                    effective_preopens=effective_preopens,
                )
            if "epoch" in trap_msg or "interrupt" in trap_msg:
                return ExecutionResult(
                    status=ExecutionStatus.TIMEOUT,
                    stderr=_limit_output_text(
                        f"Timeout after {self._config.timeout_seconds}s: {trap_msg}"
                        + (("\n" + stderr) if stderr else "")
                    ),
                    stdout=stdout,
                    elapsed_ms=elapsed_ms,
                    output_files_exceeded=self._output_files_exceeded,
                    effective_preopens=effective_preopens,
                )
            # Fix (flagged in benchmarks/pocs/README.md): preview1
            # modules lifted with wasm-tools call proc_exit() which the
            # command adapter forwards to wasi:cli/exit; wasmtime then raises
            # "Exited with i32 exit status 0" for a clean exit. Mirror the
            # preview1 sandbox and treat exit status 0 as SUCCESS.
            # ADR-002 end-of-run VERDICT on this route too (the component
            # hard-exit budget case). A guest that writes over budget and then
            # leaves through wasi:cli/exit
            # (std::process::exit, exit(), a lifted preview1 module's proc_exit)
            # arrives HERE, and this branch used to return SUCCESS without ever
            # comparing the measured bytes with the budget: 65536 B at
            # io_budget_bytes=1024 came back success/io_budget_exceeded=False
            # with the bytes on disk. The comparison below is the SAME one the
            # regular return route applies (see the end-of-run measurement
            # above). It runs AFTER the ``byte_watcher.exceeded`` check, so the
            # poller's verdict keeps precedence and ``finish()`` (which stops
            # the poller) can never mask a poller that already fired.
            if re.search(r"exit status 0", trap_msg):
                written = self._finish_bytes(byte_watcher)
                if (
                    byte_watcher is not None
                    and written is not None
                    and written > byte_watcher.limit
                ):
                    return self._iobudget_error(
                        written, elapsed_ms, effective_preopens, stderr
                    )
                return ExecutionResult(
                    status=ExecutionStatus.SUCCESS,
                    exit_code=0,
                    output_files_exceeded=self._output_files_exceeded,
                    guest_exit_observed=True,
                    stdout=stdout,
                    stderr=stderr,
                    elapsed_ms=elapsed_ms,
                    fuel_consumed=self._fuel_consumed(store),
                    io_bytes_written=written,
                    effective_preopens=effective_preopens,
                )
            return ExecutionResult(
                status=ExecutionStatus.ERROR,
                exit_code=1,
                # the guest left through wasi:cli/exit: the fact of a non-zero
                # exit is observed, the guest's own number is not carried
                guest_exit_observed=True,
                stdout=stdout,
                # The trap text is the host's reading of the exit channel; the
                # guest's own stderr stays readable behind it, and the output
                # cap verdict must survive this route as well.
                stderr=_limit_output_text(
                    trap_msg + (("\n" + stderr) if stderr else "")
                ),
                elapsed_ms=elapsed_ms,
                output_files_exceeded=self._output_files_exceeded,
                effective_preopens=effective_preopens,
            )
        except Exception as exc:
            # The run is over: stop the watcher thread (it polls every 100 ms
            # until this event is set, and this path returned without setting
            # it).
            if timeout_event is not None:
                timeout_event.set()
            stop_readers = locals().get("_stop_output_readers")
            if callable(stop_readers):
                stop_readers()
            captured_stdout = _read_capped_output(stdout_path)
            captured_stderr = _read_capped_output(stderr_path)
            if "output_files_exceeded" in locals():
                self._output_files_exceeded = output_files_exceeded.is_set()
            return ExecutionResult(
                status=ExecutionStatus.ERROR,
                exit_code=1,
                stdout=captured_stdout,
                # The host exception explains WHY the run stopped; the guest's
                # own stderr stays separately readable behind it, and the
                # output-cap verdict must survive this path too.
                stderr=_limit_output_text(str(exc) + "\n" + captured_stderr),
                output_files_exceeded=self._output_files_exceeded,
                elapsed_ms=(time.monotonic() - start_time) * 1000,
                io_bytes_written=self._finish_bytes(byte_watcher),
                effective_preopens=effective_preopens,
            )

    def _iobudget_error(
        self,
        written: int,
        elapsed_ms: float,
        effective_preopens: tuple[str, ...],
        stderr: str = "",
    ) -> ExecutionResult:
        """ADR-002 byte-wall breach on the component path.

        Same form as the preview1 breach (ERROR, ``io_budget_exceeded=True``,
        the ``"I/O budget exceeded: guest wrote N bytes ..."`` text). Only the
        named scope differs: a component has no ``/sandbox``, so the watched
        scope is the set of directories this run actually preopened. The
        guest's captured stderr and the output-cap verdict ride along: a run
        stopped for writing too much must not also lose what it printed.
        """
        return ExecutionResult(
            status=ExecutionStatus.ERROR,
            exit_code=0,
            stderr=_limit_output_text(
                "I/O budget exceeded: guest wrote "
                f"{written} bytes into the granted directories "
                f"(io_budget_bytes={self._config.io_budget_bytes})"
                + (("\n" + stderr) if stderr else "")
            ),
            elapsed_ms=elapsed_ms,
            io_bytes_written=written,
            io_budget_exceeded=True,
            output_files_exceeded=self._output_files_exceeded,
            effective_preopens=effective_preopens,
        )

    @staticmethod
    def _finish_bytes(watcher: _GuestWriteBudget | None) -> int | None:
        """Authoritative end-of-run byte count (stops and joins the poller).

        Feeds ``ExecutionResult.io_bytes_written`` so the component path
        attests the same measurement the preview1 path reports (ADR-002
        auditability) instead of a permanent ``None``.
        """
        return None if watcher is None else watcher.finish()

    def _fuel_consumed(self, store: Store | None) -> int | None:
        """Report fuel consumed for the component path (single shared
        implementation in ``_sandbox_common.fuel_consumed``).

        Returns None when fuel metering is disabled, the store was never
        constructed (trap during component parse), or the remaining fuel
        cannot be read (trap state). Resolves the missing fuel accounting
        (benchmarks/pocs/README.md).
        """
        if store is None:
            return None
        return _fuel_consumed_impl(self._config.max_fuel, store)

    @staticmethod
    def _find_run_func(instance, store: Store, component):
        """Locate the command-world entry point.

        Prefers ``wasi:cli/run@<version>`` (nested instance export); falls
        back to a direct ``run`` export (handy for hand-written components).
        """
        try:
            export_names = component.type.exports(store.engine)
        except Exception:
            export_names = ()
        for name in export_names:
            if name.startswith("wasi:cli/run@"):
                inst_index = instance.get_export_index(store, name)
                if inst_index is None:
                    continue
                run_index = instance.get_export_index(store, "run", instance=inst_index)
                if run_index is not None:
                    func = instance.get_func(store, run_index)
                    if func is not None:
                        return func
        direct = instance.get_export_index(store, "run")
        if direct is not None:
            return instance.get_func(store, direct)
        return None

    # --- Security helpers (the shared policy lives in _sandbox_common) ---

    _DANGEROUS_DIRS = _DANGEROUS_DIRS_POLICY

    @classmethod
    def _forbidden_canonical_match(cls, canon: str) -> str | None:
        """Delegate to the shared canonical allowlist check."""
        return _forbidden_canonical_match_impl(canon)

    def _canonicalize(self, dir_path: str) -> str:
        return _canonicalize_dir(dir_path)

    def _filter_dangerous_dirs(self, allow_dirs: tuple[str, ...]) -> tuple[str, ...]:
        """Filter allow_dirs down to entries that pass the canonical allowlist.

        ONE shared implementation with the Preview1 sandbox
        (``_sandbox_common.filter_dangerous_dirs``): mapping-style
        ``host::guest`` entries are split FIRST and the HOST part is checked
        against the canonical allowlist and the string denylist. (This path
        used to check the RAW entry string without splitting, so an entry
        like ``/etc::guest-etc`` bypassed the string-denylist layer here
        while being filtered on the Preview1 path — denylist drift between
        ABI paths, fixed 2026-09-29.)
        """
        return _filter_dangerous_dirs_impl(
            allow_dirs,
            split_dir_mapping=_split_dir_mapping_impl,
            canonicalize=self._canonicalize,
            forbidden_canonical_match=self._forbidden_canonical_match,
            dangerous_dirs=self._DANGEROUS_DIRS,
            under_canonical_exception=_under_canonical_exception,
        )

    def cleanup(self) -> list[str]:
        """Remove the host-owned capture directory and report what survived.

        The Preview1 facade returns the paths that outlived its own removal, so a
        residue is a fact the caller can see. This route used to answer ``None``
        while deleting with ``ignore_errors=True`` — a directory that could not
        be removed (immutable flag, permissions after an abrupt kill, a read-only
        mount) was reported as cleaned. Measured during the pre-push review with
        an unremovable capture directory. Same return shape as the facade now,
        so a component run delegated through the facade cannot lose the report.
        """
        import logging
        import shutil

        if self._host_dir is None:
            return []
        dir_path = self._host_dir
        leftovers: list[str] = []
        try:
            shutil.rmtree(dir_path)
        except FileNotFoundError:
            pass
        except OSError as exc:
            logging.getLogger(__name__).warning(
                "component capture cleanup failed, residue survives at %s: %s",
                dir_path,
                exc,
            )
            if os.path.exists(dir_path):
                leftovers.append(str(dir_path))
        self._host_dir = None
        return leftovers
