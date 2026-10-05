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
    make_output_sink as _make_output_sink,
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
    under_canonical_exception as _under_canonical_exception,
)
from ._sandbox_common import (
    validate_allow_dirs as _validate_allow_dirs_impl,
)
from .wasi_runtime import (
    ExecutionResult,
    ExecutionStatus,
    WASIConfig,
    module_size_cap_error,
)

__all__ = ["ComponentSandbox", "is_component_binary"]

# Component binary format: magic \0asm + version u32 whose low byte is 0x0d
# (0.2-era: 0x0000000d; post-Component-Model-1.0: 0x0001000d). Core modules
# use version 0x00000001.
_COMPONENT_VERSION_MARKER = 0x0D


def is_component_binary(path: str) -> bool:
    """True if the file is a component (vs. a core module) by magic bytes."""
    try:
        with open(path, "rb") as f:
            header = f.read(8)
    except OSError:
        return False
    return (
        len(header) == 8
        and header[:4] == b"\x00asm"
        and header[4] == _COMPONENT_VERSION_MARKER
    )


class ComponentSandbox:
    """WASI 0.2 component sandbox with the same resource limits as WASISandbox.

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
        resolved = Path(wasm_path).resolve()
        if not resolved.exists():
            return ExecutionResult(
                status=ExecutionStatus.ERROR,
                stderr=f"WASM component not found: {wasm_path}",
            )
        cap_error = module_size_cap_error(resolved, self._config.max_wasm_bytes)
        if cap_error is not None:
            return ExecutionResult(status=ExecutionStatus.ERROR, stderr=cap_error)
        if not is_component_binary(str(resolved)):
            return ExecutionResult(
                status=ExecutionStatus.ERROR,
                stderr=(
                    f"Not a component binary: {wasm_path} "
                    "(use WASISandbox for preview1 modules)"
                ),
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
            budget: list[int] = [_MAX_OUTPUT_BYTES]
            wasi_cfg.stdout_custom = _make_output_sink(stdout_path, budget)
            wasi_cfg.stderr_custom = _make_output_sink(stderr_path, budget)

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
                        sandbox_dir=None,
                        elapsed_ms=(time.monotonic() - start_time) * 1000,
                    )
                stdin_path = os.path.join(host_dir, "stdin.txt")
                with open(stdin_path, "w") as f:
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

            if interrupt_event is not None:
                # ADR-002: external CPU watchdog — one increment fires
                # the deadline=1 engine immediately.
                _start_interrupt_watch(engine, interrupt_event, timeout_event)

            try:
                result = run_func(store)
            finally:
                if timeout_event is not None:
                    timeout_event.set()

            stdout = _read_capped_output(stdout_path)
            stderr = _read_capped_output(stderr_path)
            elapsed_ms = (time.monotonic() - start_time) * 1000

            if isinstance(result, _component.Variant):
                if result.tag == "err":
                    return ExecutionResult(
                        status=ExecutionStatus.ERROR,
                        exit_code=1,
                        stdout=stdout,
                        stderr=f"component run returned error: {result.payload!r}",
                        elapsed_ms=elapsed_ms,
                        effective_preopens=effective_preopens,
                    )
                return ExecutionResult(
                    status=ExecutionStatus.SUCCESS,
                    exit_code=0,
                    stdout=stdout,
                    stderr=stderr,
                    elapsed_ms=elapsed_ms,
                    fuel_consumed=self._fuel_consumed(store),
                    effective_preopens=effective_preopens,
                )

            exit_code = int(result) if result is not None else 0
            status = (
                ExecutionStatus.SUCCESS if exit_code == 0 else ExecutionStatus.ERROR
            )
            return ExecutionResult(
                status=status,
                exit_code=exit_code,
                stdout=stdout,
                stderr=stderr,
                elapsed_ms=elapsed_ms,
                fuel_consumed=self._fuel_consumed(store),
                effective_preopens=effective_preopens,
            )

        except (Trap, wasmtime.WasmtimeError) as exc:
            # Stop the epoch timer if it is running (the run ended — no
            # need to keep the thread waiting out its timeout).
            if timeout_event is not None:
                timeout_event.set()
            trap_msg = str(exc)
            elapsed_ms = (time.monotonic() - start_time) * 1000
            stdout = _read_capped_output(stdout_path)
            stderr = _read_capped_output(stderr_path)

            if "all fuel consumed" in trap_msg:
                return ExecutionResult(
                    status=ExecutionStatus.FUEL_EXHAUSTED,
                    stderr=f"Fuel exhausted: {trap_msg}",
                    stdout=stdout,
                    elapsed_ms=elapsed_ms,
                    fuel_consumed=self._fuel_consumed(store),
                    effective_preopens=effective_preopens,
                )
            if _is_memory_fault_trap(trap_msg):
                return ExecutionResult(
                    status=ExecutionStatus.MEMORY_EXCEEDED,
                    stderr=(
                        f"Memory limit exceeded (max {self._config.max_memory_mb} "
                        f"MiB): {trap_msg}"
                    ),
                    stdout=stdout,
                    elapsed_ms=elapsed_ms,
                    effective_preopens=effective_preopens,
                )
            if "epoch" in trap_msg or "interrupt" in trap_msg:
                return ExecutionResult(
                    status=ExecutionStatus.TIMEOUT,
                    stderr=f"Timeout after {self._config.timeout_seconds}s: {trap_msg}",
                    stdout=stdout,
                    elapsed_ms=elapsed_ms,
                    effective_preopens=effective_preopens,
                )
            # Fix (flagged in benchmarks/pocs/README.md): preview1
            # modules lifted with wasm-tools call proc_exit() which the
            # command adapter forwards to wasi:cli/exit; wasmtime then raises
            # "Exited with i32 exit status 0" for a clean exit. Mirror the
            # preview1 sandbox and treat exit status 0 as SUCCESS.
            if re.search(r"exit status 0", trap_msg):
                return ExecutionResult(
                    status=ExecutionStatus.SUCCESS,
                    exit_code=0,
                    stdout=stdout,
                    stderr=stderr,
                    elapsed_ms=elapsed_ms,
                    fuel_consumed=self._fuel_consumed(store),
                    effective_preopens=effective_preopens,
                )
            return ExecutionResult(
                status=ExecutionStatus.ERROR,
                exit_code=1,
                stdout=stdout,
                stderr=trap_msg,
                elapsed_ms=elapsed_ms,
                effective_preopens=effective_preopens,
            )
        except Exception as exc:
            if os.environ.get("CELL_DEBUG_TRACEBACK"):  # debug branch only
                import traceback

                traceback.print_exc()
            return ExecutionResult(
                status=ExecutionStatus.ERROR,
                exit_code=1,
                stdout=_read_capped_output(stdout_path),
                stderr=str(exc),
                elapsed_ms=(time.monotonic() - start_time) * 1000,
                effective_preopens=effective_preopens,
            )

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

    def cleanup(self) -> None:
        """Remove the host-owned capture directory."""
        import shutil

        if self._host_dir is None:
            return
        shutil.rmtree(self._host_dir, ignore_errors=True)
        self._host_dir = None
