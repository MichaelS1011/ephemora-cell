"""Ephemora Cell — Isolated WASM sandbox with resource limits.

Usage:
    from ephemora_cell import run_wasm, WASISandbox, WASIConfig
    result = run_wasm("module.wasm")

    from ephemora_cell import get_profile
    config = get_profile("llm")

    from ephemora_cell import wasm_inspector
    info = wasm_inspector.inspect_module("module.wasm")

    from ephemora_cell import ExecutionReport
    report = ExecutionReport(...)

    from ephemora_cell import run_isolated
    result = run_isolated("module.wasm", WASIConfig())

    from ephemora_cell import EnginePool
    pool = EnginePool(max_engines=4)
    engine = pool.engine_for(WASIConfig())

    from ephemora_cell import ComponentSandbox, run_wasm
    result = run_wasm("module.component.wasm", abi="auto")

Failures are reported on the result, not raised: check
``ExecutionResult.status`` (success / error / timeout / fuel_exhausted /
memory_exceeded). There is deliberately no custom exception hierarchy —
the former exceptions.py classes were exported but never raised.
"""

from .engine_pool import EnginePool, config_fingerprint
from .execution_report import (
    ExecutionReport,
    PreExecutionRecord,
    verify_chain,
)
from .process_executor import measure_overhead
from .process_executor import run_isolated as _run_isolated_dict
from .profiles import get as get_profile
from .wasi_02 import ComponentSandbox, is_component_binary
from .wasi_runtime import (
    STDIN_MAX_BYTES,
    ExecutionResult,
    ExecutionStatus,
    WASIConfig,
    WASISandbox,
    run_wasm,
)
from .wasm_inspector import ModuleInfo, inspect_module


class _HybridExecutionResult(ExecutionResult):
    """ExecutionResult that also supports dict-style access for backwards compat.

    Existing code uses ``result["status"]`` (dict from process_executor),
    new code uses ``result.status`` (ExecutionResult). This hybrid supports
    both so the unified wrapper does not break legacy callers.
    """

    def __getitem__(self, key):
        if hasattr(self, key):
            return getattr(self, key)
        raise KeyError(key)

    def __contains__(self, key):
        return hasattr(self, key)

    def get(self, key, default=None):
        return getattr(self, key, default)

    def keys(self):
        """Dict-style keys: the ExecutionResult fields plus the extras the
        isolated worker report may carry, so ``dict(result)`` works."""
        import dataclasses

        names = {f.name for f in dataclasses.fields(self)}
        names.update(
            k
            for k in ("baseline_ms", "security_baseline", "io_cpu_used_seconds")
            if hasattr(self, k)
        )
        return names

    def __iter__(self):
        return iter(self.keys())

    def __len__(self):
        return len(self.keys())


def run_isolated(
    wasm_path: str,
    config=None,
    args=None,
    stdin_data=None,
    max_wasm_bytes=None,
    abi: str = "auto",
):
    """Execute a WASI module in an isolated worker subprocess.

    Unified wrapper: returns an :class:`ExecutionResult` (same type as
    :func:`run_wasm`) but also supports dict-style ``result["status"]`` for
    backwards compatibility. The underlying
    :mod:`ephemora_cell.process_executor` returns a dict; this wrapper
    converts it via :meth:`WASISandbox._result_from_report` so callers can
    use ``result.status`` uniformly.

    For the raw dict (legacy), import directly:
    ``from ephemora_cell.process_executor import run_isolated``.
    """
    from .process_executor import DEFAULT_MAX_WASM_BYTES

    if config is None:
        config = WASIConfig()
    if max_wasm_bytes is None:
        max_wasm_bytes = DEFAULT_MAX_WASM_BYTES
    raw = _run_isolated_dict(
        wasm_path,
        config,
        args=args,
        stdin_data=stdin_data,
        max_wasm_bytes=max_wasm_bytes,
        abi=abi,
    )
    base = WASISandbox._result_from_report(raw)
    # Convert to hybrid so both access styles work
    hybrid = _HybridExecutionResult(
        status=base.status,
        exit_code=base.exit_code,
        stdout=base.stdout,
        stderr=base.stderr,
        elapsed_ms=base.elapsed_ms,
        fuel_consumed=base.fuel_consumed,
        sandbox_dir=base.sandbox_dir,
        effective_preopens=base.effective_preopens,
        io_bytes_written=base.io_bytes_written,
        io_budget_exceeded=base.io_budget_exceeded,
        state_bytes=base.state_bytes,
    )
    # Carry dict extras that tests expect: baseline_ms, security_baseline, etc.
    # raw dict may contain additional keys not in ExecutionResult
    for k in ("baseline_ms", "security_baseline", "io_cpu_used_seconds"):
        if k in raw:
            object.__setattr__(hybrid, k, raw[k])
            # also make dict-style accessible via __dict__ already, but ensure getattr works
    return hybrid


# Backwards-compat alias: raw dict version
run_isolated_dict = _run_isolated_dict

__all__ = [
    "STDIN_MAX_BYTES",
    "ComponentSandbox",
    "EnginePool",
    "ExecutionReport",
    "ExecutionResult",
    "ExecutionStatus",
    "ModuleInfo",
    "PreExecutionRecord",
    "WASIConfig",
    "WASISandbox",
    "config_fingerprint",
    "get_profile",
    "inspect_module",
    "is_component_binary",
    "measure_overhead",
    "run_isolated",
    "run_isolated_dict",
    "run_wasm",
    "verify_chain",
]

__version__ = "1.0.4.2"
