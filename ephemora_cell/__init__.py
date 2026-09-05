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
from .execution_report import ExecutionReport
from .process_executor import measure_overhead, run_isolated
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

__all__ = [
    "STDIN_MAX_BYTES",
    "ComponentSandbox",
    "EnginePool",
    "ExecutionReport",
    "ExecutionResult",
    "ExecutionStatus",
    "ModuleInfo",
    "WASIConfig",
    "WASISandbox",
    "config_fingerprint",
    "get_profile",
    "inspect_module",
    "is_component_binary",
    "measure_overhead",
    "run_isolated",
    "run_wasm",
]

__version__ = "1.0.1"
