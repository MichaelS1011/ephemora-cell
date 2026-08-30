"""Generic Ephemora Cell execution layer for any agent framework.

Ephemora Cell is a WASM execution primitive — not a framework library.
Any framework, any model, any language, any OS can use this adapter.

Usage:
    from integration.ephemora_cell_agent_executor import EphemoraCellExecutor

    executor = EphemoraCellExecutor(max_fuel=100_000, timeout=5)
    result = executor.execute("module.wasm")
    if result.blocked:
        print(f"Blocked: {result.status}")
"""
from __future__ import annotations
from dataclasses import dataclass
from pathlib import Path

sys_path = str(Path(__file__).parent.parent)
import sys
sys.path.insert(0, sys_path)

from ephemora_cell import WASISandbox, WASIConfig


@dataclass
class ExecutionResult:
    """Structured result from an isolated execution."""
    status: str
    exit_code: int
    stdout: str
    stderr: str
    elapsed_ms: float
    blocked: bool


class EphemoraCellExecutor:
    """Drop-in execution layer for any agent framework.

    Wraps Ephemora Cell WASISandbox with a simple execute() interface.
    Framework-agnostic — works with Hermes, NemoClaw, LangGraph, CrewAI, etc.
    """

    def __init__(self, max_fuel: int = 100_000, timeout: int = 5, max_memory_mb: int = 16):
        self.config = WASIConfig(
            max_fuel=max_fuel,
            timeout_seconds=timeout,
            max_memory_mb=max_memory_mb,
        )

    def execute(self, wasm_path: str) -> ExecutionResult:
        """Execute a WASM module in isolation.

        Args:
            wasm_path: Path to compiled .wasm file.

        Returns:
            ExecutionResult with status, output, and timing.
        """
        sandbox = WASISandbox(config=self.config)
        try:
            result = sandbox.run(wasm_path, abi="auto")
            return ExecutionResult(
                status=result.status.value,
                exit_code=result.exit_code,
                stdout=result.stdout[:1000],
                stderr=result.stderr[:1000],
                elapsed_ms=round(result.elapsed_ms, 2),
                blocked=result.status.value != "success",
            )
        finally:
            sandbox.cleanup()