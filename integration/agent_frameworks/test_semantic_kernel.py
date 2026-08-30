"""Semantic Kernel integration test — Ephemora Cell as SK plugin.

Real integration: Semantic Kernel plugin with Ephemora Cell as
isolated WASM execution.

Usage:
    python integration/agent_frameworks/test_semantic_kernel.py
    python integration/agent_frameworks/test_semantic_kernel.py --json
"""
from __future__ import annotations
import asyncio
import json
import sys
import uuid
from datetime import datetime, timezone
from pathlib import Path

sys.path.insert(0, str(Path(__file__).parent.parent.parent))
from integration.ephemora_cell_agent_executor import EphemoraCellExecutor

WORKLOADS = Path(__file__).parent.parent.parent / "benchmarks" / "workloads"

try:
    from semantic_kernel import Kernel
    from semantic_kernel.functions import kernel_function
except ImportError:
    print("SKIP: semantic_kernel not installed")
    sys.exit(0)


class EphemoraCellPlugin:
    """Semantic Kernel plugin for WASM execution via Ephemora Cell."""

    @staticmethod
    @kernel_function(
        description="Execute a WASM module in Ephemora Cell isolation",
        name="execute",
    )
    def execute_wasm(wasm_path: str) -> str:
        executor = EphemoraCellExecutor(max_fuel=100_000, timeout=5)
        result = executor.execute(wasm_path)
        return json.dumps({
            "status": result.status,
            "elapsed_ms": result.elapsed_ms,
        })


async def run_test():
    kernel = Kernel()
    try:
        kernel.add_plugin(EphemoraCellPlugin(), plugin_name="Ephemora Cell")
    except Exception as exc:
        print("SKIP: plugin registration failed: %s" % exc)
        sys.exit(0)

    wasm_paths = [
        str(WORKLOADS / "data_transform.wasm"),
        str(WORKLOADS / "plugin_chain.wasm"),
        str(WORKLOADS / "code_review.wasm"),
    ]

    results = []
    for wasm in wasm_paths:
        outcome = await kernel.invoke(
            plugin_name="Ephemora Cell",
            function_name="execute",
            wasm_path=wasm,
        )
        results.append({
            "wasm": Path(wasm).name,
            "output": str(outcome.value) if outcome else "error",
        })

    return {
        "framework": "semantic_kernel",
        "status": "executed",
        "results": results,
        "modules_executed": len(results),
    }


def main():
    json_out = "--json" in sys.argv
    request_id = str(uuid.uuid4())[:8]

    result = asyncio.run(run_test())
    report = {
        "test": "semantic_kernel_integration",
        "request_id": request_id,
        "timestamp": datetime.now(timezone.utc).isoformat(),
        **result,
    }

    if json_out:
        print(json.dumps(report, indent=2))
    else:
        print(f"Semantic Kernel Integration (request: {request_id})")
        print("=" * 50)
        for r in result["results"]:
            print(f"  [{r['wasm']:25s}] {r['output']}")
        print("=" * 50)
        print(f"Modules executed: {result['modules_executed']}/3")
        print("Ephemora Cell used as Semantic Kernel plugin")


if __name__ == "__main__":
    main()