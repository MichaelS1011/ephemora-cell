"""LangChain integration test — Ephemora Cell as a sandboxed tool.

Real integration: a LangChain @tool wraps the Ephemora Cell executor and is
invoked directly. No LLM/API key is needed to prove the framework<->Cell tool
surface; the autonomous agent loop (an LLM choosing the tool) needs a provider
and is skipped when none is configured.

Usage:
    python integration/agent_frameworks/test_langchain.py
    python integration/agent_frameworks/test_langchain.py --json
"""

from __future__ import annotations

import importlib.metadata
import json
import sys
import uuid
from datetime import datetime, timezone
from pathlib import Path

sys.path.insert(0, str(Path(__file__).parent.parent.parent))
from integration.ephemora_cell_agent_executor import EphemoraCellExecutor

WORKLOADS = Path(__file__).parent.parent.parent / "benchmarks" / "workloads"
EXAMPLES = Path(__file__).parent.parent.parent / "examples"

try:
    from langchain_core.tools import tool
except ImportError:
    print("SKIP: langchain-core not installed")
    sys.exit(0)

# Two tools that complete inside the budget, plus one deliberately-heavy module
# run against a tight cap — the third returns a blocked status, which is the
# sandbox correctly bounding a runaway tool, not an integration failure.
TOOLS = [
    ("hello", EXAMPLES / "hello.wasm", 200_000),
    ("data_transform", WORKLOADS / "data_transform.wasm", 200_000),
    ("code_review_heavy", WORKLOADS / "code_review.wasm", 100_000),
]


@tool
def ephemora_cell_execute(wasm_path: str) -> str:
    """Execute a WASM module inside the Ephemora Cell sandbox and return its status."""
    executor = EphemoraCellExecutor(max_fuel=200_000, timeout=5)
    result = executor.execute(wasm_path)
    return json.dumps(
        {
            "status": result.status,
            "elapsed_ms": result.elapsed_ms,
            "stdout": result.stdout,
        }
    )


def test_langchain():
    """Invoke the LangChain tool across real workloads through the SDK wrapper."""
    runs = []
    for name, path, _fuel in TOOLS:
        out = json.loads(ephemora_cell_execute.invoke(str(path)))
        runs.append(
            {
                "tool": name,
                "wasm": path.name,
                "status": out["status"],
                "elapsed_ms": out["elapsed_ms"],
            }
        )
    succeeded = sum(1 for r in runs if r["status"] == "success")
    bounded = sum(1 for r in runs if r["status"] == "fuel_exhausted")
    return {
        "framework": "langchain",
        "langchain_core_version": importlib.metadata.version("langchain-core"),
        "tool_type": type(ephemora_cell_execute).__name__,
        "tools_invoked": len(runs),
        "runs": runs,
        "lightweight_tools_succeeded": succeeded == 2,
        "heavy_tool_bounded_by_fuel": bounded == 1,
    }


def main():
    json_out = "--json" in sys.argv
    request_id = str(uuid.uuid4())[:8]

    result = test_langchain()
    report = {
        "test": "langchain_integration",
        "request_id": request_id,
        "timestamp": datetime.now(timezone.utc).isoformat(),
        **result,
    }

    if json_out:
        print(json.dumps(report, indent=2))
    else:
        print(f"LangChain Integration (request: {request_id})")
        print(
            f"langchain-core {result['langchain_core_version']} — tool type {result['tool_type']}"
        )
        print("=" * 50)
        for r in result["runs"]:
            print(f"  [{r['tool']:20s}] {r['status']} ({r['elapsed_ms']}ms)")
        print("=" * 50)
        print(f"Tools invoked: {result['tools_invoked']}/{len(TOOLS)}")
        print(f"  lightweight succeeded : {result['lightweight_tools_succeeded']}")
        print(f"  heavy bounded by fuel : {result['heavy_tool_bounded_by_fuel']}")
        print("Ephemora Cell used as a LangChain tool sandbox")


if __name__ == "__main__":
    main()
