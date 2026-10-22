"""LangGraph integration test — Ephemora Cell as sandboxed tool execution.

Real integration: LangGraph StateGraph with 3 nodes, each running
WASM code in Ephemora Cell.

Usage:
    python integration/agent_frameworks/test_langgraph.py
    python integration/agent_frameworks/test_langgraph.py --json
"""

from __future__ import annotations

import importlib.metadata
import itertools
import json
import sys
import uuid
from datetime import datetime, timezone
from pathlib import Path
from typing import TypedDict

sys.path.insert(0, str(Path(__file__).parent.parent.parent))
from integration.ephemora_cell_agent_executor import EphemoraCellExecutor

WORKLOADS = Path(__file__).parent.parent.parent / "benchmarks" / "workloads"
EXAMPLES = Path(__file__).parent.parent.parent / "examples"

try:
    from langgraph.graph import StateGraph, END
except ImportError:
    print("SKIP: langgraph not installed")
    sys.exit(0)

# Three lightweight tools that complete inside the budget (proves the graph
# drives real Cell executions) plus one deliberately-heavy module run against a
# tight fuel cap — that node returns `fuel_exhausted`, which is the sandbox
# *correctly* bounding a runaway tool, not an integration failure.
TOOLS = [
    ("data_transform", WORKLOADS / "data_transform.wasm", 200_000, False),
    ("hello_rust", WORKLOADS / "hello_rust.wasm", 200_000, False),
    ("hello", EXAMPLES / "hello.wasm", 200_000, False),
    ("code_review_heavy", WORKLOADS / "code_review.wasm", 100_000, True),
]


class AgentState(TypedDict):
    tool_calls: list[str]
    results: list[dict]


def make_tool_node(wasm_path: Path, tool_name: str, max_fuel: int):
    """LangGraph node that runs WASM in Ephemora Cell."""
    executor = EphemoraCellExecutor(max_fuel=max_fuel, timeout=5)

    def node(state: AgentState) -> dict:
        result = executor.execute(str(wasm_path))
        # the refusal reason is kept in the row so the verdict below can tell
        # "the host said no" apart from "the guest failed" — a status alone reads
        # the same for both
        refused = bool(result.reason) or "refused:" in (result.stderr or "")
        return {
            "tool_calls": state.get("tool_calls", []) + [tool_name],
            "results": state.get("results", [])
            + [
                {
                    "tool": tool_name,
                    "wasm": wasm_path.name,
                    "status": result.status,
                    "blocked": result.blocked,
                    "refused": refused,
                    "reason": result.reason or (result.stderr or "")[:80] or None,
                    "elapsed_ms": result.elapsed_ms,
                }
            ],
        }

    return node


def test_langgraph():
    """Build and run a LangGraph agent that executes WASM in Ephemora Cell."""
    graph = StateGraph(AgentState)
    names = [t[0] for t in TOOLS]
    for name, path, fuel, _ in TOOLS:
        graph.add_node(name, make_tool_node(path, name, fuel))

    graph.set_entry_point(names[0])
    for a, b in itertools.pairwise(names):
        graph.add_edge(a, b)
    graph.add_edge(names[-1], END)

    app = graph.compile()
    final = app.invoke({"tool_calls": [], "results": []})
    results = final["results"]
    succeeded = [r for r in results if r["status"] == "success"]
    bounded = [r for r in results if r["status"] == "fuel_exhausted"]
    # A node that produced a refusal is NOT a node that ran a tool. Counting rows
    # alone made a wholly refused session (an engine outside the qualified line,
    # a guest that is not installed) report all_tools_ran=true and exit 0 — a
    # denial reading as a pass, which is the one thing a gate must never do.
    refused = [r for r in results if r["refused"]]

    return {
        "framework": "langgraph",
        "langgraph_version": importlib.metadata.version("langgraph"),
        "nodes_executed": len(results),
        "tool_calls": results,
        "all_tools_ran": len(results) == len(TOOLS) and not refused,
        "refusals": [r["tool"] for r in refused],
        "lightweight_tools_succeeded": len(succeeded) == 3,
        "heavy_tool_bounded_by_fuel": len(bounded) == 1,
    }


def main():
    json_out = "--json" in sys.argv
    request_id = str(uuid.uuid4())[:8]

    result = test_langgraph()
    report = {
        "test": "langgraph_integration",
        "request_id": request_id,
        "timestamp": datetime.now(timezone.utc).isoformat(),
        **result,
    }

    if json_out:
        print(json.dumps(report, indent=2))
    else:
        print(f"LangGraph Integration (request: {request_id})")
        print(f"LangGraph {result['langgraph_version']}")
        print("=" * 50)
        for tc in result["tool_calls"]:
            flag = " REFUSED" if tc["refused"] else ""
            print(f"  [{tc['tool']:20s}] {tc['status']}{flag} ({tc['elapsed_ms']}ms)")
        print("=" * 50)
        print(
            f"Nodes executed: {result['nodes_executed']}/{len(TOOLS)}  "
            f"(all_tools_ran={result['all_tools_ran']})"
        )
        if result["refusals"]:
            print(f"  refused by the host      : {result['refusals']}")
        print(
            f"  lightweight tools succeeded : {result['lightweight_tools_succeeded']}"
        )
        print(
            f"  heavy tool bounded by fuel   : {result['heavy_tool_bounded_by_fuel']}"
        )
        print("Ephemora Cell used as LangGraph tool sandbox")

    # A gate that cannot fail is not a gate. This one's own claim is that real
    # tools ran under real budgets; if they did not, the process says so.
    passed = (
        result["all_tools_ran"]
        and result["lightweight_tools_succeeded"]
        and result["heavy_tool_bounded_by_fuel"]
    )
    return 0 if passed else 1


if __name__ == "__main__":
    sys.exit(main())
