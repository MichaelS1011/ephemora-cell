"""LangGraph integration test — Ephemora Cell as sandboxed tool execution.

Real integration: LangGraph StateGraph with 3 nodes, each running
WASM code in Ephemora Cell.

Usage:
    python integration/agent_frameworks/test_langgraph.py
    python integration/agent_frameworks/test_langgraph.py --json
"""
from __future__ import annotations
import json
import sys
import uuid
from datetime import datetime, timezone
from pathlib import Path
from typing import TypedDict

sys.path.insert(0, str(Path(__file__).parent.parent.parent))
from integration.ephemora_cell_agent_executor import EphemoraCellExecutor

WORKLOADS = Path(__file__).parent.parent.parent / "benchmarks" / "workloads"

try:
    from langgraph.graph import StateGraph, END
    import langgraph
except ImportError:
    print("SKIP: langgraph not installed")
    sys.exit(0)


class AgentState(TypedDict):
    tool_calls: list[str]
    results: list[dict]


def make_tool_node(wasm_path: Path, tool_name: str):
    """LangGraph node that runs WASM in Ephemora Cell."""
    executor = EphemoraCellExecutor(max_fuel=100_000, timeout=5)

    def node(state: AgentState) -> dict:
        result = executor.execute(str(wasm_path))
        return {
            "tool_calls": state.get("tool_calls", []) + [tool_name],
            "results": state.get("results", []) + [{
                "tool": tool_name,
                "wasm": wasm_path.name,
                "status": result.status,
                "elapsed_ms": result.elapsed_ms,
            }],
        }

    return node


def test_langgraph():
    """Build and run LangGraph agent with Ephemora Cell."""
    graph = StateGraph(AgentState)

    graph.add_node("transform", make_tool_node(WORKLOADS / "data_transform.wasm", "data_transform"))
    graph.add_node("plugin", make_tool_node(WORKLOADS / "plugin_chain.wasm", "plugin_chain"))
    graph.add_node("review", make_tool_node(WORKLOADS / "code_review.wasm", "code_review"))

    graph.set_entry_point("transform")
    graph.add_edge("transform", "plugin")
    graph.add_edge("plugin", "review")
    graph.add_edge("review", END)

    app = graph.compile()
    initial = {"tool_calls": [], "results": []}
    final = app.invoke(initial)

    return {
        "framework": "langgraph",
        "langgraph_version": "installed",
        "nodes_executed": len(final["tool_calls"]),
        "tool_calls": final["results"],
        "all_executed": len(final["results"]) == 3,
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
            print(f"  [{tc['tool']:20s}] {tc['status']} ({tc['elapsed_ms']}ms)")
        print("=" * 50)
        print(f"Nodes executed: {result['nodes_executed']}/3")
        print("Ephemora Cell used as LangGraph tool sandbox")


if __name__ == "__main__":
    main()