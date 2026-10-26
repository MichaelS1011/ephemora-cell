"""CrewAI integration test — Ephemora Cell as sandboxed tool.

Real integration: CrewAI agent with Ephemora Cell as a tool for
isolated code execution.

Usage:
    python integration/agent_frameworks/test_crewai.py
    python integration/agent_frameworks/test_crewai.py --json
"""

from __future__ import annotations

import json
import sys
import uuid
from datetime import datetime, timezone
from pathlib import Path

sys.path.insert(0, str(Path(__file__).parent.parent.parent))
from integration.ephemora_cell_agent_executor import EphemoraCellExecutor

WORKLOADS = Path(__file__).parent.parent.parent / "benchmarks" / "workloads"
LIGHT = WORKLOADS / "hello_rust.wasm"

try:
    from crewai import Agent, Crew, Task
    from crewai.tools import tool
except ImportError:
    print("SKIP: crewai not installed")
    sys.exit(0)


@tool
def ephemora_cell_execute(wasm_path: str):
    """Execute a WASM module in Ephemora Cell isolation."""
    executor = EphemoraCellExecutor(max_fuel=200_000, timeout=5)
    result = executor.execute(wasm_path)
    return json.dumps(
        {
            "status": result.status,
            "elapsed_ms": result.elapsed_ms,
            "stdout": result.stdout,
        }
    )


def test_crewai():
    """Run a CrewAI crew with Ephemora Cell tool."""
    agent = Agent(
        role="Code Executor",
        goal="Execute WASM modules safely",
        backstory="You execute code in isolated sandboxes.",
        tools=[ephemora_cell_execute],
        allow_delegation=False,
    )

    wasm_files = [
        str(WORKLOADS / "data_transform.wasm"),
        str(WORKLOADS / "plugin_chain.wasm"),
        str(WORKLOADS / "code_review.wasm"),
    ]

    task = Task(
        description=f"Execute these 3 WASM modules and report results: {wasm_files}",
        expected_output="JSON with status for each module",
        agent=agent,
    )

    crew = Crew(
        agents=[agent],
        tasks=[task],
        verbose=False,
    )

    # --- offline integration proof (no LLM required) -------------------
    # The Ephemora Cell tool is a real CrewAI BaseTool bound to the agent.
    # Invoking it through CrewAI's own tool wrapper executes real WASM in the
    # sandbox — this proves the framework<->Cell integration surface without
    # calling a model. The autonomous LLM decision loop below needs a provider.
    bound_tool = agent.tools[0]
    tool_exec = json.loads(bound_tool.func(str(LIGHT)))
    binding = {
        "framework": "crewai",
        "tools_registered": [t.name for t in agent.tools],
        "tool_binding_verified": bound_tool.name == "ephemora_cell_execute",
        "tool_execution_status": tool_exec.get("status"),
    }

    # CrewAI needs OPENAI_API_KEY for the LLM loop — if missing, only the
    # tool-binding path above is exercised and the kickoff is skipped.
    import os

    if not os.environ.get("OPENAI_API_KEY"):
        return {
            **binding,
            "llm_loop": "skipped",
            "llm_reason": "OPENAI_API_KEY not set — crew.kickoff() requires an LLM provider",
        }

    result = crew.kickoff()
    return {
        **binding,
        "llm_loop": "executed",
        "raw_output": (
            str(result.raw)[:500] if hasattr(result, "raw") else str(result)[:500]
        ),
    }


def main():
    json_out = "--json" in sys.argv
    request_id = str(uuid.uuid4())[:8]

    result = test_crewai()
    report = {
        "test": "crewai_integration",
        "request_id": request_id,
        "timestamp": datetime.now(timezone.utc).isoformat(),
        **result,
    }

    if json_out:
        print(json.dumps(report, indent=2))
    else:
        print(f"CrewAI Integration (request: {request_id})")
        print("=" * 50)
        print(
            f"Tool binding verified : {result.get('tool_binding_verified')} "
            f"(registered: {result.get('tools_registered')})"
        )
        print(f"Tool executed in Cell : {result.get('tool_execution_status')}")
        print(
            f"LLM decision loop      : {result.get('llm_loop')}"
            + (
                f" — {result.get('llm_reason')}"
                if result.get("llm_loop") == "skipped"
                else ""
            )
        )
        if result.get("llm_loop") == "executed":
            print(f"Output: {result.get('raw_output', '')[:200]}")
        print("Ephemora Cell used as CrewAI tool sandbox")


if __name__ == "__main__":
    main()
