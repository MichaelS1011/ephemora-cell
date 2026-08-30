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

try:
    from crewai import Agent, Task, Crew
    from crewai.tools import tool
except ImportError:
    print("SKIP: crewai not installed")
    sys.exit(0)


@tool
def ephemora_cell_execute(wasm_path: str):
    """Execute a WASM module in Ephemora Cell isolation."""
    executor = EphemoraCellExecutor(max_fuel=100_000, timeout=5)
    result = executor.execute(wasm_path)
    return json.dumps({
        "status": result.status,
        "elapsed_ms": result.elapsed_ms,
        "stdout": result.stdout,
    })


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

    # CrewAI needs OPENAI_API_KEY — if missing, test is skipped
    import os
    if not os.environ.get("OPENAI_API_KEY"):
        return {
            "framework": "crewai",
            "status": "skipped",
            "reason": "OPENAI_API_KEY not set — crewai requires LLM provider",
            "tools_registered": ["ephemora_cell_execute"],
        }

    result = crew.kickoff()
    return {
        "framework": "crewai",
        "status": "executed",
        "raw_output": str(result.raw)[:500] if hasattr(result, "raw") else str(result)[:500],
        "tools_registered": ["ephemora_cell_execute"],
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
        print(f"Status: {result.get('status')}")
        if result.get("status") == "skipped":
            print(f"Reason: {result.get('reason')}")
        else:
            print(f"Output: {result.get('raw_output', '')[:200]}")
        print(f"Tool registered: ephemora_cell_execute")
        print("Ephemora Cell used as CrewAI tool sandbox")


if __name__ == "__main__":
    main()