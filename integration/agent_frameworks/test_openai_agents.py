"""OpenAI Agents SDK integration test — Ephemora Cell as tool.

Real integration: OpenAI Agents SDK with Ephemora Cell as a tool.

Usage:
    python integration/agent_frameworks/test_openai_agents.py
    python integration/agent_frameworks/test_openai_agents.py --json

Env (optional):
    OPENAI_BASE_URL=http://<host>:8000/v1
    MODEL=qwen3.6-27b-fp8
"""
from __future__ import annotations
import asyncio
import json
import os
import sys
import uuid
from datetime import datetime, timezone
from pathlib import Path

sys.path.insert(0, str(Path(__file__).parent.parent.parent))
from integration.ephemora_cell_agent_executor import EphemoraCellExecutor

WORKLOADS = Path(__file__).parent.parent.parent / "benchmarks" / "workloads"

try:
    from agents import Agent, Runner, function_tool
except ImportError:
    print("SKIP: openai-agents not installed")
    sys.exit(0)


@function_tool
def execute_wasm(wasm_path: str) -> str:
    """Execute a WASM module in Ephemora Cell isolation."""
    executor = EphemoraCellExecutor(max_fuel=100_000, timeout=5)
    result = executor.execute(wasm_path)
    return json.dumps({
        "status": result.status,
        "elapsed_ms": result.elapsed_ms,
    })


async def test_openai_agents():
    """Run OpenAI Agents SDK with Ephemora Cell tool."""
    model = os.environ.get("MODEL", "qwen3.6-27b-fp8")
    base_url = os.environ.get("OPENAI_BASE_URL", "http://localhost:8000/v1")
    api_key = os.environ.get("OPENAI_API_KEY", "x")
    # Ensure env vars are set for OpenAI Agents SDK
    os.environ.setdefault("OPENAI_BASE_URL", base_url)
    os.environ.setdefault("OPENAI_API_KEY", api_key)

    agent = Agent(
        name="Executor",
        model=model,
        instructions=(
            "Use execute_wasm to run each WASM module. "
            "Report combined results as JSON."
        ),
        tools=[execute_wasm],
    )

    wasm_files = [
        str(WORKLOADS / "data_transform.wasm"),
        str(WORKLOADS / "plugin_chain.wasm"),
        str(WORKLOADS / "code_review.wasm"),
    ]

    result = await Runner.run(
        starting_agent=agent,
        input=f"Execute: {json.dumps(wasm_files)}",
    )

    output = ""
    for item in result.new_items:
        if hasattr(item, "content") and item.content:
            output += item.content
    output = output[:500]

    return {
        "framework": "openai_agents",
        "status": "executed",
        "output": output,
        "tools_registered": ["execute_wasm"],
    }


def main():
    json_out = "--json" in sys.argv
    request_id = str(uuid.uuid4())[:8]

    result = asyncio.run(test_openai_agents())
    report = {
        "test": "openai_agents_integration",
        "request_id": request_id,
        "timestamp": datetime.now(timezone.utc).isoformat(),
        **result,
    }

    if json_out:
        print(json.dumps(report, indent=2))
    else:
        print(f"OpenAI Agents Integration (request: {request_id})")
        print("=" * 50)
        print(f"Status: {result.get('status')}")
        print(f"Output: {result.get('output', '')[:300]}")
        print("Ephemora Cell used as OpenAI Agents tool sandbox")


if __name__ == "__main__":
    main()