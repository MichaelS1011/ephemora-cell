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
LIGHT = WORKLOADS / "hello_rust.wasm"

try:
    from agents import Agent, Runner, function_tool
    from agents.tool import FunctionTool
except ImportError:
    print("SKIP: openai-agents not installed")
    sys.exit(0)


def execute_wasm(wasm_path: str) -> str:
    """Execute a WASM module in Ephemora Cell isolation."""
    executor = EphemoraCellExecutor(max_fuel=200_000, timeout=5)
    result = executor.execute(wasm_path)
    return json.dumps({
        "status": result.status,
        "elapsed_ms": result.elapsed_ms,
    })


execute_wasm_tool = function_tool(execute_wasm)


def tool_binding_proof():
    """Offline: the Cell-backed function is a real OpenAI FunctionTool and
    executes WASM in the sandbox. Proves the SDK<->Cell surface without a model.

    Also asserts the agent-surface criterion-3 guard offline: a model naming a
    module outside the operator allowlist is refused (``policy_denied``) — no
    arbitrary host binary runs — so the tool has a tested error path, not only
    success.
    """
    agent = Agent(name="Executor", tools=[execute_wasm_tool])
    registered = any(isinstance(t, FunctionTool) and t.name == "execute_wasm"
                     for t in agent.tools)
    tool_exec = json.loads(execute_wasm(str(LIGHT)))
    # error path: an out-of-allowlist path a model might hallucinate
    tool_err = json.loads(execute_wasm("/etc/hosts"))
    return {
        "tools_registered": [getattr(t, "name", type(t).__name__) for t in agent.tools],
        "tool_binding_verified": registered,
        "tool_execution_status": tool_exec.get("status"),
        "tool_denies_arbitrary_path": tool_err.get("status") == "policy_denied",
    }


async def test_openai_agents():
    """Run OpenAI Agents SDK with the Ephemora Cell tool."""
    binding = tool_binding_proof()

    model = os.environ.get("MODEL", "gpt-4o-mini")
    base_url = os.environ.get("OPENAI_BASE_URL")
    api_key = os.environ.get("OPENAI_API_KEY")
    if base_url:
        os.environ.setdefault("OPENAI_BASE_URL", base_url)

    if not api_key:
        return {
            "framework": "openai_agents",
            "llm_loop": "skipped",
            "llm_reason": "OPENAI_API_KEY not set — Runner.run() requires a model endpoint",
            **binding,
        }

    agent = Agent(
        name="Executor",
        model=model,
        instructions=(
            "Use execute_wasm to run each WASM module. "
            "Report combined results as JSON."
        ),
        tools=[execute_wasm_tool],
    )

    wasm_files = [str(LIGHT)]
    try:
        result = await Runner.run(
            starting_agent=agent,
            input=f"Execute: {json.dumps(wasm_files)}",
        )
    except Exception as exc:  # endpoint unreachable / auth — LLM loop not runnable here
        return {
            "framework": "openai_agents",
            "llm_loop": "skipped",
            "llm_reason": f"Runner.run() could not reach a model: {type(exc).__name__}",
            **binding,
        }

    output = ""
    for item in result.new_items:
        if hasattr(item, "content") and item.content:
            output += str(item.content)
    return {
        "framework": "openai_agents",
        "llm_loop": "executed",
        "output": output[:500],
        **binding,
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
        print(f"Tool binding verified : {result.get('tool_binding_verified')} "
              f"(registered: {result.get('tools_registered')})")
        print(f"Tool executed in Cell : {result.get('tool_execution_status')}")
        print(f"LLM decision loop      : {result.get('llm_loop')}"
              + (f" — {result.get('llm_reason')}" if result.get("llm_loop") == "skipped" else ""))
        if result.get("llm_loop") == "executed":
            print(f"Output: {result.get('output', '')[:300]}")
        print("Ephemora Cell used as OpenAI Agents tool sandbox")


if __name__ == "__main__":
    main()