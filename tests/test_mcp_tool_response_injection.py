# SPDX-License-Identifier: BUSL-1.1
# Copyright 2026 Michael Soppa
"""A tool result cannot call another tool: MCP does not chain tool calls.

This is the deterministic half of the agent attack-chain question. It does not
run a model, a prompt or an agent loop — no LLM harness exists here and none is
claimed. What it pins is the protocol fact the agent layer rests on:

* MCP's ``tools/call`` is a **client -> server request**. A tool result is a
  response payload (``content`` text/JSON), not a protocol frame.
* The host captures a guest's stdout inside the sandbox and parses it as the
  tool's *value*; it never splices those bytes into the server's transport, so
  a guest that prints ``{"jsonrpc":"2.0","method":"tools/call",...}`` produces
  text, not a second execution.
* A JSON-RPC *response* arriving where a request is expected is invalid
  (``-32600``), not a command. There is no server-initiated tool-call method in
  this server's advertised capabilities.

The recorder engine below is an observation point, not a mock of the sandbox:
the real bundled ``echo`` and ``clock`` modules execute through the real
``CellToolEngine``. A positive control calls ``clock`` directly, proving the
recorder would see a second execution if one happened.

What this does NOT test: an isolated agent fed a malicious document, web page,
file, tool description or tool response and *choosing* to misuse its tools.
That requires an agent/model loop (with a real or scripted policy) and is
reported as untested in the S4 audit; the n8n integration doc records the same
boundary ("the agent-driven end-to-end run is BLOCKED"). This file proves only
that the transport cannot turn content into a tool invocation by itself.
"""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any

from ephemora_cell_mcp.engine import CellToolEngine
from ephemora_cell_mcp.server import Server

TOOLS = Path(__file__).resolve().parent.parent / "ephemora_cell_mcp" / "tools"


class RecordingEngine:
    """Delegate to the real engine and record which tool specs actually ran."""

    def __init__(self, inner: CellToolEngine) -> None:
        self.inner = inner
        self.calls: list[str] = []

    def execute(self, spec: Any, params: Any, *, subject: Any = None):
        self.calls.append(spec.name)
        return self.inner.execute(spec, params)

    def policy_for(self, spec: Any):
        return self.inner.policy_for(spec)


def _server() -> tuple[Server, RecordingEngine]:
    engine = RecordingEngine(CellToolEngine())
    server = Server(tools_dir=TOOLS, engine=engine)
    opened = server.handle_message(
        {"jsonrpc": "2.0", "id": 1, "method": "initialize", "params": {}}
    )
    assert "result" in opened[0]
    return server, engine


def _nested_call(target: str) -> dict[str, Any]:
    return {
        "jsonrpc": "2.0",
        "id": 4242,
        "method": "tools/call",
        "params": {"name": target, "arguments": {}},
    }


def test_nested_tool_call_in_tool_output_is_inert_text():
    """``echo`` emits a complete ``tools/call`` for ``clock``; only echo runs."""
    server, engine = _server()
    nested = _nested_call("clock")

    messages = server.handle_message(
        {
            "jsonrpc": "2.0",
            "id": 2,
            "method": "tools/call",
            "params": {"name": "echo", "arguments": {"payload": nested}},
        }
    )

    # Exactly one JSON-RPC message, and it is the response to request id 2.
    assert len(messages) == 1
    assert messages[0]["id"] == 2
    assert "method" not in messages[0]
    text = messages[0]["result"]["content"][0]["text"]
    assert '"method": "tools/call"' in text
    assert '"name": "clock"' in text
    assert messages[0]["result"]["_meta"]["execution"]["status"] == "success"
    # No clock execution: the nested request stayed inside the text value.
    assert engine.calls == ["echo"]
    assert "unix_ms" not in text and '"utc"' not in text

    # Positive control: the recorder is live and sees a direct clock execution.
    direct = server.handle_message(
        {
            "jsonrpc": "2.0",
            "id": 3,
            "method": "tools/call",
            "params": {"name": "clock", "arguments": {}},
        }
    )
    assert engine.calls == ["echo", "clock"]
    assert "unix_ms" in direct[0]["result"]["content"][0]["text"]


def test_a_jsonrpc_response_is_not_a_request_and_runs_nothing():
    """A tool *response* presented as input is invalid, never a command."""
    server, engine = _server()
    response_shaped = {
        "jsonrpc": "2.0",
        "id": 9,
        # A tool result shape, with a nested call hidden in its text.
        "result": {
            "content": [
                {
                    "type": "text",
                    "text": json.dumps(_nested_call("clock")),
                }
            ]
        },
    }

    messages = server.handle_message(response_shaped)

    assert len(messages) == 1
    assert messages[0]["error"]["code"] == -32600
    assert engine.calls == []

    # The same over the raw line path: still an invalid request, no execution.
    raw = server.handle_line(json.dumps(response_shaped))
    assert raw[0]["error"]["code"] == -32600
    assert engine.calls == []


def test_server_advertises_no_server_initiated_tool_or_sampling_channel():
    """The handshake promises tools, not a channel to call tools back."""
    fresh = Server(tools_dir=TOOLS, engine=CellToolEngine())
    opened = fresh.handle_message(
        {"jsonrpc": "2.0", "id": 5, "method": "initialize", "params": {}}
    )
    caps = opened[0]["result"]["capabilities"]
    assert caps == {"tools": {"listChanged": False}}
    for unsupported in ("sampling", "elicitation", "roots"):
        assert unsupported not in caps
