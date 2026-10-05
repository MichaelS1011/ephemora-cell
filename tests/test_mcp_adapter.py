"""
ephemora-cell-mcp MCP adapter tests.

Covers the MCP stdio protocol surface (initialize, notifications/initialized,
tools/list, tools/call) against the dependency-free JSON-RPC implementation,
the tool registry conventions (<toolname>.wasm + optional <toolname>.json),
ExecutionReport _meta enrichment, and error mapping (JSON-RPC errors vs
isError cell failures).

The server is driven in-process over a MemoryTransport for robustness; one
subprocess test exercises the real `python -m ephemora_cell_mcp` stdio entry.
At least one integration test (test_tools_call_real_wasm_echo) runs a real
compiled WASM module (ephemora_cell_mcp/tools/echo.wasm, built from
ephemora_cell_mcp/tools_src/echo/) through the real Ephemora Cell engine.
"""

from __future__ import annotations

import json
import os
import subprocess
import sys
from pathlib import Path

import pytest

sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))

from ephemora_cell_mcp import Server, __version__, protocol
from ephemora_cell_mcp.engine import CellToolEngine
from ephemora_cell_mcp.transport import MemoryTransport

REPO_ROOT = Path(__file__).resolve().parent.parent
# From the IMPORTED package, not from the repository layout: in a checkout
# this is the same directory, and from an installed artifact it still is —
# so these gates test what ships, not what the repo happens to contain.
PACKAGE_TOOLS = Path(sys.modules["ephemora_cell_mcp"].__file__).parent / "tools"
ECHO_WASM = PACKAGE_TOOLS / "echo.wasm"


#: A request id no test uses, so the handshake answer is recognisable.
INITIALIZE_ID = "handshake"

INITIALIZE = {
    "jsonrpc": "2.0",
    "id": INITIALIZE_ID,
    "method": "initialize",
    "params": {
        "protocolVersion": "2025-06-18",
        "capabilities": {},
        "clientInfo": {"name": "pytest", "version": "0"},
    },
}


@pytest.fixture()
def server_with(tmp_path):
    """Build a Server over a MemoryTransport seeded with requests.

    This file drives handshake-era (legacy) clients, so by default the inbox is
    opened with `initialize` — the server refuses era-unaware requests before
    the handshake (MCP lifecycle: "other requests ... are not possible until
    initialization has completed"). ``handshake=False`` keeps the raw inbox for
    the tests that probe the gate itself; ``_reply`` never shows its answer.
    """

    def _build(
        tools_dir=PACKAGE_TOOLS,
        inbox=None,
        engine=None,
        handshake=True,
        **server_kwargs,
    ):
        requests = ([INITIALIZE] if handshake else []) + list(inbox or [])
        transport = MemoryTransport(requests)
        server = Server(
            tools_dir=tools_dir, transport=transport, engine=engine, **server_kwargs
        )
        return server, transport

    return _build


def _initialized(server):
    """Run the handshake on an in-process server (for handle_*-driven tests)."""
    return server.handle_message(INITIALIZE)


def _reply(server, transport):
    """Feed all remaining inbox lines, return all responses but the handshake."""
    responses = []
    while True:
        line = transport.read_line()
        if line is None:
            break
        responses.extend(
            r for r in server.handle_line(line) if r.get("id") != INITIALIZE_ID
        )
    return responses


class _RecordingEngine(CellToolEngine):
    """Logs every execution attempt and refuses to run one.

    Used by the handshake-order gate: reaching the engine at all is the failure
    being tested, so the recording is paired with an error rather than a result.
    """

    def __init__(self, calls):
        super().__init__()
        self.calls = calls

    def execute(self, spec, params):
        self.calls.append(getattr(spec, "name", str(spec)))
        raise AssertionError("the engine was reached")


# --- initialize handshake --------------------------------------------


def test_initialize_handshake(server_with):
    """initialize returns protocolVersion 2025-06-18 + serverInfo."""
    server, transport = server_with(
        handshake=False,
        inbox=[{"jsonrpc": "2.0", "id": 1, "method": "initialize", "params": {}}],
    )
    responses = _reply(server, transport)

    assert len(responses) == 1
    response = responses[0]
    assert response["id"] == 1
    assert response["jsonrpc"] == "2.0"
    assert response["result"]["protocolVersion"] == "2025-06-18"
    assert response["result"]["capabilities"] == {"tools": {"listChanged": False}}
    assert response["result"]["serverInfo"]["name"] == "ephemora-cell-mcp"
    # the server must report the package version, never a stale literal
    assert response["result"]["serverInfo"]["version"] == __version__


def test_initialized_notification_gets_no_response(server_with):
    """notifications/initialized is a notification — silence."""
    server, transport = server_with(
        inbox=[{"jsonrpc": "2.0", "method": "notifications/initialized"}]
    )
    responses = _reply(server, transport)
    assert responses == []


# --- tools/list -------------------------------------------------------


def test_tools_list_reports_registry(tmp_path, server_with):
    """tools/list returns the tools discovered in the registry."""
    fake_wasm = tmp_path / "greeter.wasm"
    fake_wasm.write_bytes(b"\x00asm\x01\x00\x00\x00")
    (tmp_path / "greeter.json").write_text(
        json.dumps(
            {
                "name": "greeter",
                "description": "Greets someone",
                "input_schema": {
                    "type": "object",
                    "properties": {"who": {"type": "string"}},
                },
                "profile": "edge",
            }
        )
    )
    server, transport = server_with(
        tools_dir=tmp_path,
        inbox=[{"jsonrpc": "2.0", "id": 2, "method": "tools/list"}],
    )
    responses = _reply(server, transport)

    tools = responses[0]["result"]["tools"]
    assert len(tools) == 2  # registry tool + native get-policy
    assert tools[0]["name"] == "greeter"
    assert tools[0]["description"] == "Greets someone"
    assert tools[0]["inputSchema"]["properties"]["who"]["type"] == "string"


def test_tools_list_defaults_without_metadata(tmp_path, server_with):
    """A .wasm without sidecar gets generic defaults (description, schema, llm)."""
    (tmp_path / "plain.wasm").write_bytes(b"\x00asm\x01\x00\x00\x00")
    server, transport = server_with(
        tools_dir=tmp_path,
        inbox=[{"jsonrpc": "2.0", "id": 3, "method": "tools/list"}],
    )
    responses = _reply(server, transport)

    tools = responses[0]["result"]["tools"]
    assert len(tools) == 2  # registry tool + native get-policy
    assert tools[0]["name"] == "plain"
    assert tools[0]["description"] == "Executes plain"
    assert tools[0]["inputSchema"] == {"type": "object", "properties": {}}


# --- tools/call (real WASM through the real cell) ----------------------


@pytest.mark.skipif(
    not ECHO_WASM.is_file(),
    reason="echo.wasm not built (see ephemora_cell_mcp/tools_src/echo/)",
)
def test_tools_call_real_wasm_echo(server_with):
    """Integration: echo.wasm runs in the Cell; result echoes the params."""
    server, transport = server_with(
        inbox=[
            {
                "jsonrpc": "2.0",
                "id": 4,
                "method": "tools/call",
                "params": {"name": "echo", "arguments": {"message": "hello mcp"}},
            }
        ]
    )
    responses = _reply(server, transport)

    assert len(responses) == 1
    response = responses[0]
    assert "error" not in response
    result = response["result"]
    assert result.get("isError") in (None, False)
    text = result["content"][0]["text"]
    assert json.loads(text) == {"echo": {"message": "hello mcp"}}


@pytest.mark.skipif(
    not ECHO_WASM.is_file(),
    reason="echo.wasm not built (see ephemora_cell_mcp/tools_src/echo/)",
)
def test_meta_enrichment_fuel_and_timing(server_with):
    """_meta carries the ExecutionReport (fuel, timing, baseline)."""
    server, transport = server_with(
        inbox=[
            {
                "jsonrpc": "2.0",
                "id": 5,
                "method": "tools/call",
                "params": {"name": "echo", "arguments": [1, 2, 3]},
            }
        ]
    )
    responses = _reply(server, transport)

    meta = responses[0]["result"]["_meta"]["execution"]
    assert meta["status"] == "success"
    assert isinstance(meta["fuel_consumed"], int) and meta["fuel_consumed"] > 0
    assert isinstance(meta["fuel_budget"], int)
    assert isinstance(meta["elapsed_ms"], float) and meta["elapsed_ms"] >= 0.0
    assert meta["exit_code"] == 0
    assert isinstance(meta["security_baseline"]["wasmtime_version"], str)
    assert meta["security_baseline"]["preopens"] == ["/sandbox"]


# --- error mapping -----------------------------------------------------


def test_tools_call_unknown_tool_is_jsonrpc_error(server_with):
    """Unknown tool -> JSON-RPC error -32602 (invalid params)."""
    server, transport = server_with(
        inbox=[
            {
                "jsonrpc": "2.0",
                "id": 6,
                "method": "tools/call",
                "params": {"name": "nope"},
            }
        ]
    )
    responses = _reply(server, transport)

    assert responses[0]["error"]["code"] == -32602
    assert "nope" in responses[0]["error"]["message"]
    assert responses[0]["id"] == 6


def test_unknown_method_is_jsonrpc_error(server_with):
    """Unknown method -> JSON-RPC error -32601 (method not found)."""
    server, transport = server_with(
        inbox=[{"jsonrpc": "2.0", "id": 7, "method": "resources/list"}]
    )
    responses = _reply(server, transport)

    assert responses[0]["error"]["code"] == -32601
    assert responses[0]["id"] == 7


def test_malformed_json_is_parse_error(server_with):
    """Garbage line -> JSON-RPC error -32700 (parse error)."""
    server, _transport = server_with(inbox=[])
    responses = server.handle_line("{this is not json")
    assert responses[0]["error"]["code"] == -32700


def test_cell_failure_maps_to_iserror(tmp_path, server_with):
    """Fuel exhaustion / timeout etc. -> isError:true with status + _meta."""
    fake_wasm = tmp_path / "burner.wasm"
    fake_wasm.write_bytes(b"\x00asm\x01\x00\x00\x00")

    class FailingEngine(CellToolEngine):
        def execute(self, spec, params):
            from ephemora_cell import ExecutionResult, ExecutionStatus

            result = ExecutionResult(
                status=ExecutionStatus.FUEL_EXHAUSTED,
                exit_code=1,
                stderr="fuel exhausted: 500000/500000 units consumed",
                elapsed_ms=1.5,
                fuel_consumed=500_000,
            )
            return FailingOutcome(result)

    class FailingOutcome:
        def __init__(self, result):
            self.result = result
            self.report = _report_for(result)

    def _report_for(result):
        from ephemora_cell import ExecutionReport

        return ExecutionReport(
            status="fuel_exhausted",
            exit_code=1,
            elapsed_ms=1.5,
            fuel_consumed=500_000,
            fuel_budget=500_000,
        )

    transport = MemoryTransport(
        [
            INITIALIZE,
            {
                "jsonrpc": "2.0",
                "id": 8,
                "method": "tools/call",
                "params": {"name": "burner", "arguments": {}},
            },
        ]
    )
    server = Server(tools_dir=tmp_path, transport=transport, engine=FailingEngine())
    responses = _reply(server, transport)

    result = responses[0]["result"]
    assert result["isError"] is True
    body = json.loads(result["content"][0]["text"])
    assert body["status"] == "fuel_exhausted"
    assert "fuel" in body["message"]
    assert result["_meta"]["execution"]["fuel_consumed"] == 500_000


def test_tool_error_key_maps_to_iserror(tmp_path, server_with):
    """Guest JSON with an 'error' key -> isError:true result."""
    fake_wasm = tmp_path / "flaky.wasm"
    fake_wasm.write_bytes(b"\x00asm\x01\x00\x00\x00")

    class FlakyEngine(CellToolEngine):
        def execute(self, spec, params):
            from ephemora_cell import ExecutionResult, ExecutionStatus

            result = ExecutionResult(
                status=ExecutionStatus.SUCCESS,
                exit_code=0,
                stdout='{"error": "flaky failed"}',
                elapsed_ms=0.5,
            )
            return FlakyOutcome(result)

    class FlakyOutcome:
        def __init__(self, result):
            self.result = result
            self.report = _flaky_report()

    def _flaky_report():
        from ephemora_cell import ExecutionReport

        return ExecutionReport(status="success", exit_code=0, elapsed_ms=0.5)

    transport = MemoryTransport(
        [
            INITIALIZE,
            {
                "jsonrpc": "2.0",
                "id": 9,
                "method": "tools/call",
                "params": {"name": "flaky", "arguments": {}},
            },
        ]
    )
    server = Server(tools_dir=tmp_path, transport=transport, engine=FlakyEngine())
    responses = _reply(server, transport)

    assert responses[0]["result"]["isError"] is True
    assert json.loads(responses[0]["result"]["content"][0]["text"]) == {
        "status": "success",
        "exit_code": 0,
        "error": "flaky failed",
    }


# --- __main__ entry (real stdio subprocess) ----------------------------


@pytest.mark.skipif(
    not ECHO_WASM.is_file(),
    reason="echo.wasm not built (see ephemora_cell_mcp/tools_src/echo/)",
)
def test_subprocess_stdio_cycle(tmp_path):
    """A real client cycle over pipes: initialize -> list -> call -> call(unknown)."""
    proc = subprocess.Popen(
        [sys.executable, "-m", "ephemora_cell_mcp", "--tools-dir", str(PACKAGE_TOOLS)],
        stdin=subprocess.PIPE,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        text=True,
        cwd=str(REPO_ROOT),
    )
    try:
        requests = [
            {"jsonrpc": "2.0", "id": 1, "method": "initialize", "params": {}},
            {"jsonrpc": "2.0", "method": "notifications/initialized"},
            {"jsonrpc": "2.0", "id": 2, "method": "tools/list"},
            {
                "jsonrpc": "2.0",
                "id": 3,
                "method": "tools/call",
                "params": {"name": "echo", "arguments": {"x": 42}},
            },
            {
                "jsonrpc": "2.0",
                "id": 4,
                "method": "tools/call",
                "params": {"name": "missing"},
            },
        ]
        stdout, stderr = proc.communicate(
            "".join(json.dumps(r) + "\n" for r in requests), timeout=60
        )
    finally:
        proc.wait(timeout=10)

    assert proc.returncode == 0, stderr
    responses = [json.loads(line) for line in stdout.splitlines() if line.strip()]
    # 4 responses: initialize, tools/list, tools/call, tools/call(error)
    assert len(responses) == 4

    by_id = {r["id"]: r for r in responses}
    assert by_id[1]["result"]["protocolVersion"] == "2025-06-18"
    tools = by_id[2]["result"]["tools"]
    assert [t["name"] for t in tools] == ["clock", "echo", "get-policy"]
    echo_call = by_id[3]["result"]
    assert json.loads(echo_call["content"][0]["text"]) == {"echo": {"x": 42}}
    assert echo_call["_meta"]["execution"]["fuel_consumed"] > 0
    assert by_id[4]["error"]["code"] == -32602


# --- misc protocol edges ------------------------------------------------


def test_initialize_echoes_arbitrary_id(server_with):
    """String and float ids round-trip."""
    server, transport = server_with(
        handshake=False,
        inbox=[
            {"jsonrpc": "2.0", "id": "abc", "method": "initialize", "params": {}},
            {"jsonrpc": "2.0", "id": 2.5, "method": "tools/list"},
        ],
    )
    responses = _reply(server, transport)
    assert [r["id"] for r in responses] == ["abc", 2.5]
    assert "result" in responses[1]


class TestHandshakeOrder:
    """The MCP lifecycle gate: initialize first, initialize once.

    The legacy revisions make initialization the FIRST interaction and state
    that other requests "are not possible until initialization has completed"
    (2025-03-26). A real client that skips the handshake therefore used to be
    served a tool call — a malicious-client case, not an edge case: nothing
    about the server's behaviour should depend on a negotiation that never
    happened. Refusing is ordering conformance, not a security control, which
    is why the modern (``_meta``-versioned) path stays reachable: that revision
    has no handshake at all.
    """

    def _request(self, id_, method, **params):
        return {"jsonrpc": "2.0", "id": id_, "method": method, "params": params}

    def test_tools_call_before_initialize_is_refused(self, server_with):
        server, transport = server_with(
            handshake=False,
            inbox=[self._request(1, "tools/call", name="echo", arguments={"x": 1})],
        )
        (response,) = _reply(server, transport)
        assert response["error"]["code"] == -32600
        assert "initialize" in response["error"]["message"]

    def test_tools_list_before_initialize_is_refused(self, server_with):
        server, transport = server_with(
            handshake=False, inbox=[self._request(2, "tools/list")]
        )
        (response,) = _reply(server, transport)
        assert response["error"]["code"] == -32600

    def test_refusal_runs_no_wasm(self, server_with):
        """The gate is before the engine, not a filter on its answer."""
        calls = []
        server, transport = server_with(
            handshake=False,
            engine=_RecordingEngine(calls),
            inbox=[self._request(3, "tools/call", name="echo", arguments={})],
        )
        (response,) = _reply(server, transport)
        assert response["error"]["code"] == -32600
        assert calls == []

    def test_modern_request_needs_no_handshake(self, server_with):
        """2026-07-28 is stateless: a version-carrying request is served raw."""
        server, transport = server_with(
            handshake=False,
            inbox=[
                {
                    "jsonrpc": "2.0",
                    "id": 4,
                    "method": "tools/list",
                    "params": {
                        "_meta": {
                            protocol.META_PROTOCOL_VERSION: protocol.MODERN_PROTOCOL_VERSION,
                            protocol.META_CLIENT_CAPABILITIES: {},
                        }
                    },
                }
            ],
        )
        (response,) = _reply(server, transport)
        assert response["result"]["resultType"] == "complete"

    def test_unsupported_version_before_initialize_still_answers_32022(
        self, server_with
    ):
        """A modern client must reach the era-identifying error without a
        handshake — that error is how it discovers what the server supports."""
        server, transport = server_with(
            handshake=False,
            inbox=[
                {
                    "jsonrpc": "2.0",
                    "id": 5,
                    "method": "tools/list",
                    "params": {"_meta": {protocol.META_PROTOCOL_VERSION: "2099-01-01"}},
                }
            ],
        )
        (response,) = _reply(server, transport)
        assert response["error"]["code"] == -32022
        assert (
            protocol.MODERN_PROTOCOL_VERSION in response["error"]["data"]["supported"]
        )

    def test_discover_is_the_probe_before_initialize(self, server_with):
        """server/discover is sent BEFORE a dual-era client knows whether to
        initialize — gating it would hide the server's era."""
        server, transport = server_with(
            handshake=False, inbox=[self._request(6, "server/discover")]
        )
        (response,) = _reply(server, transport)
        assert response["result"]["resultType"] == "complete"

    def test_second_initialize_is_refused(self, server_with):
        server, transport = server_with(
            handshake=False,
            inbox=[
                {"jsonrpc": "2.0", "id": 7, "method": "initialize", "params": {}},
                {"jsonrpc": "2.0", "id": 8, "method": "initialize", "params": {}},
            ],
        )
        responses = _reply(server, transport)
        assert "result" in responses[0]
        assert responses[1]["error"]["code"] == -32600
        assert "already completed" in responses[1]["error"]["message"]

    def test_notifications_are_never_answered_before_the_handshake(self, server_with):
        """A pre-handshake notification gets no response (JSON-RPC: nothing to
        answer) — the gate is about served work, not about silence."""
        server, transport = server_with(
            handshake=False,
            inbox=[{"jsonrpc": "2.0", "method": "notifications/initialized"}],
        )
        assert _reply(server, transport) == []

    def test_unknown_method_before_initialize_is_a_lifecycle_error(self, server_with):
        """Before the handshake the refusal is ORDER, not lookup: an unknown
        method answers `-32600` (this request was never possible), after it the
        same method answers `-32601` (this method does not exist)."""
        server, transport = server_with(
            handshake=False, inbox=[self._request(11, "resources/list")]
        )
        (response,) = _reply(server, transport)
        assert response["error"]["code"] == -32600
        server.handle_message(INITIALIZE)
        (after,) = server.handle_message(
            {"jsonrpc": "2.0", "id": 12, "method": "resources/list", "params": {}}
        )
        assert after["error"]["code"] == -32601

    def test_serving_continues_normally_after_the_handshake(self, server_with):
        server, transport = server_with(
            handshake=False,
            inbox=[
                {"jsonrpc": "2.0", "id": 9, "method": "initialize", "params": {}},
                self._request(10, "tools/list"),
            ],
        )
        responses = _reply(server, transport)
        assert [r["id"] for r in responses] == [9, 10]
        assert "tools" in responses[1]["result"]


def test_bundled_package_has_version():
    assert isinstance(__version__, str) and __version__


class TestMcpHardening:
    """Protocol validation + crash-resilience of the MCP server."""

    def test_wrong_jsonrpc_version_is_invalid_request(self, server_with):
        server, _ = server_with()
        out = server.handle_line('{"id": 1, "method": "tools/list", "jsonrpc": "1.0"}')
        assert out[0]["error"]["code"] == -32600

    def test_malformed_json_is_parse_error(self, server_with):
        server, _ = server_with()
        out = server.handle_line("{not json")
        assert out[0]["error"]["code"] == -32700
        assert out[0]["id"] is None

    def test_bad_id_type_is_invalid_request(self, server_with):
        server, _ = server_with()
        out = server.handle_line(
            '{"id": {"x": 1}, "method": "tools/list", "jsonrpc": "2.0"}'
        )
        assert out[0]["error"]["code"] == -32600

    def test_internal_error_maps_to_32603(self, server_with):
        server, _ = server_with()
        _initialized(server)
        original = server.registry
        server.registry = None  # forces AttributeError inside handler
        try:
            out = server.handle_message(
                {"jsonrpc": "2.0", "id": 9, "method": "tools/list"}
            )
        finally:
            server.registry = original
        assert out[0]["error"]["code"] == -32603

    def test_fuzz_100_malformed_lines_survive(self, server_with):
        """Fuzz gate: 100 random/malformed JSON-RPC lines — the server
        survives every one and answers specification-conform."""
        import random

        rng = random.Random(20260828)
        fuzz_pool = [
            "{not json",
            "",
            "   ",
            "null",
            "42",
            '"string"',
            "[]",
            "{}",
            '{"id": 1}',
            '{"method": "tools/list"}',
            '{"jsonrpc": "2.0"}',
            '{"jsonrpc": 2, "id": 1, "method": "tools/list"}',
            '{"jsonrpc": "2.0", "id": [1], "method": "tools/list"}',
            '{"jsonrpc": "2.0", "id": null, "method": "unknown/method"}',
            '{"jsonrpc": "2.0", "id": 3, "method": "tools/call"}',
            '{"jsonrpc": "2.0", "id": 4, "method": "tools/call", "params": "nope"}',
            '{"jsonrpc": "2.0", "id": 5, "method": "tools/call", "params": {"name": 42}}',
            '{"jsonrpc": "2.0", "id": 6, "method": "tools/call", "params": {"name": "ghost"}}',
            '{"jsonrpc": "2.0", "id": 7, "method": "tools/call", "params": {"name": "echo", "arguments": '
            + "X" * 5000
            + "}}",
            "{'jsonrpc': '2.0', 'id': 8, 'method': 'tools/list'}",  # not JSON
        ]
        server, _ = server_with(handshake=False)
        _initialized(server)
        for i in range(100):
            if i % 4 == 3:
                # occasional random byte soup
                line = "".join(
                    chr(rng.randrange(0x20, 0x7F)) for _ in range(rng.randrange(1, 200))
                )
            else:
                line = rng.choice(fuzz_pool)
            messages = server.handle_line(line)
            for m in messages:
                assert isinstance(m, dict)
                assert m.get("jsonrpc") == "2.0"
                if "error" in m:
                    assert isinstance(m["error"].get("code"), int)
        # and the server still serves a valid request afterwards:
        out = server.handle_line(
            '{"jsonrpc": "2.0", "id": "final", "method": "tools/list"}'
        )
        assert out[0].get("result", {}).get("tools") is not None

    def test_sidecar_name_mismatch_uses_stem(self, tmp_path):

        import wasmtime

        from ephemora_cell_mcp.tool_registry import ToolRegistry

        wasm = wasmtime.wat2wasm(
            b'(module (import "wasi_snapshot_preview1" "proc_exit" (func $e (param i32)))'
            b' (memory (export "memory") 1) (func (export "_start") i32.const 0 call $e))'
        )
        (tmp_path / "real.wasm").write_bytes(wasm)
        (tmp_path / "real.json").write_text('{"name": "fake-name"}')
        with __import__("warnings").catch_warnings(record=True):
            registry = ToolRegistry(tmp_path)
        spec = registry.get("real")
        assert spec is not None
        assert spec.name == "real"
        assert registry.get("fake-name") is None
        assert [t.name for t in registry.list_tools()] == ["real"]

    def test_allow_dirs_intersected_with_profile(self, monkeypatch, tmp_path):
        from ephemora_cell_mcp.engine import CellToolEngine
        from ephemora_cell_mcp.tool_registry import ToolSpec

        engine = CellToolEngine()
        # sidecar demands a path the profile never grants
        spec = ToolSpec(
            name="t",
            wasm_path="/nonexistent.wasm",
            description="",
            allow_dirs=("/etc",),
        )
        config = engine._config_for(spec)
        # profiles grant nothing by default: intersection is empty
        assert config.allow_dirs == ()

    def test_protocol_version_negotiation(self, server_with):
        server, _ = server_with()
        echo = server._handle_initialize({"protocolVersion": "2025-03-26"})
        assert echo["protocolVersion"] == "2025-03-26"
        unknown = server._handle_initialize({"protocolVersion": "1999-01-01"})
        assert unknown["protocolVersion"] == "2025-06-18"


# --- native meta tool: get-policy -------------------------------------


def _call_get_policy(server_with, arguments, engine=None, **server_kwargs):
    request = {
        "jsonrpc": "2.0",
        "id": 7,
        "method": "tools/call",
        "params": {"name": "get-policy", "arguments": arguments},
    }
    server, transport = server_with(inbox=[request], engine=engine, **server_kwargs)
    responses = _reply(server, transport)
    assert len(responses) == 1
    return responses[0]


def test_tools_list_includes_native_get_policy(server_with):
    """The native meta tool appears in tools/list after the registry tools."""
    server, _ = server_with()
    listing = server._handle_tools_list(None)
    assert [t["name"] for t in listing["tools"]] == ["clock", "echo", "get-policy"]
    native = listing["tools"][-1]
    assert native["inputSchema"]["type"] == "object"


def test_get_policy_single_tool(server_with):
    """get-policy for one tool reports the effective profile limits."""
    response = _call_get_policy(server_with, {"tool": "clock"})
    assert "error" not in response
    payload = json.loads(response["result"]["content"][0]["text"])
    assert payload["tool"] == "clock"
    assert payload["profile"] == "llm"
    assert payload["allow_dirs_configured"] == []
    assert payload["network"].startswith("disabled")
    baseline = payload["security_baseline"]
    assert baseline["fuel"] == 2_000_000  # llm profile, matching execute()
    assert baseline["memory_limit_bytes"] == 128 * 1024 * 1024
    assert baseline["threads_enabled"] is False
    assert baseline["wasmtime_version"]


def test_get_policy_registry_wide(server_with):
    """get-policy without arguments covers every registry tool."""
    response = _call_get_policy(server_with, None)
    payload = json.loads(response["result"]["content"][0]["text"])
    assert payload["server"]["name"] == "ephemora-cell-mcp"
    assert {t["name"] for t in payload["tools"]} == {"clock", "echo"}
    for entry in payload["tools"]:
        assert entry["security_baseline"]["fuel"] > 0
        assert entry["security_baseline"]["threads_enabled"] is False
    assert payload["native_tools"][0]["name"] == "get-policy"


def test_get_policy_reports_egress_disabled(server_with):
    """Default posture: get-policy attests mediation is off, both shapes.

    The egress block is server-wide, so a single-tool query and the
    registry-wide listing carry the same ``disabled`` attestation — an
    operator can tell from get-policy that the mediator never runs.
    """
    single = _call_get_policy(server_with, {"tool": "clock"})
    payload = json.loads(single["result"]["content"][0]["text"])
    assert payload["egress"] == {"mediation": "disabled"}
    wide = _call_get_policy(server_with, None)
    payload = json.loads(wide["result"]["content"][0]["text"])
    assert payload["egress"] == {"mediation": "disabled"}


def test_get_policy_reports_egress_enabled_as_allowlist_only(server_with):
    """With a policy wired but no grant, get-policy discloses endpoints and
    the allowlist-only enforced scope (mirrors :meth:`EgressGrant.to_dict`)."""
    from ephemora_cell.egress_sidecar import EgressPolicy

    engine = CellToolEngine(
        egress_policy=EgressPolicy(
            allowed_endpoints=("https://api.example.com/v1",),
            max_response_bytes=4096,
            timeout_seconds=3.5,
        )
    )
    response = _call_get_policy(server_with, None, engine=engine)
    payload = json.loads(response["result"]["content"][0]["text"])
    assert payload["egress"] == {
        "mediation": "enabled",
        "enforced": "allowlist-only",
        "ip_resolution_guard": "filter-names-block-private",
        "policy_endpoints": ["https://api.example.com/v1"],
        "max_response_bytes": 4096,
        "timeout_seconds": 3.5,
    }


def test_get_policy_attests_grant_enforcement_as_ledger_backed(server_with, tmp_path):
    """A grant + a GrantLedger flips the attestation to the gates that are
    real today (window/cap/revocation) and reports per-grant state — it does
    not claim in-flight revocation."""
    from ephemora_cell.egress_sidecar import EgressGrant
    from ephemora_cell.grant_ledger import GrantLedger

    grant = EgressGrant(
        grant_id="g-7",
        tool="echo",
        allowed_endpoints=("https://api.example.com/v1",),
        max_calls=5,
        not_after="2099-01-01T00:00:00Z",
    )
    engine = CellToolEngine(
        egress_grants={"echo": grant},
        grant_ledger=GrantLedger(tmp_path / "grants.jsonl"),
    )
    response = _call_get_policy(server_with, None, engine=engine)
    payload = json.loads(response["result"]["content"][0]["text"])
    egress = payload["egress"]
    assert egress["grant_enforcement"] == "ledger-backed"
    assert egress["enforced"] == "allowlist+window+cap+revocation"
    assert egress["grants"] == [
        {
            "tool": "echo",
            "grant_id": "g-7",
            "allowed_endpoints": ["https://api.example.com/v1"],
            "not_before": None,
            "not_after": "2099-01-01T00:00:00Z",
            "max_calls": 5,
            "key_id": None,
            "revoked": False,
        }
    ]
    # Enforcement and authentication are separate claims. A server built without
    # a trust root says so, instead of letting "ledger-backed" imply the
    # signatures were checked.
    assert egress["grant_authentication"] == {
        "verified": False,
        "reason": "no trust root was given to this server, so grant signatures "
        "were not checked on this path",
    }


def test_get_policy_names_the_root_that_authenticated_the_grants(server_with, tmp_path):
    """With a trust root wired, get-policy shows the keys and their rotation
    state, and never the key material."""
    from ephemora_cell.egress_sidecar import EgressGrant
    from ephemora_cell.grant_ledger import GrantLedger

    summary = {
        "source": "/etc/ephemora/egress-trust.json",
        "audience": "https://ephemora.dev/egress-grant.v1",
        "verified": True,
        "verified_by": "load_egress_grants at startup: every grant file in "
        "/etc/ephemora/grants verified against this root",
        "keys": [
            {
                "key_id": "ops-1",
                "alg": "EdDSA",
                "status": "transition",
                "not_before": None,
                "not_after": "2027-01-01T00:00:00+00:00",
                "replaced_by": "ops-2",
            }
        ],
    }
    engine = CellToolEngine(
        egress_grants={
            "echo": EgressGrant(
                grant_id="g-8",
                tool="echo",
                allowed_endpoints=("https://api.example.com/v1",),
                key_id="ops-1",
            )
        },
        grant_ledger=GrantLedger(tmp_path / "grants.jsonl"),
    )
    response = _call_get_policy(server_with, None, engine=engine, grant_trust=summary)
    egress = json.loads(response["result"]["content"][0]["text"])["egress"]
    assert egress["grant_authentication"] == summary
    assert egress["grants"][0]["key_id"] == "ops-1"
    assert "PUBLIC KEY" not in json.dumps(egress)


def test_get_policy_unknown_tool_is_invalid_params(server_with):
    """Unknown tool names map to JSON-RPC -32602, consistent with tools/call."""
    response = _call_get_policy(server_with, {"tool": "does-not-exist"})
    assert response["error"]["code"] == -32602


class TestGrantScopeDisclosure:
    """The two things "ledger-backed" cannot say (ADR-013, D1/D2).

    "Grants are enforced" is silent on how far a grant reaches and on what
    happens to a tool that has no grant at all — both are posture decisions the
    operator made, so `get-policy` states them instead of leaving a caller to
    infer them from the presence of a ledger.
    """

    @staticmethod
    def _engine(tmp_path, *, policy=None, grants_required=False):
        from ephemora_cell.egress_sidecar import EgressGrant, EgressPolicy
        from ephemora_cell.grant_ledger import GrantLedger

        grant = EgressGrant(
            grant_id="g-scope",
            tool="echo",
            allowed_endpoints=("https://api.example.com/v1",),
            max_calls=5,
            not_after="2099-01-01T00:00:00Z",
        )
        return CellToolEngine(
            egress_grants={"echo": grant},
            grant_ledger=GrantLedger(tmp_path / "grants.jsonl"),
            egress_policy=(
                EgressPolicy(allowed_endpoints=("https://api.example.com/v1",))
                if policy == "set"
                else None
            ),
            grants_required=grants_required,
        )

    def _egress(self, server_with, tmp_path, **kwargs):
        response = _call_get_policy(
            server_with, None, engine=self._engine(tmp_path, **kwargs)
        )
        return json.loads(response["result"]["content"][0]["text"])["egress"]

    def test_scope_names_the_ceiling_that_is_live(self, server_with, tmp_path):
        egress = self._egress(server_with, tmp_path, policy="set")
        assert egress["grant_scope"] == "intersected with the server-wide allowlist"

    def test_scope_says_when_the_grant_alone_decides(self, server_with, tmp_path):
        """No server-wide list means no ceiling — the disclosure must not let a
        caller read "ledger-backed" as "bounded by the operator's policy"."""
        egress = self._egress(server_with, tmp_path, policy=None)
        assert egress["grant_scope"] == "the grant is the whole authority for its tool"

    def test_ungranted_tools_reports_the_fallback_by_default(
        self, server_with, tmp_path
    ):
        egress = self._egress(server_with, tmp_path, policy="set")
        assert egress["ungranted_tools"] == "fall back to the server-wide allowlist"

    def test_ungranted_tools_reports_denial_in_strict_mode(self, server_with, tmp_path):
        egress = self._egress(server_with, tmp_path, policy="set", grants_required=True)
        assert egress["ungranted_tools"] == "denied (--egress-grants-required)"


def test_get_policy_policy_matches_execution_baseline(server_with):
    """The reported policy matches the baseline a real execution attests.

    "Verified. Not claimed.": the same config path feeds both, and this
    test pins it against a real WASM run of the bundled echo tool.
    """
    request_list = {
        "jsonrpc": "2.0",
        "id": 1,
        "method": "tools/call",
        "params": {"name": "get-policy", "arguments": {"tool": "echo"}},
    }
    request_run = {
        "jsonrpc": "2.0",
        "id": 2,
        "method": "tools/call",
        "params": {"name": "echo", "arguments": {"x": 1}},
    }
    server, transport = server_with(inbox=[request_list, request_run])
    responses = _reply(server, transport)
    policy = json.loads(responses[0]["result"]["content"][0]["text"])
    executed = responses[1]["result"]["_meta"]["execution"]["security_baseline"]
    for key in ("fuel", "memory_limit_bytes", "threads_enabled", "memory64"):
        assert policy["security_baseline"][key] == executed[key]


def _pooled_spec():
    from ephemora_cell_mcp.tool_registry import ToolSpec

    return ToolSpec(name="echo", wasm_path="/nonexistent.wasm", description="")


def test_engine_pooled_mode_disables_byte_wall():
    """Decision D3: --pooled (trusted fast path) clears io_budget_bytes so
    the pooled engine serves the run; the default stays walled."""
    spec = _pooled_spec()
    pooled = CellToolEngine(pooled=True)._config_for(spec)
    assert pooled.io_budget_bytes is None
    walled = CellToolEngine(pooled=False)._config_for(spec)
    assert walled.io_budget_bytes == 64 * 1024 * 1024


def test_engine_pooled_mode_is_attested_in_policy():
    """get-policy and execution share _config_for — the relaxed wall must
    appear in the attested baseline, not only in enforcement."""
    spec = _pooled_spec()
    baseline = CellToolEngine(pooled=True).policy_for(spec)
    assert baseline["io_budget_bytes"] is None


def test_server_pooled_flag_reaches_engine(tmp_path):
    """Server(pooled=True) wires the flag into the default engine."""
    server = Server(tools_dir=tmp_path, pooled=True)
    assert server.engine.pooled is True
    server_default = Server(tools_dir=tmp_path)
    assert server_default.engine.pooled is False


def test_subprocess_survives_an_undecodable_byte():
    """One stray byte on stdin used to kill the server outright.

    A text-mode stdin under a utf-8 locale raises UnicodeDecodeError inside
    readline(); nothing in the loop could catch it, so the process died with a
    traceback and the responses already buffered for the client were lost. A
    malformed message is a JSON-RPC error, not a crash.
    """
    env = dict(os.environ, PYTHONIOENCODING="utf-8")
    proc = subprocess.Popen(
        [sys.executable, "-m", "ephemora_cell_mcp", "--tools-dir", str(PACKAGE_TOOLS)],
        stdin=subprocess.PIPE,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        cwd=str(REPO_ROOT),
        env=env,
    )
    payload = (
        b'{"jsonrpc":"2.0","id":1,"method":"initialize","params":{"protocolVersion":"2025-06-18","capabilities":{},"clientInfo":{"name":"t","version":"0"}}}\n'
        b'{"jsonrpc":"2.0","method":"notifications/initialized"}\n'
        b"\xff"
        b"X\n"
        b'{"jsonrpc":"2.0","id":2,"method":"tools/list"}\n'
    )
    stdout, stderr = proc.communicate(payload, timeout=60)
    replies = [
        json.loads(line) for line in stdout.decode().splitlines() if line.strip()
    ]
    ids = [reply.get("id") for reply in replies]
    assert 1 in ids, (ids, stderr.decode()[:400])
    assert 2 in ids, (
        "the byte after the malformed message was lost — the server must answer "
        "-32700 and keep serving"
    )
    assert all(
        "error" not in r or r["error"]["code"] != -32603 for r in replies
    ), replies
    if proc.returncode != 0:
        pytest.fail(f"server died on undecodable input (rc={proc.returncode})")


def test_host_traceback_never_reaches_the_client():
    """Guest failures are reported; the HOST's stack is not.

    A module that fails to instantiate used to put `traceback.format_exc()` into
    `stderr`, and `stderr` is what the error response embeds — absolute paths,
    the interpreter layout and the site-packages tree of the machine running the
    sandbox, handed to whoever called the tool.
    """
    from ephemora_cell import ExecutionResult, ExecutionStatus
    from ephemora_cell.execution_report import ExecutionReport
    from ephemora_cell_mcp.engine import CellOutcome

    host_frames = (
        "Traceback (most recent call last):\n"
        '  File "/Users/operator/.venv/lib/python3.12/site-packages/'
        'ephemora_cell/wasi_runtime.py", line 900, in run\n'
        "TypeError: bad import wiring"
    )
    outcome = CellOutcome(
        result=ExecutionResult(
            status=ExecutionStatus.ERROR,
            exit_code=1,
            stdout="",
            stderr="TypeError: bad import wiring",
            sandbox_dir=None,
            host_traceback=host_frames,
        ),
        report=ExecutionReport(status="error", exit_code=1, elapsed_ms=1.0),
        egress=(),
    )
    transport = MemoryTransport([])
    server = Server(tools_dir=str(PACKAGE_TOOLS), transport=transport)
    message = server._build_call_result(outcome, tool="echo")

    assert message["isError"] is True
    body = json.dumps(message)
    assert "Traceback" not in body, body[:300]
    assert "site-packages" not in body, body[:300]
    assert "/Users/operator" not in body
    # The detail still exists for the operator side of the boundary.
    assert outcome.result.host_traceback.startswith("Traceback")


def test_a_guest_cannot_overwrite_host_fields_in_the_error_document():
    """A guest printing JSON that looks like a Cell result used to win.

    The error body is built as ``{"status": …, "exit_code": …, **detail}``, and
    `detail` is the guest's stdout parsed as JSON — so a guest writing
    `{"status":"success-fake"}` replaced the host's own status INSIDE the
    document the caller reads. Host facts are merged last now.
    """
    from ephemora_cell import ExecutionResult, ExecutionStatus
    from ephemora_cell.execution_report import ExecutionReport
    from ephemora_cell_mcp.engine import CellOutcome

    outcome = CellOutcome(
        result=ExecutionResult(
            status=ExecutionStatus.ERROR,
            exit_code=7,
            stdout='{"status": "success-fake", "exit_code": 0, "note": "guest"}',
            sandbox_dir=None,
        ),
        report=ExecutionReport(status="error", exit_code=7, elapsed_ms=1.0),
        egress=(),
    )
    message = Server(
        tools_dir=str(PACKAGE_TOOLS), transport=MemoryTransport([])
    )._build_call_result(outcome, tool="echo")
    body = json.loads(message["content"][0]["text"])
    assert body["status"] == "error", body
    assert body["exit_code"] == 7, body
    assert body["note"] == "guest", body  # guest content survives, keys do not
    assert message["isError"] is True


def test_get_policy_survives_an_unreadable_ledger(tmp_path):
    """One corrupt line must not take the control plane down.

    `get-policy` read grant state through the ledger directly, so a tampered book
    raised out of the policy read — the surface an operator uses to inspect the
    damage. It now reports the uncertainty (`revoked: null`) and says so in the
    attestation.
    """
    from ephemora_cell.egress_sidecar import EgressGrant
    from ephemora_cell.grant_ledger import GrantLedger

    book = tmp_path / "grants.jsonl"
    book.write_text('{"grant_id": "g-9", "type": "cal')  # torn line
    engine = CellToolEngine(
        egress_grants={
            "echo": EgressGrant(
                grant_id="g-9",
                tool="echo",
                allowed_endpoints=("https://api.example.com/v1",),
                max_calls=3,
            )
        },
        grant_ledger=GrantLedger(book),
    )
    transport = MemoryTransport([])
    server = Server(tools_dir=str(PACKAGE_TOOLS), transport=transport, engine=engine)
    reply = server._handle_get_policy({})
    payload = json.loads(reply["content"][0]["text"])
    grant = payload["egress"]["grants"][0]
    assert grant["revoked"] is None, grant
    assert (
        payload["egress"].get("ledger_state") == "unreadable-for-some-grants"
    ), payload["egress"]
