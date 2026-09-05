"""
P3 — ephemora-cell-mcp MCP adapter tests.

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

from ephemora_cell_mcp import Server, __version__
from ephemora_cell_mcp.engine import CellToolEngine
from ephemora_cell_mcp.transport import MemoryTransport

REPO_ROOT = Path(__file__).resolve().parent.parent
PACKAGE_TOOLS = REPO_ROOT / "ephemora_cell_mcp" / "tools"
ECHO_WASM = PACKAGE_TOOLS / "echo.wasm"


@pytest.fixture()
def server_with(tmp_path):
    """Build a Server over a MemoryTransport seeded with requests."""

    def _build(tools_dir=PACKAGE_TOOLS, inbox=None):
        transport = MemoryTransport(inbox or [])
        server = Server(tools_dir=tools_dir, transport=transport)
        return server, transport

    return _build


def _reply(server, transport):
    """Feed all remaining inbox lines, return all responses."""
    responses = []
    while True:
        line = transport.read_line()
        if line is None:
            break
        responses.extend(server.handle_line(line))
    return responses


# --- initialize handshake --------------------------------------------


def test_initialize_handshake(server_with):
    """initialize returns protocolVersion 2025-06-18 + serverInfo."""
    server, transport = server_with(
        inbox=[{"jsonrpc": "2.0", "id": 1, "method": "initialize", "params": {}}]
    )
    responses = _reply(server, transport)

    assert len(responses) == 1
    response = responses[0]
    assert response["id"] == 1
    assert response["jsonrpc"] == "2.0"
    assert response["result"]["protocolVersion"] == "2025-06-18"
    assert response["result"]["capabilities"] == {"tools": {"listChanged": False}}
    assert response["result"]["serverInfo"]["name"] == "ephemora-cell-mcp"
    assert response["result"]["serverInfo"]["version"] == "1.0.1"


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
            {
                "jsonrpc": "2.0",
                "id": 8,
                "method": "tools/call",
                "params": {"name": "burner", "arguments": {}},
            }
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
            {
                "jsonrpc": "2.0",
                "id": 9,
                "method": "tools/call",
                "params": {"name": "flaky", "arguments": {}},
            }
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
        inbox=[
            {"jsonrpc": "2.0", "id": "abc", "method": "initialize", "params": {}},
            {"jsonrpc": "2.0", "id": 2.5, "method": "initialize", "params": {}},
        ]
    )
    responses = _reply(server, transport)
    assert [r["id"] for r in responses] == ["abc", 2.5]


def test_bundled_package_has_version():
    assert __version__ == "1.0.1"


class TestM4Hardening:
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
        server, _ = server_with()
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


def _call_get_policy(server_with, arguments):
    request = {
        "jsonrpc": "2.0",
        "id": 7,
        "method": "tools/call",
        "params": {"name": "get-policy", "arguments": arguments},
    }
    server, transport = server_with(inbox=[request])
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


def test_get_policy_unknown_tool_is_invalid_params(server_with):
    """Unknown tool names map to JSON-RPC -32602, consistent with tools/call."""
    response = _call_get_policy(server_with, {"tool": "does-not-exist"})
    assert response["error"]["code"] == -32602


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
