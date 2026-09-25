"""Supervisor/control-plane reachability probes (2026 probe class).

Motivation: OX Security's CVE-2026-82533 (DeepSeek Harness, CVSS 9.4) —
a sandboxed agent reached the runtime's control plane and disabled its
own confinement. In Cell's architecture the control plane is the MCP
``Server`` + ``ToolRegistry`` + the operator-allowlisted requests dir +
the engine ``Config``; the guest's only outbound channels are
stdin/stdout and its ``/sandbox`` scratch. These probes assert that no
guest-visible surface can move a control-plane knob:

* CP-1  environment: deny-by-default — no env, no control-plane secrets
  (positive control: an explicitly granted name is the ONLY one visible);
* CP-2  request injection: guest writes a request-lookalike into its
  scratch — the requests dir never sees it (companion to
  TestTrustHandoff in tests/test_tool_signing.py);
* CP-3  tool surface: there is no tool that can change policy — a
  ``tools/call`` for a control-plane-sounding tool does not exist, and
  the only meta tool (``get-policy``) is read-only (ADR-006);
* CP-4  engine knobs: structurally frozen at every construction site —
  covered by tests/test_threads_baseline.py (referenced, not duplicated);
* CP-5  protocol abuse: oversized/handshake lines fail closed — covered
  by tests/test_transport.py (referenced, not duplicated).
"""

from __future__ import annotations

import os
import sys

sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))

import wasmtime

from ephemora_cell import WASIConfig, WASISandbox, run_wasm
from ephemora_cell_mcp.server import Server
from ephemora_cell_mcp.tool_registry import TOOL_REQUEST_SUFFIX
from ephemora_cell_mcp.transport import MemoryTransport

# Exits with the number of environment variables the guest can see.
ENV_COUNT_WAT = """(module
  (import "wasi_snapshot_preview1" "environ_sizes_get"
    (func $es (param i32 i32) (result i32)))
  (import "wasi_snapshot_preview1" "proc_exit" (func $exit (param i32)))
  (memory (export "memory") 1)
  (func (export "_start")
    i32.const 100 i32.const 104 call $es drop
    i32.const 100 i32.load call $exit
  )
)"""

# Writes "{}" into "evil.tool.request.json" on dirfd 3 (its scratch).
REQUEST_LOOKALIKE_WAT = """(module
  (import "wasi_snapshot_preview1" "path_open" (func $po
    (param i32 i32 i32 i32 i32 i64 i64 i32 i32) (result i32)))
  (import "wasi_snapshot_preview1" "fd_write" (func $fw
    (param i32 i32 i32 i32) (result i32)))
  (import "wasi_snapshot_preview1" "proc_exit" (func $exit (param i32)))
  (memory (export "memory") 1)
  (data (i32.const 0) "evil.tool.request.json")
  (data (i32.const 32) "{}")
  (func (export "_start")
    (local $err i32)
    i32.const 3 i32.const 0 i32.const 0 i32.const 22 i32.const 1
    i64.const 64 i64.const 0 i32.const 0 i32.const 100
    call $po local.set $err
    local.get $err if local.get $err call $exit end
    i32.const 64 i32.const 32 i32.store
    i32.const 68 i32.const 2 i32.store
    i32.const 100 i32.load i32.const 64 i32.const 1 i32.const 72
    call $fw local.set $err
    local.get $err call $exit
  )
)"""


class TestControlPlaneReachability:
    def test_env_denied_by_default(self, tmp_path):
        """CP-1: without an explicit allow_env grant the guest sees ZERO
        environment variables — the control plane's env is unreachable."""
        wasm = tmp_path / "env_count.wasm"
        wasm.write_bytes(wasmtime.wat2wasm(ENV_COUNT_WAT))
        result = run_wasm(str(wasm), config=WASIConfig(max_fuel=100_000))
        assert result.exit_code == 0, (
            f"guest saw {result.exit_code} environment variables — "
            "control-plane env leaked"
        )

    def test_env_grant_is_allowlist_not_leak(self, tmp_path):
        """CP-1 positive control: with an explicit grant, exactly ONE
        name is visible — proving the 0 above is a policy, not a broken
        probe."""
        wasm = tmp_path / "env_count.wasm"
        wasm.write_bytes(wasmtime.wat2wasm(ENV_COUNT_WAT))
        config = WASIConfig(max_fuel=100_000, allow_env=[("GRANTED_VAR", "x")])
        result = run_wasm(str(wasm), config=config)
        assert (
            result.exit_code == 1
        ), f"allowlist grant leaked {result.exit_code} names instead of 1"

    def test_guest_cannot_inject_tool_requests(self, tmp_path):
        """CP-2: the guest's request-lookalike lands in its scratch —
        the operator's requests dir stays empty and process_tool_requests
        has nothing to evaluate."""
        tools = tmp_path / "tools"
        requests = tmp_path / "requests"
        tools.mkdir()
        requests.mkdir()
        wasm = tmp_path / "lookalike.wasm"
        wasm.write_bytes(wasmtime.wat2wasm(REQUEST_LOOKALIKE_WAT))
        sandbox = WASISandbox(config=WASIConfig(max_fuel=1_000_000))
        try:
            result = sandbox.run(str(wasm))
            assert result.exit_code == 0, result.stderr
        finally:
            sandbox.cleanup()
        server = Server(
            tools_dir=tools,
            transport=MemoryTransport(),
            tool_requests_dir=requests,
        )
        report = server.process_tool_requests()
        assert report["accepted"] == []
        assert list(requests.glob(f"*{TOOL_REQUEST_SUFFIX}")) == []

    def test_no_policy_writing_tool_exists(self, tmp_path):
        """CP-3: the tool surface has no control-plane verbs. A
        tools/call for a sandbox-disabling tool is a plain unknown-tool
        error; get-policy (ADR-006) is read-only."""
        tools = tmp_path / "tools"
        tools.mkdir()
        server = Server(
            tools_dir=tools,
            transport=MemoryTransport(),
            tool_requests_dir=None,
        )

        def _response_for(out, request_id):
            msgs = out if isinstance(out, list) else [out]
            for m in msgs:
                if isinstance(m, dict) and m.get("id") == request_id:
                    return m
            return None

        for forbidden in (
            "disable-sandbox",
            "set-policy",
            "grant-permission",
            "load-tool",
        ):
            payload = {
                "jsonrpc": "2.0",
                "id": 1,
                "method": "tools/call",
                "params": {"name": forbidden, "arguments": {}},
            }
            response = _response_for(server.handle_message(payload), 1)
            # Unknown tool must be an error result, never an execution.
            assert response is not None, f"no response for {forbidden!r}"
            assert (
                response.get("error") is not None
                or response.get("result", {}).get("isError") is True
            ), f"control-plane tool {forbidden!r} resolved: {response}"
        # The only meta tool is READ-ONLY introspection (ADR-006): it
        # answers, and it cannot mutate anything by construction.
        gp = _response_for(
            server.handle_message(
                {
                    "jsonrpc": "2.0",
                    "id": 2,
                    "method": "tools/call",
                    "params": {"name": "get-policy", "arguments": {}},
                }
            ),
            2,
        )
        assert gp is not None and gp.get("result", {}).get("isError") is not True
