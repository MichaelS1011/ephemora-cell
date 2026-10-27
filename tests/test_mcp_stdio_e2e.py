# SPDX-License-Identifier: BUSL-1.1
# Copyright 2026 Michael Soppa

"""End-to-end MCP over the real stdio process (v1.2, controlled client).

The other MCP cases drive ``handle_message`` in-process or a recorded server. This
one starts the shipped entry point as a child process, speaks JSON-RPC on its
stdin/stdout, and checks the two things only the real process can show: an allowed
tool actually executes, a denied one is refused, and the authorization decision
lands on stderr (the audit trail) while stdout stays pure protocol.
"""

from __future__ import annotations

import json
import os
import subprocess
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

import pytest

REPO = Path(__file__).resolve().parent.parent
TOOLS = REPO / "ephemora_cell_mcp" / "tools"
ECHO_WASM = TOOLS / "echo.wasm"

POLICY = {
    "policy_version": "1.2.0-1",
    "subjects": [{"subject": "alice", "permissions": [{"tool": "echo"}]}],
}

INITIALIZE = {
    "jsonrpc": "2.0",
    "id": 1,
    "method": "initialize",
    "params": {
        "protocolVersion": "2025-06-18",
        "capabilities": {},
        "clientInfo": {"name": "ap13-probe", "version": "0"},
    },
}


def _call(request_id: int, name: str, arguments: dict) -> dict:
    return {
        "jsonrpc": "2.0",
        "id": request_id,
        "method": "tools/call",
        "params": {"name": name, "arguments": arguments},
    }


def _drive(tmp_path, *requests):
    policy = tmp_path / "policy.json"
    policy.write_text(json.dumps(POLICY), encoding="utf-8")
    payload = "\n".join(json.dumps(r) for r in requests) + "\n"
    proc = subprocess.run(
        [
            sys.executable,
            "-m",
            "ephemora_cell_mcp",
            "--tools-dir",
            str(TOOLS),
            "--tool-policy",
            str(policy),
            "--subject",
            "alice",
        ],
        input=payload,
        capture_output=True,
        text=True,
        timeout=180,
        cwd=str(REPO),
    )
    responses = [json.loads(line) for line in proc.stdout.splitlines() if line.strip()]
    return proc, responses


@pytest.mark.skipif(not ECHO_WASM.exists(), reason="package tool module not present")
def test_an_allowed_tool_runs_and_a_denied_one_is_refused(tmp_path):
    pytest.importorskip("wasmtime", reason="the run leg needs the wasm runtime")
    if os.environ.get("EPHEMORA_ALLOW_UNQUALIFIED_RUNTIME") != "1":
        # The gate refuses an unqualified engine, and rightly so; this test needs
        # the run to actually happen, so it skips rather than weakening the gate.
        from ephemora_cell.runtime_qualification import runtime_qualification

        ok, _ = runtime_qualification()
        if not ok:
            pytest.skip("signed/qualified runtime required for the live run leg")

    proc, responses = _drive(
        tmp_path,
        INITIALIZE,
        _call(2, "echo", {"hello": "world"}),
        _call(3, "clock", {}),
    )
    by_id = {r.get("id"): r for r in responses}

    assert proc.returncode == 0, proc.stderr
    assert 1 in by_id  # the handshake answered on stdout

    # The granted tool really executed (not merely authorized): the host-observed
    # execution record says success, and the guest's own answer came back.
    allowed = by_id[2]["result"]
    assert allowed.get("isError") is not True, allowed
    assert allowed["_meta"]["execution"]["status"] == "success"
    assert json.loads(allowed["content"][0]["text"]) == {"echo": {"hello": "world"}}

    assert "error" not in by_id[3], by_id[3]
    denied = by_id[3]["result"]
    assert denied["isError"] is True
    assert json.loads(denied["content"][0]["text"])["denied"] is True
    # Nothing ran for the denied call.
    assert "_meta" not in denied or "execution" not in denied.get("_meta", {})

    # A decision per call on stderr; stdout carries protocol only.
    audit = [line for line in proc.stderr.splitlines() if line.startswith("authz ")]
    assert len(audit) >= 2, proc.stderr
    records = [json.loads(line[len("authz ") :]) for line in audit]
    assert {r["decision"] for r in records} == {"ALLOW", "DENY"}
    assert all("subject" in r and "tool" in r for r in records)
    for line in proc.stdout.splitlines():
        if line.strip():
            json.loads(line)  # stdout is protocol JSON, nothing else
