# SPDX-License-Identifier: BUSL-1.1
# Copyright 2026 Michael Soppa

"""v1.2 — the authenticated subject reaches the enforcing authorizer.

Before this change the HTTP bridge authenticated each client's token into a
subject (``CURRENT_SUBJECT``) but never carried it to the stdio child, whose
authorizer only ever saw the single process ``--subject``. The bridge is the
multi-client boundary, so client B could drive a tool granted only to client
A.

The fix binds the authenticated subject to each upstream call with a keyed MAC
over a per-instance secret shared through the private spawn channel
(``subject_binding``); the child resolves the per-request subject from that
binding and refuses (fail-closed) any missing or forged binding. In direct
stdio mode a client-supplied ``_meta`` subject stays inert.

These cases need no MCP SDK: they drive the real ``Server.handle_message``
enforcement point with a stub engine and exercise the bridge's pure helpers.
"""

from __future__ import annotations

import json
import os
import sys
from pathlib import Path

sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))

from ephemora_cell import ExecutionResult, ExecutionStatus
from ephemora_cell.execution_report import ExecutionReport
from ephemora_cell_mcp.authz import Authorizer, ToolPolicy
from ephemora_cell_mcp.engine import CellOutcome
from ephemora_cell_mcp.server import Server
from ephemora_cell_mcp.subject_binding import (
    SUBJECT_KEY,
    SUBJECT_PROOF_KEY,
    subject_proof,
    verify_subject_binding,
)

PACKAGE_TOOLS = Path(sys.modules["ephemora_cell_mcp"].__file__).parent / "tools"

INITIALIZE = {
    "jsonrpc": "2.0",
    "id": "handshake",
    "method": "initialize",
    "params": {
        "protocolVersion": "2025-06-18",
        "capabilities": {},
        "clientInfo": {"name": "pytest", "version": "0"},
    },
}

SECRET = "s" * 32


class _StubEngine:
    """Records which tools actually ran; returns a successful Cell outcome."""

    def __init__(self) -> None:
        self.calls: list[str] = []

    def execute(self, spec, params, *, subject=None):
        self.calls.append(spec.name)
        return CellOutcome(
            result=ExecutionResult(
                status=ExecutionStatus.SUCCESS,
                exit_code=0,
                stdout=json.dumps({"echoed": params}),
                stderr="",
                sandbox_dir=None,
            ),
            report=ExecutionReport(status="success", exit_code=0, elapsed_ms=0.1),
            egress=(),
        )


def _policy(subjects: dict[str, list[dict]]) -> Authorizer:
    doc = {
        "policy_version": "test-1",
        "subjects": [
            {"subject": name, "permissions": perms} for name, perms in subjects.items()
        ],
    }
    return Authorizer(ToolPolicy.from_dict(doc))


def _build(**kwargs):
    engine = kwargs.pop("engine", None) or _StubEngine()
    server = Server(tools_dir=str(PACKAGE_TOOLS), engine=engine, **kwargs)
    server.handle_message(INITIALIZE)
    return server, engine


def _meta(subject: str, secret: str = SECRET) -> dict:
    return {SUBJECT_KEY: subject, SUBJECT_PROOF_KEY: subject_proof(secret, subject)}


def _call(server: Server, name: str, meta=None) -> dict:
    params: dict = {"name": name, "arguments": {}}
    if meta is not None:
        params["_meta"] = meta
    return server.handle_message(
        {"jsonrpc": "2.0", "id": 7, "method": "tools/call", "params": params}
    )[0]


def _is_denied(response: dict) -> bool:
    result = response.get("result")
    return bool(isinstance(result, dict) and result.get("isError"))


def _reason(response: dict) -> str:
    return json.loads(response["result"]["content"][0]["text"])["reason"]


# --- the binding primitive -------------------------------------------------


def test_the_binding_is_a_keyed_mac_and_rejects_forgery():
    assert verify_subject_binding(SECRET, _meta("alice")) == ("alice", None)
    forged = {SUBJECT_KEY: "alice", SUBJECT_PROOF_KEY: subject_proof(SECRET, "bob")}
    assert verify_subject_binding(SECRET, forged) == (
        None,
        "invalid upstream subject binding",
    )
    assert verify_subject_binding(SECRET, {SUBJECT_KEY: "alice"}) == (
        None,
        "missing upstream subject binding",
    )
    assert verify_subject_binding(SECRET, None) == (
        None,
        "missing upstream subject binding",
    )
    assert verify_subject_binding(None, _meta("alice")) == (
        None,
        "subject binding secret not configured",
    )


# --- end-to-end through the real enforcement point -------------------------


def test_a_call_runs_under_the_subject_the_bridge_carried():
    authorizer = _policy({"alice": [{"tool": "clock"}], "bob": [{"tool": "echo"}]})
    server, engine = _build(
        authorizer=authorizer, subject_from_upstream=True, subject_secret=SECRET
    )
    ok = _call(server, "clock", meta=_meta("alice"))
    assert not _is_denied(ok)
    denied = _call(server, "echo", meta=_meta("alice"))
    assert _is_denied(denied) and _reason(denied) == "no matching permission"
    ok = _call(server, "echo", meta=_meta("bob"))
    assert not _is_denied(ok)
    denied = _call(server, "clock", meta=_meta("bob"))
    assert _is_denied(denied)
    assert engine.calls == ["clock", "echo"]


def test_a_forged_subject_binding_is_denied_and_runs_nothing():
    authorizer = _policy({"alice": [{"tool": "clock"}]})
    server, engine = _build(
        authorizer=authorizer, subject_from_upstream=True, subject_secret=SECRET
    )
    forged = {SUBJECT_KEY: "alice", SUBJECT_PROOF_KEY: subject_proof("evil", "alice")}
    resp = _call(server, "clock", meta=forged)
    assert _is_denied(resp)
    assert _reason(resp) == "invalid upstream subject binding"
    assert engine.calls == []


def test_a_missing_binding_is_denied_in_upstream_mode():
    authorizer = _policy({"alice": [{"tool": "clock"}]})
    server, engine = _build(
        authorizer=authorizer, subject_from_upstream=True, subject_secret=SECRET
    )
    resp = _call(server, "clock")
    assert _is_denied(resp)
    assert _reason(resp) == "missing upstream subject binding"
    assert engine.calls == []


def test_direct_mode_ignores_a_client_supplied_meta_subject():
    authorizer = _policy({"alice": [{"tool": "clock"}], "bob": [{"tool": "echo"}]})
    server, engine = _build(authorizer=authorizer, subject="alice")
    # A client claiming bob's identity in _meta still gets alice's policy.
    resp = _call(server, "echo", meta=_meta("bob"))
    assert _is_denied(resp)
    ok = _call(server, "clock", meta=_meta("bob"))
    assert not _is_denied(ok)
    assert engine.calls == ["clock"]


def test_the_audit_record_names_the_carried_subject():
    records: list[dict] = []
    authorizer = _policy({"alice": [{"tool": "clock"}], "bob": [{"tool": "echo"}]})
    server, _ = _build(
        authorizer=authorizer,
        subject_from_upstream=True,
        subject_secret=SECRET,
        audit_sink=records.append,
    )
    _call(server, "echo", meta=_meta("bob"))
    _call(server, "echo", meta=_meta("alice"))
    assert records[0]["subject"] == "bob" and records[0]["decision"] == "ALLOW"
    assert records[1]["subject"] == "alice" and records[1]["decision"] == "DENY"


def test_get_policy_read_is_also_subject_bound():
    authorizer = _policy({"alice": [{"tool": "get-policy", "action": "read"}]})
    server, _ = _build(
        authorizer=authorizer, subject_from_upstream=True, subject_secret=SECRET
    )
    ok = _call(server, "get-policy", meta=_meta("alice"))
    assert not _is_denied(ok)
    denied = _call(server, "get-policy", meta=_meta("bob"))
    assert _is_denied(denied)


# --- the bridge side (no SDK needed) ---------------------------------------


def test_the_bridge_binds_the_subject_and_arms_the_child():
    from ephemora_cell_mcp.http_bridge import BridgePolicy, _child_env, _subject_meta

    meta = _subject_meta(SECRET, "alice")
    assert meta is not None
    assert verify_subject_binding(SECRET, meta) == ("alice", None)
    assert _subject_meta(None, "alice") is None  # single-token: no per-request subject
    assert _subject_meta(SECRET, None) is None  # unauthenticated: no subject

    policy = BridgePolicy(
        host="127.0.0.1",
        port=8765,
        token="t" * 40,
        allow_non_loopback=False,
        token_env="EPHEMORA_MCP_BRIDGE_TOKEN",
    )
    env = _child_env(policy, SECRET)
    assert env["EPHEMORA_MCP_SUBJECT_FROM_UPSTREAM"] == "1"
    assert env["EPHEMORA_MCP_SUBJECT_SECRET"] == SECRET
    assert "EPHEMORA_MCP_BRIDGE_TOKEN" not in env
