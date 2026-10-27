# SPDX-License-Identifier: BUSL-1.1
# Copyright 2026 Michael Soppa

"""ADR-016 per-identity MCP authorization, on the real product call path.

Every case drives :class:`ephemora_cell_mcp.Server.handle_message` — the same
entry ``serve()`` uses — so what is tested is the shipped enforcement point
inside ``_handle_tools_call`` / ``_handle_native_call``, not an isolated helper.
A stub engine stands in for the sandbox: these cases are about *whether a call
reaches execution*, not about WASM semantics (covered elsewhere).

Coverage follows the v1.2 founder directive v1.2: authorization immediately
before the tool call (v1.2), identity binding (v1.2), resource/action
scope (v1.2), audit records without secrets (v1.2), a fail-closed policy
document (v1.2) and the explicit legacy migration path (v1.2).
"""

from __future__ import annotations

import json
import os
import sys
from pathlib import Path

sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))

import pytest

from ephemora_cell import ExecutionResult, ExecutionStatus
from ephemora_cell.execution_report import ExecutionReport
from ephemora_cell_mcp.authz import ACTION_CALL, ACTION_READ, Authorizer, ToolPolicy
from ephemora_cell_mcp.engine import CellOutcome
from ephemora_cell_mcp.server import Server

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


def _policy(subjects: dict[str, list[dict]], version: str = "test-1") -> Authorizer:
    document = {
        "policy_version": version,
        "subjects": [
            {"subject": name, "permissions": perms} for name, perms in subjects.items()
        ],
    }
    return Authorizer(ToolPolicy.from_dict(document))


def _build(**kwargs):
    engine = kwargs.pop("engine", None) or _StubEngine()
    server = Server(tools_dir=str(PACKAGE_TOOLS), engine=engine, **kwargs)
    server.handle_message(INITIALIZE)
    return server, engine


def _call(server, name: str, arguments=None):
    return server.handle_message(
        {
            "jsonrpc": "2.0",
            "id": 7,
            "method": "tools/call",
            "params": {"name": name, "arguments": arguments or {}},
        }
    )[0]


def _is_denied(response: dict) -> bool:
    result = response.get("result")
    return bool(isinstance(result, dict) and result.get("isError"))


def _denial_reason(response: dict) -> str:
    text = response["result"]["content"][0]["text"]
    return json.loads(text)["reason"]


# --- v1.2: the explicit legacy migration path --------------------------


def test_without_a_policy_the_one_authenticated_client_keeps_working():
    """No --tool-policy: the pre-1.2 behaviour, unchanged (compat baseline)."""
    server, engine = _build()
    response = _call(server, "echo", {"x": 1})
    assert "result" in response and not _is_denied(response)
    assert engine.calls == ["echo"]


# --- v1.2: deny unknown / missing / unregistered / expired -------------


def test_an_unknown_client_is_denied():
    authorizer = _policy({"alice": [{"tool": "echo"}]})
    server, engine = _build(authorizer=authorizer, subject=None)
    response = _call(server, "echo")
    assert _is_denied(response)
    assert _denial_reason(response) == "unknown client"
    assert engine.calls == []


def test_a_subject_with_no_entry_is_denied():
    authorizer = _policy({"alice": [{"tool": "echo"}]})
    server, engine = _build(authorizer=authorizer, subject="mallory")
    response = _call(server, "echo")
    assert _is_denied(response)
    assert "no permissions for subject" in _denial_reason(response)
    assert engine.calls == []


def test_a_missing_permission_is_denied_but_an_allowed_tool_runs():
    authorizer = _policy({"alice": [{"tool": "clock"}]})
    server, engine = _build(authorizer=authorizer, subject="alice")
    denied = _call(server, "echo")
    assert _is_denied(denied)
    assert _denial_reason(denied) == "no matching permission"
    assert engine.calls == []
    allowed = _call(server, "clock")
    assert "result" in allowed and not _is_denied(allowed)
    assert engine.calls == ["clock"]


def test_an_expired_permission_is_denied():
    authorizer = _policy(
        {"alice": [{"tool": "echo", "not_after": 1_000.0}]}
    )  # long past
    server, engine = _build(authorizer=authorizer, subject="alice")
    response = _call(server, "echo")
    assert _is_denied(response)
    assert _denial_reason(response) == "permission expired"
    assert engine.calls == []


def test_a_not_yet_valid_permission_is_denied():
    authorizer = _policy({"alice": [{"tool": "echo", "not_before": 4_102_444_800.0}]})
    server, engine = _build(authorizer=authorizer, subject="alice")
    response = _call(server, "echo")
    assert _is_denied(response)
    assert _denial_reason(response) == "permission not yet valid"
    assert engine.calls == []


def test_an_unregistered_tool_is_denied_on_the_wire_and_audited():
    records: list[dict] = []
    authorizer = _policy({"alice": [{"tool": "*"}]})
    server, engine = _build(
        authorizer=authorizer, subject="alice", audit_sink=records.append
    )
    response = _call(server, "no-such-tool")
    # Wire shape is the pre-1.2 unknown-tool error (compatibility preserved).
    assert response["error"]["code"] == -32602
    assert engine.calls == []
    assert any(
        r["decision"] == "DENY" and r["reason"] == "unregistered tool" for r in records
    ), records


# --- v1.2: identity + resource/action scope ----------------------------


def test_client_a_cannot_call_a_tool_granted_only_to_client_b():
    authorizer = _policy(
        {
            "alice": [{"tool": "clock"}],
            "bob": [{"tool": "echo"}],
        }
    )
    server_a, engine_a = _build(authorizer=authorizer, subject="alice")
    server_b, engine_b = _build(authorizer=authorizer, subject="bob")
    assert _is_denied(_call(server_a, "echo"))
    assert _call(server_b, "echo").get("result") is not None
    assert engine_a.calls == [] and engine_b.calls == ["echo"]


def test_granting_execution_does_not_grant_reading_the_policy():
    """A tool grant and a read grant are distinct actions (v1.2)."""
    execute_only = _policy({"alice": [{"tool": "echo", "action": ACTION_CALL}]})
    server, _ = _build(authorizer=execute_only, subject="alice")
    response = _call(server, "get-policy", {"tool": "echo"})
    assert _is_denied(response)
    assert _denial_reason(response) == "no matching permission"

    read_only = _policy({"alice": [{"tool": "get-policy", "action": ACTION_READ}]})
    # get-policy reports profiles through the real engine (no guest runs).
    from ephemora_cell_mcp.engine import CellToolEngine

    server = Server(
        tools_dir=str(PACKAGE_TOOLS),
        engine=CellToolEngine(),
        authorizer=read_only,
        subject="alice",
    )
    server.handle_message(INITIALIZE)
    served = _call(server, "get-policy", {"tool": "echo"})
    assert "result" in served and not _is_denied(served)


def test_a_subject_cannot_widen_its_rights_by_naming_itself_in_the_request():
    """Identity comes from the host (--subject), never from request fields."""
    authorizer = _policy({"alice": [{"tool": "echo"}], "bob": []})
    # The server's subject is bob (empty grants); the client claims "alice"
    # in arguments — an argument field must not become the enforced identity.
    server, engine = _build(authorizer=authorizer, subject="bob")
    response = _call(server, "echo", {"subject": "alice", "as": "alice"})
    assert _is_denied(response)
    assert engine.calls == []


# --- v1.2: mutation control — the test detects a weakened rule ---------


def test_granting_the_permission_flips_the_same_call_to_allowed():
    """Mutation control: only the rule changes, the call is identical."""
    denied_authorizer = _policy({"alice": [{"tool": "clock"}]})
    server_denied, _ = _build(authorizer=denied_authorizer, subject="alice")
    assert _is_denied(_call(server_denied, "echo"))

    granted_authorizer = _policy({"alice": [{"tool": "echo"}]})
    server_allowed, engine = _build(authorizer=granted_authorizer, subject="alice")
    assert not _is_denied(_call(server_allowed, "echo"))
    assert engine.calls == ["echo"]


def test_the_deny_check_is_sensitive_to_the_enforcement_guard(monkeypatch):
    """Mutation control on the GUARD, not the rule.

    If a regression neutered the check (authorization always says yes), the
    deny cases above must flip. This test weakens the guard and asserts that
    the previously denied call is now served — proving the suite would catch
    that regression instead of passing anyway.
    """
    from ephemora_cell_mcp import authz as authz_mod

    authorizer = _policy({"alice": [{"tool": "clock"}]})
    server, engine = _build(authorizer=authorizer, subject="alice")
    assert _is_denied(_call(server, "echo"))  # guard on
    assert engine.calls == []

    def _always_allow(self, subject, tool, *, action="call", resource="*"):
        return authz_mod.Decision(
            allowed=True,
            reason="mutated",
            subject=subject,
            tool=tool,
            action=action,
            resource=resource,
            policy_version=self.policy.version,
        )

    monkeypatch.setattr(authz_mod.Authorizer, "authorize", _always_allow)
    assert not _is_denied(_call(server, "echo"))  # guard off -> allowed
    assert engine.calls == ["echo"]


# --- v1.2: audit records, no secrets -----------------------------------


def test_every_decision_is_audited_without_tokens():
    records: list[dict] = []
    secret = "sup3r-secret-bearer-token-value"
    authorizer = _policy({"alice": [{"tool": "clock"}]})
    server, _ = _build(
        authorizer=authorizer, subject="alice", audit_sink=records.append
    )
    _call(server, "echo", {"token": secret})  # denied
    _call(server, "clock")  # allowed
    assert [r["decision"] for r in records] == ["DENY", "ALLOW"]
    for record in records:
        for field in ("subject", "tool", "action", "policy_version", "reason"):
            assert field in record
        assert record["subject"] == "alice"
        assert record["policy_version"] == "test-1"
        assert secret not in json.dumps(record)


# --- v1.2: the policy document fails closed ----------------------------


def test_a_malformed_policy_document_is_a_hard_error():
    for bad in (
        [],
        {"subjects": []},  # no policy_version
        {"policy_version": "x", "subjects": "nope"},
        {"policy_version": "x", "subjects": [{"permissions": []}]},  # no subject
        {"policy_version": "x", "subjects": [{"subject": "a", "permissions": [{}]}]},
        {
            "policy_version": "x",
            "subjects": [
                {"subject": "a", "permissions": [{"tool": "e", "not_after": "soon"}]}
            ],
        },
    ):
        with pytest.raises(ValueError):
            ToolPolicy.from_dict(bad)


def test_a_duplicate_subject_is_rejected():
    with pytest.raises(ValueError):
        ToolPolicy.from_dict(
            {
                "policy_version": "x",
                "subjects": [
                    {"subject": "a", "permissions": []},
                    {"subject": "a", "permissions": []},
                ],
            }
        )


# --- CLI wiring -----------------------------------------------------------


def test_tool_policy_without_subject_is_refused_at_startup(tmp_path, monkeypatch):
    import ephemora_cell_mcp.server as server_module
    from ephemora_cell_mcp.__main__ import main

    class _NoServe:
        def __init__(self, **kwargs):
            raise AssertionError("server must not be built without a subject")

    monkeypatch.setattr(server_module, "Server", _NoServe)
    policy_path = tmp_path / "policy.json"
    policy_path.write_text(
        json.dumps({"policy_version": "x", "subjects": []}), encoding="utf-8"
    )
    code = main(["--tools-dir", str(tmp_path), "--tool-policy", str(policy_path)])
    assert code == 2


def test_a_valid_policy_is_loaded_and_passed_to_the_server(tmp_path, monkeypatch):
    import ephemora_cell_mcp.server as server_module
    from ephemora_cell_mcp.__main__ import main

    captured: dict = {}

    class _Recording:
        def __init__(self, **kwargs):
            captured.update(kwargs)

        def serve(self):
            return None

    monkeypatch.setattr(server_module, "Server", _Recording)
    policy_path = tmp_path / "policy.json"
    policy_path.write_text(
        json.dumps(
            {
                "policy_version": "1.2.0-1",
                "subjects": [{"subject": "alice", "permissions": [{"tool": "echo"}]}],
            }
        ),
        encoding="utf-8",
    )
    code = main(
        [
            "--tools-dir",
            str(tmp_path),
            "--tool-policy",
            str(policy_path),
            "--subject",
            "alice",
        ]
    )
    assert code == 0
    assert captured["subject"] == "alice"
    assert isinstance(captured["authorizer"], Authorizer)
    assert captured["authorizer"].version == "1.2.0-1"
