# SPDX-License-Identifier: BUSL-1.1
# Copyright 2026 Michael Soppa

"""The MCP server entry point's audit sink and its visible legacy mode.

Two gaps an independent review found: an enforcing deployment wrote no audit
record anywhere (the server accepted an ``audit_sink`` that the CLI never set),
and the pre-1.2 posture was spelled out only in ``--help``, so a deployment could
run with every tool callable and nothing on the console to say so.
"""

from __future__ import annotations

import json
import sys
from pathlib import Path
from typing import ClassVar

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

import pytest

import ephemora_cell_mcp.server as server_module
from ephemora_cell_mcp.__main__ import main

POLICY = {
    "policy_version": "1.2.0-1",
    "subjects": [{"subject": "alice", "permissions": [{"tool": "echo"}]}],
}


class _RecordingServer:
    instances: ClassVar[list] = []

    def __init__(self, **kwargs):
        self.kwargs = kwargs
        _RecordingServer.instances.append(self)

    def serve(self):
        return None


@pytest.fixture(autouse=True)
def _capture(monkeypatch):
    _RecordingServer.instances = []
    monkeypatch.setattr(server_module, "Server", _RecordingServer)


def _policy_file(tmp_path) -> str:
    path = tmp_path / "policy.json"
    path.write_text(json.dumps(POLICY), encoding="utf-8")
    return str(path)


def test_an_enforcing_server_gets_a_default_audit_sink(tmp_path, capsys):
    code = main(
        [
            "--tools-dir",
            str(tmp_path),
            "--tool-policy",
            _policy_file(tmp_path),
            "--subject",
            "alice",
        ]
    )
    assert code == 0
    (server,) = _RecordingServer.instances
    sink = server.kwargs["audit_sink"]
    assert callable(sink)

    # The sink writes one line per decision, and never on stdout (the protocol).
    sink({"subject": "alice", "tool": "clock", "decision": "DENY", "reason": "x"})
    captured = capsys.readouterr()
    assert captured.out == ""
    assert "authz " in captured.err
    record = json.loads(captured.err.split("authz ", 1)[1].strip())
    assert record["decision"] == "DENY"


def test_the_legacy_posture_is_announced_on_stderr(tmp_path, capsys):
    code = main(["--tools-dir", str(tmp_path), "--legacy-allow-all"])
    assert code == 0
    (server,) = _RecordingServer.instances
    assert server.kwargs["audit_sink"] is None
    err = capsys.readouterr().err
    assert "per-tool authorization is OFF" in err
    assert "--legacy-allow-all" in err


def test_no_policy_defaults_to_deny(tmp_path, capsys):
    """v1.2: without --tool-policy or --legacy-allow-all, every call is denied."""
    code = main(["--tools-dir", str(tmp_path)])
    assert code == 0
    (server,) = _RecordingServer.instances
    authorizer = server.kwargs["authorizer"]
    assert authorizer is not None
    decision = authorizer.authorize(None, "echo")
    assert not decision.allowed
    assert server.kwargs["audit_sink"] is not None


def test_a_policy_and_legacy_allow_all_are_mutually_exclusive(tmp_path, capsys):
    code = main(
        [
            "--tools-dir",
            str(tmp_path),
            "--tool-policy",
            _policy_file(tmp_path),
            "--subject",
            "alice",
            "--legacy-allow-all",
        ]
    )
    assert code == 2
    assert _RecordingServer.instances == []
