# SPDX-License-Identifier: BUSL-1.1
# Copyright 2026 Michael Soppa
"""The ``python -m ephemora_cell_mcp`` entrypoint (ADR-013 egress flags).

``main(argv=...)`` parses flags and builds a :class:`Server`; a test replaces
``Server`` with a recorder so ``serve()`` never blocks. This is the only place
the ``--egress-allow`` wiring (policy construction and its fail-closed error)
is exercised — the module otherwise has no executed caller in tests.
"""

from __future__ import annotations

import json
import os
import sys
from typing import ClassVar

sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))

import pytest

import ephemora_cell_mcp.server as server_module
from ephemora_cell.egress_sidecar import EgressGrant, EgressPolicy
from ephemora_cell.grant_ledger import GrantLedger
from ephemora_cell_mcp.__main__ import main


class _RecordingServer:
    """Stand-in for Server: capture the constructor kwargs, don't serve."""

    instances: ClassVar[list] = []
    served: ClassVar[int] = 0

    def __init__(self, **kwargs):
        self.kwargs = kwargs
        _RecordingServer.instances.append(self)

    def serve(self):
        _RecordingServer.served += 1


@pytest.fixture(autouse=True)
def _capture_server(monkeypatch):
    _RecordingServer.instances = []
    _RecordingServer.served = 0
    monkeypatch.setattr(server_module, "Server", _RecordingServer)
    # __main__ imports Server lazily from the package; patch that too.
    monkeypatch.setattr("ephemora_cell_mcp.server.Server", _RecordingServer)
    yield


def test_default_builds_no_egress_policy():
    assert main(["--tools-dir", "/nonexistent-tools"]) == 0
    (server,) = _RecordingServer.instances
    assert server.kwargs["egress_policy"] is None
    assert _RecordingServer.served == 1


def test_egress_allow_builds_the_policy_the_engine_will_enforce():
    code = main(
        [
            "--egress-allow",
            "https://api.example.com/v1",
            "--egress-allow",
            "http://127.0.0.1:8080/",
            "--egress-timeout",
            "3",
            "--egress-max-response-bytes",
            "2048",
        ]
    )
    assert code == 0
    policy = _RecordingServer.instances[0].kwargs["egress_policy"]
    assert isinstance(policy, EgressPolicy)
    assert policy.allowed_endpoints == (
        "https://api.example.com/v1",
        "http://127.0.0.1:8080/",
    )
    assert policy.timeout_seconds == 3.0
    assert policy.max_response_bytes == 2048


def test_unusable_endpoint_is_a_clean_error_not_a_startup(tmp_path, capsys):
    # A tool dir must exist or registry load fails before the flag is reached;
    # point at an empty dir so the ONLY failure is the policy construction.
    code = main(["--tools-dir", str(tmp_path), "--egress-allow", "ftp://x/v1"])
    assert code == 2
    assert "--egress-allow" in capsys.readouterr().err
    # fail-closed: no server was constructed, so nothing can serve a call
    assert _RecordingServer.instances == []
    assert _RecordingServer.served == 0


def _grant_file(dir_path, tool="echo"):
    dir_path.mkdir(parents=True, exist_ok=True)
    grant = EgressGrant(
        grant_id=f"g-{tool}",
        tool=tool,
        allowed_endpoints=("https://api.example.com/v1",),
        max_calls=5,
    )
    (dir_path / f"{tool}.egress.grant.json").write_text(
        json.dumps(grant.to_dict()), encoding="utf-8"
    )
    return grant


def test_grants_dir_and_ledger_wire_the_enforcement_into_the_server(tmp_path):
    grants_dir = tmp_path / "grants"
    grant = _grant_file(grants_dir, "echo")
    ledger = tmp_path / "gr.jsonl"
    code = main(
        [
            "--tools-dir",
            str(tmp_path),
            "--egress-grants-dir",
            str(grants_dir),
            "--grant-ledger",
            str(ledger),
        ]
    )
    assert code == 0
    kwargs = _RecordingServer.instances[0].kwargs
    assert kwargs["egress_grants"] == {"echo": grant}
    assert isinstance(kwargs["grant_ledger"], GrantLedger)


def test_grants_dir_without_a_ledger_is_a_clean_error(tmp_path, capsys):
    grants_dir = tmp_path / "grants"
    _grant_file(grants_dir)
    code = main(
        [
            "--tools-dir",
            str(tmp_path),
            "--egress-grants-dir",
            str(grants_dir),
        ]
    )
    assert code == 2
    assert "--grant-ledger" in capsys.readouterr().err
    # fail-closed: no server, so a cap/expiry is never silently unenforced
    assert _RecordingServer.instances == []


def test_a_malformed_grant_file_refuses_startup(tmp_path, capsys):
    grants_dir = tmp_path / "grants"
    _grant_file(grants_dir, "echo")
    (grants_dir / "broken.egress.grant.json").write_text("{not json", "utf-8")
    code = main(
        [
            "--tools-dir",
            str(tmp_path),
            "--egress-grants-dir",
            str(grants_dir),
            "--grant-ledger",
            str(tmp_path / "gr.jsonl"),
        ]
    )
    assert code == 2
    err = capsys.readouterr().err
    assert "grant load failed" in err
    assert "broken" in err
    assert _RecordingServer.instances == []


def _write_ed25519_pem(path):
    from cryptography.hazmat.primitives import serialization
    from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

    key = Ed25519PrivateKey.generate()
    path.write_bytes(
        key.private_bytes(
            serialization.Encoding.PEM,
            serialization.PrivateFormat.PKCS8,
            serialization.NoEncryption(),
        )
    )
    return str(path)


def test_receipt_signing_key_wires_a_signer_into_the_server(tmp_path):
    pem = _write_ed25519_pem(tmp_path / "host.pem")
    code = main(
        [
            "--tools-dir",
            str(tmp_path),
            "--receipt-signing-key",
            pem,
            "--receipt-key-id",
            "host-7",
        ]
    )
    assert code == 0
    kwargs = _RecordingServer.instances[0].kwargs
    assert callable(kwargs["receipt_signer"])
    assert kwargs["receipt_key_id"] == "host-7"


def test_default_server_gets_no_receipt_signer(tmp_path):
    code = main(["--tools-dir", str(tmp_path)])
    assert code == 0
    kwargs = _RecordingServer.instances[0].kwargs
    assert kwargs["receipt_signer"] is None


def test_unreadable_signing_key_is_a_clean_error(tmp_path, capsys):
    code = main(
        [
            "--tools-dir",
            str(tmp_path),
            "--receipt-signing-key",
            str(tmp_path / "missing.pem"),
        ]
    )
    assert code == 2
    assert "--receipt-signing-key" in capsys.readouterr().err
    assert _RecordingServer.instances == []
