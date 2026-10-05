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


def _ed25519_keypair(tmp_path, name="ops"):
    """A real operator key: private PEM on disk + public PEM for a trust root.

    Signing needs the optional ``tools-signing`` extra — a bare clone skips
    instead of erroring, CI installs the extra and runs these for real.
    """
    pytest.importorskip("cryptography")
    from cryptography.hazmat.primitives import serialization
    from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

    key = Ed25519PrivateKey.generate()
    private_path = tmp_path / f"{name}.pem"
    private_path.write_bytes(
        key.private_bytes(
            serialization.Encoding.PEM,
            serialization.PrivateFormat.PKCS8,
            serialization.NoEncryption(),
        )
    )
    public_pem = (
        key.public_key()
        .public_bytes(
            serialization.Encoding.PEM, serialization.PublicFormat.SubjectPublicKeyInfo
        )
        .decode("utf-8")
    )
    return str(private_path), public_pem


def _grant_file(dir_path, tool="echo", *, trust_dir=None, key_id="ops-1"):
    """Write a SIGNED grant envelope, plus (when asked) the trust root that
    authenticates it — the loader accepts nothing else (ADR-013)."""
    from ephemora_cell.grant_trust import (
        TRUST_ROOT_SCHEMA,
        sign_grant_document,
        signer_from_pem,
    )

    dir_path.mkdir(parents=True, exist_ok=True)
    grant = EgressGrant(
        grant_id=f"g-{tool}",
        tool=tool,
        allowed_endpoints=("https://api.example.com/v1",),
        max_calls=5,
        key_id=key_id,
    )
    private_pem, public_pem = _ed25519_keypair(dir_path.parent, tool)
    envelope = sign_grant_document(
        grant, signer=signer_from_pem(private_pem), key_id=key_id
    )
    (dir_path / f"{tool}.egress.grant.json").write_text(
        json.dumps(envelope), encoding="utf-8"
    )
    trust_file = None
    if trust_dir is not None:
        trust_file = trust_dir / "egress-trust.json"
        trust_file.write_text(
            json.dumps(
                {
                    "trust_root_version": TRUST_ROOT_SCHEMA,
                    "keys": [
                        {
                            "key_id": "ops-1",
                            "alg": "EdDSA",
                            "public_key_pem": public_pem,
                            "status": "active",
                        }
                    ],
                }
            ),
            encoding="utf-8",
        )
    return grant, private_pem, trust_file


def _grant_setup(tmp_path, tool="echo"):
    """(grants dir, trust root path, grant) for a correctly configured server."""
    grants_dir = tmp_path / "grants"
    grant, _private, trust_file = _grant_file(grants_dir, tool, trust_dir=tmp_path)
    return grants_dir, trust_file, grant


def test_grants_dir_and_ledger_wire_the_enforcement_into_the_server(tmp_path):
    grants_dir, trust_file, grant = _grant_setup(tmp_path)
    ledger = tmp_path / "gr.jsonl"
    code = main(
        [
            "--tools-dir",
            str(tmp_path),
            "--egress-grants-dir",
            str(grants_dir),
            "--grant-ledger",
            str(ledger),
            "--egress-trust",
            str(trust_file),
        ]
    )
    assert code == 0
    kwargs = _RecordingServer.instances[0].kwargs
    assert kwargs["egress_grants"] == {"echo": grant}
    assert isinstance(kwargs["grant_ledger"], GrantLedger)
    # get-policy must be able to say WHICH root authenticated these grants —
    # enforcement without authentication is a different claim.
    assert kwargs["grant_trust"]["keys"][0]["key_id"] == "ops-1"
    assert "public_key_pem" not in json.dumps(kwargs["grant_trust"])
    # The disclosure carries its own provenance: `verified` is set by the loader
    # that actually verified, not by whoever happened to hold a root object.
    assert kwargs["grant_trust"]["verified"] is True
    assert "load_egress_grants" in kwargs["grant_trust"]["verified_by"]


def test_trust_root_inside_the_grants_directory_refuses_startup(tmp_path, capsys):
    """The anchor must be out of reach of what it anchors. An operator who
    follows the docs and puts the root next to the grants gets a refusal, not a
    server that verifies every grant against a key the grants dir can overwrite."""
    from ephemora_cell.grant_trust import TRUST_ROOT_SCHEMA

    grants_dir, trust_file, _grant = _grant_setup(tmp_path)
    moved = grants_dir / "root.json"
    moved.write_text(trust_file.read_text(encoding="utf-8"), encoding="utf-8")
    assert TRUST_ROOT_SCHEMA in moved.read_text(encoding="utf-8")
    code = main(
        [
            "--tools-dir",
            str(tmp_path),
            "--egress-grants-dir",
            str(grants_dir),
            "--egress-trust",
            str(moved),
            "--grant-ledger",
            str(tmp_path / "gr.jsonl"),
        ]
    )
    assert code == 2
    assert "inside the grants directory" in capsys.readouterr().err
    assert _RecordingServer.instances == []


def test_empty_grants_dir_refuses_startup(tmp_path, capsys):
    """`--egress-grants-dir` means "install these authorities". A directory that
    yields none — a typo, a moved path, a rename that ate the only grant — must
    not start a server that then attests its grants were verified."""
    grants_dir, trust_file, _grant = _grant_setup(tmp_path)
    # The operator's one grant file leaves the directory (rename, not deletion:
    # this is exactly how a deploy goes wrong).
    (grants_dir / "echo.egress.grant.json").rename(tmp_path / "elsewhere.json")

    code = main(
        [
            "--tools-dir",
            str(tmp_path),
            "--egress-grants-dir",
            str(grants_dir),
            "--egress-trust",
            str(trust_file),
            "--grant-ledger",
            str(tmp_path / "gr.jsonl"),
        ]
    )
    assert code == 2
    err = capsys.readouterr().err
    assert "no grant files found" in err, err
    assert _RecordingServer.instances == []


def test_grants_dir_without_a_ledger_is_a_clean_error(tmp_path, capsys):
    grants_dir, trust_file, _grant = _grant_setup(tmp_path)
    code = main(
        [
            "--tools-dir",
            str(tmp_path),
            "--egress-grants-dir",
            str(grants_dir),
            "--egress-trust",
            str(trust_file),
        ]
    )
    assert code == 2
    assert "--grant-ledger" in capsys.readouterr().err
    # fail-closed: no server, so a cap/expiry is never silently unenforced
    assert _RecordingServer.instances == []


def test_grants_dir_without_a_trust_root_is_a_clean_error(tmp_path, capsys):
    """A grant is authority. Without an anchored key set there is nothing to
    authenticate it against, so the loader refuses rather than trusting files."""
    grants_dir = tmp_path / "grants"
    _grant_file(grants_dir, "echo", trust_dir=tmp_path)
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
    assert "--egress-trust" in capsys.readouterr().err
    assert _RecordingServer.instances == []


def test_unsigned_grant_document_refuses_startup(tmp_path, capsys):
    """Migration guard: the plain (pre-verification) grant file the loader used
    to accept is now refused, by name, with the reason an operator can act on."""
    grants_dir, trust_file, _grant = _grant_setup(tmp_path)
    legacy = grants_dir / "legacy.egress.grant.json"
    legacy.write_text(
        json.dumps(
            EgressGrant(
                grant_id="g-legacy",
                tool="legacy",
                allowed_endpoints=("https://api.example.com/v1",),
                max_calls=1,
            ).to_dict()
        ),
        encoding="utf-8",
    )
    code = main(
        [
            "--tools-dir",
            str(tmp_path),
            "--egress-grants-dir",
            str(grants_dir),
            "--grant-ledger",
            str(tmp_path / "gr.jsonl"),
            "--egress-trust",
            str(trust_file),
        ]
    )
    assert code == 2
    err = capsys.readouterr().err
    assert "UNSIGNED document" in err
    assert "legacy.egress.grant.json" in err
    assert _RecordingServer.instances == []


def test_tampered_grant_refuses_startup(tmp_path, capsys):
    """An edit to a signed grant (cap raised, expiry pushed) is detected at load,
    not enforced as written."""
    grants_dir, trust_file, _grant = _grant_setup(tmp_path)
    envelope_file = grants_dir / "echo.egress.grant.json"
    envelope = json.loads(envelope_file.read_text(encoding="utf-8"))
    import base64

    edited = dict(_grant.to_dict(), max_calls=999_999)
    envelope["payload"] = base64.b64encode(
        json.dumps(edited, sort_keys=True).encode()
    ).decode()
    envelope_file.write_text(json.dumps(envelope), encoding="utf-8")
    code = main(
        [
            "--tools-dir",
            str(tmp_path),
            "--egress-grants-dir",
            str(grants_dir),
            "--grant-ledger",
            str(tmp_path / "gr.jsonl"),
            "--egress-trust",
            str(trust_file),
        ]
    )
    assert code == 2
    err = capsys.readouterr().err
    # The edit breaks the signature, and the signature is checked before the
    # payload is parsed — an edited authority never reaches grant construction.
    assert "does not verify" in err
    assert _RecordingServer.instances == []


def test_unknown_signing_key_refuses_startup(tmp_path, capsys):
    """A grant signed by a key the root does not name is not an authority."""
    grants_dir = tmp_path / "grants"
    _grant_file(grants_dir, "echo", key_id="ops-stranger")
    # The root knows ops-1 only, and the envelope claims ops-stranger.
    _signing, _priv, trust_file = _grant_file(
        tmp_path / "other-grants", "clock", trust_dir=tmp_path, key_id="ops-1"
    )
    code = main(
        [
            "--tools-dir",
            str(tmp_path),
            "--egress-grants-dir",
            str(grants_dir),
            "--grant-ledger",
            str(tmp_path / "gr.jsonl"),
            "--egress-trust",
            str(trust_file),
        ]
    )
    assert code == 2
    assert "not in the trust root" in capsys.readouterr().err
    assert _RecordingServer.instances == []


def test_broken_trust_root_refuses_startup(tmp_path, capsys):
    grants_dir, _trust, _grant = _grant_setup(tmp_path)
    bad_root = tmp_path / "egress-trust.json"
    bad_root.write_text('{"trust_root_version":"egress-trust-root.v1","keys":[]}')
    code = main(
        [
            "--tools-dir",
            str(tmp_path),
            "--egress-grants-dir",
            str(grants_dir),
            "--grant-ledger",
            str(tmp_path / "gr.jsonl"),
            "--egress-trust",
            str(bad_root),
        ]
    )
    assert code == 2
    assert "non-empty 'keys'" in capsys.readouterr().err
    assert _RecordingServer.instances == []


def test_a_malformed_grant_file_refuses_startup(tmp_path, capsys):
    grants_dir, trust_file, _grant = _grant_setup(tmp_path)
    (grants_dir / "broken.egress.grant.json").write_text("{not json", "utf-8")
    code = main(
        [
            "--tools-dir",
            str(tmp_path),
            "--egress-grants-dir",
            str(grants_dir),
            "--grant-ledger",
            str(tmp_path / "gr.jsonl"),
            "--egress-trust",
            str(trust_file),
        ]
    )
    assert code == 2
    err = capsys.readouterr().err
    assert "grant load failed" in err
    assert "broken" in err
    assert _RecordingServer.instances == []


def _write_ed25519_pem(path):
    private_pem, _public = _ed25519_keypair(path.parent, path.stem)
    return private_pem


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


class TestGrantsRequiredFlag:
    """`--egress-grants-required` (ADR-013, D1): the strict posture has to be
    reachable from the CLI, and unreachable postures must fail at startup rather
    than silently degrade into the allowlist fallback."""

    def test_without_a_grants_dir_it_refuses_startup(self, tmp_path, capsys):
        code = main(["--tools-dir", str(tmp_path), "--egress-grants-required"])
        assert code == 2
        assert "--egress-grants-dir" in capsys.readouterr().err
        assert _RecordingServer.instances == []

    def test_with_grants_dir_but_no_ledger_it_refuses_startup(self, tmp_path, capsys):
        grants_dir, trust_file, _grant = _grant_setup(tmp_path)
        code = main(
            [
                "--tools-dir",
                str(tmp_path),
                "--egress-grants-dir",
                str(grants_dir),
                "--egress-trust",
                str(trust_file),
                "--egress-grants-required",
            ]
        )
        assert code == 2
        assert "--grant-ledger" in capsys.readouterr().err
        assert _RecordingServer.instances == []

    def test_reaches_the_engine_the_server_serves_with(self, tmp_path):
        grants_dir, trust_file, _grant = _grant_setup(tmp_path)
        code = main(
            [
                "--tools-dir",
                str(tmp_path),
                "--egress-grants-dir",
                str(grants_dir),
                "--grant-ledger",
                str(tmp_path / "gr.jsonl"),
                "--egress-trust",
                str(trust_file),
                "--egress-grants-required",
            ]
        )
        assert code == 0
        kwargs = _RecordingServer.instances[0].kwargs
        assert kwargs["grants_required"] is True
        # The default is the fallback, so the absence of the flag must be a
        # fact the disclosure can report, not an assumption.
        plain = main(
            [
                "--tools-dir",
                str(tmp_path),
                "--egress-grants-dir",
                str(grants_dir),
                "--grant-ledger",
                str(tmp_path / "gr2.jsonl"),
                "--egress-trust",
                str(trust_file),
            ]
        )
        assert plain == 0
        assert _RecordingServer.instances[-1].kwargs["grants_required"] is False
