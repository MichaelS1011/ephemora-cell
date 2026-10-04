# SPDX-License-Identifier: BUSL-1.1
# Copyright 2026 Michael Soppa
"""Grant authentication (ADR-013): a grant is authority, so the file alone is
never enough.

The rule under test: **a key that arrives with the artefact proves nothing about
the artefact.** Keys are anchored in a separate operator file; every grant must
be a DSSE envelope over its own canonical bytes, signed by a key that root names,
for the grant audience, inside the key's window and the grant's window. Every
deviation is a refusal, and a refusal at load means the server does not start.

Needs the optional ``tools-signing`` extra (real Ed25519 keys, no stub
signer) — a bare clone skips this file instead of erroring.
"""

from __future__ import annotations

import base64
import copy
import json
import os
import sys
from datetime import datetime, timedelta, timezone
from pathlib import Path

sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))

import pytest

from ephemora_cell.egress_sidecar import EgressGrant, load_egress_grants
from ephemora_cell.execution_report import canonical_bytes
from ephemora_cell.grant_trust import (
    GRANT_AUDIENCE,
    TRUST_ROOT_SCHEMA,
    GrantTrustError,
    GrantTrustRoot,
    issue_cli,
    sign_grant_document,
    signer_from_pem,
)

pytest.importorskip("cryptography")

from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import (
    Ed25519PrivateKey,
)


def _future(days: int = 7) -> str:
    return (datetime.now(timezone.utc) + timedelta(days=days)).isoformat()


def _past(days: int = 1) -> str:
    return (datetime.now(timezone.utc) - timedelta(days=days)).isoformat()


class _Key:
    """One operator key: private PEM on disk, public PEM for the root."""

    def __init__(self, tmp_path: Path, name: str, key_id: str) -> None:
        self.key_id = key_id
        self._private = Ed25519PrivateKey.generate()
        self.pem_path = tmp_path / f"{name}.pem"
        self.pem_path.write_bytes(
            self._private.private_bytes(
                serialization.Encoding.PEM,
                serialization.PrivateFormat.PKCS8,
                serialization.NoEncryption(),
            )
        )
        self.public_pem = (
            self._private.public_key()
            .public_bytes(
                serialization.Encoding.PEM,
                serialization.PublicFormat.SubjectPublicKeyInfo,
            )
            .decode("utf-8")
        )

    def signer(self):
        return signer_from_pem(self.pem_path)


def _grant(**overrides) -> EgressGrant:
    base = dict(
        grant_id="g-1",
        tool="weather",
        allowed_endpoints=("https://api.example.com/v1",),
        not_after="2099-01-01T00:00:00+00:00",
        max_calls=5,
        key_id="ops-1",
    )
    base.update(overrides)
    return EgressGrant(**base)


@pytest.fixture()
def ops(tmp_path):
    return _Key(tmp_path, "ops", "ops-1")


@pytest.fixture()
def root(tmp_path, ops):
    """A trust root with exactly one active operator key."""
    file = tmp_path / "root.json"
    file.write_text(
        json.dumps(
            {
                "trust_root_version": TRUST_ROOT_SCHEMA,
                "keys": [
                    {
                        "key_id": "ops-1",
                        "alg": "EdDSA",
                        "public_key_pem": ops.public_pem,
                        "status": "active",
                    }
                ],
            }
        ),
        encoding="utf-8",
    )
    return GrantTrustRoot.load(file)


def _envelope(grant, key, key_id="ops-1"):
    return sign_grant_document(grant, signer=key.signer(), key_id=key_id)


# --- the happy path: an authenticated grant is the grant that was signed -----


def test_signed_grant_verifies_and_keeps_every_field(root, ops):
    grant = _grant(max_calls=5, not_after=_future())
    verified = root.verify_envelope(_envelope(grant, ops))
    assert verified == grant
    assert verified.max_calls == 5
    assert verified.key_id == "ops-1"


def test_envelope_is_the_grants_own_canonical_bytes(root, ops):
    """What is signed is exactly ``canonical_bytes(grant.to_dict())`` — the same
    recipe every other Cell record uses, so an issuer and a verifier agree
    without a Cell-specific serialization dialect."""
    grant = _grant()
    envelope = _envelope(grant, ops)
    assert base64.b64decode(envelope["payload"]) == canonical_bytes(grant.to_dict())
    assert envelope["payloadType"] == GRANT_AUDIENCE


# --- tampering: any edit of the authority invalidates -----------------------


def test_edited_max_calls_is_refused(root, ops):
    grant = _grant(max_calls=5)
    envelope = _envelope(grant, ops)
    edited = copy.deepcopy(grant.to_dict())
    edited["max_calls"] = 5_000_000
    envelope["payload"] = base64.b64encode(
        json.dumps(edited, sort_keys=True).encode()
    ).decode()
    with pytest.raises(GrantTrustError, match="canonical bytes"):
        root.verify_envelope(envelope)


def test_non_canonical_payload_is_refused_even_if_resigned(root, ops):
    """A payload carrying a field from_document() would IGNORE (or a different
    number spelling) must not load: the signature would cover bytes the loader
    does not enforce."""
    grant = _grant()
    doc = dict(grant.to_dict(), unexpected_field="x")
    payload = canonical_bytes(doc)
    from ephemora_cell.execution_report import dsse_pae

    signature = ops.signer()(dsse_pae(payload, GRANT_AUDIENCE))
    envelope = {
        "payloadType": GRANT_AUDIENCE,
        "payload": base64.b64encode(payload).decode(),
        "signatures": [
            {
                "alg": "EdDSA",
                "keyid": "ops-1",
                "sig": base64.b64encode(signature).decode(),
            }
        ],
    }
    with pytest.raises(GrantTrustError, match="canonical bytes"):
        root.verify_envelope(envelope)


def test_flipped_signature_is_refused(root, ops):
    envelope = _envelope(_grant(), ops)
    sig = envelope["signatures"][0]["sig"]
    flipped = ("A" if sig[0] != "A" else "B") + sig[1:]
    envelope["signatures"][0]["sig"] = flipped
    with pytest.raises(GrantTrustError, match="does not verify"):
        root.verify_envelope(envelope)


def test_unsigned_legacy_document_is_refused(root, ops):
    """The pre-verification grant file (a plain document) is exactly the hole
    this closes — it cannot load, even next to valid ones."""
    with pytest.raises(GrantTrustError, match="UNSIGNED document"):
        root.verify_envelope(_grant().to_dict())


# --- the key: unknown, absent, retired, out of window -----------------------


def test_key_not_in_the_root_is_refused(root, tmp_path):
    stranger = _Key(tmp_path, "stranger", "attacker-1")
    envelope = _envelope(_grant(key_id="attacker-1"), stranger, key_id="attacker-1")
    with pytest.raises(GrantTrustError, match="not in the trust root"):
        root.verify_envelope(envelope)


def test_signature_without_a_key_id_is_refused(root, ops):
    """A key delivered with the artefact, unnamed, is not a trust anchor."""
    envelope = _envelope(_grant(), ops)
    del envelope["signatures"][0]["keyid"]
    with pytest.raises(GrantTrustError, match="keyid"):
        root.verify_envelope(envelope)


def test_valid_signature_by_a_stranger_key_relabelled_as_trusted_is_refused(
    root, tmp_path, ops
):
    """The signature is checked against the key its OWN keyid names — so taking a
    stranger's signature and stamping the trusted key id on it does not verify."""
    stranger = _Key(tmp_path, "stranger", "attacker-1")
    envelope = _envelope(_grant(key_id="attacker-1"), stranger, key_id="attacker-1")
    envelope["signatures"][0]["keyid"] = "ops-1"
    envelope["payload"] = base64.b64encode(
        canonical_bytes(_grant(key_id="ops-1").to_dict())
    ).decode()
    with pytest.raises(GrantTrustError, match="does not verify"):
        root.verify_envelope(envelope)


def test_retired_key_is_refused(tmp_path, ops):
    file = tmp_path / "rotated.json"
    file.write_text(
        json.dumps(
            {
                "trust_root_version": TRUST_ROOT_SCHEMA,
                "keys": [
                    {
                        "key_id": "ops-1",
                        "alg": "EdDSA",
                        "public_key_pem": ops.public_pem,
                        "status": "retired",
                        "replaced_by": "ops-2",
                    },
                    {
                        "key_id": "ops-2",
                        "alg": "EdDSA",
                        "public_key_pem": _Key(tmp_path, "next", "ops-2").public_pem,
                        "status": "active",
                    },
                ],
            }
        ),
        encoding="utf-8",
    )
    rotated = GrantTrustRoot.load(file)
    with pytest.raises(GrantTrustError, match="retired"):
        rotated.verify_envelope(_envelope(_grant(), ops))


def test_transition_key_is_accepted_during_rotation(tmp_path, ops):
    """Rotation is a window, not a switch: the old key keeps working while the
    new one is introduced, and the root records that it is the old one."""
    successor = _Key(tmp_path, "successor", "ops-2")
    file = tmp_path / "rotating.json"
    file.write_text(
        json.dumps(
            {
                "trust_root_version": TRUST_ROOT_SCHEMA,
                "keys": [
                    {
                        "key_id": "ops-1",
                        "alg": "EdDSA",
                        "public_key_pem": ops.public_pem,
                        "status": "transition",
                        "replaced_by": "ops-2",
                    },
                    {
                        "key_id": "ops-2",
                        "alg": "EdDSA",
                        "public_key_pem": successor.public_pem,
                        "status": "active",
                    },
                ],
            }
        ),
        encoding="utf-8",
    )
    rotating = GrantTrustRoot.load(file)
    grant = rotating.verify_envelope(_envelope(_grant(), ops))
    assert grant.grant_id == "g-1"
    summary = rotating.summary()
    assert summary["keys"][0]["status"] == "transition"
    assert summary["keys"][0]["replaced_by"] == "ops-2"


def test_key_outside_its_own_window_is_refused(tmp_path):
    key = _Key(tmp_path, "expiring", "ops-exp")
    file = tmp_path / "windowed.json"
    file.write_text(
        json.dumps(
            {
                "trust_root_version": TRUST_ROOT_SCHEMA,
                "keys": [
                    {
                        "key_id": "ops-exp",
                        "alg": "EdDSA",
                        "public_key_pem": key.public_pem,
                        "status": "active",
                        "not_before": _past(2),
                        "not_after": _past(1),
                    }
                ],
            }
        ),
        encoding="utf-8",
    )
    expired_root = GrantTrustRoot.load(file)
    with pytest.raises(GrantTrustError, match="validity window"):
        expired_root.verify_envelope(
            _envelope(_grant(key_id="ops-exp"), key, key_id="ops-exp")
        )


def test_algorithm_mismatch_between_envelope_and_root_is_refused(tmp_path, ops):
    file = tmp_path / "ec.json"
    file.write_text(
        json.dumps(
            {
                "trust_root_version": TRUST_ROOT_SCHEMA,
                "keys": [
                    {
                        "key_id": "ops-1",
                        "alg": "EdDSA",
                        "public_key_pem": ops.public_pem,
                        "status": "active",
                    }
                ],
            }
        ),
        encoding="utf-8",
    )
    verified_root = GrantTrustRoot.load(file)
    envelope = _envelope(_grant(), ops)
    envelope["signatures"][0]["alg"] = "ES256"
    with pytest.raises(GrantTrustError, match="alg"):
        verified_root.verify_envelope(envelope)


# --- audience: a receipt signed by the SAME key is not a grant --------------


def test_receipt_envelope_cannot_load_as_a_grant(root, ops):
    """The operator's key signs both receipts and grants. Without the audience
    pin, one system's artefact would be another's authority."""
    grant = _grant()
    payload = canonical_bytes(grant.to_dict())
    from ephemora_cell.execution_report import dsse_pae

    signature = ops.signer()(
        dsse_pae(payload, "https://ephemora.dev/execution-report.v1")
    )
    envelope = {
        "payloadType": "https://ephemora.dev/execution-report.v1",
        "payload": base64.b64encode(payload).decode(),
        "signatures": [
            {
                "alg": "EdDSA",
                "keyid": "ops-1",
                "sig": base64.b64encode(signature).decode(),
            }
        ],
    }
    with pytest.raises(GrantTrustError, match="audience"):
        root.verify_envelope(envelope)


def test_grant_signature_over_the_wrong_audience_is_refused(root, ops):
    """Same key, right-looking envelope, PAE computed over a different type —
    the signature must not verify."""
    grant = _grant()
    payload = canonical_bytes(grant.to_dict())
    from ephemora_cell.execution_report import dsse_pae

    signature = ops.signer()(dsse_pae(payload, "https://example.com/other.v1"))
    envelope = {
        "payloadType": GRANT_AUDIENCE,
        "payload": base64.b64encode(payload).decode(),
        "signatures": [
            {
                "alg": "EdDSA",
                "keyid": "ops-1",
                "sig": base64.b64encode(signature).decode(),
            }
        ],
    }
    with pytest.raises(GrantTrustError, match="does not verify"):
        root.verify_envelope(envelope)


# --- the grant's own expiry and key binding --------------------------------


def test_already_expired_grant_is_refused_at_load(root, ops):
    envelope = _envelope(_grant(not_after=_past(1)), ops)
    with pytest.raises(GrantTrustError, match="expired"):
        root.verify_envelope(envelope)


def test_issuing_refuses_to_sign_for_another_key(ops):
    """The tool that makes envelopes refuses to relabel a document — the divergent
    case below should never reach a loader in the first place."""
    with pytest.raises(GrantTrustError, match="being signed by"):
        sign_grant_document(_grant(key_id="ops-9"), signer=ops.signer(), key_id="ops-1")


def test_payload_naming_another_key_id_is_refused(root, ops):
    """A grant document saying 'signed by ops-9' must not load under a valid
    signature from ops-1 — label and authority may not diverge."""
    from ephemora_cell.execution_report import dsse_pae

    payload = canonical_bytes(_grant(key_id="ops-9").to_dict())
    signature = ops.signer()(dsse_pae(payload, GRANT_AUDIENCE))
    envelope = {
        "payloadType": GRANT_AUDIENCE,
        "payload": base64.b64encode(payload).decode(),
        "signatures": [
            {
                "alg": "EdDSA",
                "keyid": "ops-1",
                "sig": base64.b64encode(signature).decode(),
            }
        ],
    }
    with pytest.raises(GrantTrustError, match="signed by"):
        root.verify_envelope(envelope)


def test_payload_without_key_id_is_refused(root, ops):
    grant = _grant()
    doc = grant.to_dict()
    doc["key_id"] = None
    payload = canonical_bytes(doc)
    from ephemora_cell.execution_report import dsse_pae

    signature = ops.signer()(dsse_pae(payload, GRANT_AUDIENCE))
    envelope = {
        "payloadType": GRANT_AUDIENCE,
        "payload": base64.b64encode(payload).decode(),
        "signatures": [
            {
                "alg": "EdDSA",
                "keyid": "ops-1",
                "sig": base64.b64encode(signature).decode(),
            }
        ],
    }
    with pytest.raises(GrantTrustError, match="key_id"):
        root.verify_envelope(envelope)


# --- trust root validation at startup (never at first use) ------------------


def _write_root(tmp_path, doc, name="bad-root.json"):
    file = tmp_path / name
    file.write_text(json.dumps(doc), encoding="utf-8")
    return file


def test_root_refuses_unknown_schema_empty_keys_and_duplicates(tmp_path, ops):
    base_key = {
        "key_id": "ops-1",
        "alg": "EdDSA",
        "public_key_pem": ops.public_pem,
        "status": "active",
    }
    cases = {
        "trust_root_version": dict(
            trust_root_version="nope", audience=GRANT_AUDIENCE, keys=[base_key]
        ),
        "keys": dict(
            trust_root_version=TRUST_ROOT_SCHEMA, audience=GRANT_AUDIENCE, keys=[]
        ),
    }
    for match, doc in cases.items():
        with pytest.raises(GrantTrustError, match=match):
            GrantTrustRoot.load(_write_root(tmp_path, doc, f"{match}.json"))
    dup = dict(
        trust_root_version=TRUST_ROOT_SCHEMA,
        audience=GRANT_AUDIENCE,
        keys=[base_key, dict(base_key)],
    )
    with pytest.raises(GrantTrustError, match="duplicate key_id"):
        GrantTrustRoot.load(_write_root(tmp_path, dup, "dup.json"))


def test_root_refuses_a_wrong_audience(tmp_path, ops):
    doc = dict(
        trust_root_version=TRUST_ROOT_SCHEMA,
        audience="https://example.com/anything.v1",
        keys=[{"key_id": "k", "alg": "EdDSA", "public_key_pem": ops.public_pem}],
    )
    with pytest.raises(GrantTrustError, match="audience"):
        GrantTrustRoot.load(_write_root(tmp_path, doc, "aud.json"))


def test_root_refuses_unverifiable_key_material_and_algorithms(tmp_path, ops):
    good = {"key_id": "k", "alg": "EdDSA", "public_key_pem": ops.public_pem}
    with pytest.raises(GrantTrustError, match="not a valid PEM public key"):
        GrantTrustRoot.load(
            _write_root(
                tmp_path,
                dict(
                    trust_root_version=TRUST_ROOT_SCHEMA,
                    keys=[dict(good, public_key_pem="not a pem")],
                ),
                "pem.json",
            )
        )
    with pytest.raises(GrantTrustError, match="alg"):
        GrantTrustRoot.load(
            _write_root(
                tmp_path,
                dict(
                    trust_root_version=TRUST_ROOT_SCHEMA,
                    keys=[dict(good, alg="RS256")],
                ),
                "alg.json",
            )
        )
    with pytest.raises(GrantTrustError, match="PEM public key"):
        private_pem = ops.pem_path.read_text(encoding="utf-8")
        GrantTrustRoot.load(
            _write_root(
                tmp_path,
                dict(
                    trust_root_version=TRUST_ROOT_SCHEMA,
                    keys=[dict(good, public_key_pem=private_pem)],
                ),
                "priv.json",
            )
        )


def test_root_refuses_unknown_status_and_broken_rotation_links(tmp_path, ops):
    good = {"key_id": "k", "alg": "EdDSA", "public_key_pem": ops.public_pem}
    with pytest.raises(GrantTrustError, match="status"):
        GrantTrustRoot.load(
            _write_root(
                tmp_path,
                dict(
                    trust_root_version=TRUST_ROOT_SCHEMA,
                    keys=[dict(good, status="maybe")],
                ),
                "status.json",
            )
        )
    with pytest.raises(GrantTrustError, match="not in the root"):
        GrantTrustRoot.load(
            _write_root(
                tmp_path,
                dict(
                    trust_root_version=TRUST_ROOT_SCHEMA,
                    keys=[dict(good, replaced_by="ghost")],
                ),
                "repl.json",
            )
        )
    with pytest.raises(GrantTrustError, match="replaces itself"):
        GrantTrustRoot.load(
            _write_root(
                tmp_path,
                dict(
                    trust_root_version=TRUST_ROOT_SCHEMA,
                    keys=[dict(good, replaced_by="k")],
                ),
                "self.json",
            )
        )


def test_root_refuses_a_missing_or_unreadable_file(tmp_path):
    with pytest.raises(GrantTrustError, match="unreadable"):
        GrantTrustRoot.load(tmp_path / "nope.json")
    bad = _write_root(tmp_path, {}, "unused.json")
    bad.write_text("{ truncated", encoding="utf-8")
    with pytest.raises(GrantTrustError, match="not valid JSON"):
        GrantTrustRoot.load(bad)


def test_summary_never_carries_key_material(root):
    dumped = json.dumps(root.summary())
    assert "BEGIN PUBLIC KEY" not in dumped
    assert "ops-1" in dumped


# --- the loader: all-or-nothing over a directory ----------------------------


def test_loader_needs_a_trust_root(tmp_path):
    with pytest.raises(ValueError, match="GrantTrustRoot"):
        load_egress_grants(tmp_path, None)


def test_loader_accepts_only_signed_envelopes(tmp_path, root, ops):
    grants_dir = tmp_path / "grants"
    grants_dir.mkdir()
    (grants_dir / "weather.egress.grant.json").write_text(
        json.dumps(_envelope(_grant(), ops)), encoding="utf-8"
    )
    grants, errors = load_egress_grants(grants_dir, root)
    assert errors == []
    assert grants["weather"].max_calls == 5


def test_loader_refuses_unsigned_and_tampered_files_and_names_them(tmp_path, root, ops):
    grants_dir = tmp_path / "grants"
    grants_dir.mkdir()
    (grants_dir / "legacy.egress.grant.json").write_text(
        json.dumps(_grant(grant_id="legacy", tool="legacy").to_dict()), encoding="utf-8"
    )
    tampered = _envelope(_grant(grant_id="t", tool="tampered"), ops)
    tampered["signatures"][0]["sig"] = "AAAA" + tampered["signatures"][0]["sig"][4:]
    (grants_dir / "tampered.egress.grant.json").write_text(
        json.dumps(tampered), encoding="utf-8"
    )
    grants, errors = load_egress_grants(grants_dir, root)
    assert grants == {}
    assert len(errors) == 2
    assert any("legacy.egress.grant.json" in e for e in errors)
    assert any("tampered.egress.grant.json" in e for e in errors)


def test_loader_still_reports_duplicates_after_verification(tmp_path, root, ops):
    grants_dir = tmp_path / "grants"
    grants_dir.mkdir()
    doc = _envelope(_grant(), ops)
    (grants_dir / "a.egress.grant.json").write_text(json.dumps(doc), encoding="utf-8")
    (grants_dir / "b.egress.grant.json").write_text(json.dumps(doc), encoding="utf-8")
    grants, errors = load_egress_grants(grants_dir, root)
    assert len(grants) == 1
    assert any("duplicate" in e for e in errors)


# --- operator tooling: issuing an envelope the loader accepts ---------------


def test_issue_cli_produces_an_envelope_the_root_accepts(tmp_path, root, ops, capsys):
    grant_file = tmp_path / "document.json"
    grant_file.write_text(json.dumps(_grant().to_dict()), encoding="utf-8")
    out_file = tmp_path / "issued.egress.grant.json"
    code = issue_cli(
        [
            "--grant",
            str(grant_file),
            "--key",
            str(ops.pem_path),
            "--key-id",
            "ops-1",
            "--out",
            str(out_file),
        ]
    )
    assert code == 0
    envelope = json.loads(out_file.read_text(encoding="utf-8"))
    assert root.verify_envelope(envelope) == _grant()


def test_issue_cli_refuses_a_broken_document(tmp_path, ops, capsys):
    bad = tmp_path / "bad.json"
    bad.write_text('{"grant_version":"egress-grant.v999"}', encoding="utf-8")
    assert (
        issue_cli(
            ["--grant", str(bad), "--key", str(ops.pem_path), "--key-id", "ops-1"]
        )
        == 2
    )
    assert "grant_version" in capsys.readouterr().err
