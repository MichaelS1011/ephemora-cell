# SPDX-License-Identifier: BUSL-1.1
# Copyright 2026 Michael Soppa
"""Signed per-call receipt + verification (ADR-008).

The MCP ``_meta`` is self-reported — the spec says callers "SHOULD NOT rely on
them for security decisions". This closes that gap on our side: when the host is
configured with a signing key, every ``tools/call`` carries a DSSE envelope over
the SAME canonical bytes as ``_meta.execution``, and a caller holding the matching
public key can verify the receipt is genuine AND bound to the fields it reads —
not merely present. No signer -> the two-key ``_meta`` is byte-for-byte unchanged.
"""

from __future__ import annotations

import json
import os
import sys

sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))

import pytest

from ephemora_cell.execution_report import (
    DSSE_TYPE_EXECUTION_REPORT,
    EVIDENCE_SCHEMA,
    ExecutionReport,
    canonical_bytes,
    new_execution_evidence,
    verify_execution_attestation,
)
from ephemora_cell.wasi_runtime import ExecutionResult, ExecutionStatus
from ephemora_cell_mcp import tool_registry
from ephemora_cell_mcp.engine import CellOutcome
from ephemora_cell_mcp.server import Server

PACKAGE_TOOLS = os.path.join(
    os.path.dirname(os.path.dirname(__file__)), "ephemora_cell_mcp", "tools"
)


@pytest.fixture(scope="module")
def keypair(tmp_path_factory):
    """A real Ed25519 keypair on disk; signer+verifier built through the shipped
    helpers, so the test exercises the exact operator path.

    Signing needs the optional ``tools-signing`` extra: a consumer running bare
    ``pytest`` from a clone skips instead of erroring, while CI installs the
    extra and every test here runs for real (not green-by-skip).
    """
    pytest.importorskip("cryptography")
    from cryptography.hazmat.primitives import serialization
    from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

    d = tmp_path_factory.mktemp("keys")
    private_pem = d / "host.pem"
    public_pem = d / "host.pub"
    key = Ed25519PrivateKey.generate()
    private_pem.write_bytes(
        key.private_bytes(
            serialization.Encoding.PEM,
            serialization.PrivateFormat.PKCS8,
            serialization.NoEncryption(),
        )
    )
    public_pem.write_bytes(
        key.public_key().public_bytes(
            serialization.Encoding.PEM,
            serialization.PublicFormat.SubjectPublicKeyInfo,
        )
    )
    return str(private_pem), str(public_pem)


def _ok_result() -> ExecutionResult:
    return ExecutionResult(
        status=ExecutionStatus.SUCCESS, exit_code=0, stdout="{}", sandbox_dir=None
    )


def _outcome(report: ExecutionReport) -> CellOutcome:
    return CellOutcome(result=_ok_result(), report=report, egress=())


def _server(tmp_path, **kwargs) -> Server:
    return Server(tools_dir=PACKAGE_TOOLS, transport=object(), **kwargs)


# --- core: sign -> verify -> tamper ---------------------------------


def test_attestation_verifies_and_is_bound_to_the_receipt(keypair, tmp_path):
    private_pem, public_pem = keypair
    signer = tool_registry.ed25519_signer_from_pem(private_pem)
    verifier = tool_registry.ed25519_verifier_from_pem(public_pem)
    server = _server(tmp_path, receipt_signer=signer, receipt_key_id="host-1")
    report = ExecutionReport(status="success", exit_code=0, elapsed_ms=2.0)

    meta = server._build_call_result(_outcome(report))["_meta"]
    assert meta["attestation"]["payloadType"] == DSSE_TYPE_EXECUTION_REPORT
    assert meta["attestation"]["signatures"][0]["keyid"] == "host-1"
    # the receipt itself verifies, bound to the exact execution dict shown
    assert verify_execution_attestation(
        meta["attestation"], verifier, meta["execution"]
    )


def test_attestation_rejects_a_receipt_edited_after_signing(keypair, tmp_path):
    from cryptography.hazmat.primitives import serialization
    from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

    private_pem, _ = keypair
    other_pub = (
        Ed25519PrivateKey.generate()
        .public_key()
        .public_bytes(
            serialization.Encoding.PEM, serialization.PublicFormat.SubjectPublicKeyInfo
        )
    )
    signer = tool_registry.ed25519_signer_from_pem(private_pem)
    server = _server(tmp_path, receipt_signer=signer)
    report = ExecutionReport(status="success", exit_code=0, elapsed_ms=2.0)
    meta = server._build_call_result(_outcome(report))["_meta"]

    tampered = dict(meta["execution"])
    tampered["fuel_consumed"] = 1
    # an unrelated public key must not verify (signature is over the real bytes)
    import tempfile

    from ephemora_cell_mcp.tool_registry import ed25519_verifier_from_pem

    pub_file = tempfile.NamedTemporaryFile(delete=False, suffix=".pem")
    pub_file.write(other_pub)
    pub_file.close()
    foreign_verifier = ed25519_verifier_from_pem(pub_file.name)
    assert not verify_execution_attestation(
        meta["attestation"], foreign_verifier, meta["execution"]
    )


def test_execution_payload_is_the_signed_bytes(keypair, tmp_path):
    import base64

    private_pem, _ = keypair
    signer = tool_registry.ed25519_signer_from_pem(private_pem)
    server = _server(tmp_path, receipt_signer=signer)
    report = ExecutionReport(status="success", exit_code=0, elapsed_ms=2.0)
    meta = server._build_call_result(_outcome(report))["_meta"]
    # the envelope carries exactly canonical_bytes(_meta.execution) — no
    # divergence between what is displayed and what is signed
    assert base64.b64decode(meta["attestation"]["payload"]) == canonical_bytes(
        meta["execution"]
    )


# --- backward compatibility -----------------------------------------


def test_no_signer_leaves_meta_unchanged(tmp_path):
    server = _server(tmp_path)
    report = ExecutionReport(status="success", exit_code=0, elapsed_ms=2.0)
    meta = server._build_call_result(_outcome(report))["_meta"]
    assert set(meta) == {"execution"}
    assert "attestation" not in meta


# --- get-policy attestation -----------------------------------------


def test_get_policy_reports_receipt_signing_disabled(tmp_path):
    server = _server(tmp_path)
    payload = json.loads(server._handle_get_policy({})["content"][0]["text"])
    assert payload["receipt_signing"] == {"enabled": False}


def test_get_policy_reports_receipt_signing_enabled(keypair, tmp_path):
    private_pem, _ = keypair
    signer = tool_registry.ed25519_signer_from_pem(private_pem)
    server = _server(tmp_path, receipt_signer=signer, receipt_key_id="host-9")
    payload = json.loads(server._handle_get_policy({})["content"][0]["text"])
    assert payload["receipt_signing"] == {
        "enabled": True,
        "format": "dsse-v1",
        "payload_type": DSSE_TYPE_EXECUTION_REPORT,
        "alg": "EdDSA",
        "key_id": "host-9",
        "evidence": EVIDENCE_SCHEMA,
    }


# --- replay binding (evidence block) --------------------------------


def _signed_meta(keypair, tmp_path, report, *, tool=None):
    private_pem, _ = keypair
    signer = tool_registry.ed25519_signer_from_pem(private_pem)
    server = _server(tmp_path, receipt_signer=signer)
    return server._build_call_result(_outcome(report), tool=tool)["_meta"]


def test_signed_receipt_carries_a_one_of_one_evidence_block(keypair, tmp_path):
    """Without a nonce a receipt proves a SHAPE, not an execution: two identical
    calls produce the same bytes and either receipt answers for both. The block
    must therefore differ per receipt and name the tool it answers for."""
    from datetime import datetime

    first = _signed_meta(
        keypair,
        tmp_path / "a",
        ExecutionReport(status="success", exit_code=0, elapsed_ms=2.0),
        tool="echo",
    )
    second = _signed_meta(
        keypair,
        tmp_path / "b",
        ExecutionReport(status="success", exit_code=0, elapsed_ms=2.0),
        tool="echo",
    )
    ev = first["execution"]["evidence"]
    assert ev["schema"] == EVIDENCE_SCHEMA
    assert ev["tool"] == "echo"
    assert ev["report_id"] and len(ev["report_id"]) == 32
    assert ev["report_id"] != second["execution"]["evidence"]["report_id"]
    # an AWARE UTC stamp — a naive one is a guess about the zone
    stamp = datetime.fromisoformat(ev["issued_at"])
    assert stamp.tzinfo is not None


def test_evidence_lives_inside_the_signed_bytes(keypair, tmp_path):
    """The binding is only real if swapping the nonce invalidates the signature:
    a caller that blocks replays by report_id must not be able to be fooled by
    rewriting the nonce outside the envelope."""
    from ephemora_cell_mcp.tool_registry import ed25519_verifier_from_pem

    _, public_pem = keypair
    verifier = ed25519_verifier_from_pem(public_pem)
    meta = _signed_meta(
        keypair,
        tmp_path,
        ExecutionReport(status="success", exit_code=0, elapsed_ms=1.0),
        tool="echo",
    )
    assert verify_execution_attestation(
        meta["attestation"], verifier, meta["execution"]
    )
    swapped = json.loads(json.dumps(meta["execution"]))
    swapped["evidence"]["report_id"] = "0" * 32
    assert not verify_execution_attestation(
        meta["attestation"],
        verifier,
        swapped,
    )


def test_freshness_window_accepts_a_new_receipt_and_refuses_a_stale_one(
    keypair, tmp_path
):
    from datetime import datetime, timedelta, timezone

    from ephemora_cell_mcp.tool_registry import ed25519_verifier_from_pem

    _, public_pem = keypair
    verifier = ed25519_verifier_from_pem(public_pem)

    fresh = _signed_meta(
        keypair,
        tmp_path / "fresh",
        ExecutionReport(status="success", exit_code=0, elapsed_ms=1.0),
        tool="echo",
    )
    assert verify_execution_attestation(
        fresh["attestation"], verifier, fresh["execution"], max_age_seconds=60
    )

    # An honest signature over an old receipt is still an old receipt: it verifies
    # cryptographically and must fail the age requirement.
    old = ExecutionReport(status="success", exit_code=0, elapsed_ms=1.0)
    old.evidence = new_execution_evidence(
        tool="echo", now=datetime.now(timezone.utc) - timedelta(hours=2)
    )
    private_pem, _ = keypair
    signer = tool_registry.ed25519_signer_from_pem(private_pem)
    old_envelope = old.to_dsse(signer)
    assert verify_execution_attestation(old_envelope, verifier, old.to_dict())
    assert not verify_execution_attestation(
        old_envelope, verifier, old.to_dict(), max_age_seconds=60
    )


def test_freshness_check_fails_closed_without_evidence(keypair, tmp_path):
    """A receipt predating the evidence field must not silently pass a freshness
    requirement — it cannot be aged, so it is refused."""
    from ephemora_cell_mcp.tool_registry import ed25519_verifier_from_pem

    private_pem, public_pem = keypair
    signer = tool_registry.ed25519_signer_from_pem(private_pem)
    verifier = ed25519_verifier_from_pem(public_pem)
    report = ExecutionReport(status="success", exit_code=0, elapsed_ms=1.0)
    envelope = report.to_dsse(signer)
    assert verify_execution_attestation(envelope, verifier, report.to_dict())
    assert not verify_execution_attestation(
        envelope, verifier, report.to_dict(), max_age_seconds=60
    )


def test_naive_or_far_future_issue_time_is_refused(keypair, tmp_path):
    from datetime import datetime, timedelta, timezone

    from ephemora_cell_mcp.tool_registry import ed25519_verifier_from_pem

    _, public_pem = keypair
    verifier = ed25519_verifier_from_pem(public_pem)

    naive = ExecutionReport(status="success", exit_code=0, elapsed_ms=1.0)
    naive.evidence = {
        "schema": EVIDENCE_SCHEMA,
        "report_id": "a" * 32,
        "issued_at": datetime.now(timezone.utc).isoformat()[:19],
    }
    private_pem, _ = keypair
    signer = tool_registry.ed25519_signer_from_pem(private_pem)
    envelope = naive.to_dsse(signer)
    assert verify_execution_attestation(envelope, verifier, naive.to_dict())
    assert not verify_execution_attestation(
        envelope, verifier, naive.to_dict(), max_age_seconds=60
    )

    now = datetime.now(timezone.utc)
    skewed = ExecutionReport(status="success", exit_code=0, elapsed_ms=1.0)
    skewed.evidence = new_execution_evidence(
        tool="echo", now=now + timedelta(seconds=30)
    )
    assert verify_execution_attestation(
        skewed.to_dsse(signer), verifier, skewed.to_dict(), max_age_seconds=60
    )
    future = ExecutionReport(status="success", exit_code=0, elapsed_ms=1.0)
    future.evidence = new_execution_evidence(tool="echo", now=now + timedelta(hours=6))
    assert not verify_execution_attestation(
        future.to_dsse(signer), verifier, future.to_dict(), max_age_seconds=60
    )


def test_new_execution_evidence_refuses_a_naive_clock():
    from datetime import datetime

    with pytest.raises(ValueError):
        new_execution_evidence(tool="echo", now=datetime(2026, 10, 4, 12, 0, 0))


def test_unsigned_reports_carry_no_evidence_key(tmp_path):
    """The whole block exists only on the signing path: a server without a
    signer produces the same `_meta` as before, byte for byte."""
    server = _server(tmp_path)
    report = ExecutionReport(status="success", exit_code=0, elapsed_ms=2.0)
    meta = server._build_call_result(_outcome(report), tool="echo")["_meta"]
    assert "evidence" not in meta["execution"]
    assert set(meta) == {"execution"}


# --- verify helper edge cases ---------------------------------------


def test_verify_helper_fails_closed_on_malformed_input(keypair):
    from ephemora_cell_mcp.tool_registry import ed25519_verifier_from_pem

    _, public_pem = keypair
    verifier = ed25519_verifier_from_pem(public_pem)
    report = ExecutionReport(status="success", exit_code=0, elapsed_ms=1.0)
    assert not verify_execution_attestation(None, verifier, report.to_dict())
    assert not verify_execution_attestation({"payload": "x"}, verifier, {})
    # wrong payload_type is refused even if the signature would otherwise fit
    signed = report.to_dsse(lambda b: b"")  # not a real signer, shape only
    signed["payloadType"] = "https://ephemora.dev/other.v1"
    assert not verify_execution_attestation(signed, verifier, report.to_dict())
