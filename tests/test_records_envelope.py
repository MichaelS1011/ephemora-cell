"""Records envelope tests: pre-exec chain (ADR-008) and open standards
(DSSE envelope, detached JWS, inclusion-proof field — added with WP3b).

The pre-exec/receipt split answers the verification-order problem: a
verifier can validate what a run CLAIMED it would do (module digest,
policy fingerprint, input digest) BEFORE trusting what the run SAYS it
did. Both halves use the same signer-agnostic, JCS-canonical signing
conventions, so one keypair signs the whole chain.
"""

from __future__ import annotations

import hashlib
import os
import sys

sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))


from ephemora_cell import ExecutionReport, PreExecutionRecord, WASIConfig, verify_chain
from ephemora_cell.execution_report import canonical_bytes

# Deterministic signer/verifier pair (no crypto dependency needed to pin
# the envelope semantics; key-material behavior is covered by
# tests/test_execution_report.py with Ed25519).
_SIGN_KEY = b"deterministic-sign-key"


def _signer(data: bytes) -> bytes:
    return hashlib.sha256(_SIGN_KEY + data).digest()


def _verifier(canonical: bytes, signature: bytes) -> bool:
    return signature == hashlib.sha256(_SIGN_KEY + canonical).digest()


def _pre_exec(**overrides) -> dict:
    """Build + sign a deterministic pre-exec record."""
    build_kwargs: dict = {
        "module_bytes": b"\x00asm\x01\x00\x00\x00",
        "config": WASIConfig(max_fuel=500_000),
        "args": ["-x"],
        "stdin_data": "hello",
        "record_id": "fixed-id-0001",
        "timestamp": "2026-09-25T00:00:00.000Z",
    }
    build_kwargs.update(overrides.pop("build", {}))
    record = PreExecutionRecord.build(**build_kwargs)
    return record.sign(_signer, alg="EdDSA")


def _receipt_with_back_link(signed_pre: dict) -> dict:
    digest = hashlib.sha256(
        canonical_bytes({k: v for k, v in signed_pre.items() if k != "signature"})
    ).hexdigest()
    report = ExecutionReport(status="success", exit_code=0, elapsed_ms=1.0)
    report.back_link = {
        "pre_exec_id": signed_pre["id"],
        "pre_exec_digest": digest,
    }
    return report.sign(_signer, alg="EdDSA")


class TestPreExecutionChain:
    def test_sign_and_verify_roundtrip(self):
        signed = _pre_exec()
        assert signed["record_type"] == "ephemora.pre_exec.v1"
        assert signed["alg"] == "EdDSA"
        assert PreExecutionRecord.verify(signed, _verifier)

    def test_deterministic_build(self):
        first = _pre_exec()
        second = _pre_exec()
        assert first == second  # same id/timestamp inputs → same signed dict

    def test_tampered_payload_fails_closed(self):
        signed = _pre_exec()
        for field, value in (
            ("module_sha256", "ff" * 32),
            ("config_fingerprint", "ee" * 32),
            ("input_hash", "dd" * 32),
            ("id", "other-run"),
        ):
            tampered = dict(signed)
            tampered[field] = value
            assert not PreExecutionRecord.verify(tampered, _verifier), field

    def test_malformed_input_fails_closed(self):
        assert not PreExecutionRecord.verify(None, _verifier)
        assert not PreExecutionRecord.verify({}, _verifier)
        assert not PreExecutionRecord.verify({"signature": "zz"}, _verifier)

    def test_chain_verifies(self):
        signed_pre = _pre_exec()
        signed_receipt = _receipt_with_back_link(signed_pre)
        assert verify_chain(signed_pre, signed_receipt, _verifier)

    def test_chain_breaks_without_back_link(self):
        signed_pre = _pre_exec()
        report = ExecutionReport(status="success", exit_code=0, elapsed_ms=1.0)
        signed_receipt = report.sign(_signer, alg="EdDSA")
        assert not verify_chain(signed_pre, signed_receipt, _verifier)

    def test_chain_breaks_on_wrong_reference(self):
        """The receipt is bound to EXACTLY one pre-exec attestation: a
        back_link referencing a DIFFERENT (itself valid) pre-exec record
        must not verify."""
        other = _pre_exec(
            build={"record_id": "another-run", "timestamp": "2026-09-25T01:00:00.000Z"}
        )
        signed_receipt = _receipt_with_back_link(other)
        signed_pre = _pre_exec()
        assert not verify_chain(signed_pre, signed_receipt, _verifier)

    def test_chain_breaks_on_tampered_receipt(self):
        signed_pre = _pre_exec()
        signed_receipt = _receipt_with_back_link(signed_pre)
        signed_receipt["status"] = "fuel_exhausted"
        assert not verify_chain(signed_pre, signed_receipt, _verifier)

    def test_plain_report_schema_unchanged(self):
        """Compat pin: a report without back_link serializes EXACTLY as
        before ADR-008 (the _meta.execution schema is documented)."""
        report = ExecutionReport(status="success", exit_code=0, elapsed_ms=1.0)
        assert "back_link" not in report.to_dict()


class TestPolicyAndInputDigests:
    def test_policy_fingerprint_is_sensitive_to_policy(self):
        a = PreExecutionRecord.build(
            module_bytes=b"x",
            config=WASIConfig(max_fuel=500_000),
            record_id="i",
            timestamp="t",
        )
        b = PreExecutionRecord.build(
            module_bytes=b"x",
            config=WASIConfig(max_fuel=900_000),
            record_id="i",
            timestamp="t",
        )
        assert a.config_fingerprint != b.config_fingerprint

    def test_policy_fingerprint_excludes_env_values(self):
        """Env NAMES are policy; VALUES are secrets — the fingerprint
        must not depend on them."""
        from ephemora_cell.execution_report import policy_fingerprint

        a = policy_fingerprint(WASIConfig(allow_env=[("TOKEN", "secret-one")]))
        b = policy_fingerprint(WASIConfig(allow_env=[("TOKEN", "secret-two")]))
        assert a == b

    def test_input_digest_is_sensitive_to_input(self):
        from ephemora_cell.execution_report import input_digest

        assert input_digest(["-x"], "a") != input_digest(["-x"], "b")
        assert input_digest(["-x"], "a") != input_digest(["-y"], "a")
        assert input_digest(None, None) == input_digest([], None)
