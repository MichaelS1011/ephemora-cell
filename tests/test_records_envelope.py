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

    # === WP-B2: alg pinning (alg-confusion audit finding) ===

    def test_verify_expected_alg_match(self):
        signed = _pre_exec()
        assert PreExecutionRecord.verify(signed, _verifier, expected_alg="EdDSA")

    def test_verify_expected_alg_mismatch_fails_closed(self):
        """Valid signature, but signed under a different algorithm than the
        verifier pins — must not verify (fail-closed)."""
        signed = _pre_exec()
        assert not PreExecutionRecord.verify(signed, _verifier, expected_alg="ES256")

    def test_verify_expected_alg_missing_alg_field_fails_closed(self):
        """A pre-exec record carrying no alg at all never passes a pinned
        verification, even though the signature itself is intact."""
        record = PreExecutionRecord.build(
            module_bytes=b"\x00asm\x01\x00\x00\x00",
            config=WASIConfig(max_fuel=500_000),
            record_id="fixed-id-0001",
            timestamp="2026-09-25T00:00:00.000Z",
        )
        payload = record.to_dict()
        assert "alg" not in payload
        no_alg = {**payload, "signature": _signer(canonical_bytes(payload)).hex()}
        assert PreExecutionRecord.verify(no_alg, _verifier)  # legacy: still True
        assert not PreExecutionRecord.verify(no_alg, _verifier, expected_alg="EdDSA")

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

    def test_policy_fingerprint_sees_both_posture_knobs(self):
        """max_wasm_bytes and allow_fsync ARE posture. A fingerprint that
        ignores them lets an opened run certify itself as a closed one."""
        closed = PreExecutionRecord.build(
            module_bytes=b"x", config=WASIConfig(), record_id="i", timestamp="t"
        )
        open_sync = PreExecutionRecord.build(
            module_bytes=b"x",
            config=WASIConfig(allow_fsync=True),
            record_id="i",
            timestamp="t",
        )
        open_cap = PreExecutionRecord.build(
            module_bytes=b"x",
            config=WASIConfig(max_wasm_bytes=0),
            record_id="i",
            timestamp="t",
        )
        assert closed.config_fingerprint != open_sync.config_fingerprint
        assert closed.config_fingerprint != open_cap.config_fingerprint

    def test_pre_exec_record_attests_the_config_not_the_default(self):
        """The record a verifier sees BEFORE the run must carry the same
        posture the run will actually have — this used to be the hardcoded
        default regardless of the config passed in."""
        record = PreExecutionRecord.build(
            module_bytes=b"x",
            config=WASIConfig(allow_fsync=True, max_wasm_bytes=0),
            record_id="i",
            timestamp="t",
        )
        baseline = record.security_baseline
        assert baseline["allow_fsync"] is True
        assert baseline["max_wasm_bytes"] == 0
        # 0 means "no cap", which a bare number reads as the strictest limit.
        assert baseline["max_wasm_bytes_unlimited"] is True

        default = PreExecutionRecord.build(
            module_bytes=b"x", config=WASIConfig(), record_id="i", timestamp="t"
        ).security_baseline
        assert default["allow_fsync"] is False
        assert default["max_wasm_bytes_unlimited"] is False

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


class TestTenantAttestation:
    """ADR-012 in the envelopes: the account is attested, and its absence is
    invisible down to the signing bytes."""

    def _pre(self, **kwargs):
        return PreExecutionRecord.build(
            module_bytes=b"x",
            config=WASIConfig(),
            record_id="i",
            timestamp="t",
            **kwargs,
        )

    def _receipt(self, **kwargs):
        return ExecutionReport(
            status="success", exit_code=0, elapsed_ms=1.0
        ).apply_config(WASIConfig(), **kwargs)

    def test_no_tenant_keeps_the_signing_bytes_identical(self):
        implied = self._pre()
        explicit_none = self._pre(tenant=None, tenant_budget_ref=None)
        assert implied.to_dict() == explicit_none.to_dict()
        assert "tenant" not in implied.security_baseline
        assert "tenant_budget_ref" not in implied.security_baseline
        # same for the receipt: passing nothing and passing None must be the
        # same bytes, or every pre-1.1 receipt changes shape
        assert canonical_bytes(self._receipt()) == canonical_bytes(
            self._receipt(tenant=None, tenant_budget_ref=None)
        )
        assert "tenant" not in self._receipt().security_baseline

    def test_the_account_moves_both_halves_of_the_record(self):
        plain = self._pre()
        billed = self._pre(tenant="acme", tenant_budget_ref="0" * 16)
        assert billed.config_fingerprint != plain.config_fingerprint
        assert billed.security_baseline["tenant"] == "acme"
        assert billed.security_baseline["tenant_budget_ref"] == "0" * 16

    def test_two_accounts_under_one_config_cannot_share_an_agreement(self):
        """The point of fingerprinting the account: an agreement made for one
        tenant must not be reusable for another under an identical config."""
        acme = self._pre(tenant="acme", tenant_budget_ref="0" * 16)
        globex = self._pre(tenant="globex", tenant_budget_ref="0" * 16)
        assert acme.config_fingerprint != globex.config_fingerprint

    def test_the_budget_reference_is_recomputable_from_the_cap(self):
        from ephemora_cell import CumulativeBudget
        from ephemora_cell.execution_report import policy_fingerprint

        cap = CumulativeBudget(max_runs=5, max_total_fuel=1_000)
        record = self._pre(tenant="acme", tenant_budget_ref=cap.ref())
        assert record.security_baseline["tenant_budget_ref"] == cap.ref()
        # a verifier holding only the cap confirms the attested reference —
        # and only that: the reference binds the cap, not the consumption
        assert cap.ref() == CumulativeBudget(max_runs=5, max_total_fuel=1_000).ref()
        assert cap.ref() != CumulativeBudget(max_runs=6, max_total_fuel=1_000).ref()
        assert policy_fingerprint(WASIConfig(), tenant="acme") != policy_fingerprint(
            WASIConfig()
        )


class TestDSSE:
    """DSSE v1 envelope (PAE signing) — the in-toto/TUF interop format."""

    def test_report_roundtrip(self):
        from ephemora_cell.execution_report import dsse_verify

        report = ExecutionReport(status="success", exit_code=0, elapsed_ms=1.0)
        envelope = report.to_dsse(_signer, alg="EdDSA", key_id="k1")
        assert envelope["payloadType"]
        assert dsse_verify(envelope, _verifier)

    def test_pae_is_spec_exact(self):
        """PAE = "DSSEv1" || LE32(len(type)) || type || LE32(len(payload)) || payload."""
        from ephemora_cell.execution_report import dsse_pae

        pae = dsse_pae(b"AB", "type")
        assert (
            pae
            == b"DSSEv1"
            + (4).to_bytes(4, "little")
            + b"type"
            + (2).to_bytes(4, "little")
            + b"AB"
        )

    def test_prelude_payload_is_jcs_bytes(self):
        """The envelope payload decodes to the SAME JCS bytes the native
        sign() path feeds to the signer — digests agree across formats."""
        import base64

        from ephemora_cell.execution_report import canonical_bytes

        report = ExecutionReport(status="success", exit_code=0, elapsed_ms=1.0)
        envelope = report.to_dsse(_signer, alg="EdDSA")
        decoded = base64.b64decode(envelope["payload"], validate=True)
        assert decoded == canonical_bytes(report)

    def test_signature_is_over_pae_not_payload(self):
        """A signature over the raw payload must NOT verify: DSSE signs
        the PAE, so a verifier that skips the encoding fails closed."""
        import base64

        from ephemora_cell.execution_report import dsse_sign, dsse_verify

        envelope = dsse_sign(b'{"a":1}', payload_type="t", signer=lambda d: _signer(d))
        # re-sign the raw payload with the same key, swap it in → invalid
        wrong_sig = _signer(b'{"a":1}')
        envelope["signatures"][0]["sig"] = base64.b64encode(wrong_sig).decode()
        assert not dsse_verify(envelope, _verifier)

    def test_all_signatures_must_verify(self):
        from ephemora_cell.execution_report import dsse_sign, dsse_verify

        envelope = dsse_sign(b"p", payload_type="t", signer=_signer)
        envelope["signatures"].append({"sig": "AAAA"})
        assert not dsse_verify(envelope, _verifier)

    def test_empty_signatures_and_malformed_fail_closed(self):
        from ephemora_cell.execution_report import dsse_verify

        assert not dsse_verify(None, _verifier)
        assert not dsse_verify({}, _verifier)
        assert not dsse_verify(
            {"payloadType": "t", "payload": "eA", "signatures": []}, _verifier
        )
        assert not dsse_verify(
            {"payloadType": "t", "payload": "!!!", "signatures": [{"sig": "AAAA"}]},
            _verifier,
        )


class TestDetachedJWS:
    """Compact detached JWS over JCS (RFC 7797, b64=false, crit b64)."""

    def test_roundtrip_and_tamper(self):
        from ephemora_cell.execution_report import (
            detached_jws_sign,
            detached_jws_verify,
        )

        report = ExecutionReport(status="success", exit_code=0, elapsed_ms=1.0)
        payload = report.to_dict()
        jws = detached_jws_sign(payload, _signer, alg="EdDSA")
        # detached: the payload segment is empty
        assert jws.split(".")[1] == ""
        assert detached_jws_verify(jws, payload, _verifier)
        tampered = dict(payload)
        tampered["exit_code"] = 137
        assert not detached_jws_verify(jws, tampered, _verifier)

    def test_rejects_encoded_payload_form(self):
        """b64 must be false with crit declared — an encoded-payload JWS
        is a different standard form and fails closed here."""
        import base64
        import json as _json

        from ephemora_cell.execution_report import detached_jws_verify

        header = base64.urlsafe_b64encode(
            _json.dumps({"alg": "EdDSA"}).encode()
        ).rstrip(b"=")
        sig = base64.urlsafe_b64encode(b"\x00" * 32).rstrip(b"=")
        jws = header.decode() + ".cGF5bG9hZA." + sig.decode()
        assert not detached_jws_verify(jws, {}, _verifier)

    def test_malformed_input_fails_closed(self):
        from ephemora_cell.execution_report import detached_jws_verify

        assert not detached_jws_verify("not-a-jws", {}, _verifier)
        assert not detached_jws_verify(None, {}, _verifier)


class TestInclusionProofField:
    """Transparency-ready extension point (ADR-008): an inclusion_proof
    rides INSIDE the signed payload, so it is automatically covered by
    the signature — no format change, no network client in Cell."""

    def test_inclusion_proof_is_signature_covered(self):
        """Extension path: the proof is added to the payload BEFORE
        signing (verify() is dict-based, so no API change is needed) —
        the field is then automatically covered by the signature, and
        tampering with it fails verification."""
        report = ExecutionReport(status="success", exit_code=0, elapsed_ms=1.0)
        payload = report.to_dict()
        payload["inclusion_proof"] = {
            "log": "rekor-v2.example",
            "index": 42,
            "root": "aa" * 32,
        }
        payload["alg"] = "EdDSA"
        payload["signature"] = _signer(canonical_bytes(payload)).hex()
        assert payload["inclusion_proof"]["index"] == 42
        assert ExecutionReport.verify(payload, _verifier)
        # Tampering with the proof breaks verification (it is covered).
        payload["inclusion_proof"]["index"] = 43
        assert not ExecutionReport.verify(payload, _verifier)
