# SPDX-License-Identifier: BUSL-1.1
# Copyright 2026 Michael Soppa
"""``verify_cli`` tests: one artefact in, one honest verdict out.

Every artefact is built with the SHIPPED primitives over a REAL Ed25519
keypair, so the tests hold the same bytes an operator holds: sign -> verify ->
tamper, once per format. The two verdicts that are NOT a signature are pinned
just as hard — "linkage only" (a keyless ledger) and "not verifiable here"
(a signed artefact checked without a key), neither of which may ever read as
"verified".
"""

from __future__ import annotations

import base64
import json
import os
import subprocess
import sys

sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))

import pytest

from ephemora_cell import (
    ExecutionReport,
    Ledger,
    LedgerEntry,
    PreExecutionRecord,
    WASIConfig,
)
from ephemora_cell.execution_report import DSSE_TYPE_EXECUTION_REPORT
from ephemora_cell.ledger import record_digest
from ephemora_cell.verify_cli import (
    detect_kind,
    exit_code,
    format_report,
    to_json,
    verify_path,
)

REPO = os.path.join(os.path.dirname(__file__), "..")

#: The exact wording cmd_ledger uses — this module must not invent new claims.
LINKAGE = "order and linkage — no entry removed, moved or edited"
NO_KEY = "authorship (this path holds no key)"
TRUNCATED = "a chain truncated at the end — that needs an external head anchor"


def _new_key():
    from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

    return Ed25519PrivateKey.generate()


def _public_pem(key) -> str:
    from cryptography.hazmat.primitives import serialization

    return (
        key.public_key()
        .public_bytes(
            serialization.Encoding.PEM, serialization.PublicFormat.SubjectPublicKeyInfo
        )
        .decode("utf-8")
    )


@pytest.fixture(scope="module")
def keypair():
    """The operator keypair: a bytes->bytes signer plus the PEM a verifier gets."""
    pytest.importorskip("cryptography")
    key = _new_key()
    return key.sign, _public_pem(key)


@pytest.fixture(scope="module")
def foreign_keypair():
    pytest.importorskip("cryptography")
    key = _new_key()
    return key.sign, _public_pem(key)


def _write_json(path, doc):
    path.write_text(json.dumps(doc, indent=2), encoding="utf-8")
    return path


def _record(signer) -> dict:
    return ExecutionReport(status="success", exit_code=0, elapsed_ms=2.0).sign(
        signer, alg="EdDSA"
    )


def _pair(signer, n: int = 0):
    pre = PreExecutionRecord.build(
        module_bytes=b"\x00asm\x01\x00\x00\x00",
        config=WASIConfig(max_fuel=500_000),
        record_id=f"pre-{n:04d}",
        timestamp=f"2026-10-17T00:00:{n % 60:02d}.000Z",
    )
    signed_pre = pre.sign(signer, alg="EdDSA")
    report = ExecutionReport(status="success", exit_code=0, elapsed_ms=1.0)
    report.back_link = {
        "pre_exec_id": signed_pre["id"],
        "pre_exec_digest": record_digest(signed_pre),
    }
    return signed_pre, report.sign(signer, alg="EdDSA")


def _envelope(signer) -> dict:
    return ExecutionReport(status="success", exit_code=0, elapsed_ms=1.0).to_dsse(
        signer, alg="EdDSA", key_id="host-1"
    )


def _ledger(path, signer, count: int = 3) -> Ledger:
    ledger = Ledger(path)
    for n in range(count):
        ledger.append(LedgerEntry.from_records(*_pair(signer, n)), signer, alg="EdDSA")
    return ledger


def _artifact(kind: str, signer, tmp_path):
    if kind == "record":
        return _write_json(tmp_path / "record.json", _record(signer))
    if kind == "dsse":
        return _write_json(tmp_path / "envelope.json", _envelope(signer))
    signed_pre, receipt = _pair(signer)
    return _write_json(
        tmp_path / "chain.json", {"pre_exec": signed_pre, "receipt": receipt}
    )


# --- signed record ---------------------------------------------------


def test_signed_record_verifies_and_a_rewritten_field_breaks_it(keypair, tmp_path):
    signer, public_pem = keypair
    signed = _record(signer)
    path = _write_json(tmp_path / "record.json", signed)

    assert detect_kind(path) == "record"
    outcome = verify_path(path, public_pem)
    assert outcome.kind == "record"
    assert outcome.verified is True
    assert outcome.errors == ()
    assert outcome.proved
    assert exit_code(outcome, True) == 0

    # One rewritten field: the signature is over the canonical bytes, so it
    # cannot survive. Verified False, and the FAILED sentence is the message.
    signed["status"] = "fuel_exhausted"
    broken = verify_path(_write_json(tmp_path / "tampered.json", signed), public_pem)
    assert broken.kind == "record"
    assert broken.verified is False
    assert any("signature verification FAILED" in e for e in broken.errors)
    assert exit_code(broken, True) == 1


def test_record_attributes_the_guest_fields_to_the_record(keypair, tmp_path):
    """A signed record is evidence of what the HOST observed — its exit_code is
    the guest's, and the verdict must not surface it as this command's own."""
    signer, public_pem = keypair
    path = _write_json(tmp_path / "record.json", _record(signer))
    outcome = verify_path(path, public_pem)
    assert outcome.details["guest_exit_code"] == 0
    assert outcome.details["alg"] == "EdDSA"


# --- pre-exec / receipt chain ----------------------------------------


def test_chain_verifies_and_a_tampered_receipt_breaks_it(keypair, tmp_path):
    signer, public_pem = keypair
    signed_pre, receipt = _pair(signer)
    path = _write_json(
        tmp_path / "chain.json", {"pre_exec": signed_pre, "receipt": receipt}
    )

    assert detect_kind(path) == "chain"
    outcome = verify_path(path, public_pem)
    assert outcome.kind == "chain"
    assert outcome.verified is True
    assert exit_code(outcome, True) == 0

    receipt["status"] = "failed"
    broken = verify_path(
        _write_json(
            tmp_path / "chain.json", {"pre_exec": signed_pre, "receipt": receipt}
        ),
        public_pem,
    )
    assert broken.verified is False
    assert any("signature verification FAILED" in e for e in broken.errors)
    assert exit_code(broken, True) == 1


def test_chain_back_link_must_point_at_this_pre_exec_record(keypair, tmp_path):
    """The chain binds a receipt to EXACTLY one attestation: a receipt for a
    different (itself valid) pre-exec record is a failure, not a warning."""
    signer, public_pem = keypair
    other_pre, _ = _pair(signer, 7)
    _, receipt = _pair(signer, 1)
    path = _write_json(
        tmp_path / "chain.json", {"pre_exec": other_pre, "receipt": receipt}
    )
    outcome = verify_path(path, public_pem)
    assert outcome.verified is False
    assert exit_code(outcome, True) == 1


# --- DSSE envelope ---------------------------------------------------


def test_dsse_roundtrip_and_tampered_signature(keypair, tmp_path):
    signer, public_pem = keypair
    envelope = _envelope(signer)
    path = _write_json(tmp_path / "envelope.json", envelope)

    assert detect_kind(path) == "dsse"
    outcome = verify_path(path, public_pem)
    assert outcome.kind == "dsse"
    assert outcome.verified is True
    assert exit_code(outcome, True) == 0
    assert outcome.details["payload_type"] == DSSE_TYPE_EXECUTION_REPORT

    envelope["signatures"][0]["sig"] = base64.b64encode(b"\x00" * 64).decode("ascii")
    broken = verify_path(_write_json(tmp_path / "envelope.json", envelope), public_pem)
    assert broken.verified is False
    assert any("signature verification FAILED" in e for e in broken.errors)
    assert exit_code(broken, True) == 1


@pytest.mark.parametrize(
    "envelope",
    [
        {"payloadType": None, "payload": "eA==", "signatures": [{"sig": "AAAA"}]},
        {"payloadType": "t", "signatures": [{"sig": "AAAA"}]},
        {"payloadType": "t", "payload": "eA==", "signatures": []},
        {"payloadType": "t", "payload": "eA==", "signatures": "nope"},
        {"payloadType": "t", "payload": "eA==", "signatures": [{"alg": "EdDSA"}]},
        {"payloadType": "t", "payload": "eA==", "signatures": [{"sig": "!!"}]},
        {"payloadType": "t", "payload": "!!!", "signatures": [{"sig": "AAAA"}]},
    ],
)
def test_malformed_dsse_envelopes_are_failures_not_unverifiable(envelope, tmp_path):
    """A broken envelope is a failure (1), never "not verifiable here" (3)."""
    path = _write_json(tmp_path / "envelope.json", envelope)
    outcome = verify_path(path, None)
    assert outcome.kind == "dsse"
    assert outcome.verified is False
    assert exit_code(outcome, False) == 1
    assert outcome.errors
    assert all("no key supplied" not in e for e in outcome.errors)


# --- ledger ----------------------------------------------------------


def test_intact_ledger_proves_linkage_and_says_what_it_cannot(keypair, tmp_path):
    signer, _ = keypair
    path = tmp_path / "ledger.jsonl"
    _ledger(path, signer, count=3)

    assert detect_kind(path) == "ledger"
    outcome = verify_path(path, None)
    assert outcome.kind == "ledger"
    assert outcome.verified is True
    assert outcome.errors == ()
    assert outcome.proved == (LINKAGE,)
    assert outcome.not_proved == (NO_KEY, TRUNCATED)
    assert exit_code(outcome, False) == 0
    assert outcome.details["entries"] == 3
    assert outcome.details["head_sequence"] == 2
    assert outcome.details["signed"] is True


def test_broken_ledger_chain_exits_one(keypair, tmp_path):
    signer, _ = keypair
    path = tmp_path / "ledger.jsonl"
    ledger = _ledger(path, signer, count=3)
    entries = ledger.entries()
    entries[1]["module_sha256"] = "ff" * 32
    path.write_text(
        "".join(json.dumps(entry, separators=(",", ":")) + "\n" for entry in entries),
        encoding="utf-8",
    )
    outcome = verify_path(path, None)
    assert outcome.kind == "ledger"
    assert outcome.verified is False
    assert any("prev_hash" in e for e in outcome.errors)
    assert exit_code(outcome, False) == 1
    assert outcome.details["break_reason"]


def test_a_key_supplied_break_never_claims_to_hold_no_key(keypair, tmp_path):
    """A supplied ``--key`` must never be described as absent.

    ``--key`` plus a broken chain: the walk stops at the break, so authorship
    stays unproven — but the sentence "this path holds no key" would state the
    opposite of what the caller did. The exit code is right either way; the
    wording is the contract here, because a consumer reads it to decide what
    was and was not proved.
    """
    signer, public_pem = keypair
    path = tmp_path / "ledger.jsonl"
    ledger = _ledger(path, signer, count=3)
    entries = ledger.entries()
    entries[1]["module_sha256"] = "ff" * 32
    path.write_text(
        "".join(json.dumps(entry, separators=(",", ":")) + "\n" for entry in entries),
        encoding="utf-8",
    )
    outcome = verify_path(path, public_pem)
    assert outcome.verified is False
    assert exit_code(outcome, True) == 1
    assert any("chain break" in e for e in outcome.errors)
    assert NO_KEY not in outcome.not_proved
    assert NO_KEY not in format_report(outcome, path)
    assert "key" in " ".join(outcome.not_proved).lower()
    assert to_json(outcome, path, key_supplied=True)["details"]["key_supplied"] is True


def test_a_mixed_ledger_is_not_reported_as_having_no_signatures(keypair, tmp_path):
    """Some entries signed, one not: "no entry is signed" would be a lie.

    The signed count is reported, and the failure names the entry that could not
    be authenticated — the class of claim this whole module is held to.
    """
    signer, public_pem = keypair
    path = tmp_path / "ledger.jsonl"
    ledger = Ledger(path)
    for n in range(2):
        ledger.append(LedgerEntry.from_records(*_pair(signer, n)), signer, alg="EdDSA")
    # an unsigned head: linkage may hold, authorship cannot
    ledger.append(LedgerEntry.from_records(*_pair(signer, 2)))

    outcome = verify_path(path, public_pem)
    assert outcome.verified is False
    assert outcome.details["signed"] is True  # any entry is signed, not just the head
    assert outcome.details["signed_entries"] == 2
    assert outcome.details["entries"] == 3
    assert exit_code(outcome, True) == 1
    # neither of the two wrong sentences may appear
    assert NO_KEY not in outcome.not_proved
    assert "nothing to verify" not in " ".join(outcome.not_proved)
    assert any("signature does not verify" in e for e in outcome.errors)


def test_ledger_with_the_key_also_proves_authorship(keypair, foreign_keypair, tmp_path):
    signer, public_pem = keypair
    _, foreign_pem = foreign_keypair
    path = tmp_path / "ledger.jsonl"
    _ledger(path, signer, count=2)

    outcome = verify_path(path, public_pem)
    assert outcome.verified is True
    assert outcome.proved == (
        LINKAGE,
        "authorship — every entry verifies under the supplied key",
    )
    assert outcome.not_proved == (TRUNCATED,)
    assert exit_code(outcome, True) == 0

    stranger = verify_path(path, foreign_pem)
    assert stranger.verified is False
    assert any("signature does not verify" in e for e in stranger.errors)
    assert exit_code(stranger, True) == 1


def test_unsigned_ledger_with_a_key_is_not_sold_as_authored(keypair, tmp_path):
    """Linkage is intact but nothing is signed: a supplied key demands an
    authorship check, and there is none to run. Fail closed."""
    signer, public_pem = keypair
    path = tmp_path / "ledger.jsonl"
    ledger = Ledger(path)
    for n in range(2):
        ledger.append(LedgerEntry.from_records(*_pair(signer, n)))

    outcome = verify_path(path, public_pem)
    assert outcome.details["signed"] is False
    assert outcome.verified is False
    assert any("no ledger entry carries a signature" in e for e in outcome.errors)
    # the caller DID supply a key — the wording may not claim otherwise
    assert NO_KEY not in outcome.not_proved
    assert NO_KEY not in format_report(outcome, path)
    assert exit_code(outcome, True) == 1


# --- trust boundary: a signature that was never checked --------------


@pytest.mark.parametrize("kind", ["record", "dsse", "chain"])
def test_a_signature_without_a_key_is_never_verified(kind, keypair, tmp_path):
    signer, _ = keypair
    path = _artifact(kind, signer, tmp_path)

    outcome = verify_path(path, None)
    assert outcome.kind == kind
    assert outcome.verified is False
    assert exit_code(outcome, False) == 3
    assert outcome.not_proved == ("payload signature (no key supplied)",)
    assert outcome.errors == ("signature present but not checked (no --key supplied)",)


NOT_A_KEY = "-----BEGIN PUBLIC KEY-----\nnot a key\n-----END PUBLIC KEY-----\n"


@pytest.mark.parametrize("kind", ["record", "dsse", "chain"])
def test_an_unusable_key_is_reported_not_raised(kind, keypair, tmp_path):
    signer, _ = keypair
    path = _artifact(kind, signer, tmp_path)
    outcome = verify_path(path, NOT_A_KEY)
    assert outcome.kind == kind
    assert outcome.verified is False
    assert any("cannot use the supplied --key" in e for e in outcome.errors)
    assert exit_code(outcome, True) == 1


def test_an_unusable_key_on_a_ledger_still_reports_the_linkage(keypair, tmp_path):
    signer, _ = keypair
    path = tmp_path / "ledger.jsonl"
    _ledger(path, signer, count=2)
    outcome = verify_path(path, NOT_A_KEY)
    assert outcome.kind == "ledger"
    assert outcome.verified is False
    assert any("cannot use the supplied --key" in e for e in outcome.errors)
    assert outcome.details["break_reason"] is None
    assert exit_code(outcome, True) == 1


# --- unknown / malformed input ---------------------------------------


def test_unsigned_json_yields_no_evidence(tmp_path):
    path = _write_json(tmp_path / "plain.json", {"hello": "world"})
    outcome = verify_path(path, None)
    assert outcome.kind == "unknown"
    assert outcome.verified is False
    assert exit_code(outcome, False) == 1
    # the error must tell an operator what verify actually accepts: pointing
    # `verify` at a plain run report is a normal mistake, and "no verifiable
    # evidence" alone does not say what is missing
    message = outcome.errors[0]
    assert message.startswith(f"no verifiable evidence found in {path}")
    assert "ledger" in message
    assert "DSSE" in message
    assert "signed" in message
    assert "chain" in message


def test_empty_file_names_what_was_expected_too(tmp_path):
    path = tmp_path / "empty.jsonl"
    path.write_text("", encoding="utf-8")
    outcome = verify_path(path, None)
    assert outcome.kind == "unknown"
    assert "the file is empty" in outcome.errors[0]
    assert "ledger" in outcome.errors[0]


def test_broken_json_missing_file_and_binary_are_spoken_not_raised(tmp_path):
    broken = tmp_path / "broken.json"
    broken.write_text("{not json", encoding="utf-8")
    outcome = verify_path(broken, None)
    assert outcome.kind == "unknown"
    assert outcome.verified is False
    assert any("not valid JSON" in e for e in outcome.errors)
    assert exit_code(outcome, False) == 1

    missing = verify_path(tmp_path / "nope.json", None)
    assert missing.kind == "unknown"
    assert any("cannot read" in e for e in missing.errors)
    assert exit_code(missing, False) == 1

    binary = tmp_path / "guest.wasm"
    # A real module carries non-UTF-8 bytes; the file is refused as text, not
    # decoded into a guess about what it "probably" contains.
    binary.write_bytes(b"\x00asm\x01\x00\x00\x00\xff\xfe\x80")
    outcome = verify_path(binary, None)
    assert outcome.kind == "unknown"
    assert any("not UTF-8" in e for e in outcome.errors)
    assert exit_code(outcome, False) == 1

    directory = verify_path(tmp_path, None)
    assert directory.kind == "unknown"
    assert exit_code(directory, False) == 1


def test_a_chain_document_without_two_signed_payloads_is_malformed(tmp_path):
    not_payloads = _write_json(
        tmp_path / "chain.json", {"pre_exec": {"id": "x"}, "receipt": "nope"}
    )
    outcome = verify_path(not_payloads, None)
    assert outcome.kind == "chain"
    assert outcome.verified is False
    assert any("two signed payloads" in e for e in outcome.errors)
    assert exit_code(outcome, False) == 1

    unsigned = _write_json(
        tmp_path / "chain2.json",
        {"pre_exec": {"id": "x"}, "receipt": {"status": "success"}},
    )
    outcome = verify_path(unsigned, None)
    assert outcome.kind == "chain"
    assert outcome.verified is False
    assert any("no usable 'signature' field" in e for e in outcome.errors)
    assert exit_code(outcome, False) == 1


def test_a_non_hex_signature_is_malformed_not_a_failed_verification(tmp_path):
    path = _write_json(
        tmp_path / "record.json", {"status": "success", "signature": "not-hex"}
    )
    outcome = verify_path(path, None)
    assert outcome.kind == "record"
    assert outcome.verified is False
    assert any("no usable 'signature' field" in e for e in outcome.errors)
    assert exit_code(outcome, False) == 1


def test_chain_says_which_half_of_the_pair_broke(keypair, tmp_path):
    signer, public_pem = keypair
    signed_pre, receipt = _pair(signer)
    signed_pre["module_sha256"] = "ab" * 32
    path = _write_json(
        tmp_path / "chain.json", {"pre_exec": signed_pre, "receipt": receipt}
    )
    outcome = verify_path(path, public_pem)
    assert outcome.verified is False
    assert any("pre-execution record's own signature" in e for e in outcome.errors)
    assert exit_code(outcome, True) == 1


def test_a_dsse_envelope_declaring_a_foreign_algorithm_is_refused(keypair, tmp_path):
    """dsse_verify pins the declared algorithm: an Ed25519 verifier must not
    validate an envelope whose label claims something else."""
    signer, public_pem = keypair
    envelope = _envelope(signer)
    envelope["signatures"][0]["alg"] = "ES256"
    path = _write_json(tmp_path / "envelope.json", envelope)
    outcome = verify_path(path, public_pem)
    assert outcome.verified is False
    assert any("declares alg" in e and "EdDSA" in e for e in outcome.errors)
    assert exit_code(outcome, True) == 1


def test_an_empty_or_missing_file_is_unknown_and_keyless(tmp_path):
    empty = tmp_path / "empty.jsonl"
    empty.write_text("", encoding="utf-8")
    outcome = verify_path(empty, None)
    assert outcome.kind == "unknown"
    assert any("the file is empty" in e for e in outcome.errors)
    assert exit_code(outcome, False) == 1
    assert detect_kind(empty) == "unknown"
    assert detect_kind(tmp_path / "does-not-exist.json") == "unknown"


def test_a_ledger_swapped_for_a_symlink_is_refused(keypair, tmp_path):
    """The books are enforcement: a chain that can be replaced by a link is
    refused by the shared append-log discipline, reported as a read error."""
    signer, _ = keypair
    real = tmp_path / "ledger.jsonl"
    _ledger(real, signer, count=2)
    link = tmp_path / "link.jsonl"
    link.symlink_to(real)
    outcome = verify_path(link, None)
    assert outcome.kind == "ledger"
    assert outcome.verified is False
    assert any("cannot read ledger" in e for e in outcome.errors)
    assert exit_code(outcome, False) == 1


def test_a_json_document_that_is_not_an_object_is_unknown(tmp_path):
    path = tmp_path / "list.json"
    path.write_text("[1, 2, 3]", encoding="utf-8")
    outcome = verify_path(path, None)
    assert outcome.kind == "unknown"
    assert outcome.verified is False
    assert exit_code(outcome, False) == 1


def test_a_pretty_printed_ledger_entry_is_read_as_a_ledger(keypair, tmp_path):
    """Detection is content-based: an indented entry is a ledger that the
    one-object-per-line reader must refuse, not a "record" that happens to
    carry a sequence number."""
    signer, _ = keypair
    path = tmp_path / "ledger.jsonl"
    entry = _ledger(path, signer, count=1).entries()[0]
    pretty = tmp_path / "mislabelled.json"
    pretty.write_text(json.dumps(entry, indent=2), encoding="utf-8")
    assert detect_kind(pretty) == "ledger"
    outcome = verify_path(pretty, None)
    assert outcome.kind == "ledger"
    assert outcome.verified is False
    assert exit_code(outcome, False) == 1


def test_a_key_of_another_algorithm_is_refused(keypair, tmp_path):
    """An RSA PEM loads in the trust-root seam and would then fail EVERY
    signature — which reads as "the artefact was modified". The key type is
    pinned instead."""
    from cryptography.hazmat.primitives import serialization
    from cryptography.hazmat.primitives.asymmetric import rsa

    signer, _ = keypair
    rsa_pem = (
        rsa.generate_private_key(public_exponent=65537, key_size=2048)
        .public_key()
        .public_bytes(
            serialization.Encoding.PEM, serialization.PublicFormat.SubjectPublicKeyInfo
        )
        .decode("utf-8")
    )
    path = _write_json(tmp_path / "record.json", _record(signer))
    outcome = verify_path(path, rsa_pem)
    assert outcome.verified is False
    assert any("Ed25519" in e for e in outcome.errors)
    assert exit_code(outcome, True) == 1


# --- detection reads content, never the extension --------------------


def test_detection_reads_content_not_the_file_extension(keypair, tmp_path):
    signer, _ = keypair
    ledger_path = tmp_path / "ledger.jsonl"
    _ledger(ledger_path, signer, count=1)
    mislabelled_ledger = tmp_path / "ledger.json"
    mislabelled_ledger.write_text(
        ledger_path.read_text(encoding="utf-8"), encoding="utf-8"
    )
    assert detect_kind(mislabelled_ledger) == "ledger"

    mislabelled_record = _write_json(tmp_path / "record.jsonl", _record(signer))
    assert detect_kind(mislabelled_record) == "record"


# --- json + report rendering -----------------------------------------


def test_to_json_matches_the_schema_and_round_trips(keypair, tmp_path):
    signer, public_pem = keypair
    path = _write_json(tmp_path / "record.json", _record(signer))
    outcome = verify_path(path, public_pem)

    payload = to_json(outcome, path, True)
    assert set(payload) == {
        "schema",
        "path",
        "kind",
        "verified",
        "proved",
        "not_proved",
        "errors",
        "details",
    }
    assert payload["schema"] == "ephemora-cell/verify/1"
    assert payload["path"] == str(path)
    assert payload["kind"] == "record"
    assert payload["verified"] is True
    assert payload["details"]["key_supplied"] is True
    assert json.loads(json.dumps(payload)) == payload


def test_format_report_prints_both_sides_of_the_verdict(keypair, tmp_path):
    signer, _ = keypair
    path = tmp_path / "ledger.jsonl"
    _ledger(path, signer, count=1)

    text = format_report(verify_path(path, None), path)
    assert str(path) in text
    assert "proved: order and linkage" in text
    assert "not proved: authorship" in text

    broken = format_report(
        verify_path(tmp_path / "nope.json", None), tmp_path / "nope.json"
    )
    assert "verified: no" in broken
    assert "error:" in broken


def test_the_cryptography_import_stays_lazy():
    """The extra is optional: importing the command must not pull cryptography."""
    code = "import ephemora_cell.verify_cli, sys; print('cryptography' in sys.modules)"
    result = subprocess.run(
        [sys.executable, "-c", code],
        capture_output=True,
        text=True,
        timeout=60,
        cwd=REPO,
    )
    assert result.returncode == 0, result.stderr
    assert result.stdout.strip() == "False"
