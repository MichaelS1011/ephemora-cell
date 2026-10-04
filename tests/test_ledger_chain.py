# SPDX-License-Identifier: BUSL-1.1
# Copyright 2026 Michael Soppa
"""Ledger chain tests (ADR-011): positions, tamper evidence, writer semantics.

The chain answers the question a single signed record cannot: was this run the
next one? Linkage is checked with no key at all, so a gap is visible to anyone
holding the file; signatures add authorship on top. Both halves are pinned here,
plus the one thing the chain provably cannot see (a truncated tail).
"""

from __future__ import annotations

import hashlib
import json
import os
import sys
import threading
from itertools import pairwise

sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))

from ephemora_cell import ExecutionReport, PreExecutionRecord, WASIConfig
from ephemora_cell.execution_report import (
    canonical_bytes,
    verify_chain,
)
from ephemora_cell.ledger import (
    GENESIS_PREV_HASH,
    LEDGER_VERSION,
    Ledger,
    LedgerEntry,
    record_digest,
    signed_entry_digest,
    verify_dsse_entry,
    verify_entry_signature,
    verify_ledger,
)

_SIGN_KEY = b"deterministic-sign-key"


def _signer(data: bytes) -> bytes:
    return hashlib.sha256(_SIGN_KEY + data).digest()


def _verifier(canonical: bytes, signature: bytes) -> bool:
    return signature == hashlib.sha256(_SIGN_KEY + canonical).digest()


def _pair(n: int = 0) -> tuple[dict, dict]:
    """A signed pre-exec/receipt pair with a deterministic identity per number."""
    pre = PreExecutionRecord.build(
        module_bytes=b"\x00asm\x01\x00\x00\x00",
        config=WASIConfig(max_fuel=500_000),
        record_id=f"pre-{n:04d}",
        timestamp=f"2026-10-03T00:00:{n % 60:02d}.000Z",
    )
    signed_pre = pre.sign(_signer, alg="EdDSA")
    report = ExecutionReport(status="success", exit_code=0, elapsed_ms=1.0)
    report.back_link = {
        "pre_exec_id": signed_pre["id"],
        "pre_exec_digest": record_digest(signed_pre),
    }
    return signed_pre, report.sign(_signer, alg="EdDSA")


def _append(ledger: Ledger, n: int = 0) -> dict:
    signed_pre, signed_receipt = _pair(n)
    return ledger.append(LedgerEntry.from_records(signed_pre, signed_receipt), _signer)


class TestPositions:
    def test_first_entry_is_genesis_positioned(self, tmp_path):
        entry = _append(Ledger(tmp_path / "ledger.jsonl"))
        assert entry["sequence"] == 0
        assert entry["prev_hash"] == GENESIS_PREV_HASH
        assert entry["ledger_version"] == LEDGER_VERSION

    def test_positions_increase_and_link(self, tmp_path):
        path = tmp_path / "ledger.jsonl"
        ledger = Ledger(path)
        for n in range(3):
            _append(ledger, n)
        entries = ledger.entries()
        assert [e["sequence"] for e in entries] == [0, 1, 2]
        for previous, current in pairwise(entries):
            assert current["prev_hash"] == signed_entry_digest(previous)
        assert ledger.verify(_verifier)

    def test_head_reports_last_entry_or_none(self, tmp_path):
        ledger = Ledger(tmp_path / "ledger.jsonl")
        assert ledger.head() is None
        entry = _append(ledger, 0)
        digest = signed_entry_digest(entry)
        assert ledger.head() == (0, digest)
        second = _append(ledger, 1)
        assert ledger.head() == (1, signed_entry_digest(second))

    def test_entry_binds_both_record_digests(self, tmp_path):
        signed_pre, signed_receipt = _pair(5)
        entry = LedgerEntry.from_records(signed_pre, signed_receipt)
        assert entry.pre_exec_digest == record_digest(signed_pre)
        assert entry.receipt_digest == record_digest(signed_receipt)
        assert entry.pre_exec_id == signed_pre["id"]
        assert entry.module_sha256 == signed_pre["module_sha256"]
        assert entry.config_fingerprint == signed_pre["config_fingerprint"]

    def test_ledger_file_created_only_on_append(self, tmp_path):
        path = tmp_path / "ledger.jsonl"
        ledger = Ledger(path)
        assert ledger.head() is None
        assert not path.exists(), "constructing or querying must not leave a file"
        _append(ledger)
        assert path.exists()


class TestTamperEvidence:
    def test_tampered_middle_entry_breaks_signature_and_link(self, tmp_path):
        ledger = Ledger(tmp_path / "ledger.jsonl")
        for n in range(3):
            _append(ledger, n)
        entries = ledger.entries()
        entries[1]["receipt_digest"] = "ff" * 32
        assert not verify_entry_signature(entries[1], _verifier)
        assert not verify_ledger(entries, _verifier)
        # linkage alone catches it too, without any key
        assert not verify_ledger(entries)

    def test_removed_middle_entry_leaves_a_gap(self, tmp_path):
        ledger = Ledger(tmp_path / "ledger.jsonl")
        for n in range(3):
            _append(ledger, n)
        entries = ledger.entries()
        del entries[1]
        assert not verify_ledger(entries)

    def test_reordered_entries_break_the_chain(self, tmp_path):
        ledger = Ledger(tmp_path / "ledger.jsonl")
        for n in range(3):
            _append(ledger, n)
        entries = ledger.entries()
        entries[0], entries[1] = entries[1], entries[0]
        assert not verify_ledger(entries)

    def test_non_genesis_start_is_rejected(self, tmp_path):
        ledger = Ledger(tmp_path / "ledger.jsonl")
        for n in range(2):
            _append(ledger, n)
        assert not verify_ledger(ledger.entries()[1:])

    def test_truncated_tail_is_not_detectable_from_the_file_alone(self, tmp_path):
        """Honest limit: without an external anchor for the head, chopping the
        newest entries off the end looks exactly like a shorter chain."""
        ledger = Ledger(tmp_path / "ledger.jsonl")
        for n in range(4):
            _append(ledger, n)
        entries = ledger.entries()
        assert verify_ledger(entries, _verifier)
        assert verify_ledger(entries[:2], _verifier), "truncation is silent by design"

    def test_linkage_verifies_without_any_key(self, tmp_path):
        ledger = Ledger(tmp_path / "ledger.jsonl")
        for n in range(3):
            _append(ledger, n)
        entries = ledger.entries()
        assert verify_ledger(entries)
        forged = dict(entries[-1])
        forged["signature"] = "00" * 32
        assert verify_ledger([*entries[:-1], forged]), "linkage is keyless"
        assert not verify_ledger([*entries[:-1], forged], _verifier)

    def test_wrong_version_label_is_rejected(self, tmp_path):
        ledger = Ledger(tmp_path / "ledger.jsonl")
        _append(ledger)
        entries = ledger.entries()
        entries[0]["ledger_version"] = "v0"
        assert not verify_ledger(entries)


class TestSignatureSemantics:
    def test_alg_pinning_fails_closed(self, tmp_path):
        """The writer's default alg is ES256 (same default as the records), so a
        verifier pinned to anything else must refuse the entry."""
        entry = _append(Ledger(tmp_path / "ledger.jsonl"))
        assert entry["alg"] == "ES256"
        assert verify_entry_signature(entry, _verifier, expected_alg="ES256")
        assert not verify_entry_signature(entry, _verifier, expected_alg="EdDSA")
        # An entry signed with no alg at all still passes unpinned verification
        # (legacy path) but never a pinned one — same convention as the records.
        signed_pre, signed_receipt = _pair(6)
        payload = LedgerEntry.from_records(signed_pre, signed_receipt).to_dict()
        no_alg = {**payload, "signature": _signer(canonical_bytes(payload)).hex()}
        assert verify_entry_signature(no_alg, _verifier)
        assert not verify_entry_signature(no_alg, _verifier, expected_alg="EdDSA")

    def test_dsse_envelope_roundtrip(self, tmp_path):
        signed_pre, signed_receipt = _pair(1)
        entry = LedgerEntry.from_records(signed_pre, signed_receipt)
        entry.sequence = 0
        entry.prev_hash = GENESIS_PREV_HASH
        envelope = entry.to_dsse(_signer, alg="EdDSA", key_id="cell-test-key")
        assert envelope["payloadType"] == "https://ephemora.dev/ledger-entry.v1"
        assert envelope["signatures"][0]["keyid"] == "cell-test-key"
        assert verify_dsse_entry(envelope, _verifier)
        assert not verify_dsse_entry({**envelope, "signatures": []}, _verifier)

    def test_moved_entry_cannot_keep_its_signature(self, tmp_path):
        """Relabeling sequence/prev_hash is the obvious attack on a chain; the
        signature covers both fields, so it breaks instead."""
        ledger = Ledger(tmp_path / "ledger.jsonl")
        for n in range(2):
            _append(ledger, n)
        entries = ledger.entries()
        moved = dict(entries[1])
        moved["sequence"] = 1
        moved["prev_hash"] = GENESIS_PREV_HASH
        assert not verify_entry_signature(moved, _verifier)
        assert verify_entry_signature(entries[1], _verifier)

    def test_huge_sequence_refuses_to_sign(self, tmp_path):
        signed_pre, signed_receipt = _pair(2)
        entry = LedgerEntry.from_records(signed_pre, signed_receipt)
        entry.sequence = 2**53
        entry.prev_hash = GENESIS_PREV_HASH
        try:
            entry.sign(_signer)
        except ValueError as exc:
            assert "safe integer" in str(exc)
        else:
            raise AssertionError("sequence beyond the JCS safe range must not sign")

    def test_canonicalization_ignores_dict_insertion_order(self, tmp_path):
        signed_pre, signed_receipt = _pair(3)
        first = LedgerEntry.from_records(signed_pre, signed_receipt)
        first.sequence, first.prev_hash = 0, GENESIS_PREV_HASH
        reversed_payload = {
            key: value for key, value in reversed(list(first.to_dict().items()))
        }
        assert canonical_bytes(reversed_payload) == first.canonical_bytes()
        assert (
            hashlib.sha256(canonical_bytes(reversed_payload)).hexdigest()
            == first.digest()
        )

    def test_entry_digests_use_the_same_recipe_as_verify_chain(self, tmp_path):
        signed_pre, signed_receipt = _pair(4)
        assert verify_chain(signed_pre, signed_receipt, _verifier)
        entry = LedgerEntry.from_records(signed_pre, signed_receipt)
        payload = {k: v for k, v in signed_pre.items() if k != "signature"}
        assert (
            entry.pre_exec_digest
            == hashlib.sha256(canonical_bytes(payload)).hexdigest()
        )


class TestLedgerCLI:
    """`ephemora-cell ledger <path>` — the operator-facing verdict."""

    @staticmethod
    def _cli(*args) -> object:
        import subprocess

        return subprocess.run(
            [sys.executable, "-m", "ephemora_cell.cli", *args],
            capture_output=True,
            text=True,
            timeout=60,
            cwd=os.path.join(os.path.dirname(__file__), ".."),
        )

    def _build(self, tmp_path, count: int = 3):
        ledger = Ledger(tmp_path / "ledger.jsonl")
        for n in range(count):
            _append(ledger, n)
        return ledger

    def test_intact_chain_exits_zero_and_states_what_it_proves(self, tmp_path):
        self._build(tmp_path)
        result = self._cli("ledger", str(tmp_path / "ledger.jsonl"))
        assert result.returncode == 0, result.stderr
        assert "ledger intact" in result.stdout
        assert "head sequence 2" in result.stdout
        assert "not proved: authorship" in result.stdout

    def test_edited_entry_exits_one_with_the_position(self, tmp_path):
        ledger = self._build(tmp_path)
        entries = ledger.entries()
        entries[1]["module_sha256"] = "ff" * 32
        path = tmp_path / "ledger.jsonl"
        path.write_text(
            "".join(
                json.dumps(entry, separators=(",", ":")) + "\n" for entry in entries
            ),
            encoding="utf-8",
        )
        result = self._cli("ledger", str(path))
        assert result.returncode == 1
        assert "BROKEN" in result.stderr
        assert "entry 1" in result.stderr and "prev_hash" in result.stderr

    def test_json_verdict_carries_both_proofs_and_limits(self, tmp_path):
        self._build(tmp_path, count=1)
        result = self._cli("ledger", "--json", str(tmp_path / "ledger.jsonl"))
        assert result.returncode == 0, result.stderr
        payload = json.loads(result.stdout)
        assert payload["entries"] == 1
        assert payload["intact"] is True
        assert payload["signed"] is True
        assert "linkage" in payload["proves"]
        assert "truncated" in payload["cannot_see"]


class TestWriterSemantics:
    def test_concurrent_appends_produce_one_gapless_chain(self, tmp_path):
        path = tmp_path / "ledger.jsonl"
        writers = [Ledger(path) for _ in range(8)]
        errors: list[BaseException] = []

        def worker(index: int) -> None:
            try:
                for round_number in range(5):
                    writers[index].append(
                        LedgerEntry.from_records(*_pair(index * 5 + round_number)),
                        _signer,
                    )
            except BaseException as exc:  # surfaced in the assertion below
                errors.append(exc)

        threads = [threading.Thread(target=worker, args=(i,)) for i in range(8)]
        for thread in threads:
            thread.start()
        for thread in threads:
            thread.join()
        assert not errors
        entries = Ledger(path).entries()
        assert len(entries) == 40
        assert sorted(e["sequence"] for e in entries) == list(range(40))
        assert Ledger(path).verify(_verifier)

    def test_out_of_order_completion_keeps_the_chain_valid(self, tmp_path):
        """The isolated path finishes in a subprocess, so completion timestamps
        do not order runs. Sequence does — arrival order IS chain order."""
        ledger = Ledger(tmp_path / "ledger.jsonl")
        _append(ledger, 20)  # record timestamp 00:00:20
        _append(ledger, 5)  # record timestamp 00:00:05 — earlier, arrived second
        entries = ledger.entries()
        assert [e["sequence"] for e in entries] == [0, 1]
        assert [e["pre_exec_id"] for e in entries] == ["pre-0020", "pre-0005"]
        assert entries[0]["pre_exec_digest"] != entries[1]["pre_exec_digest"]
        assert ledger.verify(_verifier)

    def test_unsigned_append_is_labelled_unsigned(self, tmp_path):
        ledger = Ledger(tmp_path / "ledger.jsonl")
        signed_pre, signed_receipt = _pair(7)
        record = ledger.append(LedgerEntry.from_records(signed_pre, signed_receipt))
        assert "signature" not in record
        assert record["sequence"] == 0
        assert ledger.verify()

    def test_malformed_line_raises_instead_of_being_skipped(self, tmp_path):
        path = tmp_path / "ledger.jsonl"
        _append(Ledger(path))
        with path.open("a") as handle:
            handle.write("not json\n")
        try:
            Ledger(path).entries()
        except ValueError as exc:
            assert "not JSON" in str(exc)
        else:
            raise AssertionError("a corrupt line must not read as a valid ledger")

    def test_directory_and_missing_parent_are_refused(self, tmp_path):
        try:
            Ledger(tmp_path)
        except IsADirectoryError:
            pass
        else:
            raise AssertionError("a directory is not a ledger path")
        try:
            Ledger(tmp_path / "nope" / "ledger.jsonl")
        except NotADirectoryError:
            pass
        else:
            raise AssertionError("append would create the file in a missing directory")

    def test_oversized_last_line_is_refused(self, tmp_path):
        """A tail with no line break inside the read window is not a ledger this
        writer produced; appending would silently fork a chain."""
        path = tmp_path / "ledger.jsonl"
        path.write_bytes(b"x" * 70_000)
        ledger = Ledger(path)
        try:
            ledger.append(LedgerEntry.from_records(*_pair(8)), _signer)
        except ValueError as exc:
            assert "tail" in str(exc)
        else:
            raise AssertionError("the tail window guard did not fire")

    def test_records_are_unchanged_when_no_ledger_is_used(self, tmp_path):
        """Default-off proof: signing a report twice yields byte-identical
        canonical payloads, and nothing in the record path touched a ledger."""
        first, _ = _pair(9)
        second, _ = _pair(9)
        assert canonical_bytes(first) == canonical_bytes(second)
        assert json.loads(json.dumps(first)) == second
        assert list(tmp_path.iterdir()) == []
