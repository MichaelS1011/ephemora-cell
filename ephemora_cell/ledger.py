# SPDX-License-Identifier: BUSL-1.1
# Copyright 2026 Michael Soppa

"""Append-only execution ledger: a hash chain over many runs (ADR-011).

``execution_report`` already proves that ONE run is two records bound to each
other (pre-exec → receipt, :func:`~ephemora_cell.execution_report.verify_chain`).
That says nothing about the SEQUENCE of runs: nothing in a single report binds
it to the run before it, so a reordered, dropped or silently truncated history
is invisible to a verifier.

This module adds that second axis as a separate envelope, deliberately:

* the position in the chain (``sequence``, ``prev_hash``) only exists at append
  time — AFTER both records were signed — so it cannot live inside a record
  without either breaking "signed before the guest ran" or forcing a re-sign;
* existing record schemas stay frozen (ADR-008 pins the plain-report shape),
  so a chain entry references the two records by digest instead of editing them.

Verification splits in two, which is the point: :func:`verify_ledger` checks the
linkage with no key at all (anyone holding the file can see a gap), and the
per-entry signature adds authenticity on top when a verifier is supplied.

Everything here is opt-in. No caller touches a ledger unless it is constructed
explicitly, and the ledger is host-side state: never give a guest the append
path (it is not under ``allow_dirs`` by design).
"""

from __future__ import annotations

import hashlib
import json
from collections.abc import Callable, Sequence
from dataclasses import dataclass
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

from ._appendlog import AppendLog
from .execution_report import (
    ExecutionReport,
    canonical_bytes,
    dsse_sign,
    dsse_verify,
)

#: Type tag of the chain entry payload (ADR-011).
DSSE_TYPE_LEDGER_ENTRY = "https://ephemora.dev/ledger-entry.v1"

#: Schema tag carried by every entry, so a future v2 can coexist in one file.
LEDGER_VERSION = "v1"

#: The chain starts by pointing at this value; no real entry has this digest.
GENESIS_PREV_HASH = "0" * 64

#: How far back from the end of the file a single JSON line must fit. Entries
#: are a few hundred bytes; a tail with no newline inside this window means the
#: file is not a ledger we produced, and appending would corrupt the chain.
_TAIL_WINDOW_BYTES = 65_536

Verifier = Callable[[bytes, bytes], bool]
Signer = Callable[[bytes], bytes]


def record_digest(signed_record: dict[str, Any]) -> str:
    """SHA-256 of a signed record's canonical payload.

    Same recipe as ``verify_chain``: everything except ``signature``,
    RFC 8785-canonicalized. The digest is over the bytes a verifier recomputes,
    so an entry that matches this digest is bound to exactly that record.
    """
    payload = {k: v for k, v in signed_record.items() if k != "signature"}
    return hashlib.sha256(canonical_bytes(payload)).hexdigest()


def _utc_now() -> str:
    return datetime.now(timezone.utc).isoformat(timespec="milliseconds")


@dataclass
class LedgerEntry:
    """One position in the chain.

    ``sequence`` and ``prev_hash`` are assigned by :meth:`Ledger.append` under
    the writer lock — constructing an entry with a position by hand is possible
    but then it is a claim, not a record of ordering.
    """

    pre_exec_digest: str
    receipt_digest: str
    pre_exec_id: str | None = None
    module_sha256: str | None = None
    config_fingerprint: str | None = None
    appended_at: str = ""
    ledger_version: str = LEDGER_VERSION
    sequence: int = -1
    prev_hash: str = ""

    def __post_init__(self) -> None:
        if not self.appended_at:
            self.appended_at = _utc_now()

    @classmethod
    def from_records(
        cls,
        signed_pre_exec: dict[str, Any],
        signed_receipt: dict[str, Any],
    ) -> LedgerEntry:
        """Build an entry from a signed pre-exec/receipt pair.

        The two digests are computed the way a verifier will recompute them, so
        the entry pins both halves of one run rather than "a" run. Identity is
        taken from the pre-exec record: the plain receipt carries no id field at
        all (its shape is frozen by ADR-008), so the only stable handle is the
        pre-exec id plus the two digests.
        """
        return cls(
            pre_exec_digest=record_digest(signed_pre_exec),
            receipt_digest=record_digest(signed_receipt),
            pre_exec_id=signed_pre_exec.get("id"),
            module_sha256=signed_pre_exec.get("module_sha256"),
            config_fingerprint=signed_pre_exec.get("config_fingerprint"),
        )

    def to_dict(self) -> dict[str, Any]:
        return {
            "ledger_version": self.ledger_version,
            "sequence": self.sequence,
            "appended_at": self.appended_at,
            "prev_hash": self.prev_hash,
            "pre_exec_id": self.pre_exec_id,
            "pre_exec_digest": self.pre_exec_digest,
            "receipt_digest": self.receipt_digest,
            "module_sha256": self.module_sha256,
            "config_fingerprint": self.config_fingerprint,
        }

    def canonical_bytes(self) -> bytes:
        return canonical_bytes(self.to_dict())

    def digest(self) -> str:
        """SHA-256 of the canonical payload — the value the NEXT entry seals."""
        return hashlib.sha256(self.canonical_bytes()).hexdigest()

    def sign(
        self,
        signer: Signer,
        *,
        alg: str = "ES256",
    ) -> dict[str, Any]:
        """SEP-2787-style signed form: payload plus ``alg`` and ``signature``.

        The signature covers the payload including ``sequence`` and
        ``prev_hash``, so a signed entry cannot be moved, renumbered or re-parented
        without breaking its own signature.
        """
        record = dict(self.to_dict())
        record["alg"] = alg
        raw = signer(canonical_bytes(record))
        if not isinstance(raw, (bytes, bytearray)):
            raise TypeError(f"signer must return bytes, got {type(raw).__name__}")
        record["signature"] = bytes(raw).hex()
        return record

    def to_dsse(
        self,
        signer: Signer,
        *,
        type_uri: str = DSSE_TYPE_LEDGER_ENTRY,
        alg: str = "ES256",
        key_id: str | None = None,
    ) -> dict[str, Any]:
        """DSSE v1 envelope over the entry's JCS payload (parallel to sign())."""
        return dsse_sign(
            self.canonical_bytes(),
            payload_type=type_uri,
            signer=signer,
            alg=alg,
            key_id=key_id,
        )


def signed_entry_digest(signed_entry: dict[str, Any]) -> str:
    """Digest of a signed entry, ignoring its own signature (chain link input)."""
    payload = {k: v for k, v in signed_entry.items() if k != "signature"}
    return hashlib.sha256(canonical_bytes(payload)).hexdigest()


def verify_entry_signature(
    signed_entry: dict[str, Any],
    verifier: Verifier,
    *,
    expected_alg: str | None = None,
) -> bool:
    """Check one entry's own signature. Fails closed.

    Reuses :meth:`ExecutionReport.verify`, which is payload-agnostic (it strips
    ``signature``, canonicalizes, calls the verifier, and pins ``alg`` when
    asked) — one implementation, so an entry cannot verify under looser rules
    than a record does.
    """
    return ExecutionReport.verify(signed_entry, verifier, expected_alg=expected_alg)


def verify_dsse_entry(envelope: dict[str, Any], verifier: Verifier) -> bool:
    """DSSE form of an entry (see :meth:`LedgerEntry.to_dsse`)."""
    return dsse_verify(envelope, verifier)


def chain_break(
    entries: Sequence[dict[str, Any]],
    verifier: Verifier | None = None,
    *,
    expected_alg: str | None = None,
) -> str | None:
    """Return WHY the chain is broken, or ``None`` when it is intact.

    The reason is a separate return value because a CLI has to tell an operator
    which entry to look at; a bare ``False`` sends them hunting through a file
    they cannot recompute by hand.
    """
    if not isinstance(entries, Sequence) or isinstance(entries, (str, bytes)):
        return "ledger is not a sequence of entries"
    if not entries:
        return "ledger contains no entries"
    expected_prev = GENESIS_PREV_HASH
    for position, entry in enumerate(entries):
        if not isinstance(entry, dict):
            return f"entry at position {position} is not an object"
        if entry.get("ledger_version") != LEDGER_VERSION:
            return (
                f"entry {position}: ledger_version "
                f"{entry.get('ledger_version')!r} is not {LEDGER_VERSION!r}"
            )
        if entry.get("sequence") != position:
            return (
                f"entry {position}: sequence is {entry.get('sequence')!r}, "
                f"expected {position}"
            )
        if entry.get("prev_hash") != expected_prev:
            return f"entry {position}: prev_hash does not seal entry {position - 1}"
        if verifier is not None and not verify_entry_signature(
            entry, verifier, expected_alg=expected_alg
        ):
            return f"entry {position}: signature does not verify"
        expected_prev = signed_entry_digest(entry)
    return None


def verify_ledger(
    entries: Sequence[dict[str, Any]],
    verifier: Verifier | None = None,
    *,
    expected_alg: str | None = None,
) -> bool:
    """Verify a chain of signed entries in order.

    Linkage is checked without any key: ``sequence`` must start at 0 and rise by
    exactly 1, and each ``prev_hash`` must equal the digest of the entry before
    it (genesis expects :data:`GENESIS_PREV_HASH`). When ``verifier`` is given,
    every entry's signature must verify too, under the same algorithm pin as the
    records use.

    What this cannot see: a chain shortened from the head's end. Without an
    external anchor for the current head, appending fake entries or chopping the
    tail is undetectable from the file alone — see ``SECURITY.md``.
    """
    return chain_break(entries, verifier, expected_alg=expected_alg) is None


class Ledger:
    """Single-writer JSONL ledger: one line per chain entry, append-only.

    The lock is what makes ``sequence`` meaningful. Timestamps cannot order
    runs — the isolated path executes in a subprocess and the in-process and MCP
    paths do not, so completion times collide and arrive out of order. Only the
    writer, holding the exclusive lock, decides what comes next; therefore
    arrival order IS chain order, and a verifier checks sequence monotonicity
    and never timestamp monotonicity.
    """

    def __init__(self, path: str | Path) -> None:
        self.path = Path(path)
        self._log = AppendLog(path, tail_window=_TAIL_WINDOW_BYTES)

    def head(self) -> tuple[int, str] | None:
        """``(sequence, digest)`` of the current head, or None when empty.

        Creates nothing: touching a ledger is an explicit act, and a constructor
        or a status query must not leave files behind.
        """
        last = self._log.read_tail()
        if last is None:
            return None
        entry = json.loads(last)
        return int(entry["sequence"]), signed_entry_digest(entry)

    def append(
        self,
        entry: LedgerEntry,
        signer: Signer | None = None,
        *,
        alg: str = "ES256",
    ) -> dict[str, Any]:
        """Assign the next position, sign if a signer is given, and write.

        Position assignment, signing and the write share one critical section:
        if they were split, two writers could both read the same head and both
        claim to be next, which is exactly the defect the chain exists to make
        visible.

        Returns the signed dict when ``signer`` is provided, otherwise the plain
        payload — an unsigned chain is still a chain, it just proves linkage and
        not authorship, and it is labelled that way rather than looking signed.
        """

        def decide(last: bytes | None) -> dict[str, Any]:
            if last is None:
                entry.sequence = 0
                entry.prev_hash = GENESIS_PREV_HASH
            else:
                previous = json.loads(last)
                entry.sequence = int(previous["sequence"]) + 1
                entry.prev_hash = signed_entry_digest(previous)
            entry.appended_at = _utc_now()
            return entry.sign(signer, alg=alg) if signer else entry.to_dict()

        def decide_with_payload(last: bytes | None) -> tuple[dict[str, Any], bytes]:
            record = decide(last)
            return (
                record,
                json.dumps(record, separators=(",", ":")).encode("utf-8") + b"\n",
            )

        record, _ = self._log.decide_and_append(decide_with_payload)
        return record

    def entries(self) -> list[dict[str, Any]]:
        """Every line in file order. A malformed line raises; it is never skipped."""
        out: list[dict[str, Any]] = []
        for number, raw in enumerate(self._log.read_lines(), start=1):
            try:
                out.append(json.loads(raw))
            except ValueError as exc:
                raise ValueError(
                    f"ledger line {number} is not JSON: {self.path}"
                ) from exc
        return out

    def verify(
        self,
        verifier: Verifier | None = None,
        *,
        expected_alg: str | None = None,
    ) -> bool:
        return verify_ledger(self.entries(), verifier, expected_alg=expected_alg)
