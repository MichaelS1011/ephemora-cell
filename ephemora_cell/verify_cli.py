# SPDX-License-Identifier: BUSL-1.1
# Copyright 2026 Michael Soppa

"""Verify one execution artefact — and state exactly what that proves.

``ephemora verify <path> [--key host.pub]`` reads ONE artefact, decides what it
IS from its CONTENT (never from the file extension) and verifies it with the
same primitives the run used:

* JSONL ledger (ADR-011) -> ``Ledger.entries()`` + ``chain_break``;
* DSSE v1 envelope -> ``dsse_verify``;
* pre-exec/receipt pair -> ``verify_chain``;
* signed record -> ``ExecutionReport.verify``.

Every verdict is split the way ``cmd_ledger`` splits it: what WAS proved and
what was NOT. A chain of linkage is not authorship, and a signature that was
never checked is not a verification — neither is printed as "verified".

Exit codes (fail-closed, returned by :func:`exit_code`):

* ``0`` — verified, or a ledger whose linkage is intact (linkage is the maximum
  a keyless check can reach);
* ``1`` — broken: a chain break, a signature that does not verify, a malformed
  or unreadable artefact, an unusable ``--key``;
* ``3`` — not verifiable HERE: a signed artefact was found, no ``--key`` was
  supplied, so the signature was never checked (never reported as "verified").

One disclosed limit of the ledger path: it does NOT pin the entry's declared
``alg`` label. ``chain_break`` takes an ``expected_alg`` and the DSSE path refuses
a foreign label, but here the signature BYTES are checked against the supplied
key and the label is left alone — ``Ledger.append`` defaults to ``alg="ES256"``,
so pinning ``EdDSA`` would report genuine, correctly signed chains as broken. No
verdict is widened by this (an Ed25519 key cannot validate an ECDSA signature),
but a label is not evidence of an algorithm. Widening it is a deliberate
follow-up decision, not a silent change under a freeze.

No cryptography lives in this module. The Ed25519 verifier is the PEM ->
callable seam that already exists for the egress trust root
(``grant_trust._verifier_from_pem_data``); ``cryptography`` stays an optional
extra (``tools-signing``) and is imported lazily, so a keyless run needs none.
"""

from __future__ import annotations

import base64
import json
from collections.abc import Callable
from dataclasses import dataclass, replace
from pathlib import Path
from typing import Any

from .execution_report import (
    ExecutionReport,
    PreExecutionRecord,
    dsse_verify,
    verify_chain,
)
from .ledger import Ledger, chain_break

#: Schema tag of the JSON verdict (:func:`to_json`).
VERIFY_SCHEMA = "ephemora-cell/verify/1"

#: The one signature algorithm this command can check. Ed25519 keys only: a key
#: of another type is refused rather than used to fail every signature.
VERIFY_ALG = "EdDSA"

KIND_LEDGER = "ledger"
KIND_DSSE = "dsse"
KIND_CHAIN = "chain"
KIND_RECORD = "record"
KIND_UNKNOWN = "unknown"

#: Artefact kinds that carry a signature — the ones that are "not verifiable
#: here" (exit 3) when no key was supplied.
SIGNED_KINDS = frozenset({KIND_DSSE, KIND_CHAIN, KIND_RECORD})

# --- the verdict in words (cmd_ledger's wording, not a new claim) ----------

PROVED_LEDGER_LINKAGE = "order and linkage — no entry removed, moved or edited"
PROVED_LEDGER_AUTHORSHIP = "authorship — every entry verifies under the supplied key"
NOT_PROVED_LEDGER_AUTHORSHIP = "authorship (this path holds no key)"
#: Used when a key WAS supplied but the walk stopped at a chain break: the
#: sentence must never claim the caller holds no key — that would be false.
NOT_PROVED_LEDGER_AUTHORSHIP_STOPPED = (
    "authorship under the supplied key — the walk stopped at the chain break"
)
#: Same reason, other side: a key was supplied, but no entry is signed, so
#: there was nothing for it to check. Still must not read as "holds no key".
NOT_PROVED_LEDGER_AUTHORSHIP_NOTHING_SIGNED = (
    "authorship (the supplied key had nothing to verify: no entry is signed)"
)
NOT_PROVED_LEDGER_TAIL = (
    "a chain truncated at the end — that needs an external head anchor"
)
SIGNATURE_NOT_CHECKED = "signature present but not checked (no --key supplied)"
NOT_PROVED_SIGNATURE = "payload signature (no key supplied)"
SIGNATURE_FAILED = (
    "signature verification FAILED — the record was modified or signed by "
    "another key"
)
NO_USABLE_SIGNATURE = "the record carries no usable 'signature' field (hex)"
NO_CHAIN_PAYLOADS = (
    "the chain document does not carry two signed payloads " "(pre_exec + receipt)"
)
PROVED_RECORD = "the record's signature — these exact bytes, under the supplied key"
PROVED_DSSE = "the envelope's payload signature — the DSSE PAE verifies under the key"
PROVED_CHAIN = (
    "both signatures verify and the receipt's back_link binds exactly this "
    "pre-execution record"
)
NOT_PROVED_REPLAY = (
    "freshness or single use — a valid signature can be replayed; refusing a "
    "record you have already accepted is the caller's job"
)

Verifier = Callable[[bytes, bytes], bool]

#: Key sets a document must carry to be readable as that artefact.
_LEDGER_FIELDS = frozenset({"sequence", "prev_hash"})
_CHAIN_KEY_PAIRS = (("pre_exec", "receipt"), ("signed_pre_exec", "signed_receipt"))


@dataclass(frozen=True)
class VerifyOutcome:
    """One artefact's verdict: what was proved, what was not, what failed.

    ``verified`` is True only when EVERY check that was asked for AND could be
    run passed — so a keyless check of a signed artefact is never True, and an
    intact ledger is True for linkage alone. ``proved``/``not_proved`` are the
    trust boundary in words; ``errors`` hold failures and "cannot check"
    notices; ``details`` is JSON-serializable bookkeeping (it also carries the
    ``not_verifiable_here`` flag :func:`exit_code` reads).
    """

    kind: str
    verified: bool
    proved: tuple[str, ...]
    not_proved: tuple[str, ...]
    errors: tuple[str, ...]
    details: dict[str, Any]


class _UnusableKey(Exception):
    """The supplied ``--key`` cannot become an Ed25519 verifier."""


def detect_kind(path: Path) -> str:
    """What the artefact at ``path`` IS — decided from CONTENT, not extension.

    An unreadable or non-UTF-8 file is ``unknown`` here; :func:`verify_path`
    turns that into a spoken error instead of an exception.
    """
    try:
        text = Path(path).read_text(encoding="utf-8")
    except (OSError, UnicodeDecodeError):
        return KIND_UNKNOWN
    return _detect_kind_in_text(text)


def _detect_kind_in_text(text: str) -> str:
    stripped = text.strip()
    if not stripped:
        return KIND_UNKNOWN
    lines = [line for line in stripped.splitlines() if line.strip()]
    if all(_is_ledger_entry_line(line) for line in lines):
        return KIND_LEDGER
    try:
        document = json.loads(stripped)
    except ValueError:
        return KIND_UNKNOWN
    if not isinstance(document, dict):
        return KIND_UNKNOWN
    return _classify_document(document)


def _is_ledger_entry_line(line: str) -> bool:
    """One JSONL line that carries a chain position (a ledger entry)."""
    try:
        entry = json.loads(line)
    except ValueError:
        return False
    return isinstance(entry, dict) and _LEDGER_FIELDS <= entry.keys()


def _classify_document(document: dict[str, Any]) -> str:
    if _chain_operands(document) is not None:
        return KIND_CHAIN
    if "payloadType" in document and "signatures" in document:
        return KIND_DSSE
    if _LEDGER_FIELDS <= document.keys():
        # One pretty-printed entry: a ledger, even though the reader below will
        # refuse it — entries are one JSON object per line.
        return KIND_LEDGER
    if "signature" in document or "sig" in document:
        return KIND_RECORD
    return KIND_UNKNOWN


def _chain_operands(document: dict[str, Any]) -> tuple[Any, Any] | None:
    """The two payloads of a pre-exec/receipt pair, or None when not a chain."""
    for pre_key, receipt_key in _CHAIN_KEY_PAIRS:
        if pre_key in document and receipt_key in document:
            return document[pre_key], document[receipt_key]
    return None


def verify_path(path: Path, public_key_pem: str | None) -> VerifyOutcome:
    """Verify the artefact at ``path``; never raises for a bad artefact.

    A read error, a non-UTF-8 file, broken JSON and an unusable ``--key`` all
    come back as an outcome with a plain-text error — this is an operator
    command, not a stack trace. ``public_key_pem`` is the PEM TEXT of the
    verifier's Ed25519 public key (``None`` = no key supplied).

    Exit status is NOT decided here — it is :func:`exit_code`, because "not
    verifiable here" (3) and "failed" (1) are a caller's judgement call.
    """
    path = Path(path)
    try:
        text = path.read_text(encoding="utf-8")
    except OSError as exc:
        return _unknown(f"cannot read {path}: {exc}")
    except UnicodeDecodeError as exc:
        return _unknown(f"{path} is not UTF-8 text: {exc}")

    kind = _detect_kind_in_text(text)
    if kind == KIND_LEDGER:
        return _verify_ledger(path, public_key_pem)
    if kind == KIND_UNKNOWN:
        return _unknown(_no_evidence_message(text, path))
    # Detection only returned a document kind after json.loads() succeeded.
    document = json.loads(text.strip())
    if kind == KIND_DSSE:
        return _verify_dsse(document, public_key_pem)
    if kind == KIND_CHAIN:
        return _verify_chain_document(document, public_key_pem)
    return _verify_record(document, public_key_pem)


def _unknown(message: str) -> VerifyOutcome:
    return VerifyOutcome(KIND_UNKNOWN, False, (), (), (message,), {})


#: What `verify` can read, spelled out for the operator who pointed it at
#: something else. A plain run report is a perfectly good document that simply
#: carries no chain to re-check; saying only "no verifiable evidence" leaves the
#: reader to guess whether the file, the format or the tool is at fault.
_ACCEPTED_ARTEFACTS = (
    "expected one of: a JSONL execution ledger, a DSSE envelope, a signed "
    "execution record, or a pre-exec/receipt chain"
)


def _no_evidence_message(text: str, path: Path) -> str:
    if not text.strip():
        return (
            f"no verifiable evidence found in {path} (the file is empty) — "
            f"{_ACCEPTED_ARTEFACTS}"
        )
    try:
        json.loads(text.strip())
    except ValueError as exc:
        return f"{path} is not valid JSON: {exc}"
    return f"no verifiable evidence found in {path} — {_ACCEPTED_ARTEFACTS}"


def _not_checked(kind: str, details: dict[str, Any]) -> VerifyOutcome:
    """Structurally sound, but the signature was not checked (no key)."""
    return VerifyOutcome(
        kind,
        False,
        (),
        (NOT_PROVED_SIGNATURE,),
        (SIGNATURE_NOT_CHECKED,),
        {**details, "not_verifiable_here": True},
    )


def _key_problem(kind: str, details: dict[str, Any], message: str) -> VerifyOutcome:
    return VerifyOutcome(
        kind, False, (), (), (f"cannot use the supplied --key: {message}",), details
    )


# --- ledger (ADR-011) ------------------------------------------------


def _verify_ledger(path: Path, public_key_pem: str | None) -> VerifyOutcome:
    """Linkage always; authorship only when a key is supplied AND entries are signed."""
    try:
        entries = Ledger(path).entries()
    except (OSError, ValueError) as exc:
        return VerifyOutcome(
            KIND_LEDGER, False, (), (), (f"cannot read ledger: {exc}",), {}
        )
    head = entries[-1] if entries else None
    # "signed" is a property of the chain, not of its last line: a ledger with
    # two signed entries and one unsigned head must not be reported as if
    # nothing in it were signed. The count travels with the verdict.
    signed_entries = sum(
        1 for entry in entries if isinstance(entry, dict) and "signature" in entry
    )
    details: dict[str, Any] = {
        "entries": len(entries),
        "head_sequence": head.get("sequence") if isinstance(head, dict) else None,
        "signed": signed_entries > 0,
        "signed_entries": signed_entries,
        "authorship_checked": False,
        "break_reason": None,
    }
    if public_key_pem is None:
        return _ledger_outcome(chain_break(entries), details)
    try:
        verifier = _verifier_from_pem(public_key_pem)
    except _UnusableKey as exc:
        outcome = _ledger_outcome(chain_break(entries), details, key_supplied=True)
        return replace(
            outcome,
            verified=False,
            not_proved=(),
            errors=(*outcome.errors, f"cannot use the supplied --key: {exc}"),
        )
    if not details["signed"]:
        # Linkage may be perfect, but a supplied key asks for AUTHORSHIP and
        # there is nothing signed to check it against. Fail closed.
        outcome = _ledger_outcome(chain_break(entries), details, key_supplied=True)
        return replace(
            outcome,
            verified=False,
            errors=(
                *outcome.errors,
                "no ledger entry carries a signature to check against the "
                "supplied key",
            ),
        )
    details["authorship_checked"] = True
    return _ledger_outcome(chain_break(entries, verifier), details, key_supplied=True)


def _ledger_outcome(
    reason: str | None, details: dict[str, Any], key_supplied: bool = False
) -> VerifyOutcome:
    details = {**details, "break_reason": reason}
    if reason is not None:
        # A supplied key must never be reported as absent: say which of the two
        # real situations stopped the authorship claim.
        if not key_supplied:
            authorship_note = NOT_PROVED_LEDGER_AUTHORSHIP
        elif details.get("authorship_checked"):
            authorship_note = NOT_PROVED_LEDGER_AUTHORSHIP_STOPPED
        else:
            authorship_note = NOT_PROVED_LEDGER_AUTHORSHIP_NOTHING_SIGNED
        return VerifyOutcome(
            KIND_LEDGER,
            False,
            (),
            (authorship_note, NOT_PROVED_LEDGER_TAIL),
            (f"chain break: {reason}",),
            details,
        )
    if details["authorship_checked"]:
        # Linkage intact and every entry verifies under the supplied key.
        return VerifyOutcome(
            KIND_LEDGER,
            True,
            (PROVED_LEDGER_LINKAGE, PROVED_LEDGER_AUTHORSHIP),
            (NOT_PROVED_LEDGER_TAIL,),
            (),
            details,
        )
    # Linkage intact, authorship not established — the note must match what the
    # caller actually passed: a supplied key that found no signature is not a
    # path that "holds no key".
    authorship_note = (
        NOT_PROVED_LEDGER_AUTHORSHIP_NOTHING_SIGNED
        if key_supplied
        else NOT_PROVED_LEDGER_AUTHORSHIP
    )
    return VerifyOutcome(
        KIND_LEDGER,
        True,
        (PROVED_LEDGER_LINKAGE,),
        (authorship_note, NOT_PROVED_LEDGER_TAIL),
        (),
        details,
    )


# --- DSSE envelope ---------------------------------------------------


def _verify_dsse(envelope: dict[str, Any], public_key_pem: str | None) -> VerifyOutcome:
    details = _dsse_details(envelope)
    problem = _dsse_structure_problem(envelope)
    if problem is not None:
        return VerifyOutcome(KIND_DSSE, False, (), (), (problem,), details)
    if public_key_pem is None:
        return _not_checked(KIND_DSSE, details)
    try:
        verifier = _verifier_from_pem(public_key_pem)
    except _UnusableKey as exc:
        return _key_problem(KIND_DSSE, details, str(exc))
    if dsse_verify(envelope, verifier):
        return VerifyOutcome(
            KIND_DSSE, True, (PROVED_DSSE,), (NOT_PROVED_REPLAY,), (), details
        )
    errors = [SIGNATURE_FAILED]
    declared = _declared_algs(envelope)
    if any(alg != VERIFY_ALG for alg in declared):
        # The label is not decoration: dsse_verify pins the declared algorithm,
        # so say which label was refused instead of blaming the bytes.
        errors.append(
            f"the envelope declares alg {declared!r}, but this command verifies "
            f"{VERIFY_ALG} (Ed25519) signatures"
        )
    return VerifyOutcome(KIND_DSSE, False, (), (), tuple(errors), details)


def _dsse_structure_problem(envelope: dict[str, Any]) -> str | None:
    if not isinstance(envelope.get("payloadType"), str) or not envelope["payloadType"]:
        return "the DSSE envelope carries no payloadType"
    payload = envelope.get("payload")
    if not isinstance(payload, str):
        return "the DSSE envelope carries no payload"
    if not _is_base64(payload):
        return "the DSSE payload is not valid base64"
    signatures = envelope.get("signatures")
    if not isinstance(signatures, list) or not signatures:
        return "the DSSE envelope carries no signature"
    for entry in signatures:
        if not isinstance(entry, dict) or not isinstance(entry.get("sig"), str):
            return "a DSSE signature entry carries no 'sig'"
        if not _is_base64(entry["sig"]):
            return "a DSSE signature is not valid base64"
    return None


def _is_base64(value: str) -> bool:
    try:
        base64.b64decode(value, validate=True)
    except (ValueError, TypeError):
        return False
    return True


def _declared_algs(envelope: dict[str, Any]) -> list[str]:
    signatures = envelope.get("signatures")
    if not isinstance(signatures, list):
        return []
    return sorted(
        {
            entry["alg"]
            for entry in signatures
            if isinstance(entry, dict) and isinstance(entry.get("alg"), str)
        }
    )


def _dsse_details(envelope: dict[str, Any]) -> dict[str, Any]:
    signatures = envelope.get("signatures")
    entries = signatures if isinstance(signatures, list) else []
    keyids = {
        entry["keyid"]
        for entry in entries
        if isinstance(entry, dict) and isinstance(entry.get("keyid"), str)
    }
    return {
        "payload_type": envelope.get("payloadType"),
        "signatures": len(entries),
        "algs": _declared_algs(envelope),
        "keyids": sorted(keyids),
    }


# --- pre-exec / receipt chain ----------------------------------------


def _verify_chain_document(
    document: dict[str, Any], public_key_pem: str | None
) -> VerifyOutcome:
    operands = _chain_operands(document)
    if operands is None:  # pragma: no cover - detection requires both keys
        return VerifyOutcome(KIND_CHAIN, False, (), (), (NO_CHAIN_PAYLOADS,), {})
    pre_exec, receipt = operands
    details = {
        "pre_exec_id": pre_exec.get("id") if isinstance(pre_exec, dict) else None,
    }
    if not (isinstance(pre_exec, dict) and isinstance(receipt, dict)):
        return VerifyOutcome(KIND_CHAIN, False, (), (), (NO_CHAIN_PAYLOADS,), details)
    if not (_has_hex_signature(pre_exec) and _has_hex_signature(receipt)):
        return VerifyOutcome(KIND_CHAIN, False, (), (), (NO_USABLE_SIGNATURE,), details)
    if public_key_pem is None:
        return _not_checked(KIND_CHAIN, details)
    try:
        verifier = _verifier_from_pem(public_key_pem)
    except _UnusableKey as exc:
        return _key_problem(KIND_CHAIN, details, str(exc))
    if verify_chain(pre_exec, receipt, verifier):
        return VerifyOutcome(
            KIND_CHAIN, True, (PROVED_CHAIN,), (NOT_PROVED_REPLAY,), (), details
        )
    return VerifyOutcome(
        KIND_CHAIN,
        False,
        (),
        (),
        (SIGNATURE_FAILED, _chain_failure_reason(pre_exec, receipt, verifier)),
        details,
    )


def _chain_failure_reason(
    pre_exec: dict[str, Any], receipt: dict[str, Any], verifier: Verifier
) -> str:
    """Which half of the pair broke — same primitives, for the operator's log."""
    if not PreExecutionRecord.verify(pre_exec, verifier):
        return "the pre-execution record's own signature does not verify"
    if not ExecutionReport.verify(receipt, verifier):
        return "the receipt's own signature does not verify"
    return "the receipt's back_link does not bind this pre-execution record"


# --- signed record ---------------------------------------------------


def _verify_record(
    document: dict[str, Any], public_key_pem: str | None
) -> VerifyOutcome:
    details = {
        "alg": document.get("alg"),
        # The record's own exit code is the GUEST's (what the host observed of
        # the run) — never this command's verdict, so it is named as such.
        "guest_exit_code": document.get("exit_code"),
        "status": document.get("status"),
    }
    if not _has_hex_signature(document):
        return VerifyOutcome(
            KIND_RECORD, False, (), (), (NO_USABLE_SIGNATURE,), details
        )
    if public_key_pem is None:
        return _not_checked(KIND_RECORD, details)
    try:
        verifier = _verifier_from_pem(public_key_pem)
    except _UnusableKey as exc:
        return _key_problem(KIND_RECORD, details, str(exc))
    if ExecutionReport.verify(document, verifier):
        return VerifyOutcome(
            KIND_RECORD, True, (PROVED_RECORD,), (NOT_PROVED_REPLAY,), (), details
        )
    return VerifyOutcome(KIND_RECORD, False, (), (), (SIGNATURE_FAILED,), details)


def _has_hex_signature(document: dict[str, Any]) -> bool:
    value = document.get("signature")
    if not isinstance(value, str) or not value:
        return False
    try:
        bytes.fromhex(value)
    except ValueError:
        return False
    return True


# --- the key seam ----------------------------------------------------


def _verifier_from_pem(public_key_pem: str) -> Verifier:
    """PEM text -> bytes-in/bool-out Ed25519 verifier.

    Reuses the seam that already exists for the egress trust root
    (``grant_trust._verifier_from_pem_data``): same Ed25519 rule, same
    actionable message when the optional ``cryptography`` extra is missing. No
    cryptography is added here, and the imports stay inside this call, so a
    keyless run never needs the extra.
    """
    from .grant_trust import GrantTrustError, _verifier_from_pem_data

    try:
        verifier = _verifier_from_pem_data(public_key_pem, VERIFY_ALG, "--key")
    except GrantTrustError as exc:
        raise _UnusableKey(str(exc)) from exc
    # The trust-root seam loads ANY PEM public key — an RSA key would load and
    # then fail every signature, which reads as "the artefact was modified".
    # Pin the key TYPE instead: a check on the key, not cryptography of our own.
    from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey
    from cryptography.hazmat.primitives.serialization import load_pem_public_key

    try:
        key = load_pem_public_key(public_key_pem.encode("utf-8"))
    except Exception as exc:  # pragma: no cover - grant_trust refused this first
        raise _UnusableKey(f"--key is not a valid PEM public key: {exc}") from exc
    if not isinstance(key, Ed25519PublicKey):
        raise _UnusableKey(
            f"--key is a {type(key).__name__}, but this command verifies Ed25519 "
            f"({VERIFY_ALG}) signatures"
        )
    return verifier


# --- exit status and rendering ---------------------------------------


def exit_code(outcome: VerifyOutcome, key_supplied: bool) -> int:
    """The CLI status for one verdict: 0 verified, 3 not verifiable, 1 broken.

    ``3`` is reserved for "not verifiable HERE": a signed artefact that came
    without a key, so nothing was actually checked. It is only granted when the
    outcome says the artefact was structurally sound and the caller agrees no
    key was supplied — a caller that claims a key must never be told "3".
    """
    if outcome.verified:
        return 0
    if (
        not key_supplied
        and outcome.kind in SIGNED_KINDS
        and outcome.details.get("not_verifiable_here", False)
    ):
        return 3
    return 1


def to_json(outcome: VerifyOutcome, path: Path, key_supplied: bool) -> dict[str, Any]:
    """The machine-readable verdict (schema ``ephemora-cell/verify/1``).

    ``key_supplied`` is echoed inside ``details``: a consumer that sees
    ``verified: false`` must be able to tell "checked and failed" from "never
    checked" without guessing.
    """
    details = dict(outcome.details)
    details["key_supplied"] = bool(key_supplied)
    return {
        "schema": VERIFY_SCHEMA,
        "path": str(path),
        "kind": outcome.kind,
        "verified": bool(outcome.verified),
        "proved": list(outcome.proved),
        "not_proved": list(outcome.not_proved),
        "errors": list(outcome.errors),
        "details": details,
    }


def format_report(outcome: VerifyOutcome, path: Path) -> str:
    """The human-readable verdict — proved and not proved, side by side."""
    lines = [f"verify: {path}", f"  kind: {outcome.kind}"]
    lines.append(f"  verified: {'yes' if outcome.verified else 'no'}")
    lines.extend(f"  proved: {item}" for item in outcome.proved)
    lines.extend(f"  not proved: {item}" for item in outcome.not_proved)
    lines.extend(f"  error: {item}" for item in outcome.errors)
    return "\n".join(lines)
