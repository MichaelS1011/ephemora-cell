# SPDX-License-Identifier: BUSL-1.1
# Copyright 2026 Michael Soppa

"""Out-of-band trust anchor for egress grants (ADR-013).

A grant confers authority: it decides which origin a tool may reach, for how
long, and how often. Until this module, the loader trusted the FILE — the cap
and the expiry were whatever the host happened to read, and anyone who could
write into the grants directory could write an authority. Verification of a
grant's signature was the one open security claim in ADR-013; it is closed here.

The rule this module encodes: **a key that travels with the artefact proves
nothing about the artefact.** The trusted keys therefore live in a separate
operator-maintained file (the trust root), referenced by path at startup, never
inside the grants directory:

* ``--egress-trust root.json --egress-grants-dir grants/`` — every grant file
  must be a DSSE v1 envelope over the grant's canonical bytes, signed by a key
  the trust root names, for the audience ``GRANT_AUDIENCE``;
* a grant whose signature is missing, unknown to the root, expired, retired,
  bound to a different key id, or aimed at a different audience is a STARTUP
  ERROR, not a warning — the same all-or-nothing posture as a malformed grant set
  today (a half-loaded authority set would enforce some caps and silently not
  others);
* rotation is auditable in the root: an old key moves ``active`` → ``transition``
  → ``retired`` and records ``replaced_by``, so "which key signed this, and was it
  still trusted then" is a fact on disk rather than in someone's head.

Ed25519 comes from the optional ``cryptography`` package (extra
``tools-signing``); a deployment without it gets an actionable error at startup,
never a silently unverified grant.
"""

from __future__ import annotations

import argparse
import base64
import json
import sys
from collections.abc import Callable
from dataclasses import dataclass
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

from ._fsutil import atomic_write_text, read_regular_nofollow
from .egress_sidecar import EgressGrant
from .execution_report import canonical_bytes, dsse_pae
from .grant_ledger import _parse_bound  # same fail-closed bound semantics

#: The DSSE payload type a grant envelope must carry. This is the audience pin:
#: the same operator key also signs execution receipts
#: (``https://ephemora.dev/execution-report.v1``), and a receipt envelope must
#: never load as a grant.
GRANT_AUDIENCE = "https://ephemora.dev/egress-grant.v1"

#: Schema of the trust root document itself.
TRUST_ROOT_SCHEMA = "egress-trust-root.v1"

#: The one signature algorithm this path can verify. Anything else in a root is
#: refused at load rather than accepted and then silently unverifiable.
TRUST_ALGORITHMS = frozenset({"EdDSA"})

KEY_STATUS_ACTIVE = "active"
KEY_STATUS_TRANSITION = "transition"
KEY_STATUS_RETIRED = "retired"
KEY_STATUSES = frozenset({KEY_STATUS_ACTIVE, KEY_STATUS_TRANSITION, KEY_STATUS_RETIRED})

#: The fields a root key entry may carry. An unknown one is a refusal, not an
#: ignore: ``notAfter`` where ``not_after`` was meant would load a key that never
#: expires.
_KEY_FIELDS = frozenset(
    {
        "key_id",
        "alg",
        "public_key_pem",
        "status",
        "not_before",
        "not_after",
        "replaced_by",
    }
)


class GrantTrustError(ValueError):
    """A grant or a trust root the loader must refuse. Fail closed."""


@dataclass(frozen=True)
class TrustedKey:
    """One operator public key the root trusts, with its rotation state."""

    key_id: str
    alg: str
    public_key_pem: str
    status: str = KEY_STATUS_ACTIVE
    not_before: str | None = None
    not_after: str | None = None
    replaced_by: str | None = None

    def window_open(self, moment: datetime) -> bool:
        lower = _parse_bound(self.not_before, "key not_before")
        upper = _parse_bound(self.not_after, "key not_after")
        if lower is not None and moment < lower:
            return False
        # not_after on a key is exclusive, exactly like a grant bound.
        if upper is not None and moment >= upper:
            return False
        return True

    def summary(self) -> dict[str, Any]:
        """What ``get-policy`` may say about this key — never the key material."""
        return {
            "key_id": self.key_id,
            "alg": self.alg,
            "status": self.status,
            "not_before": self.not_before,
            "not_after": self.not_after,
            "replaced_by": self.replaced_by,
        }


@dataclass(frozen=True)
class GrantTrustRoot:
    """The operator's trusted key set, anchored OUTSIDE the grants directory."""

    audience: str
    keys: tuple[TrustedKey, ...]
    source: str = "<in-memory>"

    # ---- loading ----

    @classmethod
    def load(cls, path: str | Path) -> GrantTrustRoot:
        """Read and validate a trust root. Refuses anything incomplete.

        Validation happens at startup, not at first use: a root with a typo in a
        PEM block, an unknown algorithm or a ``replaced_by`` pointing at a key
        that does not exist is a configuration error the operator can still fix,
        and a server that starts anyway is a server that believes it enforces
        something it does not.
        """
        file = Path(path)
        try:
            # Read without following a link, from the descriptor that was
            # checked: an anchor that can be swapped between the check and the
            # read is not an anchor.
            text = read_regular_nofollow(file).decode("utf-8", errors="strict")
        except (OSError, UnicodeDecodeError) as e:
            raise GrantTrustError(f"trust root is unreadable: {file}: {e}") from e
        try:
            doc = json.loads(text)
        except json.JSONDecodeError as e:
            raise GrantTrustError(f"trust root is not valid JSON: {file}: {e}") from e
        if not isinstance(doc, dict):
            raise GrantTrustError("trust root must be a JSON object")
        version = doc.get("trust_root_version")
        if version != TRUST_ROOT_SCHEMA:
            raise GrantTrustError(
                f"unsupported trust_root_version {version!r} (expected "
                f"{TRUST_ROOT_SCHEMA!r})"
            )
        audience = doc.get("audience", GRANT_AUDIENCE)
        if audience != GRANT_AUDIENCE:
            # Domain separation is not a preference: a root that would accept a
            # different payload type lets another system's document in.
            raise GrantTrustError(
                f"trust root audience {audience!r} is not {GRANT_AUDIENCE!r}"
            )
        raw_keys = doc.get("keys")
        if not isinstance(raw_keys, list) or not raw_keys:
            raise GrantTrustError("trust root needs a non-empty 'keys' list")

        keys: list[TrustedKey] = []
        seen: set[str] = set()
        for index, entry in enumerate(raw_keys):
            key = _parse_key(entry, index)
            if key.key_id in seen:
                raise GrantTrustError(f"duplicate key_id {key.key_id!r} in trust root")
            seen.add(key.key_id)
            keys.append(key)
        for key in keys:
            if key.replaced_by is not None and key.replaced_by not in seen:
                raise GrantTrustError(
                    f"key {key.key_id!r} names replaced_by "
                    f"{key.replaced_by!r}, which is not in the root"
                )
            if key.replaced_by == key.key_id:
                raise GrantTrustError(f"key {key.key_id!r} replaces itself")
        return cls(audience=audience, keys=tuple(keys), source=str(file))

    def key(self, key_id: str) -> TrustedKey | None:
        for candidate in self.keys:
            if candidate.key_id == key_id:
                return candidate
        return None

    def verifier_for(self, key: TrustedKey) -> Callable[[bytes, bytes], bool]:
        """Verifier bound to ONE trusted key — never to a key the artefact names."""
        return _verifier_from_pem_data(key.public_key_pem, key.alg, key.key_id)

    def summary(self) -> dict[str, Any]:
        """Operator-visible posture for ``get-policy``."""
        return {
            "source": self.source,
            "audience": self.audience,
            "keys": [key.summary() for key in self.keys],
        }

    # ---- verification ----

    def verify_envelope(
        self, envelope: Any, *, now: datetime | None = None
    ) -> EgressGrant:
        """Turn a signed envelope into an :class:`EgressGrant`, or refuse.

        Every step fails closed, in this order:

        1. the envelope is DSSE-shaped and its ``payloadType`` is exactly this
           root's audience (a receipt signed by the same key is not a grant);
        2. every listed signature carries a ``keyid`` this root trusts, that key
           is not retired, is inside its own validity window, uses the root's
           algorithm, and the signature verifies over the DSSE PAE — verified
           BEFORE the payload is parsed, so no unauthenticated byte ever drives
           grant construction or produces a parse error an attacker can read as
           an oracle;
        3. the payload is the canonical bytes of a complete, valid grant
           document — an edited or dropped field changes the bytes, an unknown
           key in the document is refused rather than ignored, and a bound or cap
           the enforcement layer could not read is refused here rather than
           surfacing as an internal error on the first call;
        4. the grant's own ``key_id`` equals the signing key id, and the named
           key is the one that produced each signature (otherwise a valid
           signature could be re-labelled under a different key id);
        5. the grant is not already expired at load — a grant whose window closed
           is stale authority, not a harmless no-op, and refusing it keeps the
           operator's directory honest.
        """
        moment = now or datetime.now(timezone.utc)
        if moment.tzinfo is None:
            raise GrantTrustError("now must be an aware datetime (UTC)")
        if not isinstance(envelope, dict):
            raise GrantTrustError("grant file must be a DSSE envelope object")
        if "payloadType" not in envelope and "grant_version" in envelope:
            # The shape the loader accepted before authentication existed. Naming
            # it is the difference between "convert your grants" and a message
            # an operator has to decode.
            raise GrantTrustError(
                "grant file is an UNSIGNED document — every grant must be a DSSE "
                "envelope signed by a key in the trust root (issue one with "
                "python -m ephemora_cell.grant_trust)"
            )
        payload_type = envelope.get("payloadType")
        if payload_type != self.audience:
            raise GrantTrustError(
                f"envelope audience {payload_type!r} is not {self.audience!r}"
            )
        payload_b64 = envelope.get("payload")
        if not isinstance(payload_b64, str):
            raise GrantTrustError("envelope is missing a base64 'payload'")
        try:
            payload = _b64_canonical(payload_b64, "envelope payload")
        except ValueError as e:
            raise GrantTrustError(str(e)) from e

        signatures = envelope.get("signatures")
        if not isinstance(signatures, list) or not signatures:
            raise GrantTrustError("grant envelope carries no signatures")
        try:
            pae = dsse_pae(payload, payload_type)
        except (TypeError, ValueError) as e:  # pragma: no cover - shape already checked
            raise GrantTrustError(f"cannot build the DSSE PAE: {e}") from e

        # Checked per signature, each against the key its OWN keyid names: a
        # signature must verify under the key it is attributed to, so a valid
        # signature can never be re-labelled with another (stronger) key id.
        used: list[str] = []
        for entry in signatures:
            if not isinstance(entry, dict):
                raise GrantTrustError("signature entry must be an object")
            key_id = entry.get("keyid")
            if not isinstance(key_id, str) or not key_id:
                raise GrantTrustError(
                    "signature entry has no 'keyid' — the root never trusts a key "
                    "that travels with the artefact unlabeled"
                )
            key = self.key(key_id)
            if key is None:
                raise GrantTrustError(f"key {key_id!r} is not in the trust root")
            if key.status == KEY_STATUS_RETIRED:
                raise GrantTrustError(
                    f"key {key_id!r} is retired (replaced_by={key.replaced_by!r})"
                )
            if entry.get("alg") != key.alg:
                raise GrantTrustError(
                    f"signature alg {entry.get('alg')!r} does not match the root's "
                    f"{key.alg!r} for key {key_id!r}"
                )
            if not key.window_open(moment):
                raise GrantTrustError(
                    f"key {key_id!r} is outside its validity window "
                    f"[{key.not_before}, {key.not_after})"
                )
            try:
                raw = _b64_canonical(entry.get("sig", ""), f"signature for {key_id!r}")
            except (ValueError, TypeError) as e:
                raise GrantTrustError(
                    f"signature for key {key_id!r} is not valid base64: {e}"
                ) from e
            if not bool(self.verifier_for(key)(pae, raw)):
                raise GrantTrustError(
                    f"grant signature does not verify under trusted key {key_id!r}"
                )
            used.append(key_id)

        # Only now — over bytes a trusted key has signed — is the payload read.
        grant = _grant_from_payload(payload)

        if grant.key_id is None:
            raise GrantTrustError(
                "grant document must name its key_id — an envelope whose payload "
                "does not say which key signed it can be re-wrapped"
            )
        if grant.key_id not in used:
            raise GrantTrustError(
                f"grant payload names key_id {grant.key_id!r} but the envelope is "
                f"signed by {sorted(set(used))}"
            )

        expires = _parse_bound(grant.not_after, "not_after")
        if expires is not None and moment >= expires:
            raise GrantTrustError(
                f"grant {grant.grant_id!r} is already expired "
                f"(not_after={grant.not_after})"
            )
        return grant


def _b64_canonical(text: Any, what: str) -> bytes:
    """Decode base64 that re-encodes to exactly the same characters.

    ``validate=True`` still accepts aliases (``AAH=`` decodes like ``AAE=``). A
    verifier that accepted them would sign-check bytes with no unique textual
    identity, so the same authority could be written two ways and content-hashing
    an envelope would stop being reliable.
    """
    if not isinstance(text, str):
        raise ValueError(f"{what} is not a base64 string")
    try:
        raw = base64.b64decode(text, validate=True)
    except (ValueError, TypeError) as e:
        raise ValueError(f"{what} is not valid base64: {e}") from e
    if base64.b64encode(raw).decode("ascii") != text:
        raise ValueError(f"{what} is not canonical base64 (a re-encoded alias)")
    return raw


def _parse_key(entry: Any, index: int) -> TrustedKey:
    if not isinstance(entry, dict):
        raise GrantTrustError(f"keys[{index}] must be an object")
    unknown = sorted(set(entry) - _KEY_FIELDS)
    if unknown:
        # A key document with a misspelled field ("notAfter") would otherwise
        # load as a key with NO expiry — a silent authority extension.
        raise GrantTrustError(
            f"keys[{index}] carries unknown field(s) {unknown}; a typo here would "
            f"silently drop a limit, so the root refuses them"
        )
    for field in ("key_id", "alg", "public_key_pem"):
        value = entry.get(field)
        if not isinstance(value, str) or not value:
            raise GrantTrustError(f"keys[{index}] is missing a non-empty {field!r}")
    status = entry.get("status", KEY_STATUS_ACTIVE)
    if status not in KEY_STATUSES:
        raise GrantTrustError(
            f"keys[{index}] has unknown status {status!r} "
            f"(expected one of {sorted(KEY_STATUSES)})"
        )
    alg = entry["alg"]
    if alg not in TRUST_ALGORITHMS:
        raise GrantTrustError(
            f"keys[{index}] names alg {alg!r}; this path verifies "
            f"{sorted(TRUST_ALGORITHMS)}"
        )
    key = TrustedKey(
        key_id=entry["key_id"],
        alg=alg,
        public_key_pem=entry["public_key_pem"],
        status=status,
        not_before=entry.get("not_before"),
        not_after=entry.get("not_after"),
        replaced_by=entry.get("replaced_by"),
    )
    # Validate the material and the window at startup, not at first grant.
    key.window_open(datetime.now(timezone.utc))
    _verifier_from_pem_data(key.public_key_pem, key.alg, key.key_id)
    return key


def _grant_from_payload(payload: bytes) -> EgressGrant:
    """Decode the envelope payload into a grant, pinned to its canonical form."""
    try:
        doc = json.loads(payload.decode("utf-8"))
    except (UnicodeDecodeError, json.JSONDecodeError) as e:
        raise GrantTrustError(f"grant payload is not UTF-8 JSON: {e}") from e
    if not isinstance(doc, dict):
        raise GrantTrustError("grant payload must be a JSON object")
    try:
        grant = EgressGrant.from_document(doc)
    except (ValueError, TypeError) as e:
        raise GrantTrustError(f"grant document is invalid: {e}") from e
    # The signed bytes must be the canonical form of exactly this document. A
    # payload carrying extra keys (which from_document would ignore) or a
    # different number spelling would verify as a signature over something the
    # loader does not enforce.
    if payload != canonical_bytes(grant.to_dict()):
        raise GrantTrustError(
            "grant payload is not the canonical bytes of the grant it decodes to "
            "(an edited or non-canonical document)"
        )
    # The enforcement consumer reads these three, so they are validated here and
    # not at the first mediated call: a grant the ledger cannot interpret is an
    # incomplete authority, and ADR-013 refuses incomplete authority at startup.
    try:
        _parse_bound(grant.not_before, "not_before")
        _parse_bound(grant.not_after, "not_after")
    except ValueError as e:
        raise GrantTrustError(f"grant window is unusable: {e}") from e
    cap = grant.max_calls
    if cap is not None and (
        isinstance(cap, bool) or not isinstance(cap, int) or cap < 0
    ):
        raise GrantTrustError(
            f"grant max_calls must be a non-negative integer or null, got {cap!r}"
        )
    return grant


def _verifier_from_pem_data(
    pem: str, alg: str, key_id: str
) -> Callable[[bytes, bytes], bool]:
    """Ed25519 verifier from PEM text (the root carries keys inline).

    Mirrors :func:`ephemora_cell_mcp.tool_registry.ed25519_verifier_from_pem`
    but takes the text straight from the root document, and keeps the same
    actionable message when the optional extra is missing.
    """
    if alg != "EdDSA":  # pragma: no cover - guarded at parse time
        raise GrantTrustError(f"alg {alg!r} is not verifiable here")
    try:
        from cryptography.hazmat.primitives.serialization import load_pem_public_key
    except ImportError as e:
        raise GrantTrustError(
            f"grant trust root needs the optional 'cryptography' package "
            f"(pip install 'ephemora-cell[tools-signing]') to verify key "
            f"{key_id!r}"
        ) from e
    try:
        key = load_pem_public_key(pem.encode("utf-8"))
    except Exception as e:  # cryptography raises ValueError/OpenSSL errors here
        raise GrantTrustError(
            f"key {key_id!r} is not a valid PEM public key: {e}"
        ) from e
    verify = getattr(key, "verify", None)
    if verify is None:
        raise GrantTrustError(f"key {key_id!r} is not a public key")

    def _verifier(canonical: bytes, signature: bytes) -> bool:
        from cryptography.exceptions import InvalidSignature

        try:
            verify(signature, canonical)
            return True
        except InvalidSignature:
            return False
        except Exception:
            # Wrong-sized signature etc.: unverifiable, which is a refusal.
            return False

    return _verifier


def signer_from_pem(path: str | Path) -> Callable[[bytes], bytes]:
    """Ed25519 signer for issuing grant envelopes (operator tooling)."""
    try:
        from cryptography.hazmat.primitives.serialization import load_pem_private_key
    except ImportError as e:
        raise GrantTrustError(
            "issuing signed grants needs the optional 'cryptography' package "
            "(pip install 'ephemora-cell[tools-signing]')"
        ) from e
    pem = Path(path).read_bytes()
    key = load_pem_private_key(pem, password=None)
    sign = getattr(key, "sign", None)
    if sign is None:
        raise GrantTrustError(f"{path!r} is not a private key")

    def _sign(canonical: bytes) -> bytes:
        return sign(canonical)

    return _sign


def sign_grant_document(
    grant: EgressGrant,
    *,
    signer: Callable[[bytes], bytes],
    key_id: str,
    audience: str = GRANT_AUDIENCE,
) -> dict[str, Any]:
    """Produce the envelope :meth:`GrantTrustRoot.verify_envelope` accepts.

    The grant document carries its ``key_id`` — the loader refuses a payload
    that does not name the key that signs it. Refusing to sign a document that
    already names a DIFFERENT key keeps that binding honest at the issuing end
    too, instead of producing an envelope the loader will reject.
    """
    if grant.key_id is not None and grant.key_id != key_id:
        raise GrantTrustError(
            f"grant document names key_id {grant.key_id!r} but is being signed by "
            f"{key_id!r}"
        )
    signed = EgressGrant(
        grant_id=grant.grant_id,
        tool=grant.tool,
        allowed_endpoints=grant.allowed_endpoints,
        allowed_methods=grant.allowed_methods,
        not_before=grant.not_before,
        not_after=grant.not_after,
        max_calls=grant.max_calls,
        key_id=key_id,
    )
    payload = canonical_bytes(signed.to_dict())
    signature = signer(dsse_pae(payload, audience))
    if not isinstance(signature, (bytes, bytearray)):
        raise GrantTrustError("signer must return bytes")
    return {
        "payloadType": audience,
        "payload": base64.b64encode(payload).decode("ascii"),
        "signatures": [
            {
                "alg": "EdDSA",
                "keyid": key_id,
                "sig": base64.b64encode(bytes(signature)).decode("ascii"),
            }
        ],
    }


def issue_cli(argv: list[str] | None = None) -> int:
    """``python -m ephemora_cell.grant_trust`` — sign a grant document.

    Operators need a way to produce what the loader accepts, without that path
    becoming a documentation archaeology project. Reads a plain grant document
    (``EgressGrant.to_dict()`` shape), writes the envelope.
    """
    parser = argparse.ArgumentParser(
        prog="python -m ephemora_cell.grant_trust",
        description="sign an egress grant document into its DSSE envelope",
    )
    parser.add_argument(
        "--grant", required=True, metavar="FILE", help="grant document JSON"
    )
    parser.add_argument(
        "--key", required=True, metavar="PEM", help="Ed25519 private key"
    )
    parser.add_argument(
        "--key-id", required=True, metavar="ID", help="key id recorded in the envelope"
    )
    parser.add_argument(
        "--out", metavar="FILE", help="where to write the envelope (default stdout)"
    )
    args = parser.parse_args(argv)

    try:
        doc = json.loads(Path(args.grant).read_text(encoding="utf-8"))
        grant = EgressGrant.from_document(doc)
        envelope = sign_grant_document(
            grant, signer=signer_from_pem(args.key), key_id=args.key_id
        )
    except (GrantTrustError, OSError, ValueError) as e:
        print(f"error: {e}", file=sys.stderr)
        return 2
    text = json.dumps(envelope, indent=2, sort_keys=True)
    if args.out:
        # Atomic publication: a grants directory scanned by a starting server
        # must never see a half-written envelope under its final name.
        atomic_write_text(args.out, text + "\n")
        print(f"wrote {args.out}")
    else:
        print(text)
    return 0


if __name__ == "__main__":  # pragma: no cover - entry point shim
    raise SystemExit(issue_cli())
