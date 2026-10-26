# SPDX-License-Identifier: BUSL-1.1
# Copyright 2026 Michael Soppa

"""Subject binding across the bridge -> stdio-child process boundary.

The HTTP bridge authenticates a client's bearer token into a *subject* and
must carry that subject to the tool-call authorization that runs inside the
stdio child process. The child is the enforcing point, so the subject has to
cross a process boundary per request — and the directive forbids taking it
from client-manipulable fields (``arguments``, ``_meta``).

The trust anchor is the spawn channel itself: the bridge starts the child and
holds the only write end of its stdin. To make that trust explicit and
checkable — and to keep a client-supplied ``_meta`` inert forever — the bridge
binds the subject with a keyed MAC over a per-instance secret that only the
bridge and this child share:

    proof = HMAC-SHA256(secret, subject)

The child only accepts a subject whose proof matches, so a forged ``_meta``
subject is refused even if a future change forwards client ``_meta``.
"""

from __future__ import annotations

import hashlib
import hmac

#: ``_meta`` key the bridge writes and the child reads for the subject.
SUBJECT_KEY = "_ephemora_subject"
#: ``_meta`` key carrying the HMAC proof for :data:`SUBJECT_KEY`.
SUBJECT_PROOF_KEY = "_ephemora_subject_proof"
#: Env var the bridge sets to tell the child it runs behind the bridge and
#: must read the per-request subject instead of a single process subject.
ENV_SUBJECT_FROM_UPSTREAM = "EPHEMORA_MCP_SUBJECT_FROM_UPSTREAM"
#: Env var carrying the per-instance MAC secret (never client-visible).
ENV_SUBJECT_SECRET = "EPHEMORA_MCP_SUBJECT_SECRET"


def subject_proof(secret: str, subject: str) -> str:
    """HMAC-SHA256 hex digest binding ``subject`` to ``secret``."""
    return hmac.new(
        secret.encode("utf-8"), subject.encode("utf-8"), hashlib.sha256
    ).hexdigest()


def verify_subject_binding(
    secret: str | None, meta: object
) -> tuple[str | None, str | None]:
    """Return ``(subject, error)`` for a bridge-carried subject.

    ``meta`` is the request's ``_meta`` dict (or anything a client could have
    shaped). A missing, malformed or unbound subject returns ``(None, reason)``;
    a valid binding returns ``(subject, None)``.
    """
    if not isinstance(meta, dict):
        return None, "missing upstream subject binding"
    subject = meta.get(SUBJECT_KEY)
    proof = meta.get(SUBJECT_PROOF_KEY)
    if not isinstance(subject, str) or not subject:
        return None, "missing upstream subject binding"
    if not isinstance(proof, str) or not proof:
        return None, "missing upstream subject binding"
    if secret is None:
        return None, "subject binding secret not configured"
    expected = subject_proof(secret, subject)
    if not hmac.compare_digest(expected, proof):
        return None, "invalid upstream subject binding"
    return subject, None
