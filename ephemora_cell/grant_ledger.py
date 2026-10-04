# SPDX-License-Identifier: BUSL-1.1
# Copyright 2026 Michael Soppa
"""Egress-grant enforcement: per-grant usage caps, expiry and revocation.

An :class:`~ephemora_cell.egress_sidecar.EgressGrant` is a signed *description*
of an egress allowance — who, to what, until when, how many calls. This module
turns that description into a control: it is the consumer that reads
``not_before`` / ``not_after`` / ``max_calls`` and honours a revocation, so the
grant's fields stop being schema-only.

The three claims this makes checkable, and the one it deliberately does not:

* **Cap, window and revocation are decided and charged in one critical
  section.** The read that decides ("there is room") and the write that spends
  it share :meth:`AppendLog.decide_and_append`'s exclusive lock — the same
  discipline as :meth:`~ephemora_cell.tenant.TenantStore.admit`. Two threads
  each seeing ``calls < max_calls`` cannot both spend the last slot.
* **Usage is charged only for a call that will actually be made.** A request
  denied by the allowlist never reaches :meth:`record_call`, so a refused fetch
  does not burn a grant slot. ``calls`` counts fetches attempted, not requests
  seen.
* **The file is the evidence.** Each approved line records ``calls_after``, the
  count it must produce; a reader replays from the empty book, so deleting or
  editing a call line shows up as a mismatch, not as a plausible number.

* **Not instantly revocable, and not in-flight.** A revocation takes effect at
  the NEXT :meth:`record_call`; a fetch already handed to
  :func:`~ephemora_cell.egress_sidecar.execute_request` is not recalled. The
  wording here is the wording the docs must keep.
"""

from __future__ import annotations

import json
from dataclasses import dataclass
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

from ._appendlog import AppendLog
from .egress_sidecar import EgressGrant

#: Line schema tag; a future version can coexist in one file.
GRANT_ENTRY_VERSION = "egress-grant-entry.v1"


class GrantTamperError(ValueError):
    """A booked line does not match the state replay recomputes from it.

    Raised for a call line whose ``calls_after`` disagrees with the running
    count, or a malformed line — the book is not trustworthy, so the caller
    must fail closed rather than grant on top of it.
    """


@dataclass(frozen=True)
class GrantState:
    """The replayed state of one grant id."""

    grant_id: str
    calls: int
    revoked_at: datetime | None

    def to_dict(self) -> dict[str, Any]:
        return {
            "grant_id": self.grant_id,
            "calls": self.calls,
            "revoked_at": self.revoked_at.isoformat() if self.revoked_at else None,
        }


@dataclass(frozen=True)
class GrantDecision:
    """The answer to "may this mediated call be made under the grant".

    ``calls`` is the count AFTER the decision: for an approval it already
    includes this call; for a refusal it is the count as it stands (nothing was
    spent). ``limit`` names which gate refused, so a transport can report it
    without parsing prose.
    """

    allowed: bool
    reason: str
    grant_id: str
    calls: int
    limit: str | None = None

    def to_dict(self) -> dict[str, Any]:
        return {
            "allowed": self.allowed,
            "reason": self.reason,
            "grant_id": self.grant_id,
            "calls": self.calls,
            "limit": self.limit,
        }


def _utcnow() -> datetime:
    return datetime.now(timezone.utc)


def _stamp(moment: datetime) -> str:
    return moment.isoformat(timespec="milliseconds")


def _parse_bound(value: str | None, field: str) -> datetime | None:
    """Parse an ISO-8601 bound to an aware datetime, or None (no bound).

    Fail closed: a naive timestamp or an unparseable one raises, because a
    naive bound cannot be compared to a UTC clock without inventing an offset —
    silently assuming one would make an expiry read as valid.
    """
    if value is None:
        return None
    if not isinstance(value, str) or not value:
        raise ValueError(f"{field} must be an ISO-8601 string or null")
    candidate = value[:-1] + "+00:00" if value.endswith("Z") else value
    try:
        parsed = datetime.fromisoformat(candidate)
    except ValueError as e:
        raise ValueError(f"{field} is not a valid ISO-8601 timestamp: {value!r}") from e
    if parsed.tzinfo is None:
        raise ValueError(
            f"{field} must carry a UTC offset (naive timestamp): {value!r}"
        )
    return parsed


def _line(**fields: Any) -> dict[str, Any]:
    record: dict[str, Any] = {"grant_entry_version": GRANT_ENTRY_VERSION}
    for key, value in fields.items():
        if value is None:
            continue
        record[key] = _stamp(value) if isinstance(value, datetime) else value
    return record


def _encode(record: dict[str, Any]) -> bytes:
    return (
        json.dumps(record, sort_keys=True, separators=(",", ":")).encode("utf-8")
        + b"\n"
    )


class GrantLedger:
    """Append-only per-grant book: charge a call, refuse a call, revoke a grant."""

    def __init__(self, path: str | Path) -> None:
        self.path = Path(path)
        self._log = AppendLog(path)

    # ---- reading ----

    def usage(self, grant_id: str) -> GrantState:
        """The replayed state of one grant. Missing file reads as an empty book."""
        return self._replay(grant_id)

    def verify(self) -> list[str]:
        """Replay every grant and report lines that do not seal.

        Returns a list of human-readable problems; an empty list means the book
        is internally consistent. It cannot see a truncated tail (the last lines
        are simply gone), which is why the CLI attestation states that limit.
        """
        problems: list[str] = []
        seen: dict[str, GrantState] = {}
        for number, raw in enumerate(self._log.read_lines(), start=1):
            try:
                line = json.loads(raw)
            except json.JSONDecodeError:
                problems.append(f"grant line {number} is not JSON: {self.path}")
                continue
            if not isinstance(line, dict):
                problems.append(f"grant line {number} is not an object: {self.path}")
                continue
            grant_id = line.get("grant_id")
            if not isinstance(grant_id, str):
                problems.append(f"grant line {number} has no grant_id: {self.path}")
                continue
            state = seen.get(grant_id, GrantState(grant_id, 0, None))
            state, error = _apply(state, line)
            seen[grant_id] = state
            if error is not None:
                problems.append(f"grant line {number}: {error}")
        return problems

    # ---- writing ----

    def record_call(
        self, grant: EgressGrant, *, now: datetime | None = None
    ) -> GrantDecision:
        """Charge one egress call against ``grant``, or refuse it.

        The gate order is revocation, then validity window, then cap — each
        refusal is booked as a ``refuse`` line (so the denial is itself audit
        evidence) and spends nothing. An approval appends a ``call`` line
        carrying the new ``calls_after`` and increments the count.
        """
        if not isinstance(grant, EgressGrant):
            raise TypeError(f"grant must be an EgressGrant, got {type(grant).__name__}")
        clock = now or _utcnow()
        # Parse the window once, outside the lock: a malformed bound is a
        # construction error in the grant, not a state the book can change, and
        # refusing it here keeps a bad grant from ever reaching the write.
        try:
            not_before = _parse_bound(grant.not_before, "not_before")
            not_after = _parse_bound(grant.not_after, "not_after")
        except ValueError as e:
            raise ValueError(
                f"grant {grant.grant_id!r} has a malformed bound: {e}"
            ) from e

        def decide(_last: bytes | None) -> tuple[GrantDecision, bytes]:
            state = self._replay(grant.grant_id)
            if state.revoked_at is not None:
                refusal = GrantDecision(
                    allowed=False,
                    reason=f"grant revoked at {_stamp(state.revoked_at)}",
                    grant_id=grant.grant_id,
                    calls=state.calls,
                    limit="revoked",
                )
                return refusal, _encode(
                    _line(
                        kind="refuse",
                        grant_id=grant.grant_id,
                        tool=grant.tool,
                        at=clock,
                        reason=refusal.reason,
                        limit=refusal.limit,
                    )
                )
            if not_before is not None and clock < not_before:
                refusal = GrantDecision(
                    allowed=False,
                    reason=f"grant not valid before {_stamp(not_before)}",
                    grant_id=grant.grant_id,
                    calls=state.calls,
                    limit="not_before",
                )
                return refusal, _encode(
                    _line(
                        kind="refuse",
                        grant_id=grant.grant_id,
                        tool=grant.tool,
                        at=clock,
                        reason=refusal.reason,
                        limit=refusal.limit,
                    )
                )
            if not_after is not None and clock >= not_after:
                refusal = GrantDecision(
                    allowed=False,
                    reason=f"grant expired at {_stamp(not_after)}",
                    grant_id=grant.grant_id,
                    calls=state.calls,
                    limit="expired",
                )
                return refusal, _encode(
                    _line(
                        kind="refuse",
                        grant_id=grant.grant_id,
                        tool=grant.tool,
                        at=clock,
                        reason=refusal.reason,
                        limit=refusal.limit,
                    )
                )
            prospective = state.calls + 1
            # The cap is inclusive: a max_calls of N admits N calls, not N+1.
            if grant.max_calls is not None and prospective > grant.max_calls:
                refusal = GrantDecision(
                    allowed=False,
                    reason=f"grant call cap reached ({grant.max_calls})",
                    grant_id=grant.grant_id,
                    calls=state.calls,
                    limit="max_calls",
                )
                return refusal, _encode(
                    _line(
                        kind="refuse",
                        grant_id=grant.grant_id,
                        tool=grant.tool,
                        at=clock,
                        reason=refusal.reason,
                        limit=refusal.limit,
                        calls_after=state.calls,
                    )
                )
            approval = GrantDecision(
                allowed=True,
                reason="ok",
                grant_id=grant.grant_id,
                calls=prospective,
            )
            return approval, _encode(
                _line(
                    kind="call",
                    grant_id=grant.grant_id,
                    tool=grant.tool,
                    at=clock,
                    calls_after=prospective,
                )
            )

        decision, _ = self._log.decide_and_append(decide)
        return decision

    def revoke(
        self, grant_id: str, *, reason: str = "operator", now: datetime | None = None
    ) -> dict[str, Any]:
        """Mark a grant revoked. Effective at the next :meth:`record_call`.

        Idempotent to state: a second revoke does not un-revoke; replay keeps
        the earliest revocation as the fact. It does not touch in-flight or
        already-delivered responses.
        """
        if not grant_id:
            raise ValueError("grant_id must be non-empty")
        clock = now or _utcnow()

        def decide(_last: bytes | None) -> tuple[dict[str, Any], bytes]:
            record = _line(
                kind="revoke",
                grant_id=grant_id,
                at=clock,
                reason=reason,
            )
            return record, _encode(record)

        record, _ = self._log.decide_and_append(decide)
        return record

    # ---- internals ----

    def _replay(self, grant_id: str) -> GrantState:
        state = GrantState(grant_id, 0, None)
        for number, raw in enumerate(self._log.read_lines(), start=1):
            try:
                line = json.loads(raw)
            except json.JSONDecodeError as e:
                raise GrantTamperError(
                    f"grant line {number} is not JSON: {self.path}"
                ) from e
            if not isinstance(line, dict) or line.get("grant_id") != grant_id:
                continue
            state, error = _apply(state, line)
            if error is not None:
                raise GrantTamperError(f"grant line {number}: {error}")
        return state


def _apply(state: GrantState, line: dict[str, Any]) -> tuple[GrantState, str | None]:
    """Fold one grant line into state, returning ``(state, error_or_None)``.

    The state is ALWAYS advanced by what the book *implies* (a call line
    increments by one, regardless of the count it booked), so a single edited
    line surfaces as exactly one divergence and does not cascade into every
    later line. The caller decides what an error means: :meth:`_replay` fails
    closed, :meth:`verify` reports and keeps folding.
    """
    kind = line.get("kind")
    if kind == "call":
        calls = state.calls + 1
        booked = line.get("calls_after")
        error = None
        if not isinstance(booked, int) or booked != calls:
            error = (
                f"call booked calls_after={booked!r} but the book produces "
                f"{calls} — a line was edited, dropped or reordered"
            )
        return GrantState(state.grant_id, calls, state.revoked_at), error
    if kind == "revoke":
        if state.revoked_at is not None:
            return state, None
        try:
            revoked_at = _parse_bound(line.get("at"), "at")
        except ValueError as e:
            return state, str(e)
        return GrantState(state.grant_id, state.calls, revoked_at), None
    if kind == "refuse":
        # A refusal books nothing; its calls_after (when capped) must still agree.
        booked = line.get("calls_after")
        if booked is not None and booked != state.calls:
            return (
                state,
                f"refusal booked calls_after={booked!r} but the book holds "
                f"{state.calls}",
            )
        return state, None
    return state, f"unknown kind {kind!r}"
