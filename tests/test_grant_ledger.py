# SPDX-License-Identifier: BUSL-1.1
# Copyright 2026 Michael Soppa
"""Egress-grant enforcement: window, cap, revocation and tamper evidence.

These tests target the ADR-013 enforcement core directly. The engine/MCP
integration lives in ``tests/test_egress_sidecar.py`` and
``tests/test_mcp_adapter.py``; here we prove the book's guarantees in
isolation, because they are the claims a grant marketing rests on.
"""

from __future__ import annotations

import json
import os
import sys
import threading
from datetime import datetime, timedelta, timezone

sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))

import pytest

from ephemora_cell.egress_sidecar import EgressGrant
from ephemora_cell.grant_ledger import GrantLedger, GrantTamperError


def _grant(gid="g-1", tool="weather", max_calls=None, not_before=None, not_after=None):
    return EgressGrant(
        grant_id=gid,
        tool=tool,
        allowed_endpoints=("https://api.example.com/v1",),
        max_calls=max_calls,
        not_before=not_before,
        not_after=not_after,
    )


def _iso(moment: datetime) -> str:
    return moment.isoformat(timespec="milliseconds")


@pytest.fixture()
def ledger(tmp_path):
    return GrantLedger(tmp_path / "grants.jsonl")


# --- cap ---


def test_uncapped_grant_charges_every_call(ledger):
    grant = _grant()
    for expected in range(1, 6):
        decision = ledger.record_call(grant)
        assert decision.allowed is True
        assert decision.calls == expected


def test_cap_is_inclusive_not_off_by_one(ledger):
    # A max_calls of 2 admits 2 calls, never 3.
    grant = _grant(max_calls=2)
    assert ledger.record_call(grant).allowed is True
    assert ledger.record_call(grant).allowed is True
    third = ledger.record_call(grant)
    assert third.allowed is False
    assert third.limit == "max_calls"
    # A refusal spends nothing.
    assert ledger.usage(grant.grant_id).calls == 2


def test_refused_call_does_not_spend_a_slot(ledger):
    grant = _grant(max_calls=1)
    assert ledger.record_call(grant).allowed is True
    assert ledger.record_call(grant).allowed is False
    # The cap refusal is booked as audit evidence but did not increment.
    assert ledger.usage(grant.grant_id).calls == 1


def test_cap_survives_a_reload(ledger, tmp_path):
    grant = _grant(max_calls=3)
    ledger.record_call(grant)
    ledger.record_call(grant)
    reopened = GrantLedger(tmp_path / "grants.jsonl")
    assert reopened.usage(grant.grant_id).calls == 2
    assert reopened.record_call(grant).allowed is True
    assert reopened.record_call(grant).allowed is False


def test_contending_threads_overshoot_the_cap_by_nobody(ledger):
    # 20 threads against a cap of 7: exactly 7 approvals, 13 refusals. The
    # read-decide-write shares one lock, so the last slot cannot be spent twice.
    grant = _grant(max_calls=7)
    allowed = []
    lock = threading.Lock()

    def worker():
        decision = ledger.record_call(grant)
        with lock:
            allowed.append(decision.allowed)

    threads = [threading.Thread(target=worker) for _ in range(20)]
    for t in threads:
        t.start()
    for t in threads:
        t.join()
    assert sum(1 for a in allowed if a) == 7
    assert ledger.usage(grant.grant_id).calls == 7


# --- validity window ---


def test_call_before_not_before_is_refused(ledger):
    now = datetime(2026, 10, 4, 12, tzinfo=timezone.utc)
    grant = _grant(not_before=_iso(now + timedelta(hours=1)))
    decision = ledger.record_call(grant, now=now)
    assert decision.allowed is False
    assert decision.limit == "not_before"
    assert ledger.usage(grant.grant_id).calls == 0


def test_call_after_not_after_is_expired(ledger):
    now = datetime(2026, 10, 4, 12, tzinfo=timezone.utc)
    grant = _grant(not_after=_iso(now - timedelta(seconds=1)))
    decision = ledger.record_call(grant, now=now)
    assert decision.allowed is False
    assert decision.limit == "expired"


def test_not_after_boundary_is_exclusive(ledger):
    now = datetime(2026, 10, 4, 12, tzinfo=timezone.utc)
    # A grant expiring AT `now` refuses at `now` — the endpoint is not
    # inclusive, matching the "valid while now < not_after" wording.
    grant = _grant(not_after=_iso(now))
    assert ledger.record_call(grant, now=now).limit == "expired"
    earlier = _grant(gid="g-2", not_after=_iso(now))
    assert ledger.record_call(earlier, now=now - timedelta(milliseconds=1)).allowed


def test_z_suffix_is_accepted_and_naive_bound_is_refused(ledger):
    # A UTC 'Z' bound parses; a naive (offsetless) bound is refused rather than
    # silently assumed to be local time.
    grant = _grant(gid="g-z", not_after="2099-01-01T00:00:00Z")
    assert ledger.record_call(grant).allowed is True
    naive = _grant(gid="g-naive", not_before="2020-01-01T00:00:00")
    with pytest.raises(ValueError, match="malformed bound"):
        ledger.record_call(naive)


# --- revocation ---


def test_revoke_refuses_the_next_call_and_is_effective_at_this_one(ledger):
    grant = _grant(gid="rev")
    assert ledger.record_call(grant).allowed is True
    ledger.revoke("rev")
    decision = ledger.record_call(grant)
    assert decision.allowed is False
    assert decision.limit == "revoked"
    # Already-charged call was not recalled.
    assert ledger.usage("rev").calls == 1


def test_revoke_is_effective_even_within_an_open_window(ledger):
    now = datetime(2026, 10, 4, 12, tzinfo=timezone.utc)
    grant = _grant(gid="rev2", not_after=_iso(now + timedelta(days=1)))
    assert ledger.record_call(grant, now=now).allowed is True
    ledger.revoke("rev2", now=now)
    assert ledger.record_call(grant, now=now).limit == "revoked"


def test_revocation_order_is_idempotent(ledger):
    ledger.revoke("g")
    ledger.revoke("g", reason="second")
    state = ledger.usage("g")
    assert state.revoked_at is not None
    assert ledger.record_call(_grant(gid="g")).allowed is False


# --- tamper evidence ---


def test_editing_a_booked_count_is_caught(ledger, tmp_path):
    grant = _grant(gid="tamper")
    ledger.record_call(grant)
    ledger.record_call(grant)
    path = tmp_path / "grants.jsonl"
    lines = path.read_text().splitlines()
    # Rewrite the second call's booked count to a plausible lie (5).
    obj = json.loads(lines[-1])
    obj["calls_after"] = 5
    lines[-1] = json.dumps(obj, sort_keys=True, separators=(",", ":"))
    path.write_text("\n".join(lines) + "\n")
    with pytest.raises(GrantTamperError):
        GrantLedger(path).usage("tamper")


def test_dropping_a_middle_call_line_is_caught(ledger, tmp_path):
    grant = _grant(gid="drop")
    for _ in range(3):
        ledger.record_call(grant)
    path = tmp_path / "grants.jsonl"
    lines = path.read_text().splitlines()
    kept = [ln for i, ln in enumerate(lines) if i != 1]  # drop the 2nd call
    path.write_text("\n".join(kept) + "\n")
    with pytest.raises(GrantTamperError):
        GrantLedger(path).usage("drop")


def test_verify_reports_the_offending_line(tmp_path):
    path = tmp_path / "grants.jsonl"
    ledger = GrantLedger(path)
    grant = _grant(gid="v")
    ledger.record_call(grant)
    ledger.record_call(grant)
    assert ledger.verify() == []
    lines = path.read_text().splitlines()
    obj = json.loads(lines[0])
    obj["calls_after"] = 99
    lines[0] = json.dumps(obj, sort_keys=True, separators=(",", ":"))
    path.write_text("\n".join(lines) + "\n")
    problems = ledger.verify()
    assert len(problems) == 1
    assert "line 1" in problems[0]


def test_a_truncated_tail_is_not_detectable_from_the_file_alone(tmp_path):
    # Honest limit: verify() proves the surviving lines are internally
    # consistent, but a whole last call simply removed leaves no mismatch. This
    # test pins that the limit is real, not a claim of total tamper detection.
    path = tmp_path / "grants.jsonl"
    ledger = GrantLedger(path)
    grant = _grant(gid="trunc")
    ledger.record_call(grant)
    ledger.record_call(grant)
    ledger.record_call(grant)
    lines = path.read_text().splitlines()
    path.write_text("\n".join(lines[:2]) + "\n")
    reopened = GrantLedger(path)
    assert reopened.verify() == []  # the book still seals...
    assert reopened.usage("trunc").calls == 2  # ...but one call is invisible


# --- construction guards ---


def test_record_call_requires_an_egress_grant(ledger):
    with pytest.raises(TypeError):
        ledger.record_call({"grant_id": "dict"})


def test_revoke_requires_a_grant_id(ledger):
    with pytest.raises(ValueError):
        ledger.revoke("")


# --- the book itself is part of the boundary --------------------------------


def test_the_book_refuses_to_be_a_symlink(tmp_path):
    """Caps and revocations live in this file. A name here that points somewhere
    else (or that is swapped between check and open) resets the enforcement, so
    the writer refuses to follow it rather than appending through it."""
    real = tmp_path / "real.jsonl"
    link = tmp_path / "grants.jsonl"
    GrantLedger(real).record_call(_grant(max_calls=1))
    link.symlink_to(real)
    ledger = GrantLedger(link)
    with pytest.raises(OSError, match="symbolic links"):
        ledger.record_call(_grant(max_calls=1))


@pytest.mark.skipif(os.geteuid() == 0, reason="root ignores file permissions")
def test_a_ledger_that_cannot_be_written_refuses_the_call_WITH_an_audit(tmp_path):
    """An unreadable/unwritable book used to raise out through the mediator: the
    fetch was denied, but no audit line and no `_meta.egress` survived, and one
    corrupt record switched off every grant in the process. Denial is still a
    decision, so it must be recorded as one."""
    from ephemora_cell.egress_sidecar import mediate_with_grant

    path = tmp_path / "grants.jsonl"
    path.write_text("")
    os.chmod(path, 0o400)
    try:
        ledger = GrantLedger(path)
        outcome = mediate_with_grant(
            _grant(max_calls=5),
            ledger,
            json.dumps({"url": "https://api.example.com/v1", "method": "GET"}),
        )
    finally:
        os.chmod(path, 0o644)

    assert outcome.audit.decision == "denied", outcome.audit
    assert outcome.audit.limit == "ledger", outcome.audit
    assert outcome.response_doc["ok"] is False
    assert not outcome.response_doc.get("content"), outcome.response_doc
