# SPDX-License-Identifier: BUSL-1.1
# Copyright 2026 Michael Soppa

"""v1.1 tenant books stay readable, are not writable, and migrate explicitly.

A v1.1 settle line has no ``booking_version=2``. The v1.2 reader refuses such
a line for every write decision (stripping the version must not bypass the
audit binding), but a regular v1.1 book must not become unreadable. The
migration copies its settled totals into a new v2 book, leaves the old file
untouched, and carries expired reservations as conservative charges.
"""

from __future__ import annotations

import hashlib
import json
import os
import sys

import pytest

sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))

from ephemora_cell.tenant import Charge, TenantStore


def _line(**fields):
    fields.setdefault("tenant_entry_version", "v1")
    return fields


def _legacy_book(path) -> str:
    totals0 = {
        "runs": 0,
        "fuel": 0,
        "output_bytes": 0,
        "wall_ms": 0,
        "violations": 0,
        "refused": 0,
    }
    totals1 = {
        "runs": 1,
        "fuel": 100,
        "output_bytes": 20,
        "wall_ms": 30,
        "violations": 0,
        "refused": 0,
    }
    lines = [
        _line(
            kind="admit",
            tenant="tenant:a",
            at="2026-10-01T00:00:00+00:00",
            admit_id="a1",
            expires_at="2026-10-01T01:00:00+00:00",
            charge={"fuel": 1000, "output_bytes": 2000, "wall_ms": 3000},
            totals=totals0,
        ),
        _line(
            kind="settle",
            tenant="tenant:a",
            at="2026-10-01T00:00:30+00:00",
            admit_id="a1",
            charge={"fuel": 100, "output_bytes": 20, "wall_ms": 30},
            totals=totals1,
        ),
        _line(
            kind="admit",
            tenant="tenant:a",
            at="2026-10-01T00:01:00+00:00",
            admit_id="a2",
            expires_at="2026-10-01T00:01:01+00:00",
            charge={"fuel": 500, "output_bytes": 600, "wall_ms": 700},
            totals=totals1,
        ),
    ]
    path.write_text(
        "".join(json.dumps(line, sort_keys=True) + "\n" for line in lines),
        encoding="utf-8",
    )
    return hashlib.sha256(path.read_bytes()).hexdigest()


def test_a_legacy_book_is_readable_but_not_writable(tmp_path):
    book = tmp_path / "legacy.jsonl"
    digest = _legacy_book(book)
    store = TenantStore(book)
    usage = store.usage("tenant:a")
    assert usage.legacy_book is True
    assert usage.legacy_settles == 1
    assert usage.runs == 1
    assert usage.charged == Charge(fuel=100, output_bytes=20, wall_ms=30)
    assert usage.recovered == Charge(fuel=500, output_bytes=600, wall_ms=700)
    assert usage.recovered_expired_runs == 1

    admission = store.admit(
        "tenant:a",
        reserve=Charge(fuel=10, output_bytes=10, wall_ms=10),
    )
    assert admission.allowed is False
    assert "legacy_book" in (admission.reason or "")
    # The refusal did not append a line.
    assert hashlib.sha256(book.read_bytes()).hexdigest() == digest
    with pytest.raises(ValueError, match="legacy_book"):
        store.settle("tenant:a", "a1", charge=Charge(fuel=1, output_bytes=1, wall_ms=1))
    with pytest.raises(ValueError, match="legacy_book"):
        store.expire("tenant:a", "a2")


def test_migration_carries_settled_and_recovered_totals(tmp_path):
    book = tmp_path / "legacy.jsonl"
    digest = _legacy_book(book)
    target = tmp_path / "v2.jsonl"
    store = TenantStore(book)
    summary = store.migrate_to(target)
    assert summary["source_sha256"] == digest
    assert len(summary["tenants"]) == 1
    assert summary["tenants"][0]["runs"] == 2
    assert summary["tenants"][0]["charge"] == {
        "fuel": 600,
        "output_bytes": 620,
        "wall_ms": 730,
    }
    assert summary["tenants"][0]["recovered_runs"] == 1
    # The old file is untouched.
    assert hashlib.sha256(book.read_bytes()).hexdigest() == digest

    migrated = TenantStore(target)
    usage = migrated.usage("tenant:a")
    assert usage.legacy_book is False
    assert usage.runs == 2
    assert usage.charged == Charge(fuel=600, output_bytes=620, wall_ms=730)
    assert usage.legacy_recovered_runs == 1

    admission = migrated.admit(
        "tenant:a",
        reserve=Charge(fuel=1000, output_bytes=2000, wall_ms=3000),
    )
    assert admission.allowed is True, admission.reason
    migrated.settle(
        "tenant:a",
        admission.admit_id,
        charge=Charge(fuel=10, output_bytes=10, wall_ms=10),
    )
    after = migrated.usage("tenant:a")
    assert after.runs == 3
    assert after.charged == Charge(fuel=610, output_bytes=630, wall_ms=740)


def test_migration_refuses_an_active_reservation_or_an_existing_target(tmp_path):
    book = tmp_path / "legacy.jsonl"
    _legacy_book(book)
    target = tmp_path / "v2.jsonl"
    TenantStore(book).migrate_to(target)
    with pytest.raises(ValueError, match="already exists"):
        TenantStore(book).migrate_to(target)

    active = tmp_path / "active.jsonl"
    active.write_text(
        json.dumps(
            _line(
                kind="admit",
                tenant="tenant:a",
                at="2026-10-01T00:00:00+00:00",
                admit_id="a1",
                expires_at="2099-01-01T00:00:00+00:00",
                charge={"fuel": 1, "output_bytes": 1, "wall_ms": 1},
                totals={
                    "runs": 0,
                    "fuel": 0,
                    "output_bytes": 0,
                    "wall_ms": 0,
                    "violations": 0,
                    "refused": 0,
                },
            ),
            sort_keys=True,
        )
        + "\n"
        + json.dumps(
            _line(
                kind="settle",
                tenant="tenant:a",
                at="2026-10-01T00:00:30+00:00",
                admit_id="a1",
                charge={"fuel": 1, "output_bytes": 1, "wall_ms": 1},
                totals={
                    "runs": 1,
                    "fuel": 1,
                    "output_bytes": 1,
                    "wall_ms": 1,
                    "violations": 0,
                    "refused": 0,
                },
            ),
            sort_keys=True,
        )
        + "\n",
        encoding="utf-8",
    )
    # a1 is settled in this fixture, so add a second, active admission.
    with open(active, "a", encoding="utf-8") as handle:
        handle.write(
            json.dumps(
                _line(
                    kind="admit",
                    tenant="tenant:a",
                    at="2026-10-01T00:02:00+00:00",
                    admit_id="a2",
                    expires_at="2099-01-01T00:00:00+00:00",
                    charge={"fuel": 1, "output_bytes": 1, "wall_ms": 1},
                    totals={
                        "runs": 1,
                        "fuel": 1,
                        "output_bytes": 1,
                        "wall_ms": 1,
                        "violations": 0,
                        "refused": 0,
                    },
                ),
                sort_keys=True,
            )
            + "\n"
        )
    with pytest.raises(ValueError, match="active reservation"):
        TenantStore(active).migrate_to(tmp_path / "active-v2.jsonl")


def test_cli_tenant_usage_and_migrate(tmp_path, monkeypatch, capsys):
    from ephemora_cell import cli

    book = tmp_path / "legacy.jsonl"
    _legacy_book(book)
    target = tmp_path / "v2.jsonl"
    monkeypatch.setattr(
        sys,
        "argv",
        [
            "ephemora",
            "tenant",
            "usage",
            str(book),
            "--tenant",
            "tenant:a",
            "--json",
        ],
    )
    cli.main()
    usage = json.loads(capsys.readouterr().out)
    assert usage["legacy_book"] is True

    monkeypatch.setattr(
        sys,
        "argv",
        [
            "ephemora",
            "tenant",
            "migrate",
            str(book),
            "--out",
            str(target),
            "--json",
        ],
    )
    cli.main()
    summary = json.loads(capsys.readouterr().out)
    assert summary["source_sha256"] == hashlib.sha256(book.read_bytes()).hexdigest()
    assert target.is_file()


def test_migration_carries_a_v2_tenant_in_a_mixed_book(tmp_path):
    from ephemora_cell.tenant import Charge, TenantStore

    book = tmp_path / "mixed.jsonl"
    _legacy_book(book)
    other = tmp_path / "b.jsonl"
    store = TenantStore(other)
    admission = store.admit(
        "tenant:b", reserve=Charge(fuel=1000, output_bytes=2000, wall_ms=3000)
    )
    store.settle(
        "tenant:b",
        admission.admit_id,
        charge=Charge(fuel=7, output_bytes=8, wall_ms=9),
    )
    with open(book, "a", encoding="utf-8") as handle:
        handle.write(other.read_text(encoding="utf-8"))
    target = tmp_path / "v2-mixed.jsonl"
    summary = TenantStore(book).migrate_to(target)
    assert {entry["tenant"] for entry in summary["tenants"]} == {
        "tenant:a",
        "tenant:b",
    }
    b = TenantStore(target).usage("tenant:b")
    assert b.runs == 1
    assert b.charged == Charge(fuel=7, output_bytes=8, wall_ms=9)


def test_a_full_v2_strip_is_read_as_legacy_and_still_not_writable(tmp_path):
    """Stripping ALL v2 evidence is outside the self-consistency boundary.

    The book is then indistinguishable from v1.1: it is read as legacy and
    refuses new bookings, but its historical totals are whatever the writer
    left. The boundary is file ownership/mode, not the totals chain.
    """
    from ephemora_cell.tenant import Charge, TenantStore

    book = tmp_path / "v2.jsonl"
    store = TenantStore(book)
    admission = store.admit(
        "tenant:a", reserve=Charge(fuel=1000, output_bytes=2000, wall_ms=3000)
    )
    store.settle(
        "tenant:a",
        admission.admit_id,
        charge=Charge(fuel=7, output_bytes=8, wall_ms=9),
    )
    stripped = []
    for raw in book.read_text(encoding="utf-8").splitlines():
        record = json.loads(raw)
        record.pop("booking_version", None)
        for key in (
            "unknown_charged_runs",
            "unknown_fuel_charged",
            "unknown_output_charged",
            "unknown_output_runs",
            "unknown_wall_charged_ms",
            "unknown_wall_runs",
        ):
            record.get("totals", {}).pop(key, None)
        stripped.append(json.dumps(record, sort_keys=True) + "\n")
    book.write_text("".join(stripped), encoding="utf-8")

    usage = store.usage("tenant:a")
    assert usage.legacy_book is True
    assert usage.runs == 1
    refused = store.admit("tenant:a", reserve=Charge(fuel=1, output_bytes=1, wall_ms=1))
    assert refused.allowed is False
    assert "legacy_book" in (refused.reason or "")


def test_migration_preserves_the_audit_counters(tmp_path):
    from ephemora_cell.tenant import Charge, TenantStore

    book = tmp_path / "mixed.jsonl"
    _legacy_book(book)
    other = tmp_path / "b.jsonl"
    store = TenantStore(other)
    admission = store.admit(
        "tenant:b", reserve=Charge(fuel=1000, output_bytes=2000, wall_ms=3000)
    )
    store.settle(
        "tenant:b",
        admission.admit_id,
        charge=Charge(fuel=500, output_bytes=600, wall_ms=700),
        unknown=True,
        unknown_fuel_charged=500,
        unknown_output=True,
        unknown_output_charged=600,
    )
    before = store.usage("tenant:b")
    with open(book, "a", encoding="utf-8") as handle:
        handle.write(other.read_text(encoding="utf-8"))

    target = tmp_path / "v2-audit.jsonl"
    TenantStore(book).migrate_to(target)
    after = TenantStore(target).usage("tenant:b")
    assert after.unknown_fuel_charged == before.unknown_fuel_charged == 500
    assert after.unknown_output_charged == before.unknown_output_charged == 600
    assert after.unknown_charged_runs == before.unknown_charged_runs == 1
    assert after.unknown_output_runs == before.unknown_output_runs == 1
