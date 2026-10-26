# SPDX-License-Identifier: BUSL-1.1
# Copyright 2026 Michael Soppa

"""v1.2 — a host-wide budget that free tenant ids cannot escape.

The pre-fix admission checked a ``CumulativeBudget`` against the *calling*
tenant only (``TenantStore.admit`` replayed one tenant's lines). A caller who
chooses ``--tenant`` freely could therefore spend a fresh per-tenant budget per
id: eight ids, twenty attempts each, a global cap of 25 — and 160 admissions.

The fix adds a host budget applied to the WHOLE book (all tenants), so the
global cap holds no matter which tenant string a caller picks. The tenant
budget stays as a second, narrower layer.
"""

from __future__ import annotations

import json
import os
import subprocess
import sys
import time
from pathlib import Path

import pytest

sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))

from ephemora_cell.tenant import Charge, CumulativeBudget, TenantStore

REPO = Path(__file__).resolve().parent.parent


def _store(tmp_path):
    return TenantStore(tmp_path / "host.jsonl")


def test_eight_free_tenant_ids_cannot_exceed_the_host_cap(tmp_path):
    store = _store(tmp_path)
    tenant_budget = CumulativeBudget(max_runs=25)
    host_budget = CumulativeBudget(max_runs=25)

    admitted = 0
    host_refused = 0
    for tenant in (f"t{i}" for i in range(8)):
        for _ in range(20):
            admission = store.admit(
                tenant,
                reserve=Charge(),
                budget=tenant_budget,
                host_budget=host_budget,
            )
            if admission.allowed:
                admitted += 1
            elif admission.reason.startswith("host budget exhausted"):
                host_refused += 1
    assert admitted == 25
    assert host_refused == 8 * 20 - 25


def test_without_a_host_budget_the_old_per_tenant_behaviour_holds(tmp_path):
    """Negative control: the host cap is the thing being tested, not the tenant cap."""
    store = _store(tmp_path)
    tenant_budget = CumulativeBudget(max_runs=25)
    admitted = 0
    for tenant in (f"t{i}" for i in range(8)):
        for _ in range(20):
            admission = store.admit(tenant, reserve=Charge(), budget=tenant_budget)
            if admission.allowed:
                admitted += 1
    assert admitted == 8 * 20  # 160: per-tenant only, the defect


def test_the_host_budget_is_independent_of_the_tenant_string(tmp_path):
    """One tenant exhausting the host cap refuses everyone, not just that tenant."""
    store = _store(tmp_path)
    tenant_budget = CumulativeBudget(max_runs=1000)
    host_budget = CumulativeBudget(max_runs=3)
    for _ in range(3):
        assert store.admit(
            "a", reserve=Charge(), budget=tenant_budget, host_budget=host_budget
        ).allowed
    # A DIFFERENT tenant id is still refused: the host cap is shared.
    refused = store.admit(
        "b", reserve=Charge(), budget=tenant_budget, host_budget=host_budget
    )
    assert not refused.allowed
    assert refused.reason.startswith("host budget exhausted")


def test_the_tenant_budget_still_applies_beside_the_host_budget(tmp_path):
    store = _store(tmp_path)
    tenant_budget = CumulativeBudget(max_runs=2)
    host_budget = CumulativeBudget(max_runs=1000)
    for _ in range(2):
        assert store.admit(
            "a", reserve=Charge(), budget=tenant_budget, host_budget=host_budget
        ).allowed
    refused = store.admit(
        "a", reserve=Charge(), budget=tenant_budget, host_budget=host_budget
    )
    assert not refused.allowed
    assert refused.reason.startswith("budget exhausted")


def test_an_inconsistent_tenant_edit_is_refused(tmp_path):
    """v1.2 honest scope, pinned: the totals chain proves the book is
    internally consistent, so editing a booked charge without recomputing that
    line's `totals` is caught at the next read. This is a self-consistency check,
    not a keyed proof — a writer who recomputes the totals passes (file-mode is
    the real boundary). The test locks the catchable case so the claim cannot be
    quietly re-strengthened.
    """
    store = _store(tmp_path)
    for _ in range(2):
        adm = store.admit(
            "a", reserve=Charge(fuel=1), budget=CumulativeBudget(max_runs=10)
        )
        store.settle("a", adm.admit_id, charge=Charge(fuel=1))
    path = tmp_path / "host.jsonl"
    lines = [
        json.loads(raw)
        for raw in path.read_text(encoding="utf-8").splitlines()
        if raw.strip()
    ]
    for line in lines:  # inflate one booked settle charge without fixing its totals
        if line.get("kind") == "settle":
            line["charge"]["fuel"] = int(line["charge"].get("fuel", 0)) + 5
            break
    path.write_text(
        "".join(json.dumps(rec, sort_keys=True) + "\n" for rec in lines),
        encoding="utf-8",
    )
    with pytest.raises(ValueError):
        store.admit("a", reserve=Charge(fuel=1), budget=CumulativeBudget(max_runs=10))


# --- v1.2: atomic global admission under REAL cross-process concurrency ---

_CHILD = """
import os, sys, time
from ephemora_cell.tenant import Charge, CumulativeBudget, TenantStore
book, cap, attempts, tenant, start = (
    sys.argv[1], int(sys.argv[2]), int(sys.argv[3]), sys.argv[4], sys.argv[5]
)
while not os.path.exists(start):        # release all workers at once
    time.sleep(0.002)
store = TenantStore(book)
hb = CumulativeBudget(max_runs=cap)
n = 0
for _ in range(attempts):
    try:
        if store.admit(tenant, reserve=Charge(), host_budget=hb).allowed:
            n += 1
    except OSError:
        pass
print(n)
"""


def test_parallel_processes_never_overcommit_the_host_budget(tmp_path):
    """Six separate OS processes, released together, hammer one shared book.

    The sequential test above shows the cap holds for one caller. This is the
    v1.2 concurrency claim: the exclusive flock in decide_and_append must make
    'read the whole book → decide → append' atomic ACROSS processes, so the sum of
    admissions never exceeds the cap however the processes interleave.
    """
    cap = 25
    procs = 6
    attempts = 10  # 60 concurrent attempts against a cap of 25
    book = tmp_path / "host.jsonl"
    start = tmp_path / "go"
    children = [
        subprocess.Popen(
            [
                sys.executable,
                "-c",
                _CHILD,
                str(book),
                str(cap),
                str(attempts),
                f"t{i}",
                str(start),
            ],
            cwd=str(REPO),
            stdout=subprocess.PIPE,
            text=True,
        )
        for i in range(procs)
    ]
    time.sleep(0.6)  # let every worker reach the barrier
    start.touch()
    counts = [int((c.stdout.readline() or "0").strip() or "0") for c in children]
    for c in children:
        c.wait(timeout=60)
    total = sum(counts)
    assert total == cap, (
        f"parallel admission over/under-committed: {total} admitted, cap {cap}, "
        f"per-proc {counts}"
    )


def test_a_store_without_flags_adopts_the_recorded_host_cap(tmp_path):
    """The declared cap lives in the book; a later flagless process enforces it."""
    book = tmp_path / "host.jsonl"
    capping = TenantStore(book)
    capping.bind_host_budget(CumulativeBudget(max_runs=2))
    flagless = TenantStore(book)
    results = [flagless.admit("t", reserve=Charge()) for _ in range(3)]
    assert [result.allowed for result in results] == [True, True, False]
    assert results[2].reason.startswith("host budget exhausted")
    with pytest.raises(ValueError, match="exceeds the cap"):
        flagless.bind_host_budget(CumulativeBudget(max_runs=3))


def test_a_renamed_tenant_label_is_refused(tmp_path):
    """T3/F5: an edited tenant field must not drop usage out of the host sum."""
    book = tmp_path / "host.jsonl"
    store = TenantStore(book)
    for _ in range(2):
        admission = store.admit("t", reserve=Charge(fuel=1))
        store.settle("t", admission.admit_id, charge=Charge(fuel=1))
    lines = [json.loads(raw) for raw in book.read_text(encoding="utf-8").splitlines()]
    for line in reversed(lines):
        if line.get("kind") == "settle":
            line["tenant"] = "@bad"
            break
    book.write_text(
        "".join(json.dumps(record, sort_keys=True) + "\n" for record in lines),
        encoding="utf-8",
    )
    with pytest.raises(ValueError):
        store.admit(
            "t2",
            reserve=Charge(fuel=1),
            host_budget=CumulativeBudget(max_runs=10),
        )


def test_the_cli_refuses_a_zero_cap_and_creates_no_book(tmp_path):
    book = tmp_path / "book.jsonl"
    fixture = REPO / "tests" / "fixtures" / "wat_run.wasm"
    proc = subprocess.run(
        [
            sys.executable,
            "-m",
            "ephemora_cell.cli",
            "run",
            str(fixture),
            "--abi",
            "preview1",
            "--tenant",
            "t",
            "--tenant-book",
            str(book),
            "--host-max-runs",
            "0",
        ],
        capture_output=True,
        text=True,
        timeout=120,
        cwd=str(REPO),
    )
    assert proc.returncode == 2, proc.stderr
    assert "positive" in proc.stderr
    assert not book.exists()
