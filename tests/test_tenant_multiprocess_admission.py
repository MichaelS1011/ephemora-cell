# SPDX-License-Identifier: BUSL-1.1
# Copyright 2026 Michael Soppa

"""Host-wide admission control across independent OS processes (v1.2).

The cap lives in :class:`ephemora_cell.tenant.TenantStore`, whose read-decide-write
runs under one exclusive ``flock``. That is an *assertion* in the module; this
file turns it into a measurement: eight genuinely separate processes race for the
same budget in one book, and the total number of admissions must equal the cap —
not eight times it.
"""

from __future__ import annotations

import os
import subprocess
import sys
import time
from pathlib import Path

sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))

from ephemora_cell.tenant import Charge, CumulativeBudget, TenantStore

REPO_ROOT = Path(__file__).resolve().parent.parent

#: Child program: hammer one shared book with a fixed budget, print how many
#: admissions it won. Run with the interpreter that runs the tests.
_CHILD = """
import sys
from ephemora_cell.tenant import Charge, CumulativeBudget, TenantStore

path, cap, attempts = sys.argv[1], int(sys.argv[2]), int(sys.argv[3])
store = TenantStore(path)
budget = CumulativeBudget(max_runs=cap)
allowed = 0
for _ in range(attempts):
    admission = store.admit("host", reserve=Charge(fuel=1), budget=budget)
    if admission.allowed:
        allowed += 1
print(allowed)
"""


def _run_children(book: str, cap: int, attempts: int, workers: int):
    env = dict(os.environ)
    env["PYTHONPATH"] = str(REPO_ROOT) + os.pathsep + env.get("PYTHONPATH", "")
    procs = [
        subprocess.Popen(
            [sys.executable, "-c", _CHILD, book, str(cap), str(attempts)],
            cwd=str(REPO_ROOT),
            env=env,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True,
        )
        for _ in range(workers)
    ]
    results = []
    for proc in procs:
        out, err = proc.communicate(timeout=120)
        results.append((proc.returncode, out.strip(), err.strip()))
    return results


def test_eight_processes_cannot_multiply_the_hostwide_budget(tmp_path):
    """160 attempts from 8 processes, a cap of 25 -> exactly 25 admissions."""
    cap, attempts, workers = 25, 20, 8
    book = str(tmp_path / "host-book.jsonl")
    results = _run_children(book, cap, attempts, workers)

    assert all(code == 0 for code, _, _ in results), results
    allowed = [int(out) for _, out, _ in results]
    assert sum(allowed) == cap, (allowed, results)
    assert sum(allowed) != cap * workers  # the failure this test exists for

    # The book itself agrees: exactly `cap` admit lines, the rest refused.
    store = TenantStore(book)
    kinds = [entry.get("kind") for entry in store.entries()]
    assert kinds.count("admit") == cap, kinds
    assert kinds.count("refuse") == workers * attempts - cap, kinds


def test_an_expired_lease_frees_its_slot_for_the_next_run(tmp_path):
    """A worker killed holding an admission must not block the host forever.

    The lease is bounded by ``ttl_seconds``; once it lapses its reservation
    stops counting, so a fresh admit with a cap of 1 is allowed again. This is
    the recovery primitive behind the SIGKILL case (v1.2).
    """
    store = TenantStore(str(tmp_path / "host-book.jsonl"))
    budget = CumulativeBudget(max_runs=1)

    first = store.admit("host", reserve=Charge(fuel=1), budget=budget, ttl_seconds=0.05)
    assert first.allowed
    # While the lease is live the slot is taken, even though nothing settled.
    blocked = store.admit("host", reserve=Charge(fuel=1), budget=budget)
    assert not blocked.allowed and blocked.limit == "runs"

    time.sleep(0.25)
    after_expiry = store.admit("host", reserve=Charge(fuel=1), budget=budget)
    assert after_expiry.allowed, "an expired lease still blocked the host"
