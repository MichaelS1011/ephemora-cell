# SPDX-License-Identifier: BUSL-1.1
# Copyright 2026 Michael Soppa

"""Crash recovery of the shared account book (v1.2).

A worker that is SIGKILLed while holding an admission must not leave the host
permanently blocked, and must not corrupt the book for everyone else. Both halves
are measured with a real child process and a real SIGKILL.
"""

from __future__ import annotations

import json
import os
import signal
import subprocess
import sys
import time
from pathlib import Path

sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))

from ephemora_cell.tenant import Charge, CumulativeBudget, TenantStore

REPO = Path(__file__).resolve().parent.parent

#: Child: take one admission, then hold it and sleep until killed.
_HOLDER = """
import sys, time
from ephemora_cell.tenant import Charge, CumulativeBudget, TenantStore
book, ttl = sys.argv[1], float(sys.argv[2])
store = TenantStore(book)
adm = store.admit("crash", reserve=Charge(fuel=1),
                  budget=CumulativeBudget(max_runs=1), ttl_seconds=ttl)
print("ALLOWED" if adm.allowed else "DENIED", flush=True)
time.sleep(60)
"""


def _spawn_holder(book: str, ttl: float) -> subprocess.Popen:
    env = dict(os.environ)
    env["PYTHONPATH"] = str(REPO)
    proc = subprocess.Popen(
        [sys.executable, "-c", _HOLDER, book, str(ttl)],
        env=env,
        cwd=str(REPO),
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        text=True,
    )
    assert proc.stdout.readline().strip() == "ALLOWED"
    return proc


def test_a_sigkilled_holder_leaves_the_book_readable_and_frees_the_slot(tmp_path):
    book = str(tmp_path / "book.jsonl")
    holder = _spawn_holder(book, ttl=0.8)

    # While the holder is alive its reservation counts: a second run with the
    # same cap and tenant is refused.
    store = TenantStore(book)
    blocked = store.admit(
        "crash", reserve=Charge(fuel=1), budget=CumulativeBudget(max_runs=1)
    )
    assert not blocked.allowed

    # Kill it the way a crashed worker dies — no chance to clean up.
    holder.send_signal(signal.SIGKILL)
    holder.wait(timeout=30)
    assert holder.returncode == -signal.SIGKILL
    assert holder.poll() is not None  # no zombie worker left behind

    # The book is still a valid book: every line parses and the totals replay.
    # (Two lines, because the refused attempt above is logged too — a refusal is
    # an audit fact, not noise.)
    entries = store.entries()
    kinds = [e.get("kind") for e in entries]
    assert kinds.count("admit") == 1, kinds
    assert kinds.count("refuse") == 1, kinds
    assert json.dumps(entries)  # serialisable, not half-written

    # Before the TTL elapses the dead holder still holds the slot (honest: a
    # crash is not treated as a clean release) ...
    still_blocked = store.admit(
        "crash", reserve=Charge(fuel=1), budget=CumulativeBudget(max_runs=1)
    )
    assert not still_blocked.allowed

    # ... and after it, the slot is free again without anyone settling anything.
    time.sleep(1.0)
    recovered = store.admit(
        "crash", reserve=Charge(fuel=1), budget=CumulativeBudget(max_runs=1)
    )
    assert recovered.allowed, "a crashed holder blocked the account indefinitely"


# --- v1.2: the lease must outlive a legitimate run (no early reclaim) -----

from ephemora_cell.wasi_runtime import (  # noqa: E402  (after the functional import)
    DEFAULT_LEASE_TTL_SECONDS,
    LEASE_GRACE_SECONDS,
    _lease_ttl_seconds,
)


def test_the_default_timeout_keeps_the_historical_lease():
    """Nothing changes for the qualified default (timeout 30 s ⇒ 900 s lease)."""
    assert _lease_ttl_seconds(30) == DEFAULT_LEASE_TTL_SECONDS == 900.0


def test_the_lease_extends_past_a_long_configured_timeout():
    """A caller who sets a wall-clock above the default floor is not overcommitted.

    The old fixed 900 s lease would reclaim a still-running worker's slot here;
    the tie guarantees the lease exceeds the run plus grace.
    """
    timeout = 5000  # far above the 900 s default
    lease = _lease_ttl_seconds(timeout)
    assert lease == 2 * (timeout + 5) + LEASE_GRACE_SECONDS
    assert lease > timeout, "a lease shorter than the run allows early reclaim"


def test_the_lease_always_exceeds_the_run_plus_a_margin():
    """Invariant across the whole range: lease ≥ timeout + grace AND ≥ default."""
    for timeout in (0, 1, 30, 300, 600, 601, 1000, 86_400):
        lease = _lease_ttl_seconds(timeout)
        assert lease >= DEFAULT_LEASE_TTL_SECONDS
        assert lease >= 2 * (max(timeout + 5, 5)) + LEASE_GRACE_SECONDS
