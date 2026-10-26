# SPDX-License-Identifier: BUSL-1.1
# Copyright 2026 Michael Soppa

"""Unknown fuel is a ceiling, never a proven zero.

The accounting path is the product path (``WASISandbox.run`` + the real
``TenantStore``), with only the engine call replaced so a crash is
deterministic. Positive controls prove a measured zero stays zero; negative
controls prove a crash cannot free the fuel budget it may have consumed.
"""

from __future__ import annotations

import os
import signal
import subprocess
import sys
import threading
import time

import pytest

sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))

import json

from ephemora_cell import ExecutionResult, ExecutionStatus, WASIConfig, WASISandbox
from ephemora_cell.process_executor import run_isolated
from ephemora_cell.tenant import Charge, CumulativeBudget, TenantStore

REPO = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))


def _store(tmp_path) -> TenantStore:
    return TenantStore(tmp_path / "tenant.jsonl")


def _install(monkeypatch, result: ExecutionResult) -> None:
    monkeypatch.setattr(WASISandbox, "_execute", lambda self, *a, **k: result)


def _run(sandbox, store, budget=None):
    return sandbox.run(
        "m.wasm",
        tenant="acme",
        tenant_budget=budget,
        tenant_store=store,
        trust="trusted",
    )


def _settle(store) -> dict:
    return [e for e in store.entries("acme") if e["kind"] == "settle"][-1]


def test_unknown_worker_fuel_is_booked_at_the_per_run_ceiling(tmp_path, monkeypatch):
    result = ExecutionResult(
        status=ExecutionStatus.ERROR,
        fuel_consumed=None,
        execution_started=True,
        worker_started=True,
    )
    _install(monkeypatch, result)
    store = _store(tmp_path)
    sandbox = WASISandbox(WASIConfig(max_fuel=1000))
    _run(sandbox, store)

    settle = _settle(store)
    usage = store.usage("acme")
    assert settle["charge"]["fuel"] == 1000
    assert settle["unknown"] is True
    assert settle["unknown_fuel_charged"] == 1000
    assert usage.charged.fuel == 1000
    assert usage.unknown_fuel_charged == 1000


def test_a_measured_zero_is_not_inflated(tmp_path, monkeypatch):
    """The negative control for the negative control: a real 0 stays 0."""
    result = ExecutionResult(
        status=ExecutionStatus.SUCCESS,
        fuel_consumed=0,
        execution_started=True,
        guest_exit_observed=True,
    )
    _install(monkeypatch, result)
    store = _store(tmp_path)
    sandbox = WASISandbox(WASIConfig(max_fuel=1000))
    _run(sandbox, store)

    settle = _settle(store)
    assert settle["charge"]["fuel"] == 0
    assert "unknown" not in settle
    assert "unknown_fuel_charged" not in settle
    assert store.usage("acme").unknown_fuel_charged == 0


def test_a_run_that_never_started_is_a_measured_zero(tmp_path, monkeypatch):
    result = ExecutionResult(
        status=ExecutionStatus.ERROR,
        fuel_consumed=None,
        execution_started=False,
    )
    _install(monkeypatch, result)
    store = _store(tmp_path)
    sandbox = WASISandbox(WASIConfig(max_fuel=1000))
    _run(sandbox, store)

    settle = _settle(store)
    assert settle["charge"]["fuel"] == 0
    assert "unknown" not in settle
    assert store.usage("acme").unknown_fuel_charged == 0


def test_retry_with_two_measured_attempts_charges_the_sum(tmp_path, monkeypatch):
    result = ExecutionResult(
        status=ExecutionStatus.SUCCESS,
        fuel_consumed=400,
        execution_started=True,
        worker_attempts=2,
        first_attempt_crashed=True,
        first_attempt_fuel_consumed=300,
        first_attempt_execution_started=True,
        first_attempt_stdout_bytes=3,
        first_attempt_stderr_bytes=4,
    )
    _install(monkeypatch, result)
    store = _store(tmp_path)
    sandbox = WASISandbox(WASIConfig(max_fuel=1000))
    _run(sandbox, store)

    settle = _settle(store)
    assert settle["charge"]["fuel"] == 700
    assert "unknown" not in settle
    assert settle["charge"]["output_bytes"] >= 7


def test_unknown_first_attempt_plus_measured_retry_charges_both(tmp_path, monkeypatch):
    result = ExecutionResult(
        status=ExecutionStatus.SUCCESS,
        fuel_consumed=400,
        execution_started=True,
        worker_attempts=2,
        first_attempt_crashed=True,
        first_attempt_fuel_consumed=None,
        first_attempt_execution_started=True,
        first_attempt_stdout_bytes=None,
        first_attempt_stderr_bytes=None,
        first_attempt_output_unknown=True,
    )
    _install(monkeypatch, result)
    store = _store(tmp_path)
    sandbox = WASISandbox(WASIConfig(max_fuel=1000))
    _run(sandbox, store)

    settle = _settle(store)
    assert settle["charge"]["fuel"] == 1400
    assert settle["unknown"] is True
    assert settle["unknown_fuel_charged"] == 1000
    assert settle["unknown_output"] is True


def test_two_unknown_attempts_are_charged_two_ceilings(tmp_path, monkeypatch):
    result = ExecutionResult(
        status=ExecutionStatus.ERROR,
        fuel_consumed=None,
        execution_started=True,
        worker_attempts=2,
        first_attempt_crashed=True,
        first_attempt_fuel_consumed=None,
        first_attempt_execution_started=True,
        first_attempt_output_unknown=True,
    )
    _install(monkeypatch, result)
    store = _store(tmp_path)
    sandbox = WASISandbox(WASIConfig(max_fuel=1000))
    _run(sandbox, store)

    settle = _settle(store)
    assert settle["charge"]["fuel"] == 2000
    assert settle["unknown_fuel_charged"] == 2000


def test_timeout_without_a_fuel_report_is_a_breach_and_unknown(tmp_path, monkeypatch):
    result = ExecutionResult(
        status=ExecutionStatus.TIMEOUT,
        fuel_consumed=None,
        execution_started=True,
    )
    _install(monkeypatch, result)
    store = _store(tmp_path)
    sandbox = WASISandbox(WASIConfig(max_fuel=1000))
    _run(sandbox, store)

    settle = _settle(store)
    assert settle["charge"]["fuel"] == 1000
    assert settle["unknown"] is True
    assert settle["violation"] is True
    assert store.usage("acme").violations == 1


def test_the_ten_crash_probe_no_longer_gets_a_free_budget(tmp_path, monkeypatch):
    """The original probe: ten crashes under a 10_000 fuel cap.

    Before the fix all ten were admitted with charged.fuel = 0. The upper-bound
    charge plus the two-attempt reservation now stops the loop after nine.
    """
    result = ExecutionResult(
        status=ExecutionStatus.ERROR,
        fuel_consumed=None,
        execution_started=True,
    )
    _install(monkeypatch, result)
    store = _store(tmp_path)
    sandbox = WASISandbox(WASIConfig(max_fuel=1000))
    budget = CumulativeBudget(max_total_fuel=10_000, max_runs=20)
    allowed = refused = 0
    for _ in range(10):
        outcome = _run(sandbox, store, budget)
        if "budget exhausted" in outcome.stderr:
            refused += 1
        else:
            allowed += 1

    usage = store.usage("acme")
    assert (allowed, refused) == (9, 1)
    assert usage.runs == 9
    assert usage.charged.fuel == 9000
    assert usage.unknown_fuel_charged == 9000
    assert usage.unknown_charged_runs == 9
    assert usage.refused == 1
    assert usage.inflight == 0


def _report_module(tmp_path):
    import wasmtime

    path = tmp_path / "trivial.wasm"
    path.write_bytes(
        wasmtime.wat2wasm(
            '(module (import "wasi_snapshot_preview1" "proc_exit" '
            '(func $exit (param i32))) (memory (export "memory") 1) '
            '(func (export "_start") i32.const 0 call $exit))'
        )
    )
    return str(path)


def _crash_report(*, fuel: int, stdout: str = "guest-out", stderr: str = "guest-err"):
    return json.dumps(
        {
            "status": "error",
            "exit_code": 1,
            "stdout": stdout,
            "stderr": stderr,
            "elapsed_ms": 1.0,
            "fuel_consumed": fuel,
            "execution_started": True,
            "effective_preopens": [],
            "baseline_ms": 0.0,
        }
    ).encode()


def test_a_single_attempt_with_a_report_is_charged_once(tmp_path, monkeypatch):
    """The verifier's counterexample: rc=1 with a complete report must not
    become measured-first + conservative-final."""
    calls = {"n": 0}

    def fake_spawn(cmd, payload, process_timeout, env):
        calls["n"] += 1
        return 1, _crash_report(fuel=3), b"panic"

    monkeypatch.setattr("ephemora_cell.process_executor._spawn_worker", fake_spawn)
    report = run_isolated(
        _report_module(tmp_path),
        WASIConfig(max_fuel=1000, allow_dirs=(str(tmp_path),)),
    )
    assert calls["n"] == 1
    assert report["worker_attempts"] == 1
    assert report["fuel_consumed"] == 3
    assert report["execution_started"] is True

    result = WASISandbox._result_from_report(report)
    monkeypatch.setattr(WASISandbox, "_execute", lambda self, *a, **k: result)
    store = _store(tmp_path)
    _run(WASISandbox(WASIConfig(max_fuel=1000)), store)
    settle = _settle(store)
    assert settle["charge"]["fuel"] == 3
    assert "unknown" not in settle
    assert "unknown_fuel_charged" not in settle
    # The final result carries the guest output; the first-attempt fields are
    # not added a second time for a single attempt.
    assert "guest-out" in result.stdout
    assert "guest-err" in result.stderr


def test_first_unknown_plus_final_zero_is_not_charged_twice(tmp_path, monkeypatch):
    """Verifier: first no report, second report fuel=0 -> 1000, not 2000."""
    calls = {"n": 0}

    def fake_spawn(cmd, payload, process_timeout, env):
        calls["n"] += 1
        if calls["n"] == 1:
            return 1, b"", b"panic"
        return 1, _crash_report(fuel=0), b"panic"

    monkeypatch.setattr("ephemora_cell.process_executor._spawn_worker", fake_spawn)
    report = run_isolated(_report_module(tmp_path), WASIConfig(max_fuel=1000))
    assert calls["n"] == 2
    assert report["worker_attempts"] == 2
    assert report["fuel_consumed"] == 0
    assert report["first_attempt_fuel_consumed"] is None
    assert report["first_attempt_execution_started"] is True

    result = WASISandbox._result_from_report(report)
    monkeypatch.setattr(WASISandbox, "_execute", lambda self, *a, **k: result)
    store = _store(tmp_path)
    _run(WASISandbox(WASIConfig(max_fuel=1000)), store)
    settle = _settle(store)
    assert settle["charge"]["fuel"] == 1000
    assert settle["unknown"] is True
    assert settle["unknown_fuel_charged"] == 1000


def test_measured_first_plus_missing_last_uses_conservative_last(tmp_path, monkeypatch):
    """Verifier mixed case: first report fuel=3, last no report -> 1003."""
    calls = {"n": 0}

    def fake_spawn(cmd, payload, process_timeout, env):
        calls["n"] += 1
        if calls["n"] == 1:
            return 1, _crash_report(fuel=3), b"panic"
        return 1, b"", b"panic"

    monkeypatch.setattr("ephemora_cell.process_executor._spawn_worker", fake_spawn)
    report = run_isolated(_report_module(tmp_path), WASIConfig(max_fuel=1000))
    assert calls["n"] == 2
    assert report["worker_attempts"] == 2
    assert report["fuel_consumed"] is None
    assert report["first_attempt_fuel_consumed"] == 3

    result = WASISandbox._result_from_report(report)
    monkeypatch.setattr(WASISandbox, "_execute", lambda self, *a, **k: result)
    store = _store(tmp_path)
    _run(WASISandbox(WASIConfig(max_fuel=1000)), store)
    settle = _settle(store)
    assert settle["charge"]["fuel"] == 1003
    assert settle["unknown"] is True
    assert settle["unknown_fuel_charged"] == 1000


def test_expired_lease_keeps_output_and_wall_too(tmp_path):
    store = _store(tmp_path)
    budget = CumulativeBudget(max_total_output_bytes=1000, max_total_wall_ms=1000)
    first = store.admit(
        "acme",
        reserve=Charge(output_bytes=1000, wall_ms=1000),
        budget=budget,
        ttl_seconds=0.05,
    )
    assert first.allowed
    time.sleep(0.1)
    usage = store.usage("acme")
    assert usage.recovered.output_bytes == 1000
    assert usage.recovered.wall_ms == 1000
    blocked = store.admit(
        "acme", reserve=Charge(output_bytes=1, wall_ms=1), budget=budget
    )
    assert not blocked.allowed
    assert blocked.limit in ("output_bytes", "wall_ms")
    store.expire("acme", first.admit_id)
    assert store.usage("acme").recovered == Charge()
    assert store.admit(
        "acme", reserve=Charge(output_bytes=1, wall_ms=1), budget=budget
    ).allowed


def test_settle_refuses_an_upper_bound_above_the_reservation(tmp_path):
    store = _store(tmp_path)
    admission = store.admit("acme", reserve=Charge(fuel=100))
    with pytest.raises(ValueError, match="exceeds the admission's fuel reservation"):
        store.settle(
            "acme",
            admission.admit_id,
            charge=Charge(fuel=100),
            unknown=True,
            unknown_fuel_charged=101,
        )


def test_an_upper_bound_requires_the_unknown_flag(tmp_path):
    store = _store(tmp_path)
    admission = store.admit("acme", reserve=Charge(fuel=100))
    with pytest.raises(ValueError, match="requires unknown=True"):
        store.settle(
            "acme",
            admission.admit_id,
            charge=Charge(fuel=100),
            unknown_fuel_charged=100,
        )


def test_expired_lease_keeps_its_fuel_and_frees_only_the_slot(tmp_path):
    store = _store(tmp_path)
    budget = CumulativeBudget(max_total_fuel=10_000)
    first = store.admit(
        "acme", reserve=Charge(fuel=2000), budget=budget, ttl_seconds=0.05
    )
    assert first.allowed
    time.sleep(0.1)
    usage = store.usage("acme")
    assert usage.inflight == 0 and usage.reserved == Charge()
    assert usage.recovered.fuel == 2000
    assert usage.recovered_expired_runs == 1
    assert store.admit("acme", reserve=Charge(fuel=8000), budget=budget).allowed
    over = store.admit("acme", reserve=Charge(fuel=8001), budget=budget)
    assert not over.allowed and over.limit == "fuel"


def test_parallel_crashes_are_each_charged_once(tmp_path, monkeypatch):
    result = ExecutionResult(
        status=ExecutionStatus.ERROR,
        fuel_consumed=None,
        execution_started=True,
    )
    _install(monkeypatch, result)
    store = _store(tmp_path)
    sandbox = WASISandbox(WASIConfig(max_fuel=1000))
    budget = CumulativeBudget(max_total_fuel=10_000)
    barrier = threading.Barrier(4)
    outcomes: list[str] = []
    lock = threading.Lock()

    def worker() -> None:
        barrier.wait()
        outcome = _run(sandbox, store, budget)
        with lock:
            outcomes.append(outcome.stderr)

    threads = [threading.Thread(target=worker) for _ in range(4)]
    for thread in threads:
        thread.start()
    for thread in threads:
        thread.join()

    usage = store.usage("acme")
    assert usage.runs == 4
    assert usage.charged.fuel == 4000
    assert usage.unknown_fuel_charged == 4000
    assert usage.inflight == 0
    assert not [text for text in outcomes if "budget exhausted" in text]


_HOLDER = """
import sys, time
from ephemora_cell.tenant import Charge, CumulativeBudget, TenantStore
book = sys.argv[1]
store = TenantStore(book)
adm = store.admit("crash", reserve=Charge(fuel=2000),
                  budget=CumulativeBudget(max_total_fuel=10000),
                  ttl_seconds=0.3)
print("ALLOWED" if adm.allowed else "DENIED", flush=True)
time.sleep(60)
"""


def test_a_sigkilled_holder_still_books_its_fuel_after_the_lease_lapses(tmp_path):
    book = str(tmp_path / "book.jsonl")
    env = dict(os.environ)
    env["PYTHONPATH"] = REPO
    holder = subprocess.Popen(
        [sys.executable, "-c", _HOLDER, book],
        env=env,
        cwd=REPO,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        text=True,
    )
    try:
        assert holder.stdout is not None
        assert holder.stdout.readline().strip() == "ALLOWED"
    finally:
        holder.send_signal(signal.SIGKILL)
        holder.wait(timeout=30)
    assert holder.returncode == -signal.SIGKILL

    time.sleep(0.6)
    store = TenantStore(book)
    usage = store.usage("crash")
    assert usage.inflight == 0
    assert usage.recovered.fuel == 2000
    assert usage.recovered_expired_runs == 1
    budget = CumulativeBudget(max_total_fuel=10_000)
    assert store.admit("crash", reserve=Charge(fuel=8000), budget=budget).allowed
    assert not store.admit("crash", reserve=Charge(fuel=8001), budget=budget).allowed
