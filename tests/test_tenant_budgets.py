# SPDX-License-Identifier: BUSL-1.1
# Copyright 2026 Michael Soppa
"""Tenant accounting and admission (ADR-012).

The properties under test are the ones the release claims: reservations are
never billed, refusal happens before the run, derived totals cannot be edited
into agreement, and nothing happens at all when no tenant is attached.
"""

from __future__ import annotations

import inspect
import json
import os
import sys
import threading
from datetime import datetime, timedelta, timezone

sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))

import pytest
import wasmtime

from ephemora_cell import (
    ExecutionResult,
    ExecutionStatus,
    WASIConfig,
    WASISandbox,
    process_executor,
)
from ephemora_cell._sandbox_common import _MAX_OUTPUT_BYTES
from ephemora_cell.tenant import (
    Charge,
    CumulativeBudget,
    TenantId,
    TenantStore,
    TenantUsage,
)


def _store(tmp_path):
    return TenantStore(tmp_path / "tenant.jsonl")


class TestTenantId:
    @pytest.mark.parametrize(
        "value", ["acme", "acme.corp", "team_a-2", "x" * 128, "tenant:eu:1"]
    )
    def test_accepts_operator_labels(self, value):
        assert TenantId(value) == value

    @pytest.mark.parametrize(
        "value", ["", " pad", "pad ", ".hidden", "has space", "has/slash", "ünicode"]
    )
    def test_rejects_unusable_labels(self, value):
        with pytest.raises(ValueError):
            TenantId(value)

    def test_rejects_overlong_and_non_string(self):
        with pytest.raises(ValueError):
            TenantId("x" * 129)
        with pytest.raises(ValueError):
            TenantId(42)  # type: ignore[arg-type]


class TestChargeAndBudget:
    def test_rejects_negative_huge_and_float(self):
        for bad in (
            {"fuel": -1},
            {"wall_ms": 2**53},
            {"output_bytes": 1.5},
            {"fuel": True},
        ):
            with pytest.raises(ValueError):
                Charge(**bad)

    def test_plus_and_the_jcs_bound(self):
        assert Charge(fuel=5, output_bytes=2, wall_ms=3).plus(
            Charge(fuel=1, output_bytes=1, wall_ms=1)
        ) == Charge(fuel=6, output_bytes=3, wall_ms=4)
        # crossing the RFC 8785 ceiling is refused, not silently rounded
        with pytest.raises(ValueError):
            Charge(fuel=1).plus(Charge(fuel=2**53))

    def test_budget_validates_and_rejects_unknown_window(self):
        with pytest.raises(ValueError):
            CumulativeBudget(max_total_fuel=0)
        with pytest.raises(ValueError):
            CumulativeBudget(window="day")
        budget = CumulativeBudget(max_total_fuel=1000)
        assert budget.violation(1, Charge(fuel=1001)) == "fuel"
        assert budget.violation(1, Charge(fuel=1000)) is None

    def test_budget_ref_is_stable_and_dimension_sensitive(self):
        a = CumulativeBudget(max_total_fuel=1000).ref()
        b = CumulativeBudget(max_total_fuel=1000).ref()
        c = CumulativeBudget(max_total_wall_ms=1000).ref()
        assert a == b and a != c and len(a) == 16


class TestAdmissionAndSettlement:
    def test_admit_reserves_and_settle_books_actuals(self, tmp_path):
        store = _store(tmp_path)
        budget = CumulativeBudget(max_total_fuel=10_000)
        admission = store.admit("acme", reserve=Charge(fuel=4000), budget=budget)
        assert admission.allowed and admission.admit_id
        usage = store.usage("acme")
        assert usage.runs == 0 and usage.charged.fuel == 0
        assert usage.reserved.fuel == 4000 and usage.inflight == 1
        assert admission.projected is not None
        assert admission.projected.charged.fuel == 4000  # 0 settled + 4000 reserved

        store.settle(
            "acme",
            admission.admit_id,
            charge=Charge(fuel=900, output_bytes=12, wall_ms=5),
        )
        after = store.usage("acme")
        assert (after.runs, after.charged.fuel, after.inflight) == (1, 900, 0)
        assert after.reserved == Charge()

    def test_reservation_is_never_billed(self, tmp_path):
        store = _store(tmp_path)
        budget = CumulativeBudget(max_total_fuel=1000)
        for _ in range(3):
            store.admit("acme", reserve=Charge(fuel=1000), budget=budget)
        usage = store.usage("acme")
        assert usage.runs == 0 and usage.charged == Charge()
        assert usage.refused == 2 and usage.inflight == 1

    def test_admission_refuses_before_the_run_starts(self, tmp_path):
        store = _store(tmp_path)
        budget = CumulativeBudget(max_total_fuel=1000)
        first = store.admit("acme", reserve=Charge(fuel=0), budget=budget)
        store.settle("acme", first.admit_id, charge=Charge(fuel=950))
        second = store.admit("acme", reserve=Charge(fuel=100), budget=budget)
        assert not second.allowed
        assert second.reason == "budget exhausted: fuel"
        assert store.usage("acme").refused == 1
        # a refusal is recorded, but it books nothing
        lines = [entry["kind"] for entry in store.entries("acme")]
        assert lines == ["admit", "settle", "refuse"]

    def test_run_cap_counts_reservations_not_only_finished_runs(self, tmp_path):
        store = _store(tmp_path)
        budget = CumulativeBudget(max_runs=2)
        assert store.admit("acme", reserve=Charge(), budget=budget).allowed
        assert store.admit("acme", reserve=Charge(), budget=budget).allowed
        third = store.admit("acme", reserve=Charge(), budget=budget)
        assert not third.allowed and third.reason == "budget exhausted: runs"

    def test_accounting_without_budget_never_refuses(self, tmp_path):
        store = _store(tmp_path)
        for _ in range(5):
            admission = store.admit("acme", reserve=Charge(fuel=10**9))
            assert admission.allowed
            store.settle("acme", admission.admit_id, charge=Charge(fuel=1))
        assert store.usage("acme").charged.fuel == 5

    def test_expired_reservation_stops_blocking(self, tmp_path):
        store = _store(tmp_path)
        budget = CumulativeBudget(max_total_fuel=1000)
        stuck = store.admit(
            "acme", reserve=Charge(fuel=1000), budget=budget, ttl_seconds=0.05
        )
        assert stuck.allowed
        blocked = store.admit("acme", reserve=Charge(fuel=1), budget=budget)
        assert not blocked.allowed
        from time import sleep

        sleep(0.1)
        expired_view = store.usage("acme")
        assert expired_view.inflight == 0 and expired_view.reserved == Charge()
        assert store.admit("acme", reserve=Charge(fuel=1), budget=budget).allowed
        # the abandoned reservation is explicitly retired in the file
        store.expire("acme", stuck.admit_id)
        assert store.usage("acme").runs == 0

    def test_unknown_or_foreign_admission_is_refused(self, tmp_path):
        store = _store(tmp_path)
        with pytest.raises(ValueError):
            store.settle("acme", "deadbeef", charge=Charge(fuel=1))
        admission = store.admit("acme", reserve=Charge(fuel=1))
        with pytest.raises(ValueError):
            store.settle("other", admission.admit_id or "", charge=Charge(fuel=1))

    def test_violation_and_unknown_flags_are_counted(self, tmp_path):
        store = _store(tmp_path)
        admission = store.admit("acme", reserve=Charge(fuel=10))
        store.settle(
            "acme",
            admission.admit_id,
            charge=Charge(wall_ms=7),
            violation=True,
            unknown=True,
        )
        usage = store.usage("acme")
        assert (usage.violations, usage.unknown_charged_runs) == (1, 1)

    def test_parallel_admissions_cannot_oversell_a_run_cap(self, tmp_path):
        store = _store(tmp_path)
        budget = CumulativeBudget(max_runs=7)
        admitted: list[bool] = []
        lock = threading.Lock()

        def worker() -> None:
            result = store.admit("acme", reserve=Charge(), budget=budget)
            with lock:
                admitted.append(result.allowed)

        threads = [threading.Thread(target=worker) for _ in range(20)]
        for thread in threads:
            thread.start()
        for thread in threads:
            thread.join()
        assert sum(admitted) == 7
        assert store.usage("acme").inflight == 7


class TestEvidenceProperties:
    def test_two_store_objects_share_the_state(self, tmp_path):
        path = tmp_path / "tenant.jsonl"
        first, second = TenantStore(path), TenantStore(path)
        admission = first.admit("acme", reserve=Charge(fuel=5))
        assert second.usage("acme").reserved.fuel == 5
        second.settle("acme", admission.admit_id, charge=Charge(fuel=3))
        assert first.usage("acme").charged.fuel == 3

    def test_edited_totals_do_not_silently_pass(self, tmp_path):
        store = _store(tmp_path)
        admission = store.admit("acme", reserve=Charge(fuel=100))
        store.settle("acme", admission.admit_id, charge=Charge(fuel=100))
        lines = [json.dumps(entry, sort_keys=True) for entry in store.entries("acme")]
        # rewrite the last line's booked fuel without touching its totals block
        forged = json.loads(lines[-1])
        forged["charge"]["fuel"] = 1
        (tmp_path / "tenant.jsonl").write_text(
            lines[0] + "\n" + json.dumps(forged, sort_keys=True) + "\n",
            encoding="utf-8",
        )
        with pytest.raises(ValueError, match="do not match"):
            store.usage("acme")

    def test_reordered_lines_are_detected(self, tmp_path):
        store = _store(tmp_path)
        admission = store.admit("acme", reserve=Charge(fuel=100))
        store.settle("acme", admission.admit_id, charge=Charge(fuel=100))
        lines = [json.dumps(entry, sort_keys=True) for entry in store.entries("acme")]
        (tmp_path / "tenant.jsonl").write_text(
            lines[1] + "\n" + lines[0] + "\n", encoding="utf-8"
        )
        with pytest.raises(ValueError):
            store.usage("acme")

    def test_malformed_line_raises_instead_of_being_skipped(self, tmp_path):
        store = _store(tmp_path)
        store.admit("acme", reserve=Charge(fuel=1))
        with (tmp_path / "tenant.jsonl").open("a") as handle:
            handle.write("nonsense\n")
        with pytest.raises(ValueError, match="not JSON"):
            store.entries("acme")

    def test_unknown_line_kind_is_refused(self, tmp_path):
        store = _store(tmp_path)
        store.admit("acme", reserve=Charge(fuel=1))
        with (tmp_path / "tenant.jsonl").open("a") as handle:
            handle.write(
                json.dumps(
                    {
                        "tenant_entry_version": "v1",
                        "kind": "grants",
                        "tenant": "acme",
                        "totals": {
                            "runs": 0,
                            "fuel": 0,
                            "output_bytes": 0,
                            "wall_ms": 0,
                            "violations": 0,
                            "refused": 0,
                        },
                    },
                    sort_keys=True,
                )
                + "\n"
            )
        with pytest.raises(ValueError, match="unknown tenant line kind"):
            store.usage("acme")

    def test_reading_never_creates_the_file(self, tmp_path):
        path = tmp_path / "tenant.jsonl"
        store = TenantStore(path)
        assert store.usage("acme").runs == 0
        assert not path.exists()

    def test_tenants_are_isolated_in_the_book(self, tmp_path):
        store = _store(tmp_path)
        one = store.admit("acme", reserve=Charge(fuel=10))
        two = store.admit("globex", reserve=Charge(fuel=999))
        store.settle("acme", one.admit_id, charge=Charge(fuel=10))
        store.settle("globex", two.admit_id, charge=Charge(fuel=999))
        assert store.usage("acme").charged == Charge(fuel=10)
        assert store.usage("globex").charged == Charge(fuel=999)
        assert len(store.entries()) == 4 and len(store.entries("acme")) == 2


class TestUsageProjections:
    def test_projected_adds_reservations(self):
        usage = TenantUsage(
            tenant="acme",
            runs=2,
            charged=Charge(fuel=100, wall_ms=20),
            reserved=Charge(fuel=50, wall_ms=5),
            inflight=1,
        )
        projected = usage.projected()
        assert projected.runs == 3
        assert projected.charged == Charge(fuel=150, wall_ms=25)

    def test_now_can_be_supplied_for_expiry(self, tmp_path):
        store = _store(tmp_path)
        store.admit(
            "acme",
            reserve=Charge(fuel=10),
            ttl_seconds=60,
        )
        past = datetime.now(timezone.utc)
        future = past + timedelta(hours=1)
        assert store.usage("acme", now=future).reserved.fuel == 0
        assert store.usage("acme", now=past).reserved.fuel == 10


TRIVIAL_WAT = b"""
(module
  (import "wasi_snapshot_preview1" "proc_exit" (func $exit (param i32)))
  (memory (export "memory") 1)
  (func (export "_start")
    i32.const 0
    call $exit
  )
)
"""


def _module(tmp_path):
    path = tmp_path / "module.wasm"
    path.write_bytes(wasmtime.wat2wasm(TRIVIAL_WAT))
    return path


def _bookkeeper(tmp_path, result):
    """Replace ``_execute`` with a recorder, so a test sees the guts once.

    The whole point of putting admission in :meth:`WASISandbox.run` is that
    every execution path runs underneath it. Recording the single call into
    ``_execute`` proves that without depending on wasmtime for the three
    dispatch modes.
    """
    calls: list[tuple[str, dict]] = []

    def fake(self, wasm_path, **kwargs):
        calls.append((wasm_path, kwargs))
        return result

    return calls, fake


class TestRunEnforcement:
    def test_no_tenant_means_no_book_at_all(self, tmp_path):
        sandbox = WASISandbox(WASIConfig(max_fuel=200_000))
        store = TenantStore(tmp_path / "tenant.jsonl")
        try:
            result = sandbox.run(str(_module(tmp_path)))
        finally:
            sandbox.cleanup()
        assert result.status is ExecutionStatus.SUCCESS
        assert result.tenant is None and result.tenant_budget_ref is None
        assert not (tmp_path / "tenant.jsonl").exists()
        assert store.usage("acme").runs == 0

    def test_the_knobs_are_all_or_nothing(self, tmp_path):
        sandbox = WASISandbox()
        module = str(_module(tmp_path))
        with pytest.raises(ValueError, match="no tenant_store"):
            sandbox.run(module, tenant="acme")
        with pytest.raises(ValueError, match="without a tenant"):
            sandbox.run(module, tenant_store=_store(tmp_path))
        with pytest.raises(ValueError, match="without a tenant"):
            sandbox.run(module, tenant_budget=CumulativeBudget(max_runs=1))

    def test_reservation_is_the_configs_own_wall(self):
        tight = WASISandbox(
            WASIConfig(max_fuel=4000, io_budget_bytes=1000, timeout_seconds=5)
        )
        assert tight.reservation() == Charge(
            fuel=4000,
            output_bytes=2 * _MAX_OUTPUT_BYTES + 1000,
            wall_ms=5000,
        )
        # An unbounded knob contributes 0 rather than an invented number.
        open_ended = WASISandbox(WASIConfig(max_fuel=None, io_budget_bytes=None))
        assert open_ended.reservation() == Charge(
            fuel=0, output_bytes=2 * _MAX_OUTPUT_BYTES, wall_ms=30_000
        )

    def test_refusal_starts_nothing(self, tmp_path):
        store = _store(tmp_path)
        booked = store.admit("acme", reserve=Charge())
        store.settle("acme", booked.admit_id, charge=Charge())
        sandbox = WASISandbox()
        try:
            # A path that does not exist: reaching the guts would say so.
            result = sandbox.run(
                str(tmp_path / "absent.wasm"),
                tenant="acme",
                tenant_budget=CumulativeBudget(max_runs=1),
                tenant_store=store,
            )
        finally:
            sandbox.cleanup()
        assert result.status is ExecutionStatus.ERROR
        assert "tenant budget exhausted: runs" in result.stderr
        assert "not found" not in result.stderr
        assert result.tenant == "acme"
        assert [line["kind"] for line in store.entries("acme")] == [
            "admit",
            "settle",
            "refuse",
        ]

    @pytest.mark.parametrize(
        "flags",
        [
            {},
            {"use_subprocess": True},
            {"abi": "component"},
            {"abi": "auto", "use_engine_pool": False},
        ],
        ids=["preview1", "subprocess", "component", "auto-unpooled"],
    )
    def test_every_dispatch_is_billed_exactly_once(self, tmp_path, monkeypatch, flags):
        calls, fake = _bookkeeper(
            tmp_path,
            ExecutionResult(status=ExecutionStatus.SUCCESS, fuel_consumed=77),
        )
        monkeypatch.setattr(WASISandbox, "_execute", fake)
        store = _store(tmp_path)
        budget = CumulativeBudget(max_runs=2)
        sandbox = WASISandbox()
        result = sandbox.run(
            "module.wasm",
            tenant="acme",
            tenant_budget=budget,
            tenant_store=store,
            **flags,
        )
        assert len(calls) == 1, "run() must reach the guts through _execute only"
        assert calls[0][1]["abi"] == flags.get("abi", "preview1")
        assert calls[0][1]["use_subprocess"] == flags.get("use_subprocess", False)
        assert result.fuel_consumed == 77
        usage = store.usage("acme")
        assert (usage.runs, usage.charged.fuel, usage.inflight) == (1, 77, 0)
        # the receipt carries what the host decided, not what the guest saw
        assert result.tenant == "acme" and result.tenant_budget_ref == budget.ref()

    def test_a_run_that_never_returns_gives_its_reservation_back(
        self, tmp_path, monkeypatch
    ):
        def explode(self, wasm_path, **kwargs):
            raise RuntimeError("worker died")

        monkeypatch.setattr(WASISandbox, "_execute", explode)
        store = _store(tmp_path)
        with pytest.raises(RuntimeError, match="worker died"):
            WASISandbox().run("m.wasm", tenant="acme", tenant_store=store)
        assert store.usage("acme").inflight == 0
        assert store.usage("acme").runs == 0
        assert [line["kind"] for line in store.entries("acme")] == ["admit", "expire"]

    @pytest.mark.parametrize(
        "result,expect",
        [
            (
                ExecutionResult(status=ExecutionStatus.ERROR, fuel_consumed=None),
                {"unknown_charged_runs": 1, "violations": 0},
            ),
            (
                ExecutionResult(status=ExecutionStatus.TIMEOUT, fuel_consumed=5),
                {"unknown_charged_runs": 0, "violations": 1},
            ),
            (
                ExecutionResult(
                    status=ExecutionStatus.SUCCESS,
                    fuel_consumed=5,
                    io_budget_exceeded=True,
                ),
                {"unknown_charged_runs": 0, "violations": 1},
            ),
        ],
        ids=["no-fuel", "timeout", "io-budget"],
    )
    def test_flags_come_from_the_result(self, tmp_path, monkeypatch, result, expect):
        _, fake = _bookkeeper(tmp_path, result)
        monkeypatch.setattr(WASISandbox, "_execute", fake)
        store = _store(tmp_path)
        WASISandbox().run("m.wasm", tenant="acme", tenant_store=store)
        usage = store.usage("acme")
        assert usage.runs == 1
        assert usage.unknown_charged_runs == expect["unknown_charged_runs"]
        assert usage.violations == expect["violations"]

    def test_the_worker_never_sees_the_tenant(self, tmp_path, monkeypatch):
        seen: list[bytes] = []
        original = process_executor._spawn_worker

        def spy(cmd, payload, process_timeout):
            seen.append(payload)
            return original(cmd, payload, process_timeout)

        monkeypatch.setattr(process_executor, "_spawn_worker", spy)
        store = _store(tmp_path)
        sandbox = WASISandbox(WASIConfig(max_fuel=200_000))
        try:
            result = sandbox.run(
                str(_module(tmp_path)),
                use_subprocess=True,
                tenant="acme",
                tenant_store=store,
            )
        finally:
            sandbox.cleanup()
        assert result.status is ExecutionStatus.SUCCESS, result.stderr
        assert seen, "the isolation path never reached the worker"
        assert all(b"acme" not in payload for payload in seen)
        # admission and booking both happened in THIS process
        assert store.usage("acme").runs == 1
        assert (
            "tenant" not in inspect.signature(process_executor.run_isolated).parameters
        )

    def test_a_budget_smaller_than_one_runs_wall_refuses_everything(self, tmp_path):
        store = _store(tmp_path)
        sandbox = WASISandbox(WASIConfig(max_fuel=10_000))
        result = sandbox.run(
            "m.wasm",
            tenant="acme",
            tenant_budget=CumulativeBudget(max_total_fuel=1000),
            tenant_store=store,
        )
        # Not a bug to paper over: the reservation IS the per-run wall, so a
        # cap below one run's ceiling can never be met. Sizing budgets against
        # the walls is the operator's decision, and the refusal says so.
        assert "tenant budget exhausted: fuel" in result.stderr
        assert store.usage("acme").refused == 1
