# SPDX-License-Identifier: BUSL-1.1
# Copyright 2026 Michael Soppa

"""D2 local qualification: one unit per dimension, conservative unknowns.

The public contract is still a Founder decision. These tests prove the local
implementation the Founder authorised: raw sandbox bytes (not the truncated
text) are the output unit; an unknown output/wall is booked at its enforced
ceiling instead of zero; a lapsed lease keeps the whole reservation; and the
audit counters are bound to the same settle line as the authoritative charge.
"""

from __future__ import annotations

import json
import os
import subprocess
import sys
import time

import pytest

sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))

from ephemora_cell import WASIConfig, WASISandbox
from ephemora_cell._sandbox_common import OUTPUT_FILE_HARD_LIMIT
from ephemora_cell.tenant import (
    Charge,
    CumulativeBudget,
    TenantStore,
)
from ephemora_cell.wasi_runtime import ExecutionStatus

PRINT_WAT = """
(module
  (import "wasi_snapshot_preview1" "fd_write"
    (func $write (param i32 i32 i32 i32) (result i32)))
  (import "wasi_snapshot_preview1" "proc_exit" (func $exit (param i32)))
  (memory (export "memory") 1)
  (data (i32.const 8) "0123456789abcdef")
  (data (i32.const 32) "\\08\\00\\00\\00\\10\\00\\00\\00")
  (func (export "_start")
    i32.const 1
    i32.const 32
    i32.const 1
    i32.const 40
    call $write
    drop
    i32.const 0
    call $exit))
"""


def _module(tmp_path) -> str:
    import wasmtime

    path = tmp_path / "print.wasm"
    path.write_bytes(wasmtime.wat2wasm(PRINT_WAT))
    return str(path)


def _store(tmp_path) -> TenantStore:
    return TenantStore(tmp_path / "tenant.jsonl")


def _settle_unknown_all(store, admission):
    return store.settle(
        "acme",
        admission.admit_id,
        charge=Charge(fuel=1000, output_bytes=1000, wall_ms=5000),
        unknown=True,
        unknown_fuel_charged=1000,
        unknown_output=True,
        unknown_output_charged=1000,
        unknown_wall=True,
        unknown_wall_charged_ms=5000,
    )


def test_settle_binds_unknown_counters_to_the_authoritative_totals(tmp_path):
    store = _store(tmp_path)
    admission = store.admit(
        "acme", reserve=Charge(fuel=1000, output_bytes=1000, wall_ms=5000)
    )
    line = _settle_unknown_all(store, admission)
    assert line["booking_version"] == 2
    assert line["totals"]["unknown_fuel_charged"] == 1000
    assert line["totals"]["unknown_output_charged"] == 1000
    assert line["totals"]["unknown_wall_charged_ms"] == 5000
    usage = store.usage("acme")
    assert usage.unknown_fuel_charged == 1000
    assert usage.unknown_output_charged == 1000
    assert usage.unknown_output_runs == 1
    assert usage.unknown_wall_charged_ms == 5000
    assert usage.unknown_wall_runs == 1


@pytest.mark.parametrize(
    ("field", "value"),
    [
        ("unknown_fuel_charged", 999),
        ("unknown_output_charged", 999),
        ("unknown_wall_charged_ms", 4999),
    ],
)
def test_editing_a_conservative_audit_field_without_totals_is_detected(
    tmp_path, field, value
):
    store = _store(tmp_path)
    admission = store.admit(
        "acme", reserve=Charge(fuel=1000, output_bytes=1000, wall_ms=5000)
    )
    _settle_unknown_all(store, admission)
    lines = store.path.read_text().splitlines()
    record = json.loads(lines[-1])
    record[field] = value
    lines[-1] = json.dumps(record, sort_keys=True, separators=(",", ":"))
    store.path.write_text("\n".join(lines) + "\n")
    with pytest.raises(ValueError, match="totals do not match"):
        store.usage("acme")


def test_a_v2_line_missing_a_bound_audit_total_is_rejected(tmp_path):
    store = _store(tmp_path)
    admission = store.admit(
        "acme", reserve=Charge(fuel=1000, output_bytes=1000, wall_ms=5000)
    )
    _settle_unknown_all(store, admission)
    lines = store.path.read_text().splitlines()
    record = json.loads(lines[-1])
    del record["totals"]["unknown_output_charged"]
    lines[-1] = json.dumps(record, sort_keys=True, separators=(",", ":"))
    store.path.write_text("\n".join(lines) + "\n")
    with pytest.raises(ValueError, match="lacks audit totals"):
        store.usage("acme")


def test_stripping_the_booking_version_from_a_settle_is_rejected(tmp_path):
    store = _store(tmp_path)
    admission = store.admit(
        "acme", reserve=Charge(fuel=1000, output_bytes=1000, wall_ms=5000)
    )
    _settle_unknown_all(store, admission)
    lines = store.path.read_text().splitlines()
    record = json.loads(lines[-1])
    record.pop("booking_version", None)
    for key in (
        "unknown_fuel_charged",
        "unknown_output_charged",
        "unknown_wall",
        "unknown_wall_charged_ms",
    ):
        record.pop(key, None)
    for key in (
        "unknown_fuel_charged",
        "unknown_output_charged",
        "unknown_output_runs",
        "unknown_wall_charged_ms",
        "unknown_wall_runs",
    ):
        record["totals"].pop(key, None)
    lines[-1] = json.dumps(record, sort_keys=True, separators=(",", ":"))
    store.path.write_text("\n".join(lines) + "\n")
    with pytest.raises(ValueError, match="without booking_version=2"):
        store.usage("acme")


def test_conservative_amounts_must_fit_reservation_and_charge(tmp_path):
    store = _store(tmp_path)
    admission = store.admit(
        "acme", reserve=Charge(fuel=100, output_bytes=100, wall_ms=100)
    )
    with pytest.raises(ValueError, match="exceeds the admission's fuel reservation"):
        store.settle(
            "acme",
            admission.admit_id,
            charge=Charge(fuel=100, output_bytes=100, wall_ms=100),
            unknown=True,
            unknown_fuel_charged=101,
        )
    with pytest.raises(ValueError, match="output_bytes reservation"):
        store.settle(
            "acme",
            admission.admit_id,
            charge=Charge(fuel=100, output_bytes=100, wall_ms=100),
            unknown=True,
            unknown_output=True,
            unknown_output_charged=101,
        )
    with pytest.raises(ValueError, match="inside the authoritative charge"):
        store.settle(
            "acme",
            admission.admit_id,
            charge=Charge(fuel=100, output_bytes=50, wall_ms=100),
            unknown=True,
            unknown_output=True,
            unknown_output_charged=60,
        )
    with pytest.raises(ValueError, match="wall_ms reservation"):
        store.settle(
            "acme",
            admission.admit_id,
            charge=Charge(fuel=100, output_bytes=100, wall_ms=101),
            unknown=True,
            unknown_wall=True,
            unknown_wall_charged_ms=102,
        )


def test_a_lapsed_lease_holds_fuel_output_and_wall_after_a_real_kill(tmp_path):
    store = _store(tmp_path)
    holder = subprocess.Popen([sys.executable, "-c", "import time; time.sleep(30)"])
    try:
        admission = store.admit(
            "acme",
            reserve=Charge(fuel=1000, output_bytes=1000, wall_ms=5000),
            ttl_seconds=0.05,
        )
        assert admission.allowed
        time.sleep(0.12)
        holder.kill()
        holder.wait(timeout=10)
        usage = store.usage("acme")
        assert usage.recovered == Charge(fuel=1000, output_bytes=1000, wall_ms=5000)
        assert usage.recovered_expired_runs == 1
        assert usage.projected().charged == usage.recovered
        blocked = store.admit(
            "acme",
            reserve=Charge(fuel=1, output_bytes=1, wall_ms=1),
            budget=CumulativeBudget(
                max_total_output_bytes=1000, max_total_wall_ms=5000
            ),
        )
        assert blocked.allowed is False
        assert blocked.limit in ("output_bytes", "wall_ms")
    finally:
        if holder.poll() is None:
            holder.kill()
            holder.wait(timeout=10)


def test_measured_output_is_the_raw_byte_charge_not_the_text(tmp_path):
    store = _store(tmp_path)
    sandbox = WASISandbox(
        WASIConfig(max_fuel=10_000_000, io_budget_bytes=64 * 1024, timeout_seconds=5)
    )
    try:
        result = sandbox.run(
            _module(tmp_path),
            tenant="acme",
            tenant_store=store,
            trust="untrusted",
        )
    finally:
        sandbox.cleanup()
    assert result.status is ExecutionStatus.SUCCESS
    assert isinstance(result.io_bytes_written, int)
    assert result.io_bytes_written > 0
    line = store.entries("acme")[-1]
    assert line["kind"] == "settle"
    assert line["charge"]["output_bytes"] == result.io_bytes_written
    assert line.get("unknown_output") is None
    assert line["totals"]["unknown_output_charged"] == 0


def test_unknown_output_is_charged_at_the_enforced_ceiling(monkeypatch, tmp_path):
    def crash(cmd, payload, process_timeout, env):
        return 1, b"", b"panic"

    monkeypatch.setattr("ephemora_cell.process_executor._spawn_worker", crash)
    store = _store(tmp_path)
    config = WASIConfig(
        max_fuel=1000,
        io_budget_bytes=4096,
        timeout_seconds=1,
        allow_dirs=(str(tmp_path),),
    )
    sandbox = WASISandbox(config)
    try:
        result = sandbox.run(
            _module(tmp_path),
            tenant="acme",
            tenant_store=store,
            trust="untrusted",
        )
    finally:
        sandbox.cleanup()
    assert result.status is ExecutionStatus.ERROR
    usage = store.usage("acme")
    ceiling = 4096 + 2 * OUTPUT_FILE_HARD_LIMIT
    assert usage.unknown_output_runs == 1
    assert usage.unknown_output_charged == ceiling
    assert usage.charged.output_bytes == ceiling
    assert usage.unknown_fuel_charged == 1000
    assert usage.charged.fuel == 1000


def test_a_lost_report_after_real_cleanup_is_unknown_output(monkeypatch, tmp_path):
    import ephemora_cell.process_executor as process_executor

    real_spawn = process_executor._spawn_worker

    def drop_report(cmd, payload, process_timeout, env):
        returncode, _raw_out, raw_err = real_spawn(cmd, payload, process_timeout, env)
        return returncode, b"", raw_err

    monkeypatch.setattr(process_executor, "_spawn_worker", drop_report)
    store = _store(tmp_path)
    sandbox = WASISandbox(
        WASIConfig(max_fuel=1_000_000, io_budget_bytes=4096, timeout_seconds=5)
    )
    try:
        result = sandbox.run(
            _module(tmp_path),
            tenant="acme",
            tenant_store=store,
            trust="untrusted",
        )
    finally:
        sandbox.cleanup()
    assert result.status is ExecutionStatus.ERROR
    assert result.worker_started is True
    assert result.output_bytes_unknown is True
    assert result.output_bytes_observed == 0
    usage = store.usage("acme")
    # Two attempts, no report: fuel and output are booked at their ceilings.
    assert usage.unknown_fuel_charged == 2 * 1_000_000
    assert usage.unknown_output_runs == 1
    assert usage.unknown_output_charged == 2 * (4096 + 2 * OUTPUT_FILE_HARD_LIMIT)
    assert usage.charged.output_bytes == usage.unknown_output_charged
    assert usage.charged.fuel == usage.unknown_fuel_charged


def test_accounted_untrusted_unbounded_budgets_are_refused(tmp_path):
    store = _store(tmp_path)
    module = _module(tmp_path)
    for config in (
        WASIConfig(max_fuel=None, io_budget_bytes=4096),
        WASIConfig(max_fuel=1000, io_budget_bytes=None),
    ):
        sandbox = WASISandbox(config)
        try:
            result = sandbox.run(
                module,
                tenant="acme",
                tenant_store=store,
                trust="untrusted",
            )
        finally:
            sandbox.cleanup()
        assert result.status is ExecutionStatus.ERROR
        assert "unbounded:" in result.stderr
        assert result.execution_started is False
    # No admission line was written for a refusal.
    assert store.entries("acme") == []


def test_explicitly_trusted_unbounded_run_is_not_refused_by_the_d2_guard(
    tmp_path,
):
    store = _store(tmp_path)
    sandbox = WASISandbox(WASIConfig(max_fuel=None, timeout_seconds=2))
    try:
        result = sandbox.run(
            _module(tmp_path),
            tenant="acme",
            tenant_store=store,
            trust="trusted",
        )
    finally:
        sandbox.cleanup()
    assert result.status is ExecutionStatus.SUCCESS
