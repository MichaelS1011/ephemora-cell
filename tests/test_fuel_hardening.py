"""Fuel-determinism hardening (GHSA-m63x-6p34-q65x, wasmtime 47.0.x).

`call_ref` (function-references) and `try_table` (exceptions) can discard
callee fuel, so a guest could run exponentially longer than its budget.
The Cell engine enforces these proposals off at every Config construction
site — a guest module using either opcode must fail to compile
(fail-closed), plain modules must keep running, and the execution record
must attest the enforced posture.
"""

from __future__ import annotations

import os
import sys

import wasmtime

sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))

from ephemora_cell import ExecutionReport, ExecutionStatus, WASIConfig, run_wasm

# Recursive work via call_ref — the exact opcode the advisory identifies.
CALL_REF_WAT = r"""
(module
  (type $t (func (param i32) (result i32)))
  (func $work (type $t)
    (local $i i32)
    (loop $l
      (local.set $i (i32.add (local.get $i) (i32.const 1)))
      (br_if $l (i32.lt_u (local.get $i) (local.get 0)))
    )
    (local.get $i)
  )
  (table 1 funcref)
  (elem (i32.const 0) $work)
  (func (export "_start")
    (loop $rounds
      (drop (call_ref $t (i32.const 300) (ref.func $work)))
      (br_if $rounds (i32.const 1))
    )
  )
)
"""

# Exception throw/catch across a call — the second advisory path.
TRY_TABLE_WAT = r"""
(module
  (type $t (func (param i32) (result i32)))
  (func $work (type $t)
    (local $i i32)
    (loop $l
      (local.set $i (i32.add (local.get $i) (i32.const 1)))
      (br_if $l (i32.lt_u (local.get $i) (local.get 0)))
    )
    (local.get $i)
  )
  (tag $e)
  (table 1 funcref)
  (elem (i32.const 0) $work)
  (func (export "_start")
    (loop $rounds
      (block $h
        (try_table (catch_all $h)
          (drop (call_ref $t (i32.const 300) (ref.func $work)))
          (throw $e)
        )
      )
      (br_if $rounds (i32.const 1))
    )
  )
)
"""

TRIVIAL_WAT = '(module (func (export "_start")))'


class TestEnforcedOffProposals:
    def test_call_ref_module_rejected(self, tmp_path):
        wasm = tmp_path / "call_ref.wasm"
        wasm.write_bytes(wasmtime.wat2wasm(CALL_REF_WAT))
        result = run_wasm(str(wasm), max_fuel=1_000_000, timeout_seconds=5)
        assert result.status == ExecutionStatus.ERROR, result.status
        assert "failed to compile" in (result.stderr or "")

    def test_try_table_module_rejected(self, tmp_path):
        wasm = tmp_path / "try_table.wasm"
        wasm.write_bytes(wasmtime.wat2wasm(TRY_TABLE_WAT))
        result = run_wasm(str(wasm), max_fuel=1_000_000, timeout_seconds=5)
        assert result.status == ExecutionStatus.ERROR, result.status
        # parse-stage rejection names the disabled proposal directly
        assert "failed to parse" in (result.stderr or "")
        assert "exceptions proposal not enabled" in (result.stderr or "")

    def test_plain_module_still_runs(self, tmp_path):
        """Positive control: the hardening must not reject ordinary guests."""
        wasm = tmp_path / "trivial.wasm"
        wasm.write_bytes(wasmtime.wat2wasm(TRIVIAL_WAT))
        result = run_wasm(str(wasm), max_fuel=1_000_000, timeout_seconds=5)
        assert result.status == ExecutionStatus.SUCCESS, result.status

    def test_baseline_attests_enforced_off(self):
        """The execution record cannot claim features the engine rejects."""
        report = ExecutionReport(
            status="success", exit_code=0, elapsed_ms=0.1
        ).apply_config(WASIConfig(max_fuel=1_000_000))
        baseline = report.security_baseline
        assert baseline["function_references_enabled"] is False
        assert baseline["exceptions_enabled"] is False
        assert baseline["gc_enabled"] is False
        assert baseline["tail_calls_enabled"] is False
