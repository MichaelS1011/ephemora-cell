"""Explicit proposal policy — compile-probe matrix against the hardened engine.

Wasmtime 47 ships several proposals enabled by engine default (Wasm GC,
exceptions, function-references — the exact surface of the fuel-amplification
advisory GHSA-m63x-6p34-q65x). Cell's rule: proposals are enforced-off unless
the shipped WASI surface needs them. These probes compile minimal modules
against the production engine posture, so any upgrade that silently flips a
default fails here instead of in production.

Mirrors the knob block in ``wasi_runtime`` / ``engine_pool`` / ``wasi_02``
(the SpyConfig test in ``test_threads_baseline.py`` keeps those sites in
sync with this posture).
"""

from __future__ import annotations

import os
import sys

import pytest

sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))

import wasmtime


def _hardened_engine(**overrides: bool) -> wasmtime.Engine:
    config = wasmtime.Config()
    config.consume_fuel = True
    config.epoch_interruption = True
    config.wasm_threads = False
    config.wasm_multi_memory = False
    config.wasm_function_references = False
    config.wasm_exceptions = False
    config.wasm_gc = False
    config.wasm_tail_call = False
    config.wasm_stack_switching = False
    # Memory64's engine default flipped ON in the 47 line — Cell mirrors the
    # WASIConfig opt-in explicitly at every site (that this probe needs the
    # explicit False is exactly the silent-default drift the policy tests).
    config.wasm_memory64 = False
    for name, value in overrides.items():
        setattr(config, name, value)
    return wasmtime.Engine(config)


# (name, wat, why-rejected) — validated against the hardened engine.
REJECTED_PROBES = {
    "shared_memory_threads": (
        '(module (memory 1 shared) (func (export "_start")))',
        "threads proposal — shared memories (P1 #11)",
    ),
    "call_ref_function_references": (
        "(module (type $t (func)) (table 1 funcref)"
        " (elem (i32.const 0) $f)"
        " (func $f)"
        ' (func (export "_start") (call_ref $t (ref.func $f))))',
        "function-references — callee fuel can be discarded (GHSA-m63x-6p34-q65x)",
    ),
    "try_table_exceptions": (
        '(module (tag $e) (func (export "_start") (block $h (try_table (catch_all $h)))))',
        "exceptions — catch path can discard fuel (GHSA-m63x-6p34-q65x); "
        "vm2 CVE-2026-26956 escapes ride try_table/JSTag",
    ),
    "wasm_gc": (
        "(module (type $s (struct))"
        ' (func (export "_start") (drop (struct.new $s))))',
        "GC — not needed by any Cell workload",
    ),
    "tail_call": (
        "(module (func $f (return_call $f)))",
        "tail-calls — not needed by any Cell workload",
    ),
    "memory64_default_off": (
        '(module (memory i64 1) (func (export "_start")))',
        "memory64 is a per-config opt-in (WASIConfig.memory64)",
    ),
}

# Spec-core proposals the shipped WASI surface (wasip1 linking + wasip2
# components) builds on — must keep compiling.
ACCEPTED_PROBES = {
    "simd": '(module (func (export "_start") (result i32) (i32x4.extract_lane 0 (v128.const i32x4 1 2 3 4))))',
    "bulk_memory": '(module (memory 1) (func (export "_start") (memory.fill (i32.const 0) (i32.const 0) (i32.const 1))))',
    "multi_value": '(module (func (export "_start") (result i32 i32) (i32.const 1) (i32.const 2)))',
    "sign_extension": '(module (func (export "_start") (result i32) (i32.extend8_s (i32.const 1))))',
    "reference_types": '(module (table 1 funcref) (func (export "_start")))',
}


@pytest.mark.parametrize("name", sorted(REJECTED_PROBES))
def test_policy_rejects(name):
    wat, _reason = REJECTED_PROBES[name]
    wasm = wasmtime.wat2wasm(wat)
    with pytest.raises(wasmtime.WasmtimeError, match=r"."):
        wasmtime.Module(_hardened_engine(), wasm)


@pytest.mark.parametrize("name", sorted(ACCEPTED_PROBES))
def test_policy_accepts(name):
    wasm = wasmtime.wat2wasm(ACCEPTED_PROBES[name])
    module = wasmtime.Module(_hardened_engine(), wasm)
    assert module is not None


def test_memory64_optin_positive_control():
    """memory64 stays reachable when the operator opts in (WASIConfig
    .memory64 mirrors the knob) — the rejection above is the default, not
    a hard ban."""
    wasm = wasmtime.wat2wasm(REJECTED_PROBES["memory64_default_off"][0])
    module = wasmtime.Module(_hardened_engine(wasm_memory64=True), wasm)
    assert module is not None
