#!/usr/bin/env python3
"""Ephemora Cell — GC PoC driver.

Run from the repo root:

    .venv/bin/python benchmarks/pocs/gc_poc/run_gc_poc.py

Scenarios (all against the Ephemora Cell sandbox):
  A. WASISandbox (preview1): GC workload runs; fuel exhaustion; memory
     limit via Store.set_limits; epoch timeout.
  B. ComponentSandbox: hand-written component wrapping a self-contained GC
     module (direct `run` export) + `wasm-tools component new` lifted GC
     module (wasi:cli/run entry point via the command adapter).
  C. Timing: GC vs non-GC arithmetic twin at the same loop count (runtime,
     fuel), plus wat2wasm / wasmtime compile times.

Emits results.json and a human-readable summary.
"""
from __future__ import annotations

import json
import os
import statistics
import sys
import time

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__)))))
from ephemora_cell import (
    ComponentSandbox,
    ExecutionStatus,
    WASIConfig,
    WASISandbox,
)

HERE = os.path.dirname(os.path.abspath(__file__))
RESULTS = os.path.join(HERE, "results.json")

GC_WORKLOAD = os.path.join(HERE, "gc_workload.wasm")
ARITH_WORKLOAD = os.path.join(HERE, "arith_workload.wasm")
GC_INFINITE = os.path.join(HERE, "gc_infinite.wasm")
GC_GROW = os.path.join(HERE, "gc_grow.wasm")
GC_WRAPPER = os.path.join(HERE, "gc_wrapper.wasm")
GC_WRAPPER_INF = os.path.join(HERE, "gc_wrapper_inf.wasm")
LIFTED = os.path.join(HERE, "lifted.wasm")

FUEL_FULL = 100_000_000
FUEL_TINY = 50_000


def status_name(r) -> str:
    return str(r.status).split(".")[1].lower()


def run_median(path: str, *, config: WASIConfig, args=None, n: int = 5,
               abi: str = "preview1") -> dict:
    """Run n times, return median timing + first-run result details."""
    times: list[float] = []
    fuels: list[int] = []
    last = None
    for i in range(n):
        s = WASISandbox(config)
        r = s.run(path, args=args, abi=abi)
        s.cleanup()
        times.append(r.elapsed_ms)
        if r.fuel_consumed is not None:
            fuels.append(r.fuel_consumed)
        last = r
    return {
        "status": status_name(last),
        "exit_code": last.exit_code,
        "stdout": last.stdout.strip(),
        "stderr": (last.stderr or "")[:200],
        "elapsed_ms_median": round(statistics.median(times), 2),
        "elapsed_ms_min": round(min(times), 2),
        "elapsed_ms_all": [round(t, 2) for t in times],
        "fuel_consumed": last.fuel_consumed,
        "fuel_median": int(statistics.median(fuels)) if fuels else None,
    }


def scenario_a() -> dict:
    """Preview1 WASISandbox scenarios."""
    out = {}

    r = run_median(GC_WORKLOAD, config=WASIConfig(max_fuel=FUEL_FULL, timeout_seconds=30))
    out["gc_workload_preview1"] = r
    assert r["status"] == "success", r["stderr"]
    assert "gc-workload done" in r["stdout"]

    r = run_median(ARITH_WORKLOAD, config=WASIConfig(max_fuel=FUEL_FULL, timeout_seconds=30))
    out["arith_workload_preview1"] = r
    assert r["status"] == "success"

    r = run_median(GC_INFINITE, config=WASIConfig(max_fuel=FUEL_TINY, timeout_seconds=30), n=1)
    out["gc_fuel_exhausted_preview1"] = r
    assert r["status"] == "fuel_exhausted", r["stderr"]

    r = run_median(GC_INFINITE, config=WASIConfig(max_fuel=None, timeout_seconds=1), n=1)
    out["gc_epoch_timeout_preview1"] = r
    assert r["status"] == "timeout", r["stderr"]

    r = run_median(GC_GROW, config=WASIConfig(max_fuel=FUEL_FULL, timeout_seconds=30,
                                              max_memory_mb=2), n=1)
    out["gc_memory_limit_preview1"] = r
    assert r["status"] == "error", r["stderr"]  # memory.grow past limit traps

    # GC-only churn (no linear memory growth) is NOT limited by Store.set_limits
    # — the GC heap is separate from linear memory. Confirms the knob's scope.
    r = run_median(GC_WORKLOAD, config=WASIConfig(max_fuel=FUEL_FULL, timeout_seconds=30,
                                                  max_memory_mb=1), n=3)
    out["gc_heap_not_limited_by_store_limits"] = r
    assert r["status"] == "success"

    return out


def scenario_b() -> dict:
    """ComponentSandbox (WASI 0.2) GC scenarios."""
    out = {}

    # Hand-written component: self-contained GC core module, direct `run`.
    s = ComponentSandbox(WASIConfig(max_fuel=FUEL_FULL))
    r = s.run(GC_WRAPPER)
    s.cleanup()
    out["gc_wrapper_component"] = {
        "status": status_name(r), "exit_code": r.exit_code,
        "stdout": r.stdout, "stderr": (r.stderr or "")[:200],
        "elapsed_ms": round(r.elapsed_ms, 2),
        "fuel_consumed": r.fuel_consumed,
    }
    assert r.status == ExecutionStatus.SUCCESS, r.stderr

    s = ComponentSandbox(WASIConfig(max_fuel=10_000))
    r = s.run(GC_WRAPPER)
    s.cleanup()
    out["gc_wrapper_fuel_component"] = {
        "status": status_name(r), "stdout": r.stdout,
        "stderr": (r.stderr or "")[:200], "elapsed_ms": round(r.elapsed_ms, 2),
    }
    assert r.status == ExecutionStatus.FUEL_EXHAUSTED, r.stderr

    s = ComponentSandbox(WASIConfig(max_fuel=None, timeout_seconds=1))
    r = s.run(GC_WRAPPER_INF)
    s.cleanup()
    out["gc_wrapper_timeout_component"] = {
        "status": status_name(r), "stdout": r.stdout,
        "stderr": (r.stderr or "")[:200], "elapsed_ms": round(r.elapsed_ms, 2),
    }
    assert r.status == ExecutionStatus.TIMEOUT, r.stderr

    s = ComponentSandbox(WASIConfig(max_fuel=10_000))
    r = s.run(GC_WRAPPER_INF)
    s.cleanup()
    out["gc_wrapper_inf_fuel_component"] = {
        "status": status_name(r), "stdout": r.stdout,
        "stderr": (r.stderr or "")[:200], "elapsed_ms": round(r.elapsed_ms, 2),
    }
    assert r.status == ExecutionStatus.FUEL_EXHAUSTED, r.stderr

    # Lifted GC module (wasm-tools, command adapter) — entry point is
    # wasi:cli/run@0.2.3, not the direct `run`.
    s = ComponentSandbox(WASIConfig(max_fuel=FUEL_FULL))
    r = s.run(LIFTED)
    s.cleanup()
    out["gc_lifted_component"] = {
        "status": status_name(r), "exit_code": r.exit_code,
        "stdout": r.stdout, "stderr": (r.stderr or "")[:200],
        "elapsed_ms": round(r.elapsed_ms, 2),
    }
    # The lifted GC module's _start calls proc_exit(0); the preview1->0.2
    # adapter forwards it to wasi:cli/exit which traps "Exited with i32 exit
    # status 0". Status depends on the sandbox's exit-0 handling (see README
    # findings). We only assert stdout was captured either way.
    assert "gc-workload done" in r.stdout, r.stderr

    # Exports of the lifted GC component — entry-point naming.
    import wasmtime
    from wasmtime import component as _component
    eng = wasmtime.Engine()
    comp = _component.Component.from_file(eng, LIFTED)
    exports = list(comp.type.exports(eng))
    out["lifted_gc_exports"] = [str(n) for n in exports]
    out["lifted_gc_run_found"] = any(str(n).startswith("wasi:cli/run@") for n in exports)

    return out


def scenario_c(a: dict) -> dict:
    """Timing + compile-time comparison, GC vs arithmetic twin."""
    out = {}

    # wat2wasm compile time (text -> binary), best of 20.
    w2w_gc, w2w_ar = [], []
    for _ in range(20):
        import wasmtime
        t0 = time.perf_counter()
        bytes(wasmtime.wat2wasm(open(os.path.join(HERE, "gc_workload.wat")).read()))
        w2w_gc.append((time.perf_counter() - t0) * 1000)
        t0 = time.perf_counter()
        bytes(wasmtime.wat2wasm(open(os.path.join(HERE, "arith_workload.wat")).read()))
        w2w_ar.append((time.perf_counter() - t0) * 1000)
    out["wat2wasm_gc_ms"] = round(min(w2w_gc), 3)
    out["wat2wasm_arith_ms"] = round(min(w2w_ar), 3)

    # wasmtime Module compile time (binary -> compiled), best of 10.
    import wasmtime
    eng = wasmtime.Engine()
    mc_gc, mc_ar = [], []
    for _ in range(10):
        t0 = time.perf_counter()
        wasmtime.Module.from_file(eng, GC_WORKLOAD)
        mc_gc.append((time.perf_counter() - t0) * 1000)
        t0 = time.perf_counter()
        wasmtime.Module.from_file(eng, ARITH_WORKLOAD)
        mc_ar.append((time.perf_counter() - t0) * 1000)
    out["module_compile_gc_ms"] = round(min(mc_gc), 3)
    out["module_compile_arith_ms"] = round(min(mc_ar), 3)

    # Runtime, same loop count (100_000): median of 7 sandbox runs each.
    a["gc_workload_preview1"]["loop_count"] = 100_000
    a["arith_workload_preview1"]["loop_count"] = 100_000
    return out


def main() -> None:
    print("=" * 72)
    print("Ephemora Cell — GC PoC")
    print("=" * 72)

    results = {}
    results["gc_engine_config"] = {
        "wasmtime_py": "47.0.1",
        "wasmtime_cli": "34.0.0",
        "wasm_gc_flag_set_by_sandbox": None,  # sandbox never sets Config.wasm_gc
        "wasm_gc_default": "enabled (verified: default Config() compiles GC modules;"
                           " Config(wasm_gc=False) rejects them)",
    }

    print("\n[A] Preview1 WASISandbox scenarios")
    a = scenario_a()
    results["scenario_a"] = a
    for k, v in a.items():
        print(f"  {k}: {v['status']}  stdout={v['stdout']!r:.60}")

    print("\n[B] ComponentSandbox (WASI 0.2) scenarios")
    b = scenario_b()
    results["scenario_b"] = b
    for k, v in b.items():
        if isinstance(v, dict):
            print(f"  {k}: {v.get('status')}  stdout={str(v.get('stdout'))[:60]!r}")

    print("\n[C] Timing: GC vs arithmetic twin (same loop count)")
    c = scenario_c(a)
    results["scenario_c"] = c
    gc_t = a["gc_workload_preview1"]["elapsed_ms_median"]
    ar_t = a["arith_workload_preview1"]["elapsed_ms_median"]
    gc_f = a["gc_workload_preview1"]["fuel_median"]
    ar_f = a["arith_workload_preview1"]["fuel_median"]
    print(f"  wat2wasm:        GC {c['wat2wasm_gc_ms']} ms vs arith {c['wat2wasm_arith_ms']} ms")
    print(f"  Module.compile:  GC {c['module_compile_gc_ms']} ms vs arith {c['module_compile_arith_ms']} ms")
    print(f"  run (median):    GC {gc_t} ms vs arith {ar_t} ms   ({gc_t/ar_t:.2f}x)")
    print(f"  fuel (median):   GC {gc_f} vs arith {ar_f}   ({gc_f/ar_f:.2f}x)")

    with open(RESULTS, "w") as f:
        json.dump(results, f, indent=2)
    print(f"\nresults written to {RESULTS}")


if __name__ == "__main__":
    main()
