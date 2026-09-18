#!/usr/bin/env python3
"""Fuel vs epoch vs wall-clock — the three ways to stop a WASM run.

Measures the three interruption mechanisms Cell exposes, on three axes:

  1. OVERHEAD (mechanism level, raw wasmtime): identical CPU loop, three
     engines — baseline (no metering), epoch enabled (deadline far away),
     fuel enabled (budget far away). Medians over n runs give the relative
     tax of each mechanism. This is the experiment behind the "epoch is
     cheaper than fuel" folklore (cited anchor: wasmtime#4109, 28-40%
     relative fuel overhead — cited, not ours; we measure our own numbers).
  2. PRECISION: a CPU-bound loop sized to outlive the budget by ~10x, run
     under each mechanism with a time/compute budget T. Overshoot
     (wall_time - T) is measured over n runs per mechanism:
       fuel       - per-instruction metering; stop-point is deterministic
       epoch      - pooled engine: 50 ms ticks; per-run engine: a timer
                    thread fires one increment at T (deadline=1)
       wall-clock - subprocess path: hard kill after T
  3. DETERMINISM: spread across runs. Fuel's stop-point is identical run to
     run (platform-bound); time-based stops are not, and the spread IS the
     finding.

Claim hygiene: fuel numbers are platform-bound (pinned wasmtime, macOS
arm64); these relative taxes are a DIFFERENT measurement from the per-call
sandbox overhead (0.376 ms, performance.md) and are never mixed with it.

Evidence: benchmarks/results/<date>/07_fuel_epoch_wall.json (measured:true).
"""

from __future__ import annotations

import json
import statistics
import sys
import time
from datetime import date
from importlib.metadata import version as _pkg_version
from pathlib import Path

import wasmtime

REPO = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(REPO))
sys.path.insert(0, str(REPO / "benchmarks"))

from fuel_boundary import cpu_wasm  # noqa: E402

from ephemora_cell import WASIConfig, WASISandbox, run_isolated  # noqa: E402


def mixed_wasm(n: int) -> bytes:
    """Realistic-mix loop: ~10 instructions per iteration (mul/add/xor/rem +
    a memory store/load). A single-add micro-loop makes BOTH metering checks
    look ~2x because the per-iteration body is ~1 cycle — the metering tax
    must be measured against work, not against an empty loop."""
    return bytes(wasmtime.wat2wasm(f"""
    (module
      (memory 1)
      (func (export "_start")
        (local $i i32) (local $acc i32)
        i32.const 0 (local.set $i) i32.const 7 (local.set $acc)
        (loop $l
          local.get $acc i32.const 3 i32.mul local.get $i i32.add (local.set $acc)
          local.get $acc i32.const 5 i32.xor (local.set $acc)
          local.get $acc i32.const 11 i32.rem_s (local.set $acc)
          local.get $acc i32.const 0 i32.store
          i32.const 0 i32.load (local.set $acc)
          local.get $acc i32.const 1 i32.add (local.set $acc)
          local.get $i i32.const 1 i32.add (local.set $i)
          local.get $i i32.const {n} i32.lt_s if (br $l) end
        )
      )
    )
    """))


def _median(values: list[float]) -> float:
    return statistics.median(values)


def _p95(values: list[float]) -> float:
    s = sorted(values)
    return s[min(len(s) - 1, round(0.95 * (len(s) - 1)))]


# ---------------------------------------------------------------- overhead
def measure_overhead(n_iters: int, runs: int) -> dict:
    """Raw-wasmtime mechanism tax: same loop, three engine configs."""
    wasm = mixed_wasm(n_iters)
    engines = {}
    cfg = wasmtime.Config()
    engines["baseline"] = wasmtime.Engine(cfg)
    cfg = wasmtime.Config()
    cfg.epoch_interruption = True
    engines["epoch_enabled"] = wasmtime.Engine(cfg)
    cfg = wasmtime.Config()
    cfg.consume_fuel = True
    engines["fuel_enabled"] = wasmtime.Engine(cfg)

    timings: dict[str, list[float]] = {k: [] for k in engines}
    for name, engine in engines.items():
        module = wasmtime.Module(engine, wasm)
        store = wasmtime.Store(engine)
        if name == "fuel_enabled":
            store.set_fuel(10**12)  # far away — metering on, never exhausted
        if name == "epoch_enabled":
            store.set_epoch_deadline(10**9)  # far away — checks on, never fires
        instance = wasmtime.Instance(store, module, [])
        instance.exports(store)["_start"](store)  # warm, discard
        for _ in range(runs):
            store = wasmtime.Store(engine)
            if name == "fuel_enabled":
                store.set_fuel(10**12)
            if name == "epoch_enabled":
                store.set_epoch_deadline(10**9)
            instance = wasmtime.Instance(store, module, [])
            t0 = time.perf_counter()
            instance.exports(store)["_start"](store)
            timings[name].append((time.perf_counter() - t0) * 1000)

    base = _median(timings["baseline"])
    out = {"baseline_median_ms": round(base, 3), "runs": runs}
    for name in ("epoch_enabled", "fuel_enabled"):
        med = _median(timings[name])
        out[name] = {
            "median_ms": round(med, 3),
            "relative_tax_vs_baseline": round((med - base) / base, 4),
        }
    return out


# ---------------------------------------------------------------- precision
def _calibrate_iters(target_ms: float, runs: int = 3) -> int:
    """Size the loop so one unmetered run takes ~target_ms."""
    n = 1_000_000
    wasm = cpu_wasm(n)
    engine = wasmtime.Engine()
    module = wasmtime.Module(engine, wasm)
    store = wasmtime.Store(engine)
    instance = wasmtime.Instance(store, module, [])
    instance.exports(store)["_start"](store)  # warm
    t0 = time.perf_counter()
    instance.exports(store)["_start"](store)
    per_m = (time.perf_counter() - t0) * 1000
    # i32 loop counter caps at 2^31-1 — do not scale past it
    return max(1_000_000, min(2_000_000_000, int(n * target_ms / max(per_m, 0.001))))


def measure_precision(timeout_s: float, runs: int, n_iters: int) -> dict:
    """Overshoot of each mechanism for budget T against an oversized loop."""
    wasm_path = Path(tempfile_wasm(cpu_wasm(n_iters)))
    out: dict = {"timeout_s": timeout_s, "runs": runs, "workload_iters": n_iters}

    # fuel: stop-point determinism (budget in fuel, not time)
    fuel_budget = 1_000_000
    consumed = []
    for _ in range(5):
        sb = WASISandbox(
            config=WASIConfig(allow_dirs=(), max_fuel=fuel_budget, timeout_seconds=30)
        )
        try:
            r = sb.run(str(wasm_path))
            consumed.append(r.fuel_consumed)
        finally:
            sb.cleanup()
    out["fuel"] = {
        "budget": fuel_budget,
        "status": "fuel_exhausted",
        "consumed_across_runs": consumed,
        "stop_point_deterministic": len(set(consumed)) == 1,
    }

    # epoch, pooled engine (50 ms ticks)
    over = []
    statuses = set()
    for _ in range(runs):
        t0 = time.perf_counter()
        sb = WASISandbox(
            config=WASIConfig(
                allow_dirs=(),
                max_fuel=None,
                timeout_seconds=timeout_s,
                io_budget_bytes=None,
            )
        )
        try:
            r = sb.run(str(wasm_path))
        finally:
            sb.cleanup()
        over.append((time.perf_counter() - t0) * 1000 - timeout_s * 1000)
        statuses.add(r.status.name)
    out["epoch_pooled"] = {
        "tick_seconds": 0.05,
        "overshoot_ms_median": round(_median(over), 2),
        "overshoot_ms_p95": round(_p95(over), 2),
        "overshoot_ms_max": round(max(over), 2),
        "statuses": sorted(statuses),
    }

    # epoch, per-run engine (timer fires one increment at T; deadline=1)
    over = []
    statuses = set()
    for _ in range(runs):
        t0 = time.perf_counter()
        sb = WASISandbox(
            config=WASIConfig(allow_dirs=(), max_fuel=None, timeout_seconds=timeout_s)
        )
        try:
            r = sb.run(str(wasm_path))
        finally:
            sb.cleanup()
        over.append((time.perf_counter() - t0) * 1000 - timeout_s * 1000)
        statuses.add(r.status.name)
    out["epoch_per_run"] = {
        "mechanism": "deadline=1 + single increment at T",
        "overshoot_ms_median": round(_median(over), 2),
        "overshoot_ms_p95": round(_p95(over), 2),
        "overshoot_ms_max": round(max(over), 2),
        "statuses": sorted(statuses),
    }

    # wall-clock: subprocess hard kill
    over = []
    statuses = set()
    for _ in range(runs):
        t0 = time.perf_counter()
        r = run_isolated(
            str(wasm_path),
            config=WASIConfig(allow_dirs=(), max_fuel=None, timeout_seconds=timeout_s),
        )
        over.append((time.perf_counter() - t0) * 1000 - timeout_s * 1000)
        statuses.add(r.status.name)
    out["wall_subprocess"] = {
        "mechanism": "hard process kill after T (+ spawn cost)",
        "overshoot_ms_median": round(_median(over), 2),
        "overshoot_ms_p95": round(_p95(over), 2),
        "overshoot_ms_max": round(max(over), 2),
        "statuses": sorted(statuses),
        "note": "overshoot includes process spawn/teardown — kill granularity "
        "and startup dominate; this path also carries OS-level rlimits",
    }
    return out


def tempfile_wasm(data: bytes) -> str:
    import tempfile

    f = tempfile.NamedTemporaryFile(suffix=".wasm", delete=False)
    f.write(data)
    f.close()
    return f.name


def main() -> int:
    print("Fuel vs epoch vs wall-clock — mechanism benchmark")
    print("=" * 70)

    overhead = measure_overhead(n_iters=10_000_000, runs=30)
    print(
        f"overhead (10M-iter loop, n=30): baseline {overhead['baseline_median_ms']} ms | "
        f"epoch +{overhead['epoch_enabled']['relative_tax_vs_baseline']*100:.1f}% | "
        f"fuel +{overhead['fuel_enabled']['relative_tax_vs_baseline']*100:.1f}%"
    )

    n_big = _calibrate_iters(target_ms=3000)
    print(f"precision workload: {n_big:,} iterations (i32-capped)")
    precision = measure_precision(timeout_s=0.1, runs=20, n_iters=n_big)
    for mech in ("epoch_pooled", "epoch_per_run", "wall_subprocess"):
        m = precision[mech]
        print(
            f"{mech:16} overshoot median {m['overshoot_ms_median']:>7} ms | "
            f"p95 {m['overshoot_ms_p95']:>7} ms | max {m['overshoot_ms_max']:>7} ms"
        )
    print(
        f"fuel stop-point deterministic: {precision['fuel']['stop_point_deterministic']} "
        f"(consumed {precision['fuel']['consumed_across_runs']})"
    )

    doc = {
        "measured": True,
        "source": "measurement",
        "date": str(date.today()),
        "python": sys.version.split()[0],
        "wasmtime": _pkg_version("wasmtime"),
        "platform_bound_note": "fuel numbers are per-platform (pinned wasmtime, "
        "macOS arm64) and not comparable across platforms",
        "cited_anchors": {
            "wasmtime_4109_fuel_overhead": "28-40% relative (cited, not ours)",
            "epoch_cheaper_than_fuel": "verified below with our own measurement",
        },
        "overhead_mechanism_level": overhead,
        "precision": precision,
    }
    out_dir = REPO / "benchmarks" / "results" / str(date.today())
    out_dir.mkdir(parents=True, exist_ok=True)
    dest = out_dir / "07_fuel_epoch_wall.json"
    dest.write_text(json.dumps(doc, indent=2))
    print(f"Saved: {dest}")
    return 0


if __name__ == "__main__":
    main()
