"""Benchmark guard — order-of-magnitude regression check for CI.

Deliberately LOOSE thresholds: this guards against a ~100x-scale
regression (engine pooling broken, fuel/epoch accidentally enabled on
every run), NOT against platform noise. Timing on shared CI runners is
far too volatile for tight gates, and fuel counts are per-platform
(see SECURITY.md) — so the only fuel assertion is INVARIANCE within a
single run: same module, same runner -> identical fuel_consumed.

Checks:
  1. pooled warm wall median < 5 ms   (measured ~0.5 ms on Mac M5,
     ~2-3 ms on ubuntu-latest runners)
  2. default path wall median < 20 ms (measured ~1 ms on Mac M5)
  3. pooled guest median < 5 ms       (measured ~0.17 ms on Mac M5)
  4. fuel invariance: two identical runs consume identical fuel

Exit code 0 = pass; 1 = threshold violated. Prints a one-line summary.
"""

from __future__ import annotations

import sys
import time
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

import wasmtime

from ephemora_cell import ExecutionStatus, WASIConfig, WASISandbox

WASM = Path(__file__).resolve().parents[1] / "examples" / "hello.wasm"

N = 200
WARMUP = 20

THRESHOLDS = {
    "pooled_wall_median_ms": 5.0,
    "default_wall_median_ms": 20.0,
    "pooled_guest_median_ms": 5.0,
}


def median(xs: list[float]) -> float:
    xs = sorted(xs)
    return xs[len(xs) // 2]


def timed_scenario(config: WASIConfig) -> tuple[float, float]:
    sandbox = WASISandbox(config=config)
    try:
        for _ in range(WARMUP):
            sandbox.run(str(WASM))
        walls = []
        guests = []
        for _ in range(N):
            t0 = time.perf_counter()
            result = sandbox.run(str(WASM))
            walls.append((time.perf_counter() - t0) * 1000)
            guests.append(result.elapsed_ms)
        return median(walls), median(guests)
    finally:
        sandbox.cleanup()


def fuel_invariance() -> tuple[bool, str]:
    """Same module + same runner twice -> identical fuel_consumed."""
    wat = """
    (module
      (func (export "_start")
        (local $i i32)
        i32.const 0 (local.set $i)
        (loop $l
          local.get $i i32.const 1 i32.add (local.set $i)
          local.get $i i32.const 1000 i32.lt_s if (br $l) end
        )
      )
    )
    """
    wasm_bytes = bytes(wasmtime.wat2wasm(wat))
    tmp = WASM.parent / "_fuel_guard_tmp.wasm"
    tmp.write_bytes(wasm_bytes)
    try:
        fuels = []
        for _ in range(2):
            sandbox = WASISandbox(config=WASIConfig(max_fuel=1_000_000))
            try:
                result = sandbox.run(str(tmp))
                if result.status != ExecutionStatus.SUCCESS:
                    return False, f"guard module failed: {result.status.value}"
                fuels.append(result.fuel_consumed)
            finally:
                sandbox.cleanup()
        ok = fuels[0] == fuels[1] and fuels[0] is not None
        return ok, f"fuel run1={fuels[0]} run2={fuels[1]}"
    finally:
        tmp.unlink(missing_ok=True)


def main() -> int:
    failures = []

    pooled_wall, pooled_guest = timed_scenario(WASIConfig(io_budget_bytes=None))
    default_wall, _ = timed_scenario(WASIConfig())

    checks = [
        ("pooled_wall_median_ms", pooled_wall, THRESHOLDS["pooled_wall_median_ms"]),
        ("default_wall_median_ms", default_wall, THRESHOLDS["default_wall_median_ms"]),
        ("pooled_guest_median_ms", pooled_guest, THRESHOLDS["pooled_guest_median_ms"]),
    ]
    for name, value, limit in checks:
        status = "ok" if value < limit else "FAIL"
        print(f"{name}: {value:.3f} ms (limit {limit}) [{status}]")
        if value >= limit:
            failures.append(f"{name}={value:.3f} >= {limit}")

    ok, detail = fuel_invariance()
    print(f"fuel_invariance: {detail} [{'ok' if ok else 'FAIL'}]")
    if not ok:
        failures.append(f"fuel_invariance: {detail}")

    if failures:
        print(f"benchmark-guard: {len(failures)} failure(s)")
        return 1
    print("benchmark-guard: pass")
    return 0


if __name__ == "__main__":
    sys.exit(main())
