"""Fuel Metering Boundary Characterization.

Measures exact fuel consumption at the exhaustion boundary for:
  1. CPU-bound workloads (deterministic fuel/iteration curve)
  2. I/O-bound workloads (quantifies the I/O bypass gap)
  3. Exhaustion boundary (binary search for exact fuel budget)

Produces reproducible fuel-vs-output curves.
"""
import json
import os
import sys
import tempfile
import wasmtime

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
from ephemora_cell import WASISandbox, WASIConfig, ExecutionStatus


# ============================================================
# Payloads
# ============================================================

def cpu_wasm(n: int) -> bytes:
    """CPU: N iterations of i32.add."""
    return bytes(wasmtime.wat2wasm(f"""
    (module
      (func (export "_start")
        (local $i i32) (local $acc i32)
        i32.const 0 (local.set $i) i32.const 0 (local.set $acc)
        (loop $l
          local.get $acc i32.const 1 i32.add (local.set $acc)
          local.get $i i32.const 1 i32.add (local.set $i)
          local.get $i i32.const {n} i32.lt_s if (br $l) end
        )
      )
    )
    """))


def io_wasm(n: int) -> bytes:
    """I/O: N x fd_write(32 bytes).

    Fixed: the iovec struct is written explicitly to memory and the
    data segment lives OUTSIDE the iovec area. The previous version passed
    iovs_ptr=0 while the data segment sat at address 0, so the iovec decoded
    as buf=0x41414141/len=0x41414141, failed bounds-checking and every
    fd_write returned EFAULT — zero bytes were ever written (measurement
    artifact behind the old "~2.1 MB possible" claim).
    """
    return bytes(wasmtime.wat2wasm(f"""
    (module
      (import "wasi_snapshot_preview1" "fd_write" (func $fd_write
        (param i32 i32 i32 i32) (result i32)))
      (import "wasi_snapshot_preview1" "proc_exit" (func $exit (param i32)))
      (memory (export "memory") 1)
      (data (i32.const 512) "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA")
      (func (export "_start")
        (local $i i32)
        i32.const 0 (local.set $i)
        (loop $l
          i32.const 0 i32.const 512 i32.store
          i32.const 4 i32.const 32 i32.store
          i32.const 1 i32.const 0 i32.const 1 i32.const 8
          call $fd_write drop
          local.get $i i32.const 1 i32.add (local.set $i)
          local.get $i i32.const {n} i32.lt_s if (br $l) end
        )
        i32.const 0 call $exit
      )
    )
    """))


def mixed_wasm(n: int) -> bytes:
    """Mixed: N x (1 CPU add + 1 fd_write). Same iovec fix as io_wasm."""
    return bytes(wasmtime.wat2wasm(f"""
    (module
      (import "wasi_snapshot_preview1" "fd_write" (func $fd_write
        (param i32 i32 i32 i32) (result i32)))
      (import "wasi_snapshot_preview1" "proc_exit" (func $exit (param i32)))
      (memory (export "memory") 1)
      (data (i32.const 512) "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA")
      (func (export "_start")
        (local $i i32) (local $acc i32)
        i32.const 0 (local.set $i) i32.const 0 (local.set $acc)
        (loop $l
          local.get $acc i32.const 1 i32.add (local.set $acc)
          i32.const 0 i32.const 512 i32.store
          i32.const 4 i32.const 32 i32.store
          i32.const 1 i32.const 0 i32.const 1 i32.const 8
          call $fd_write drop
          local.get $i i32.const 1 i32.add (local.set $i)
          local.get $i i32.const {n} i32.lt_s if (br $l) end
        )
        i32.const 0 call $exit
      )
    )
    """))


# ============================================================
# Measurement helpers
# ============================================================

def run_wasm(wasm_bytes, max_fuel, timeout=10):
    tmp = tempfile.NamedTemporaryFile(suffix=".wasm", delete=False)
    tmp.write(wasm_bytes); tmp.close()
    sandbox = WASISandbox(config=WASIConfig(
        max_fuel=max_fuel,
        timeout_seconds=timeout,
        max_memory_mb=32,
        allow_dirs=(),
    ))
    result = sandbox.run(tmp.name)
    sandbox.cleanup()
    os.unlink(tmp.name)
    return result


def fuel_curve(label, wasm_fn, steps, fuel_budget=20_000_000):
    """Measure fuel/iteration across workload sizes (only successful runs)."""
    print(f"\n{label}:")
    curve = []
    for n in steps:
        result = run_wasm(wasm_fn(n), fuel_budget)
        entry = {
            "iterations": n,
            "status": result.status.value,
            "fuel_consumed": result.fuel_consumed,
            "elapsed_ms": round(result.elapsed_ms, 3),
            "stdout_bytes": len(result.stdout),
        }
        if result.fuel_consumed is not None:
            entry["fuel_per_iter"] = round(result.fuel_consumed / n, 3)
        curve.append(entry)
        status_str = entry["status"].upper()
        fuel_str = f"{result.fuel_consumed:,}" if result.fuel_consumed else "N/A"
        per_str = f"~{entry.get('fuel_per_iter', 0):.1f}/iter" if "fuel_per_iter" in entry else ""
        print(f"  n={n:>8,}: fuel={fuel_str:>12} [{status_str:>5}] {per_str}")
    return curve


def find_exhaustion(label, wasm_fn, fuel_budget=1_000_000):
    """Binary search: find max iterations that complete at given fuel budget."""
    print(f"\n{label} (fuel_budget={fuel_budget:,}):")

    # Quick range finding
    low, high = 1, 10
    while True:
        r = run_wasm(wasm_fn(high), fuel_budget)
        if r.status != ExecutionStatus.SUCCESS:
            break
        low = high
        high *= 5
        if high > 100_000_000:
            break

    # Binary search
    while high - low > 1:
        mid = (low + high) // 2
        r = run_wasm(wasm_fn(mid), fuel_budget)
        if r.status == ExecutionStatus.SUCCESS:
            low = mid
        else:
            high = mid
        if high - low <= 1:
            break

    # Final measurement at boundary
    r_success = run_wasm(wasm_fn(low), fuel_budget)
    r_fail = run_wasm(wasm_fn(low + 1), fuel_budget)

    result = {
        "fuel_budget": fuel_budget,
        "max_iterations": low,
        "fuel_consumed_at_success": r_success.fuel_consumed,
        "status_at_success": r_success.status.value,
        "status_at_fail": r_fail.status.value,
        "elapsed_success_ms": round(r_success.elapsed_ms, 3),
        "elapsed_fail_ms": round(r_fail.elapsed_ms, 3),
    }

    print(f"  Boundary at n={low:,}")
    print(f"  At n={low:,}: {r_success.status.value} (fuel={r_success.fuel_consumed or 0:,})")
    print(f"  At n={low+1:,}: {r_fail.status.value}")
    return result


def r_squared(xs, ys):
    n = len(xs)
    if n < 2:
        return 0.0
    mx = sum(xs) / n
    my = sum(ys) / n
    ss_tot = sum((y - my) ** 2 for y in ys)
    num = sum((x - mx) * (y - my) for x, y in zip(xs, ys))
    den = sum((x - mx) ** 2 for x in xs)
    slope = num / max(den, 1)
    ss_res = sum((y - (my + slope * (x - mx))) ** 2 for x, y in zip(xs, ys))
    return 1 - (ss_res / max(ss_tot, 1))


def main():
    print("=" * 60)
    print("Ephemora Cell Fuel Metering Boundary Characterization")
    print("=" * 60)

    results = {}

    # 1. CPU fuel curve (linear region)
    cpu_steps = [100, 1_000, 10_000, 50_000, 100_000, 500_000, 1_000_000, 5_000_000]
    cpu_curve = fuel_curve("CPU-bound (i32.add)", cpu_wasm, cpu_steps)
    results["cpu_curve"] = cpu_curve

    # Avg fuel per CPU iteration (from successful runs only)
    cpu_success = [c for c in cpu_curve if c["fuel_consumed"] is not None]
    avg_cpu_per_iter = (
        sum(c["fuel_consumed"] / c["iterations"] for c in cpu_success) / len(cpu_success)
        if cpu_success else 0
    )

    # I/O fuel curve
    io_steps = [10, 100, 500, 1_000, 5_000, 10_000, 50_000, 100_000, 500_000]
    io_curve = fuel_curve("I/O-bound (fd_write 32B)", io_wasm, io_steps, fuel_budget=20_000_000)
    results["io_curve"] = io_curve

    io_success = [c for c in io_curve if c["fuel_consumed"] is not None]
    avg_io_per_write = (
        sum(c["fuel_consumed"] / c["iterations"] for c in io_success) / len(io_success)
        if io_success else 0
    )

    # Mixed fuel curve
    mixed_steps = [100, 500, 1_000, 5_000, 10_000, 50_000, 100_000]
    mixed_curve = fuel_curve("Mixed (CPU + I/O)", mixed_wasm, mixed_steps)
    results["mixed_curve"] = mixed_curve

    # 2. Exhaustion boundaries at default max_fuel=1M
    print("\n" + "=" * 60)
    print("Exhaustion Boundaries (default max_fuel=1,000,000)")
    print("=" * 60)

    cpu_boundary = find_exhaustion("CPU exhaustion boundary", cpu_wasm, 1_000_000)
    io_boundary = find_exhaustion("I/O exhaustion boundary", io_wasm, 1_000_000)
    results["cpu_boundary_1m"] = cpu_boundary
    results["io_boundary_1m"] = io_boundary

    # 3. R^2 linearity
    print("\n" + "=" * 60)
    print("Linearity (R^2)")
    print("=" * 60)

    cpu_xs = [c["iterations"] for c in cpu_success]
    cpu_ys = [c["fuel_consumed"] for c in cpu_success]
    cpu_r2 = r_squared(cpu_xs, cpu_ys)

    io_xs = [c["iterations"] for c in io_success]
    io_ys = [c["fuel_consumed"] for c in io_success]
    io_r2 = r_squared(io_xs, io_ys)

    print(f"  CPU: R^2 = {cpu_r2:.6f} ({len(cpu_success)} points)")
    print(f"  I/O: R^2 = {io_r2:.6f} ({len(io_success)} points)")
    results["r_squared"] = {"cpu": cpu_r2, "io": io_r2}

    # 4. Summary
    print("\n" + "=" * 60)
    print("Summary")
    print("=" * 60)
    print(f"  Fuel per CPU iteration: ~{avg_cpu_per_iter:.1f}")
    print(f"  Fuel per fd_write (32B):  ~{avg_io_per_write:.1f}")
    if avg_cpu_per_iter > 0:
        ratio = avg_cpu_per_iter / avg_io_per_write if avg_io_per_write > 0 else float('inf')
        print(f"  I/O bypasses fuel by ~{ratio:.0f}x (CPU costs {avg_cpu_per_iter:.0f} fuel, I/O costs {avg_io_per_write:.0f} fuel)")

    if io_boundary.get("max_iterations"):
        io_bytes = io_boundary["max_iterations"] * 32
        print(f"\n  At default max_fuel=1,000,000:")
        print(f"    CPU:   {cpu_boundary['max_iterations']:,} iterations before FUEL_EXHAUSTED")
        print(f"    I/O:   {io_boundary['max_iterations']:,} writes before FUEL_EXHAUSTED")
        print(f"    I/O:   {io_bytes:,} bytes ({io_bytes/1024/1024:.2f} MB)")

    out = "/tmp/ephemora_cell-fuel-boundary.json"
    with open(out, "w") as f:
        json.dump(results, f, indent=2)
    print(f"\nFull data: {out}")
    return results


if __name__ == "__main__":
    main()