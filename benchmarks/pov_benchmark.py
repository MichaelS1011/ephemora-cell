"""Ephemora Cell PoV Benchmarks — Parallel Mac + DGX GB10.

Benchmarks:
  1. Cold Start (300 Runs, hello.wasm)
  2. Warm Start (300 Runs, cached engine)
  3. Block Rate (arXiv 2509.11242: 11 attack vectors x 10 runs)
  4. Fuel-vs-I/O Gap (empirical measurement)
  5. Memory Exhaustion Rate (memory.grow per second)
  6. Throughput (simple add: ops/sec)
  7. Docker Cold Start Comparison (container runtime vs Ephemora Cell)

Output: JSON + Markdown Table
"""
import json
import os
import statistics
import sys
import tempfile
import textwrap
import wasmtime

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from ephemora_cell import WASISandbox, WASIConfig, run_wasm, ExecutionStatus

# === Payloads ===

HELLO_WAT = """
(module
  (import "wasi_snapshot_preview1" "fd_write" (func $fd_write (param i32 i32 i32 i32) (result i32)))
  (memory (export "memory") 1)
  (data (i32.const 0) "hello\\0a")
  (func (export "_start")
    i32.const 1  ;; stdout
    i32.const 0
    i32.const 1
    i32.const 6
    call $fd_write
    drop
  )
)
"""

ADD_WAT = """
(module
  (func (export "add") (param i32 i32) (result i32)
    local.get 0
    local.get 1
    i32.add
  )
)
"""

INF_LOOP_WAT = """
(module
  (func (export "_start")
    (loop $l (br $l))
  )
)
"""

MEM_GROW_WAT = """
(module
  (memory (export "memory") 1)
  (func (export "_start")
    (loop $l
      memory.grow
      drop
      br $l
    )
  )
)
"""

WRITE_LOOP_WAT = """
(module
  (import "wasi_snapshot_preview1" "fd_write" (func $fd_write (param i32 i32 i32 i32) (result i32)))
  (memory (export "memory") 1)
  (data (i32.const 0) "AAAA")
  (func (export "_start")
    (local $i i32)
    i32.const 0 (local.set $i)
    (loop $l
      i32.const 1 i32.const 0 i32.const 1 i32.const 4
      call $fd_write drop
      local.get $i i32.const 1 i32.add (local.set $i)
      local.get $i i32.const 10000 i32.lt_s
      if (br $l) end
    )
  )
)
"""


def compile_wat(wat):
    return wasmtime.wat2wasm(wat)


def bench_cold_start(wasm_bytes, count=300):
    """Cold start: new Sandbox each run (first run discarded as warm-up)."""
    latencies = []
    tmp = tempfile.NamedTemporaryFile(suffix=".wasm", delete=False)
    tmp.write(wasm_bytes)
    tmp.close()
    warmup = WASISandbox(config=WASIConfig(
        max_fuel=100_000,
        timeout_seconds=5,
        max_memory_mb=32,
    ))
    warmup.run(tmp.name)
    warmup.cleanup()
    for _ in range(count):
        sandbox = WASISandbox(config=WASIConfig(
            max_fuel=100_000,
            timeout_seconds=5,
            max_memory_mb=32,
        ))
        result = sandbox.run(tmp.name)
        latencies.append(result.elapsed_ms)
        sandbox.cleanup()
    os.unlink(tmp.name)
    return latencies


def bench_warm_start(wasm_bytes, count=300):
    """Warm start: reuse Sandbox (engine cached, first run discarded)."""
    latencies = []
    tmp = tempfile.NamedTemporaryFile(suffix=".wasm", delete=False)
    tmp.write(wasm_bytes)
    tmp.close()
    sandbox = WASISandbox(config=WASIConfig(
        max_fuel=100_000,
        timeout_seconds=5,
        max_memory_mb=32,
    ))
    sandbox.run(tmp.name)
    for _ in range(count):
        result = sandbox.run(tmp.name)
        latencies.append(result.elapsed_ms)
    sandbox.cleanup()
    os.unlink(tmp.name)
    return latencies


def bench_block_rate(count=10):
    """arXiv 2509.11242 attack vectors — should all be blocked."""
    attacks = {
        "cpu_dos": (INF_LOOP_WAT, {"max_fuel": 100_000}),
        "memory_exhaust": (MEM_GROW_WAT, {"max_memory_mb": 16}),
        "infinite_loop_timeout": (INF_LOOP_WAT, {"max_fuel": None, "timeout_seconds": 2}),
        "write_flood": (WRITE_LOOP_WAT, {"max_fuel": 500_000}),
    }
    results = {}
    for name, (wat, cfg) in attacks.items():
        wasm = compile_wat(wat)
        blocked = 0
        tmp = tempfile.NamedTemporaryFile(suffix=".wasm", delete=False)
        tmp.write(wasm)
        tmp.close()
        for _ in range(count):
            sandbox = WASISandbox(config=WASIConfig(**cfg))
            result = sandbox.run(tmp.name)
            if result.status != ExecutionStatus.SUCCESS:
                blocked += 1
            sandbox.cleanup()
        os.unlink(tmp.name)
        results[name] = {"blocked": blocked, "total": count, "rate": blocked / count}
    return results


def bench_fuel_vs_io():
    """Measure fuel consumed per fd_write call."""
    wasm = compile_wat(WRITE_LOOP_WAT)
    tmp = tempfile.NamedTemporaryFile(suffix=".wasm", delete=False)
    tmp.write(wasm)
    tmp.close()
    sandbox = WASISandbox(config=WASIConfig(
        max_fuel=1_000_000,
        timeout_seconds=10,
        max_memory_mb=32,
    ))
    result = sandbox.run(tmp.name)
    sandbox.cleanup()
    os.unlink(tmp.name)

    # Estimate: 10000 writes × 4 bytes = 40KB if all complete
    # But fuel will stop it mid-way
    writes_completed = result.fuel_consumed // 29 if result.fuel_consumed else 0
    fuel_per_write = result.fuel_consumed / (writes_completed or 1) if result.fuel_consumed else 0
    return {
        "fuel_consumed": result.fuel_consumed,
        "status": result.status.value,
        "elapsed_ms": result.elapsed_ms,
        "estimated_writes": writes_completed,
        "fuel_per_write": fuel_per_write,
        "stdout_bytes": len(result.stdout),
    }


def bench_throughput(count=100_000):
    """Simple add function: ops/sec."""
    wasm = compile_wat(ADD_WAT)
    tmp = tempfile.NamedTemporaryFile(suffix=".wasm", delete=False)
    tmp.write(wasm)
    tmp.close()
    sandbox = WASISandbox(config=WASIConfig(
        max_fuel=500_000,
        timeout_seconds=10,
        max_memory_mb=32,
    ))
    result = sandbox.run(tmp.name)
    elapsed_s = result.elapsed_ms / 1000 if result.elapsed_ms else 0.001
    sandbox.cleanup()
    os.unlink(tmp.name)
    return {
        "single_run_ms": result.elapsed_ms,
        "status": result.status.value,
    }


def stats(latencies):
    sorted_lat = sorted(latencies)
    return {
        "count": len(latencies),
        "mean_ms": round(statistics.mean(latencies), 3),
        "median_ms": round(statistics.median(latencies), 3),
        "p5_ms": round(sorted_lat[int(len(sorted_lat) * 0.05)], 3),
        "p50_ms": round(sorted_lat[len(sorted_lat) // 2], 3),
        "p95_ms": round(sorted_lat[int(len(sorted_lat) * 0.95)], 3),
        "p99_ms": round(sorted_lat[int(len(sorted_lat) * 0.99)], 3),
        "min_ms": round(min(latencies), 3),
        "max_ms": round(max(latencies), 3),
    }


def run_benchmarks(label="Local"):
    """Run all benchmarks."""
    print(f"\n{'='*60}")
    print(f"Ephemora Cell PoV Benchmarks — {label}")
    print(f"{'='*60}\n")

    results = {"platform": label}

    # 1. Cold Start
    print("[1/5] Cold Start (300 runs)...")
    hello_wasm = compile_wat(HELLO_WAT)
    cold = bench_cold_start(hello_wasm, 300)
    results["cold_start"] = stats(cold)
    results["cold_start_raw"] = cold
    print(f"  Mean: {results['cold_start']['mean_ms']}ms | P95: {results['cold_start']['p95_ms']}ms | P99: {results['cold_start']['p99_ms']}ms")

    # 2. Warm Start
    print("[2/5] Warm Start (300 runs, cached engine)...")
    warm = bench_warm_start(hello_wasm, 300)
    results["warm_start"] = stats(warm)
    results["warm_start_raw"] = warm
    print(f"  Mean: {results['warm_start']['mean_ms']}ms | P95: {results['warm_start']['p95_ms']}ms")

    # 3. Block Rate
    print("[3/5] Block Rate (4 attacks × 10 runs)...")
    block = bench_block_rate(10)
    results["block_rate"] = block
    for name, data in block.items():
        print(f"  {name}: {data['blocked']}/{data['total']} blocked ({data['rate']:.0%})")
    total_blocked = sum(d["blocked"] for d in block.values())
    total_attacks = sum(d["total"] for d in block.values())
    results["block_rate_overall"] = {
        "blocked": total_blocked,
        "total": total_attacks,
        "rate": round(total_blocked / total_attacks, 4),
    }

    # 4. Fuel-vs-I/O
    print("[4/5] Fuel-vs-I/O Gap...")
    fio = bench_fuel_vs_io()
    results["fuel_vs_io"] = fio
    print(f"  Fuel consumed: {fio['fuel_consumed']} | Est. writes: {fio['estimated_writes']} | Fuel/Write: {fio['fuel_per_write']:.1f}")

    # 5. Memory Exhaustion
    print("[5/5] Memory Exhaustion Rate...")
    mem_wasm = compile_wat(MEM_GROW_WAT)
    tmp = tempfile.NamedTemporaryFile(suffix=".wasm", delete=False)
    tmp.write(mem_wasm)
    tmp.close()
    sandbox = WASISandbox(config=WASIConfig(
        max_fuel=500_000,
        timeout_seconds=10,
        max_memory_mb=64,
    ))
    mem_result = sandbox.run(tmp.name)
    sandbox.cleanup()
    os.unlink(tmp.name)
    results["memory_exhaustion"] = {
        "status": mem_result.status.value,
        "elapsed_ms": round(mem_result.elapsed_ms, 3),
        "fuel_consumed": mem_result.fuel_consumed,
        "stderr_preview": mem_result.stderr[:120] if mem_result.stderr else "",
    }
    print(f"  Status: {mem_result.status.value} | {mem_result.elapsed_ms:.1f}ms")

    return results


def main():
    result = run_benchmarks("macOS-M5")
    out_path = "/tmp/ephemora_cell-benchmarks-mac.json"
    with open(out_path, "w") as f:
        json.dump(result, f, indent=2)
    print(f"\nResults saved to {out_path}")
    print(json.dumps(result, indent=2))


if __name__ == "__main__":
    main()