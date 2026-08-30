#!/usr/bin/env python3
# Ephemora Cell — host-scheduler impact of high-frequency small I/O
"""Measure HOST degradation caused by a sandboxed guest doing sustained
high-frequency small I/O.

Design (measured:true):
  * A "canary" subprocess loops { append 64B to an UNRELATED file;
    sleep(10ms); record wake jitter + write latency } and prints a JSON
    summary. It shares nothing with the sandbox attack except the
    machine (scheduler + filesystem).
  * Baseline phase: canary alone, 5 s.
  * Attack phases: canary runs for the whole window; 1 s in, a
    run_isolated() guest starts with max_fuel=None (trusted config —
    the realistic DoS case) and loops file writes (write_flood) or
    path_open+fd_close churn (open_churn) until the epoch timeout kills
    it (~10 s).
  * Impact = canary jitter/write-latency during attack window vs
    baseline, plus attack throughput (writes/s, opens/s, bytes).

Output: results JSON next to this script.
"""

from __future__ import annotations

import json
import shutil
import statistics
import subprocess
import sys
import time
from concurrent.futures import ThreadPoolExecutor
from pathlib import Path

import wasmtime

REPO = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(REPO))

from ephemora_cell import ExecutionStatus, WASIConfig, run_isolated

CANARY_SECONDS_BASELINE = 5.0
CANARY_SECONDS_ATTACK = 12.0
ATTACK_TIMEOUT = 10

CANARY_SRC = r"""
import json, statistics, sys, time
duration = float(sys.argv[1])
path = sys.argv[2]
f = open(path, "ab")
jitters, latencies = [], []
end = time.perf_counter() + duration
while time.perf_counter() < end:
    t0 = time.perf_counter()
    f.write(b"C" * 64)
    f.flush()
    t1 = time.perf_counter()
    time.sleep(0.01)
    t2 = time.perf_counter()
    latencies.append((t1 - t0) * 1e6)
    jitters.append((t2 - t1 - 0.01) * 1e3)
print(json.dumps({
    "n": len(jitters),
    "jitter_ms_mean": statistics.mean(jitters),
    "jitter_ms_p95": sorted(jitters)[int(len(jitters) * 0.95)],
    "jitter_ms_max": max(jitters),
    "write_us_mean": statistics.mean(latencies),
    "write_us_p95": sorted(latencies)[int(len(latencies) * 0.95)],
    "write_us_max": max(latencies),
}))
"""

WRITE_FLOOD_WAT = """
(module
  (import "wasi_snapshot_preview1" "fd_write" (func $fd_write
    (param i32 i32 i32 i32) (result i32)))
  (import "wasi_snapshot_preview1" "path_open" (func $path_open
    (param i32 i32 i32 i32 i32 i64 i64 i32 i32) (result i32)))
  (import "wasi_snapshot_preview1" "proc_exit" (func $proc_exit (param i32)))
  (memory (export "memory") 1)
  (data (i32.const 8) "probe.txt")
  (data (i32.const 32) "AAAAAAAA")
  (data (i32.const 64) "\\20\\00\\00\\00\\08\\00\\00\\00")
  (func (export "_start") (local $e i32)
    i32.const 3 i32.const 0 i32.const 8 i32.const 9 i32.const 1
    i64.const 64 i64.const 64 i32.const 0 i32.const 100
    call $path_open
    local.set $e
    local.get $e
    if i32.const 2 call $proc_exit end
    (loop $l
      i32.const 100 i32.load
      i32.const 64 i32.const 1 i32.const 104
      call $fd_write drop
      br $l
    )
  )
)
"""

STAT_FLOOD_WAT = """
(module
  (import "wasi_snapshot_preview1" "fd_filestat_get" (func $fstat
    (param i32 i32) (result i32)))
  (memory (export "memory") 1)
  (func (export "_start")
    (loop $l
      i32.const 3 i32.const 512 call $fstat drop
      br $l
    )
  )
)
"""

OPEN_CHURN_WAT = """
(module
  (import "wasi_snapshot_preview1" "fd_write" (func $fd_write
    (param i32 i32 i32 i32) (result i32)))
  (import "wasi_snapshot_preview1" "path_open" (func $path_open
    (param i32 i32 i32 i32 i32 i64 i64 i32 i32) (result i32)))
  (import "wasi_snapshot_preview1" "fd_close" (func $fd_close
    (param i32) (result i32)))
  (memory (export "memory") 1)
  (data (i32.const 8) "probe.txt")
  (func (export "_start")
    (loop $l
      i32.const 3 i32.const 0 i32.const 8 i32.const 9 i32.const 1
      i64.const 64 i64.const 64 i32.const 0 i32.const 512
      call $path_open drop
      i32.const 512 i32.load call $fd_close drop
      br $l
    )
  )
)
"""


def canary_stats(duration: float, path: Path) -> dict:
    proc = subprocess.run(
        [sys.executable, "-c", CANARY_SRC, str(duration), str(path)],
        capture_output=True, text=True, timeout=duration + 30, check=True,
    )
    return json.loads(proc.stdout.strip().splitlines()[-1])


def run_attack(mode: str, wasm: Path, datadir: Path, subdir: str = "") -> dict:
    if subdir:
        datadir = datadir / subdir
        datadir.mkdir(exist_ok=True)
    config = WASIConfig(
        max_fuel=None,               # trusted config: the realistic DoS surface
        timeout_seconds=ATTACK_TIMEOUT,
        allow_dirs=(str(datadir),),
        disk_quota_bytes=512 * 1024 * 1024,
    )
    t0 = time.perf_counter()
    result = run_isolated(str(wasm), config)
    wall = time.perf_counter() - t0
    probe = datadir / "probe.txt"
    bytes_written = probe.stat().st_size if probe.exists() else 0
    # Gate check: with ADR-002 budgets active (defaults), attacks end with
    # ERROR "I/O budget exceeded" instead of running out the full timeout.
    assert result["status"] in (
        ExecutionStatus.TIMEOUT,
        ExecutionStatus.SUCCESS,
        ExecutionStatus.ERROR,
    ), f"{mode}: unexpected status {result['status']}"
    budget_breached = result.get("io_budget_exceeded", False)
    if budget_breached:
        assert "I/O budget exceeded" in str(result["stderr"]), result["stderr"][:200]
    writes = bytes_written // 8 if mode == "write_flood" else None
    return {
        "mode": mode,
        "status": result["status"].value,
        "io_budget_exceeded": budget_breached,
        "io_cpu_used_seconds": result.get("io_cpu_used_seconds"),
        "attack_wall_seconds": round(wall, 3),
        "bytes_written": bytes_written,
        "writes_estimated": writes,
        "writes_per_second": round(writes / wall, 0) if writes else None,
        "stderr_head": str(result["stderr"])[:120],
    }


def main() -> int:
    stamp = time.strftime("%Y-%m-%d")
    outdir = Path(__file__).resolve().parent
    datadir = Path.home() / f".ephemora_m10_{time.monotonic_ns()}"
    datadir.mkdir()
    canary_path = Path.home() / f".ephemora_m10_canary_{time.monotonic_ns()}.bin"
    try:
        write_wasm = datadir / "write_flood.wasm"
        write_wasm.write_bytes(wasmtime.wat2wasm(WRITE_FLOOD_WAT))
        churn_wasm = datadir / "open_churn.wasm"
        churn_wasm.write_bytes(wasmtime.wat2wasm(OPEN_CHURN_WAT))

        # --- baseline: canary alone ---
        baseline = canary_stats(CANARY_SECONDS_BASELINE, canary_path)
        print("baseline jitter mean/p95/max [ms]:",
              round(baseline["jitter_ms_mean"], 3),
              round(baseline["jitter_ms_p95"], 3),
              round(baseline["jitter_ms_max"], 3))

        # --- attack 1: write flood ---
        with ThreadPoolExecutor(max_workers=2) as ex:
            canary_future = ex.submit(
                canary_stats, CANARY_SECONDS_ATTACK, canary_path
            )
            time.sleep(1.0)  # canary settles before the guest starts
            attack1 = run_attack("write_flood", write_wasm, datadir)
            impact1 = canary_future.result()
        (datadir / "probe.txt").unlink(missing_ok=True)

        # --- attack 2: open churn ---
        with ThreadPoolExecutor(max_workers=2) as ex:
            canary_future = ex.submit(
                canary_stats, CANARY_SECONDS_ATTACK, canary_path
            )
            time.sleep(1.0)
            attack2 = run_attack("open_churn", churn_wasm, datadir)
            impact2 = canary_future.result()
        (datadir / "probe.txt").unlink(missing_ok=True)

        # --- attack 3: stat flood (host FS stat, ZERO bytes written) ---
        stat_wasm = datadir / "stat_flood.wasm"
        stat_wasm.write_bytes(wasmtime.wat2wasm(STAT_FLOOD_WAT))
        with ThreadPoolExecutor(max_workers=2) as ex:
            canary_future = ex.submit(
                canary_stats, CANARY_SECONDS_ATTACK, canary_path
            )
            time.sleep(1.0)
            attack3 = run_attack("stat_flood", stat_wasm, datadir)
            impact3 = canary_future.result()

        # --- attack 4: 4x parallel write floods ---
        with ThreadPoolExecutor(max_workers=5) as ex:
            canary_future = ex.submit(
                canary_stats, CANARY_SECONDS_ATTACK, canary_path
            )
            time.sleep(1.0)
            futures = [
                ex.submit(
                    run_attack, "write_flood", write_wasm, datadir, f"p{i}"
                )
                for i in range(4)
            ]
            attacks4 = [f.result() for f in futures]
            impact4 = canary_future.result()
        par_wall = max(a["attack_wall_seconds"] for a in attacks4)
        par_bytes = sum(a["bytes_written"] for a in attacks4)
        attack4 = {
            "mode": "write_flood_x4_parallel",
            "status": ",".join(a["status"] for a in attacks4),
            "attack_wall_seconds": par_wall,
            "bytes_written": par_bytes,
            "writes_per_second": round(par_bytes / 8 / par_wall, 0),
            "stderr_head": "",
        }

        def degradation(impact: dict) -> dict:
            return {
                "jitter_mean_x_baseline": round(
                    impact["jitter_ms_mean"] / max(baseline["jitter_ms_mean"], 1e-9), 2
                ),
                "jitter_p95_x_baseline": round(
                    impact["jitter_ms_p95"] / max(baseline["jitter_ms_p95"], 1e-9), 2
                ),
                "write_latency_mean_x_baseline": round(
                    impact["write_us_mean"] / max(baseline["write_us_mean"], 1e-9), 2
                ),
                "write_latency_p95_x_baseline": round(
                    impact["write_us_p95"] / max(baseline["write_us_p95"], 1e-9), 2
                ),
            }

        report = {
            "measured": True,
            "source": "measurement",
            "date": stamp,
            "wasmtime": "47.0.1",
            "platform": sys.platform,
            "method": (
                "canary subprocess (unrelated-file appends + 10ms sleep loop) "
                "measures scheduler jitter and write latency baseline vs "
                "during a sandboxed guest attack (run_isolated worker, "
                "max_fuel=None trusted config, epoch timeout 10s)"
            ),
            "baseline_canary": baseline,
            "write_flood": {
                "attack": attack1,
                "canary_during": impact1,
                "degradation": degradation(impact1),
            },
            "open_churn": {
                "attack": attack2,
                "canary_during": impact2,
                "degradation": degradation(impact2),
            },
            "stat_flood": {
                "attack": attack3,
                "canary_during": impact3,
                "degradation": degradation(impact3),
            },
            "write_flood_x4_parallel": {
                "attack": attack4,
                "canary_during": impact4,
                "degradation": degradation(impact4),
            },
        }
        outfile = outdir / f"attack_results_{stamp}.json"
        outfile.write_text(json.dumps(report, indent=2))
        print(json.dumps(report["write_flood"]["degradation"], indent=2))
        print(json.dumps(report["open_churn"]["degradation"], indent=2))
        print(f"wrote {outfile}")
    finally:
        shutil.rmtree(datadir, ignore_errors=True)
        canary_path.unlink(missing_ok=True)
    return 0


if __name__ == "__main__":
    sys.exit(main())
