#!/usr/bin/env python3
# Ephemora Cell — cost of cross-call state via the filesystem path
"""Measure per-run cost of carrying state between N consecutive runs.

Today's only cross-call channel inside the sandbox is a PERSISTENT
PREOPENED DIRECTORY: run k appends to state.bin, run k+1 reads it back.
This harness measures:

  * trivial      — stateless run baseline (proc_exit guest)
  * fs_state     — read-modify-write of state.bin through a preopen dir
                   (open append, write a 32-byte record, close) plus a
                   read-back of the whole file
  * fs_state_big — same with a 1 MiB state file (read-modify-write)

Delta fs_state - trivial = the per-run price of filesystem state.
Output: JSON (measured:true).
"""

from __future__ import annotations

import json
import shutil
import statistics
import sys
import time
from pathlib import Path

import wasmtime

REPO = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(REPO))

from ephemora_cell import WASIConfig, WASISandbox

TRIVIAL_WAT = """
(module
  (import "wasi_snapshot_preview1" "proc_exit" (func $exit (param i32)))
  (memory (export "memory") 1)
  (func (export "_start") i32.const 0 call $exit)
)
"""

# Append a 32-byte record to state.bin (fdflags=1 => append), then read
# the whole file back into memory (up to 128 KiB).
STATE_WAT = """
(module
  (import "wasi_snapshot_preview1" "fd_write" (func $fd_write
    (param i32 i32 i32 i32) (result i32)))
  (import "wasi_snapshot_preview1" "fd_read" (func $fd_read
    (param i32 i32 i32 i32) (result i32)))
  (import "wasi_snapshot_preview1" "fd_seek" (func $fd_seek
    (param i32 i64 i32 i32) (result i32)))
  (import "wasi_snapshot_preview1" "fd_close" (func $fd_close
    (param i32) (result i32)))
  (import "wasi_snapshot_preview1" "path_open" (func $path_open
    (param i32 i32 i32 i32 i32 i64 i64 i32 i32) (result i32)))
  (import "wasi_snapshot_preview1" "proc_exit" (func $exit (param i32)))
  (memory (export "memory") 2)
  (data (i32.const 8) "state.bin")
  (data (i32.const 32) "ABCDEFGHIJKLMNOPABCDEFGHIJKLMNOP")
  (data (i32.const 96) "\\20\\00\\00\\00\\20\\00\\00\\00")
  (func (export "_start") (local $fd i32) (local $e i32)
    ;; open state.bin with O_CREAT + append
    i32.const 3 i32.const 0 i32.const 8 i32.const 9 i32.const 1
    i64.const 70 i64.const 70 i32.const 1 i32.const 100
    call $path_open
    local.set $e
    local.get $e
    if i32.const 2 call $exit end
    ;; append a 32-byte record
    i32.const 100 i32.load
    i32.const 96 i32.const 1 i32.const 128
    call $fd_write
    local.set $e
    local.get $e
    if i32.const 3 call $exit end
    ;; close the append handle
    i32.const 100 i32.load
    call $fd_close
    drop
    ;; reopen read-only and read the whole file back (128 KiB window)
    i32.const 3 i32.const 0 i32.const 8 i32.const 9 i32.const 0
    i64.const 2 i64.const 2 i32.const 0 i32.const 100
    call $path_open
    local.set $e
    local.get $e
    if i32.const 4 call $exit end
    i32.const 100 i32.load
    i32.const 160 i32.const 1 i32.const 132
    call $fd_read
    drop
    i32.const 100 i32.load
    call $fd_close
    drop
    i32.const 0 call $exit
  )
)
"""

N_RUNS = 100


def run_series(name: str, wat: str, allow_dirs, big_file: bool) -> dict:
    datadir = Path.home() / f".ephemora_m12_{time.monotonic_ns()}"
    datadir.mkdir()
    try:
        wasm = datadir / f"{name}.wasm"
        wasm.write_bytes(wasmtime.wat2wasm(wat))
        if big_file:
            (datadir / "state.bin").write_bytes(b"S" * (1024 * 1024))
        config = WASIConfig(
            max_fuel=10_000_000, timeout_seconds=30, allow_dirs=(str(datadir),)
        )
        walls = []
        for _ in range(N_RUNS):
            sandbox = WASISandbox(config=config)
            try:
                t0 = time.perf_counter()
                result = sandbox.run(str(wasm))
                walls.append(time.perf_counter() - t0)
            finally:
                sandbox.cleanup()
            assert result.status.value == "success", result.stderr[:200]
        state_file = datadir / "state.bin"
        size = state_file.stat().st_size if state_file.exists() else 0
        return {
            "mode": name,
            "runs": N_RUNS,
            "mean_ms": round(statistics.mean(walls) * 1000, 2),
            "p95_ms": round(sorted(walls)[int(N_RUNS * 0.95)] * 1000, 2),
            "final_state_bytes": size,
        }
    finally:
        shutil.rmtree(datadir, ignore_errors=True)


def main() -> int:
    stamp = time.strftime("%Y-%m-%d")
    outdir = Path(__file__).resolve().parent

    trivial = run_series("trivial", TRIVIAL_WAT, (), False)
    fs_state = run_series("fs_state", STATE_WAT, None, False)
    fs_big = run_series("fs_state_big", STATE_WAT, None, True)

    state_overhead_small = round(fs_state["mean_ms"] - trivial["mean_ms"], 2)
    state_overhead_big = round(fs_big["mean_ms"] - trivial["mean_ms"], 2)
    print(f"trivial     : {trivial['mean_ms']} ms/run")
    print(f"fs_state    : {fs_state['mean_ms']} ms/run (+{state_overhead_small})")
    print(f"fs_state_1M : {fs_big['mean_ms']} ms/run (+{state_overhead_big})")

    report = {
        "measured": True,
        "source": "measurement",
        "date": stamp,
        "wasmtime": "47.0.1",
        "platform": sys.platform,
        "method": (
            "100 consecutive in-process runs; fs_state opens state.bin "
            "append, writes a 32-byte record, closes, reopens read-only and "
            "reads the file back; delta vs trivial run = per-run state cost"
        ),
        "results": [trivial, fs_state, fs_big],
        "state_cost_per_run_ms": {
            "small_state": state_overhead_small,
            "big_state_1mib": state_overhead_big,
        },
    }
    outfile = outdir / f"results_{stamp}.json"
    outfile.write_text(json.dumps(report, indent=2))
    print(f"wrote {outfile}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
