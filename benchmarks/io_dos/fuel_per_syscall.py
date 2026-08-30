#!/usr/bin/env python3
# Ephemora Cell — fuel cost per WASI syscall (fuel-bypass inventory)
"""Measure the guest-visible fuel cost of each WASI preview1 host call.

Method: run a module whose _start is a counted loop calling ONE WASI
syscall N times, with max_fuel set. fuel_consumed / N = fuel per
iteration (loop + counter + call). The same loop WITHOUT the call is
the baseline; (variant - baseline) approximates the syscall's fuel
price. Wall-clock / N gives a rough host-cost proxy.

This is the inventory input: syscalls with LOW fuel price but
REAL host work (file writes, opens) are the fuel-bypass surface that
the I/O budget must cover.

Output: JSON (measured:true schema) next to this script.
"""

from __future__ import annotations

import json
import shutil
import sys
import time
from pathlib import Path

REPO = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(REPO))

import wasmtime

from ephemora_cell import WASIConfig, WASISandbox

# Common memory layout for all variants:
#   8..32   path string   32..64 payload   64..72 iovec{ptr,len}
#   100..104 opened fd    104..108 nwritten/nread/errno scratch
#   512+    misc scratch
TEMPLATE = """
(module
  (import "wasi_snapshot_preview1" "{fn}" (func $f {params} (result i32)))
  (import "wasi_snapshot_preview1" "proc_exit" (func $exit (param i32)))
  (memory (export "memory") 1)
  (data (i32.const 8) "{path}")
  (data (i32.const 32) "BBBBBBBB")
  (data (i32.const 64) "\\20\\00\\00\\00\\08\\00\\00\\00")
  (func (export "_start") (local $i i32) (local $fd i32) (local $e i32)
    ;; optional pre-loop setup (open the probe file once)
{setup}
    (loop $l
{body}
      local.get $i
      i32.const 1
      i32.add
      local.set $i
      local.get $i
      i32.const {n}
      i32.lt_u
      br_if $l
    )
    i32.const 0
    call $exit
  )
)
"""

EMPTY_SETUP = ""
OPEN_RW_SETUP = """    ;; path_open(dirfd=3, "probe.txt", O_CREAT, read+write rights, &fd@100)
    i32.const 3 i32.const 0 i32.const 8 i32.const 9 i32.const 1
    i64.const 70 i64.const 70 i32.const 0 i32.const 100
    call $open
    local.set $e
    local.get $e
    if i32.const 2 call $exit end"""

# NOTE: the setup phase uses the SAME imported function as the loop for
# open-file variants; those variants therefore import fd_open-capable
# path_open and use a second import for the measured call. To keep the
# harness single-import, open-file variants measure the PAIR
# (setup excluded from the loop) — the loop body re-opens/closes or
# reads/writes via the stored fd. Two shapes below:
#  A) one-shot setup + loop on stored fd (read/write/seek/stat)
#  B) open+close pair inside the loop (path_open cost measured directly)

VARIANTS = {
    # name: (fn, params, setup, body, N, needs_dirs)
    "baseline_loop": (
        "clock_time_get", "(param i32 i64 i32)", EMPTY_SETUP,
        "      ;; (no syscall — baseline loop; import unused)",
        50_000, False,
    ),
    "clock_time_get": (
        "clock_time_get", "(param i32 i64 i32)",
        EMPTY_SETUP,
        "      i32.const 0 i64.const 1 i32.const 512 call $f drop",
        50_000, False,
    ),
    "random_get": (
        "random_get", "(param i32 i32)",
        EMPTY_SETUP,
        "      i32.const 512 i32.const 32 call $f drop",
        50_000, False,
    ),
    "sched_yield": (
        "sched_yield", "(param )",
        EMPTY_SETUP,
        "      call $f drop",
        10_000, False,
    ),
    "environ_sizes_get": (
        "environ_sizes_get", "(param i32 i32)",
        EMPTY_SETUP,
        "      i32.const 512 i32.const 516 call $f drop",
        50_000, False,
    ),
    "fd_prestat_get": (
        "fd_prestat_get", "(param i32 i32)",
        EMPTY_SETUP,
        "      i32.const 3 i32.const 512 call $f drop",
        50_000, True,   # fd 3 only exists with a preopen
    ),
    "fd_fdstat_get": (
        "fd_fdstat_get", "(param i32 i32)",
        EMPTY_SETUP,
        "      i32.const 3 i32.const 512 call $f drop",
        50_000, True,
    ),
    "fd_filestat_get": (
        "fd_filestat_get", "(param i32 i32)",
        EMPTY_SETUP,
        "      i32.const 3 i32.const 512 call $f drop",
        50_000, True,
    ),
    "fd_write_stdout_capped": (
        "fd_write", "(param i32 i32 i32 i32)",
        EMPTY_SETUP,
        # fd 1 = custom sink; 10k x 8B exceeds the 10KB budget -> EFBIG-
        # style capped sink returns (this measures the CAPPED path)
        "      i32.const 1 i32.const 64 i32.const 1 i32.const 104 call $f drop",
        20_000, False,
    ),
    "fd_write_file_real": (
        "fd_write", "(param i32 i32 i32 i32)",
        OPEN_RW_SETUP,
        "      i32.const 100 i32.load i32.const 64 i32.const 1 i32.const 104"
        " call $f drop",
        10_000, True,
    ),
    "fd_read_file_real": (
        "fd_read", "(param i32 i32 i32 i32)",
        OPEN_RW_SETUP,
        "      i32.const 100 i32.load i32.const 64 i32.const 1 i32.const 104"
        " call $f drop",
        10_000, True,
    ),
    "fd_seek_file": (
        "fd_seek", "(param i32 i64 i32 i32)",
        OPEN_RW_SETUP,
        "      i32.const 100 i32.load i64.const 0 i32.const 0 i32.const 104"
        " call $f drop",
        50_000, True,
    ),
    "path_open_plus_close": (
        "path_open", "(param i32 i32 i32 i32 i32 i64 i64 i32 i32)",
        EMPTY_SETUP,
        # open "probe.txt" (creat) + fd_close per iteration = full open cost
        "      i32.const 3 i32.const 0 i32.const 8 i32.const 9 i32.const 1"
        " i64.const 70 i64.const 70 i32.const 0 i32.const 512 call $f drop"
        "\n      i32.const 512 i32.load call $close drop",
        1_000, True,
    ),
}

# fd_close import needed by path_open_plus_close — handled via a second
# import injected in the template below.
TWO_IMPORT_TEMPLATE = """
(module
  (import "wasi_snapshot_preview1" "{fn}" (func $f {params} (result i32)))
  (import "wasi_snapshot_preview1" "fd_close" (func $close (param i32) (result i32)))
  (import "wasi_snapshot_preview1" "path_open" (func $open
    (param i32 i32 i32 i32 i32 i64 i64 i32 i32) (result i32)))
  (import "wasi_snapshot_preview1" "proc_exit" (func $exit (param i32)))
  (memory (export "memory") 1)
  (data (i32.const 8) "{path}")
  (data (i32.const 32) "BBBBBBBB")
  (data (i32.const 64) "\\20\\00\\00\\00\\08\\00\\00\\00")
  (func (export "_start") (local $i i32) (local $fd i32) (local $e i32)
{setup}
    (loop $l
{body}
      local.get $i
      i32.const 1
      i32.add
      local.set $i
      local.get $i
      i32.const {n}
      i32.lt_u
      br_if $l
    )
    i32.const 0
    call $exit
  )
)
"""


def run_variant(name: str, spec: tuple, datadir: Path) -> dict:
    fn, params, setup, body, n, needs_dirs = spec
    if name == "fd_read_file_real":
        # pre-create the probe file so reads return data
        probe = datadir / "probe.txt"
        if not probe.exists():
            probe.write_text("X" * 4096)
    wat = TWO_IMPORT_TEMPLATE.format(
        fn=fn, params=params, setup=setup, body=body, n=n, path="probe.txt"
    )
    wasm = wasmtime.wat2wasm(wat)
    probe_path = datadir / "probe.txt"
    config = WASIConfig(
        max_fuel=5_000_000_000,
        timeout_seconds=60,
        allow_dirs=(str(datadir),) if needs_dirs else (),
    )
    sandbox = WASISandbox(config=config)
    wasm_file = datadir / f"probe_{name}.wasm"
    wasm_file.write_bytes(wasm)
    t0 = time.perf_counter()
    try:
        result = sandbox.run(str(wasm_file))
    finally:
        sandbox.cleanup()
    wall = time.perf_counter() - t0
    if result.status.value != "success":
        raise RuntimeError(
            f"{name}: status={result.status.value} exit={result.exit_code} "
            f"stderr={result.stderr[:300]!r}"
        )
    assert result.fuel_consumed is not None, f"{name}: no fuel reported"
    return {
        "name": name,
        "n": n,
        "fuel_consumed": result.fuel_consumed,
        "fuel_per_iteration": round(result.fuel_consumed / n, 3),
        "host_wall_seconds": round(wall, 4),
        "host_us_per_call": round(wall * 1e6 / n, 3),
    }


def main() -> int:
    stamp = time.strftime("%Y-%m-%d")
    outdir = Path(__file__).resolve().parent
    datadir = Path.home() / f".ephemora_m10_{time.monotonic_ns()}"
    datadir.mkdir()
    try:
        results = {}
        for name, spec in VARIANTS.items():
            results[name] = run_variant(name, spec, datadir)
            print(
                f"{name:26s} fuel/iter={results[name]['fuel_per_iteration']:9.2f} "
                f"host_us/call={results[name]['host_us_per_call']:8.2f}"
            )
    finally:
        shutil.rmtree(datadir, ignore_errors=True)

    baseline = results["baseline_loop"]["fuel_per_iteration"]
    report = {
        "measured": True,
        "source": "measurement",
        "date": stamp,
        "wasmtime": "47.0.1",
        "method": (
            "counted loop calling one WASI syscall N times, max_fuel set; "
            "fuel_per_iteration = fuel_consumed/N; net syscall cost = "
            "variant - baseline_loop (loop + counter overhead)"
        ),
        "baseline_fuel_per_iteration": baseline,
        "results": [],
    }
    for name, r in results.items():
        row = dict(r)
        if name != "baseline_loop":
            row["net_fuel_per_call"] = round(
                r["fuel_per_iteration"] - baseline, 3
            )
        report["results"].append(row)
    outfile = outdir / f"results_{stamp}.json"
    outfile.write_text(json.dumps(report, indent=2))
    print(f"\nwrote {outfile}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
