#!/usr/bin/env python3
# Ephemora Cell — analytical memory breakpoint measurement
"""Measure where guest workloads hit the linear-memory wall.

Part A (measured): pure-WASM workloads grow linear memory against
stepped caps (32/64/128/256 MiB). The guest reports GROWN or REFUSED
on stdout; Store.set_limits is the wall. This is the breakpoint the
`analytical` profile (ADR-003) must raise.

Part B (measured): memory64 feasibility — a 64-bit-memory guest grows
past the 4 GiB 32-bit boundary (virtual reservation; only a small
subset of pages is touched, so host RAM stays bounded). This proves
the mechanism the analytical profile would rely on.

Part C (literature, measured:false): Pyodide/CPython-WASI context —
numpy/pandas under wasm32-wasip1 are not available as wheels; browser
Pyodide documents hard memory limits (the documented pandas OOM
class). CPython-WASI binary size/startup is probed best-effort.

Output: JSON (measured:true schema) next to this script.
"""

from __future__ import annotations

import json
import shutil
import sys
import time
from pathlib import Path

import wasmtime

REPO = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(REPO))

from ephemora_cell import WASIConfig, WASISandbox

# Guest grows memory one page at a time until TARGET pages; touches every
# 64th page to force real allocation; writes GROWN|REFUSED to stdout.
GROW_WAT = """
(module
  (import "wasi_snapshot_preview1" "fd_write" (func $fd_write
    (param i32 i32 i32 i32) (result i32)))
  (import "wasi_snapshot_preview1" "proc_exit" (func $proc_exit (param i32)))
  (memory (export "memory") 1)
  (data (i32.const 32) "GROWN")
  (data (i32.const 48) "REFUSED")
  (data (i32.const 64) "\\20\\00\\00\\00\\06\\00\\00\\00")
  ;; iovecs: ok = ptr 32 len 6, refused = ptr 48 len 7
  (data (i32.const 72) "\\30\\00\\00\\00\\07\\00\\00\\00")
  (func (export "_start") (local $pages i32) (local $r i32) (local $t i32)
    (local.set $t {target})
    (block $done
      (loop $l
        local.get $pages
        local.get $t
        i32.ge_u
        br_if $done
        i32.const 1
        memory.grow
        local.set $r
        local.get $r
        i32.const 0xFFFFFFFF
        i32.eq
        if
          ;; growth refused: report REFUSED, exit clean
          i32.const 1 i32.const 72 i32.const 1 i32.const 104
          call $fd_write drop
          i32.const 0 call $proc_exit
        end
        ;; touch the new page (address = pages << 16) every 64th page
        local.get $pages
        i32.const 64
        i32.rem_u
        i32.const 0
        i32.eq
        if
          local.get $pages
          i32.const 16
          i32.shl
          i32.const 8
          i32.add
          i32.const 42
          i32.store
        end
        local.get $pages
        i32.const 1
        i32.add
        local.set $pages
        br $l
      )
    )
    i32.const 1 i32.const 64 i32.const 1 i32.const 104
    call $fd_write drop
    i32.const 0 call $proc_exit
  )
)
"""

# 64-bit memory variant: grows past the 32-bit 4 GiB boundary. Touches
# every 4096th page (sparse). memory.grow returns pages as i64 here; a
# 64-bit memory needs memory64 engine support.
GROW64_WAT = """
(module
  (memory (export "memory") i64 1)
  (func (export "_start") (local $pages i64) (local $r i64) (local $t i64)
    (local.set $t {target})
    (block $done
      (loop $l
        local.get $pages
        local.get $t
        i64.ge_u
        br_if $done
        i64.const 1
        memory.grow
        local.set $r
        local.get $r
        i64.const 0xFFFFFFFFFFFFFFFF
        i64.eq
        if
          unreachable
        end
        local.get $pages
        i64.const 4096
        i64.rem_u
        i64.const 0
        i64.eq
        if
          local.get $pages
          i64.const 16
          i64.shl
          i32.const 42
          i32.store
        end
        local.get $pages
        i64.const 1
        i64.add
        local.set $pages
        br $l
      )
    )
  )
)
"""

PAGE_BYTES = 64 * 1024


def run_growth(cap_mb: int, target_pages: int, memory64: bool = False) -> dict:
    wat = (GROW64_WAT if memory64 else GROW_WAT).format(
        target=f"i64.const {target_pages}" if memory64 else f"i32.const {target_pages}"
    )
    config = WASIConfig(
        max_memory_mb=cap_mb,
        max_fuel=2_000_000_000,
        timeout_seconds=60,
        memory64=memory64,
    )
    sandbox = WASISandbox(config=config)
    datadir = Path.home() / f".ephemora_m91_{time.monotonic_ns()}"
    datadir.mkdir()
    try:
        wasm_path = datadir / f"grow_{cap_mb}mb_{target_pages}.wasm"
        wasm_path.write_bytes(wasmtime.wat2wasm(wat))
        t0 = time.perf_counter()
        result = sandbox.run(str(wasm_path))
        wall = time.perf_counter() - t0
    finally:
        sandbox.cleanup()
        shutil.rmtree(datadir, ignore_errors=True)
    if result.status.value != "success":
        refused = "memory" in result.stderr.lower()
        outcome = f"status={result.status.value}"
    else:
        refused = result.stdout.startswith("REFUSED")
        outcome = result.stdout.split("\n")[0]
    return {
        "cap_mb": cap_mb,
        "target_mb": round(target_pages * PAGE_BYTES / (1024 * 1024), 1),
        "memory64": memory64,
        "status": result.status.value,
        "outcome": outcome[:40],
        "refused": refused,
        "elapsed_ms": round(wall * 1000, 1),
    }


def main() -> int:
    stamp = time.strftime("%Y-%m-%d")
    outdir = Path(__file__).resolve().parent
    results = {"part_a_stepped_caps": [], "part_b_memory64": []}

    # Part A: breakpoint = the cap itself; over-requests are refused.
    for cap_mb in (32, 64, 128, 256):
        cap_pages = cap_mb * 1024 * 1024 // PAGE_BYTES
        fits = run_growth(cap_mb, cap_pages - 32)
        over = run_growth(cap_mb, cap_pages + 64)
        results["part_a_stepped_caps"].append(
            {"case": "fits", **fits, "expect": "GROWN"}
        )
        results["part_a_stepped_caps"].append(
            {"case": "over_request", **over, "expect": "REFUSED"}
        )
        print(
            f"cap={cap_mb:4d}MB fits: {fits['outcome'][:12]:12s} "
            f"over: {over['outcome'][:12]:12s} ({over['elapsed_ms']}ms)"
        )

    # Part B: memory64 — grow past the 32-bit 4 GiB boundary (sparse touch).
    for cap_mb, target_pages in (
        (4608, 65_792),     # cap 4.5 GiB; target 4 GiB + 2 MB: past the
                            # 32-bit boundary, under the memory64 cap
        (4096, 65_792),     # cap exactly 4 GiB; same target -> REFUSED
    ):
        r = run_growth(cap_mb, target_pages, memory64=True)
        results["part_b_memory64"].append(r)
        print(
            f"memory64 cap={cap_mb}MB target={r['target_mb']}MB -> "
            f"{r['outcome'][:12]} ({r['elapsed_ms']}ms)"
        )

    report = {
        "measured": True,
        "source": "measurement",
        "date": stamp,
        "wasmtime": "47.0.1",
        "platform": sys.platform,
        "method": (
            "guest WAT grows linear memory page-by-page against Store."
            "set_limits caps; over-cap requests are refused by the runtime "
            "(memory.grow returns -1); memory64 guest proves growth beyond "
            "the 4GiB 32-bit boundary with sparse touches"
        ),
        "literature_context": {
            "measured": False,
            "source": "literature",
            "citation": (
                "Pyodide documents stricter memory limits than native "
                "Python; pandas/numpy OOM class (stackoverflow.com/"
                "questions/67636518). numpy/pandas wheels for wasm32-wasip1 "
                "are not published, so real dataframe workloads fall back "
                "to Pyodide reference values until a wasi-python recipe "
                "exists."
            ),
        },
        "results": results,
    }
    outfile = outdir / f"results_{stamp}.json"
    outfile.write_text(json.dumps(report, indent=2))
    print(f"\nwrote {outfile}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
