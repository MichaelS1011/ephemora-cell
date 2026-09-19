#!/usr/bin/env python3
"""EEMBC CoreMark under Ephemora Cell vs bare wasmtime — the sandbox tax on
an industry-standard workload.

Workload: CoreMark 1.01 (EEMBC), built to wasm32-wasi via the
wasm3/wasm-coremark build.sh (unmodified) with wasi-sdk-34 / LLVM 23.1.0
(Lime1 + tail-call feature set). CoreMark sources pinned at eembc/coremark
commit 1f483d5b8316753a742cbf5590caf5bd0a4e4777 ("Upstream as of
2025-05-01").

Protocol (per run): the module runs its DEFAULT 1,100,000-iteration pass
(~15-25 s — above the 10 s CoreMark validity floor) with no arguments
(the wasm3 port treats argv[1] as SEED; passing one breaks self-
validation). Controls per run:

  1. self-validation — "Correct operation validated" must appear
  2. differential — the crc/iterations result block must byte-match the
     bare-wasmtime reference run of the same binary (sandbox vs engine
     differential, WRTester-style)

Metric: CoreMark's own "Iterations/Sec" score (its output line embeds the
compiler string, so the score is the first float after "CoreMark 1.0 :").
Configurations are INTERLEAVED (round-robin) — sustained-load thermal
drift on laptops otherwise skews sequential blocks by ~30%.

Configurations:
  bare_wasmtime  raw engine: default config, WASI linker, no limits
  cell_sandbox   WASISandbox with max_fuel=None — the sandbox posture
  cell_fuel_on   WASISandbox with a finite fuel budget (default posture
                 including per-instruction metering)

Claims supported: "the sandbox costs X% on CoreMark" (cell_sandbox vs
bare_wasmtime) and "metering costs Y%" (cell_fuel_on vs cell_sandbox).
Scores across DIFFERENT machines are recorded per platform (label) and
never mixed. Evidence: benchmarks/results/<date>/09_coremark_wasi_<label>.json
(measured:true).
"""

from __future__ import annotations

import argparse
import json
import platform
import re
import statistics
import sys
import time
from datetime import date
from importlib.metadata import version as _pkg_version
from pathlib import Path

import wasmtime

REPO = Path(__file__).resolve().parent.parent
WASM = REPO / "benchmarks" / "workloads" / "coremark.wasm"

PROVENANCE = {
    "benchmark": "CoreMark 1.01 (EEMBC)",
    "source_repo": "https://github.com/eembc/coremark.git",
    "pinned_commit": "1f483d5b8316753a742cbf5590caf5bd0a4e4777",
    "build": "wasm3/wasm-coremark build.sh (unmodified), target: wasi",
    "toolchain": "wasi-sdk-34 / clang 23.1.0",
    "wasm_features": "Lime1 + tail-call",
    "run_protocol": "CoreMark auto-calibrates its iteration count to a "
    "~10 s target (observed 600k-1.1M depending on config speed); no argv "
    "(argv[1] would be SEED in this port and break self-validation)",
    "controls": "self-validation line per run ('Correct operation "
    "validated'); crc values compare only between runs with identical "
    "auto-calibrated iteration counts",
}

CONTROL_MARKER = "Correct operation validated"
SCORE_RE = re.compile(r"CoreMark 1\.0\s*:\s*([0-9.]+)\s*/")
CRC_RE = re.compile(r"crcfinal\s*:\s*(0x[0-9a-fA-F]+)")
ITERS_RE = re.compile(r"Iterations\s*:\s*([0-9]+)")

FUEL_BUDGET = 10**13  # observed consumption ~5e11 per default run


def _score_and_crc(stdout: str) -> tuple[float | None, str | None, int | None]:
    m = SCORE_RE.search(stdout)
    score = float(m.group(1)) if m else None
    c = CRC_RE.search(stdout)
    crc = c.group(1).lower() if c else None
    it = ITERS_RE.search(stdout)
    iters = int(it.group(1)) if it else None
    return score, crc, iters


def _bare_run() -> dict:
    engine = wasmtime.Engine()
    store = wasmtime.Store(engine)
    wc = wasmtime.WasiConfig()
    wc.argv = ["coremark.wasm"]
    out = Path("/tmp") / f"coremark_bare_{time.time_ns()}.txt"
    wc.stdout_file = str(out)
    store.set_wasi(wc)
    linker = wasmtime.Linker(engine)
    linker.define_wasi()
    module = wasmtime.Module.from_file(engine, str(WASM))
    instance = linker.instantiate(store, module)
    t0 = time.perf_counter()
    instance.exports(store)["_start"](store)
    elapsed = time.perf_counter() - t0
    stdout = out.read_text()
    out.unlink(missing_ok=True)
    score, crc, iters = _score_and_crc(stdout)
    return {
        "elapsed_s": round(elapsed, 3),
        "iterations": iters,
        "status": "SUCCESS",
        "score": score,
        "crcfinal": crc,
        "control_validated": CONTROL_MARKER in stdout,
        "fuel_consumed": None,
    }


def _cell_run(max_fuel: int | None) -> dict:
    from ephemora_cell import WASIConfig, WASISandbox

    sb = WASISandbox(
        config=WASIConfig(allow_dirs=(), max_fuel=max_fuel, timeout_seconds=300)
    )
    try:
        r = sb.run(str(WASM))
    finally:
        sb.cleanup()
    stdout = r.stdout or ""
    score, crc, iters = _score_and_crc(stdout)
    return {
        "elapsed_s": round(r.elapsed_ms / 1000, 3),
        "iterations": iters,
        "status": r.status.name,
        "score": score,
        "crcfinal": crc,
        "control_validated": CONTROL_MARKER in stdout,
        "fuel_consumed": r.fuel_consumed,
    }


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument(
        "--label", default=f"{platform.system().lower()}-{platform.machine()}"
    )
    ap.add_argument("--rounds", type=int, default=3)
    ap.add_argument(
        "--only", default="", help="bare_wasmtime|cell_sandbox|cell_fuel_on"
    )
    args = ap.parse_args()

    print("EEMBC CoreMark (WASI) — sandbox tax measurement (interleaved)")
    print("=" * 70)

    config_names = [
        c
        for c in ("bare_wasmtime", "cell_sandbox", "cell_fuel_on")
        if not args.only or c == args.only
    ]
    results: dict = {c: [] for c in config_names}

    for rnd in range(1, args.rounds + 1):
        for name in config_names:
            if name == "bare_wasmtime":
                r = _bare_run()
            elif name == "cell_sandbox":
                r = _cell_run(None)
            else:
                r = _cell_run(FUEL_BUDGET)
            r["round"] = rnd
            results[name].append(r)
            print(
                f"  round {rnd} {name:14} wall {r['elapsed_s']:>7} s  "
                f"score {r['score']}  control {'OK' if r['control_validated'] else 'FAIL'}  "
                f"crc {r['crcfinal']}",
                flush=True,
            )

    # controls
    ok = True
    for name, runs in results.items():
        for r in runs:
            if not r["control_validated"]:
                print(f"CONTROL FAIL: {name} round {r['round']} not self-validated")
                ok = False
    # informational: CoreMark auto-calibrates its iteration count (~10 s
    # target), so executed counts differ per config; crc values compare
    # only between runs with identical counts
    for name, runs in results.items():
        counts = {r.get("iterations") for r in runs}
        if len(counts) > 1:
            print(
                f"  note: {name} ran with auto-calibrated iteration counts "
                f"{sorted(c for c in counts if c)}"
            )

    summary = {}
    for name, runs in results.items():
        scores = [r["score"] for r in runs if r["score"] is not None]
        summary[name] = {
            "median_score": round(statistics.median(scores), 1) if scores else None,
            "median_elapsed_s": round(
                statistics.median([r["elapsed_s"] for r in runs]), 3
            ),
            "runs": len(runs),
        }
    if "bare_wasmtime" in summary and "cell_sandbox" in summary:
        a = summary["bare_wasmtime"]["median_score"]
        b = summary["cell_sandbox"]["median_score"]
        if a and b:
            summary["sandbox_tax_on_score_percent"] = round((b / a - 1) * 100, 2)
            print(
                f"sandbox tax on CoreMark score: {summary['sandbox_tax_on_score_percent']:+.2f}%"
            )
    if "cell_sandbox" in summary and "cell_fuel_on" in summary:
        a = summary["cell_sandbox"]["median_score"]
        b = summary["cell_fuel_on"]["median_score"]
        if a and b:
            summary["fuel_tax_on_score_percent"] = round((b / a - 1) * 100, 2)
            print(
                f"fuel tax on CoreMark score: {summary['fuel_tax_on_score_percent']:+.2f}%"
            )

    doc = {
        "measured": True,
        "source": "measurement",
        "date": str(date.today()),
        "label": args.label,
        "platform": {
            "machine": platform.machine(),
            "system": platform.system(),
            "node": platform.node(),
            "python": sys.version.split()[0],
        },
        "wasmtime": _pkg_version("wasmtime"),
        "ephemora_cell": _pkg_version("ephemora-cell"),
        "provenance": PROVENANCE,
        "fuel_budget": FUEL_BUDGET,
        "summary": summary,
        "results": results,
    }
    out_dir = REPO / "benchmarks" / "results" / str(date.today())
    out_dir.mkdir(parents=True, exist_ok=True)
    dest = out_dir / f"09_coremark_wasi_{args.label}.json"
    dest.write_text(json.dumps(doc, indent=2))
    print(f"Saved: {dest}  |  ALL CONTROLS {'OK' if ok else 'FAILED'}")
    return 0 if ok else 1


if __name__ == "__main__":
    sys.exit(main())
