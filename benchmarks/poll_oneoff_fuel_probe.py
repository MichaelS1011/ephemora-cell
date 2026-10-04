#!/usr/bin/env python3
"""Does GHSA-j366-h8gg-77pm (poll_oneoff host work without fuel) bite Cell?

The advisory: wasmtime's WASI p1 poll_oneoff performs O(n) host work over the
subscription array without consuming fuel or checking exhaustion. Fixed in
48.0.4 / 49.0.2; the named workaround (-Spreview0=n) is not reachable from
wasmtime-py, so the only lever a Python host has is its own walls.

Probe: same guest instruction count, different subscription count n. If fuel
stays flat while wall time grows with n, the bypass is real on this engine and
the growth shows which wall actually bounds it (fuel cannot).

Run: .venv/bin/python benchmarks/poll_oneoff_fuel_probe.py
Exit 0 = the bypass reproduces on this engine (flat fuel, growing wall).
Exit 1 = it no longer does, so the SECURITY.md triage entry needs re-checking
against whatever engine version is installed at that point.
"""

from __future__ import annotations

import os
import sys
import tempfile
import time
from pathlib import Path

REPO = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(REPO))

import wasmtime  # noqa: E402

from ephemora_cell import WASIConfig, WASISandbox  # noqa: E402

ROUNDS = 400
MEMORY_PAGES = 32  # 2 MiB of zeroed guest memory


def wat_for(nsubs: int) -> str:
    """poll_oneoff(subs /*zeroed*/, events, nsubs, nready_out) in a loop.

    The p1 ABI gives this import FOUR i32 params: the `expected $size` payload
    (number of events stored) comes back through an out-pointer, so a
    three-param declaration does not link against wasmtime 47.

    The subscription area is left ZEROED by the data segment: tag 0 (clock),
    timeout 0, so each subscription is already satisfied and the call should
    return without sleeping. Whatever the guest instruction count is, it is the
    SAME for every n — only the host-side work over the array scales. n=0 is
    the floor: the host rejects it with EINVAL without touching the array.
    """
    sub_bytes = 48
    if nsubs * sub_bytes + nsubs * 16 + 1024 > MEMORY_PAGES * 65536:
        raise SystemExit(f"n={nsubs} does not fit in {MEMORY_PAGES} pages")
    events = nsubs * sub_bytes + 512
    nready = MEMORY_PAGES * 65536 - 64
    return f"""(module
  (import "wasi_snapshot_preview1" "poll_oneoff"
    (func $poll (param i32 i32 i32 i32) (result i32)))
  (memory (export "memory") {MEMORY_PAGES})
  (func (export "_start")
    (local $i i32)
    (block $done
      (loop $l
        (br_if $done (i32.ge_u (local.get $i) (i32.const {ROUNDS})))
        (drop
          (call $poll
            (i32.const 0)
            (i32.const {events})
            (i32.const {nsubs})
            (i32.const {nready})))
        (local.set $i (i32.add (local.get $i) (i32.const 1)))
        (br $l)))))
"""


def measure(nsubs: int) -> dict:
    wasm = tempfile.NamedTemporaryFile(suffix=".wasm", delete=False)
    try:
        wasm.write(wasmtime.wat2wasm(wat_for(nsubs)))
        wasm.close()
        config = WASIConfig(
            max_memory_mb=64,
            max_fuel=200_000_000,
            timeout_seconds=120,
            allow_dirs=(),
        )
        sandbox = WASISandbox(config=config)
        try:
            t0 = time.monotonic()
            result = sandbox.run(wasm.name)
            wall_ms = (time.monotonic() - t0) * 1000
        finally:
            sandbox.cleanup()
    finally:
        os.unlink(wasm.name)
    return {
        "nsubs": nsubs,
        "status": result.status.value,
        "fuel": result.fuel_consumed,
        "wall_ms": round(wall_ms, 1),
        "stderr": (result.stderr or "")[:90],
    }


def main() -> int:
    print(f"poll_oneoff — {ROUNDS} Runden, gleiche Gast-Instruktionen, wachsendes n")
    rows = [measure(n) for n in (0, 1, 500, 5_000, 20_000)]
    for r in rows:
        print(
            f"  n={r['nsubs']:>6} {r['status']:<16} fuel={r['fuel']} "
            f"wall={r['wall_ms']:>8} ms  {r['stderr']}"
        )
    biggest = rows[-1]
    floor = min(r["wall_ms"] for r in rows if r["fuel"] is not None)
    fuels = {r["fuel"] for r in rows}
    print("\nDeutung:")
    print(f"  fuel over all counts: {sorted(fuels)}")
    print(f"  fastest wall={floor} ms  slowest wall={biggest['wall_ms']} ms")
    if len(fuels) == 1 and biggest["wall_ms"] >= 10 * max(floor, 0.1):
        print(
            "\n  Reproduziert: gleichbleibender Fuel-Verbrauch, wachsende Host-Zeit."
            "\n  Die Wall bounded hier — Fuel nicht (GHSA-j366-h8gg-77pm)."
        )
        return 0
    print(
        "\n  NICHT reproduziert: entweder ist die Host-Arbeit jetzt bepreist"
        "\n  (Engine gepatcht — dann M2 neu prüfen) oder der Lauf ist fehlgeschlagen."
        "\n  SECURITY.md-Triage aktualisieren, bevor diese Zahlen zitiert werden."
    )
    return 1


if __name__ == "__main__":
    raise SystemExit(main())
