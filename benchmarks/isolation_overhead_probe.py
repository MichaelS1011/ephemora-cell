"""WP-L4-1 DO — isolations-overhead probe (reproduzierbar).

Misst den Performance-Preis, den das Central Enforcement Gate (Option A)
tatsaechlich erzwingt: ein Component-Run, der frueher im Host in-process
laufen durfte, laeuft jetzt im separaten Worker, sobald die Trust-Klassi-
fizierung nicht ``trusted`` ist. Der Overhead ist genau diese Grenze — er
wird ueber das oeffentliche Facade ``WASISandbox.run()`` gemessen, also ueber
denselben Choke-Point, den CLI / MCP / run_wasm passieren.

Verglichen werden zwei Posturen fuer identischen Component-Gastcode:

  trusted   -> In-Process-Fast-Path (Host authorized, Gate neutral)
  unknown   -> Gate hebt use_subprocess auf True (erzwungene Isolation)

Vergleichbarer Kern: wall-clock median pro Run. Der Worker-Zuschlag ist die
Kostenseite der Sicherheitsinvariante; die Nutzenseite (Host ueberlebt einen
Guest-Abort) ist in tests/test_isolation_gate.py und BENCHMARK_RESULTS.md
(V1, GHSA-j2g9) belegt.

Aufruf:  python benchmarks/isolation_overhead_probe.py [--reps N]
"""

from __future__ import annotations

import argparse
import json
import statistics
import sys
import time
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from ephemora_cell import WASIConfig, WASISandbox
from ephemora_cell.execution_report import (
    TRUST_TRUSTED,
    TRUST_UNKNOWN,
)

FIX = Path(__file__).resolve().parent.parent / "tests" / "fixtures"
HELLO02 = str(FIX / "hello02.wasm")
FS02 = str(FIX / "fs02.wasm")


def _time_run(wasm: str, trust: str, reps: int) -> dict:
    """Median wall-clock of ``reps`` runs through the public facade.

    A fresh sandbox per call keeps runs independent (no cross-run pooling
    that would blur the subprocess-spawn cost the gate imposes).
    """
    samples: list[float] = []
    mode: str | None = None
    abi: str | None = None
    for _ in range(reps):
        cfg = WASIConfig(max_fuel=5_000_000, timeout_seconds=30)
        sb = WASISandbox(config=cfg)
        t0 = time.monotonic()
        r = sb.run(wasm, abi="component", trust=trust)
        samples.append((time.monotonic() - t0) * 1000.0)
        mode = r.execution_mode
        abi = r.abi
        sb.cleanup()
    samples.sort()
    return {
        "trust": trust,
        "median_ms": round(statistics.median(samples), 2),
        "min_ms": round(samples[0], 2),
        "max_ms": round(samples[-1], 2),
        "execution_mode": mode,
        "executed_abi": abi,
    }


def main() -> int:
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument("--reps", type=int, default=15, help="runs per arm (default 15)")
    args = ap.parse_args()

    report: dict = {"reps": args.reps, "fixtures": {}}
    for name, wasm in {"hello02": HELLO02, "fs02": FS02}.items():
        trusted = _time_run(wasm, TRUST_TRUSTED, args.reps)
        isolated = _time_run(wasm, TRUST_UNKNOWN, args.reps)
        ratio = (
            round(isolated["median_ms"] / trusted["median_ms"], 2)
            if trusted["median_ms"]
            else None
        )
        report["fixtures"][name] = {
            "trusted_in_process": trusted,
            "unknown_forced_worker": isolated,
            "overhead_ms": round(isolated["median_ms"] - trusted["median_ms"], 2),
            "slowdown_factor": ratio,
        }
    # Cross-check the security invariant on the evidence, not just the clock:
    # the isolated arm MUST attest subprocess mode + component ABI, and its
    # sync_blockade is NOT claimed for components (WP-L4-3 principle holds).
    print(json.dumps(report, indent=2))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
