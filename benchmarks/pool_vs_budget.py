"""Pooled vs default-path latency — which config earns the 'warm pooled' claim?

The engine pool is bypassed whenever io_budget_bytes is set (default:
64 MiB, ADR-002) or an external interrupt_event is passed, because budgeted
runs need a per-run engine with deadline=1 (epoch-interruption contract).
The README's "0.12ms warm pooled" therefore holds only for trusted runs
with io_budget_bytes=None; the DEFAULT one-liner is a per-run-engine path.

Since 1.2.0 there is a second split (ADR-015): only ``trust="trusted"``
(an explicit host authorisation) keeps the in-process fast path; a run under
any other posture (``unknown`` is the default) is routed through the
disposable worker process. The first two scenarios pin ``trust="trusted"``
so they keep measuring the in-process engine question; the third scenario
measures the actual default posture — the worker's process lifecycle cost.

This measures all three, wall-clock around WASISandbox.run() (engine build
included), n timed runs after 50 warmup runs, hello.wasm guest. Output JSON
carries the measured:true convention (source: measurement).
"""

from __future__ import annotations

import json
import platform
import statistics
import sys
import time
from datetime import date, datetime
from importlib.metadata import version as _pkg_version
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from ephemora_cell import WASIConfig, WASISandbox

WARMUP = 50
WASM = Path(__file__).resolve().parents[1] / "examples" / "hello.wasm"

SCENARIOS = {
    "pooled_warm (trust=trusted, io_budget_bytes=None)": (
        WASIConfig(io_budget_bytes=None),
        "trusted",
    ),
    "default (trust=trusted, io_budget_bytes=64MiB, per-run engine)": (
        WASIConfig(),
        "trusted",
    ),
    "default_posture (trust=unknown -> disposable worker, ADR-015)": (
        WASIConfig(),
        "unknown",
    ),
}


def measure(name: str, config: WASIConfig, trust: str, n: int = 1000) -> dict:
    sandbox = WASISandbox(config=config)
    try:
        for _ in range(WARMUP):
            result = sandbox.run(str(WASM), trust=trust)
            assert result.status.name == "SUCCESS", result.stderr[:200]
        walls = []
        elapsed = []
        for _ in range(n):
            t0 = time.perf_counter()
            result = sandbox.run(str(WASM), trust=trust)
            walls.append((time.perf_counter() - t0) * 1000)
            elapsed.append(result.elapsed_ms)
        walls.sort()
        elapsed.sort()
        return {
            "n": n,
            "trust": trust,
            "wall_ms_median": round(statistics.median(walls), 4),
            "wall_ms_p95": round(walls[int(0.95 * len(walls))], 4),
            "wall_ms_min": round(walls[0], 4),
            "guest_elapsed_ms_median": round(statistics.median(elapsed), 4),
        }
    finally:
        sandbox.cleanup()


def main() -> None:
    import argparse

    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--n", type=int, default=1000,
                        help="timed runs per scenario (default 1000)")
    args = parser.parse_args()
    n = args.n

    out = {
        "measured": True,
        "source": "measurement",
        "date": str(date.today()),
        "generated_at": datetime.now().isoformat(timespec="seconds"),
        "python": platform.python_version(),
        "wasmtime": _pkg_version("wasmtime"),
        "guest": "examples/hello.wasm",
        "n": n,
        "warmup": WARMUP,
        "scenarios": {},
    }
    for name, (config, trust) in SCENARIOS.items():
        out["scenarios"][name] = measure(name, config, trust, n)
        print(f"{name}:")
        for key, value in out["scenarios"][name].items():
            print(f"  {key}: {value}")

    results_dir = (
        Path(__file__).resolve().parents[1]
        / "benchmarks"
        / "results"
        / str(date.today())
    )
    results_dir.mkdir(parents=True, exist_ok=True)
    dest = results_dir / "pool_vs_budget.json"
    dest.write_text(json.dumps(out, indent=2))
    print(f"\nRaw: {dest}")


if __name__ == "__main__":
    main()
