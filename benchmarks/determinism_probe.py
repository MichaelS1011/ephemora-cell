#!/usr/bin/env python3
"""Cross-architecture determinism probe for Ephemora Cell.

Runs the same tool call N times through the real Engine and reports the
ExecutionReport fields. Goal: prove fuel_consumed is deterministic and
identical across architectures (macOS arm64 vs. Ubuntu/Grace arm64 vs.
Ubuntu x86_64) when the wasmtime version is pinned.

Run on any machine with the repo venv installed:

    .venv/bin/python benchmarks/determinism_probe.py
"""

from __future__ import annotations

import json
import statistics
import sys
import time
from pathlib import Path

REPO = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(REPO))

from ephemora_cell import WASISandbox, WASIConfig  # noqa: E402

TOOL = REPO / "ephemora_cell_mcp" / "tools" / "echo.wasm"
N = int(sys.argv[1]) if len(sys.argv) > 1 else 10


def main() -> None:
    if not TOOL.exists():
        raise SystemExit(f"echo.wasm not found at {TOOL}")
    import platform

    config = WASIConfig(max_memory_mb=128, max_fuel=2_000_000, timeout_seconds=30)
    sandbox = WASISandbox(config)
    print(f"machine: {platform.machine()} | sys: {platform.system()} "
          f"{platform.release()} | wasmtime: 47.0.1", file=sys.stderr)
    print(f"tool: {TOOL.name} | runs: {N} | params: {{\"params\": {{\"greeting\": \"probe\"}}}}",
          file=sys.stderr)

    fuels: list[int] = []
    elapsed: list[float] = []
    for _ in range(N):
        t0 = time.perf_counter()
        report = sandbox.run(str(TOOL), stdin_data=json.dumps({"params": {"greeting": "probe"}}))
        dt = (time.perf_counter() - t0) * 1000.0
        fuels.append(report.fuel_consumed)
        elapsed.append(report.elapsed_ms)
    print(json.dumps({
        "fuel_consumed": fuels,
        "fuel_median": statistics.median(fuels),
        "fuel_spread": max(fuels) - min(fuels),
        "elapsed_ms": elapsed,
        "elapsed_median": round(statistics.median(elapsed), 4),
        "elapsed_spread": round(max(elapsed) - min(elapsed), 4),
        "status": report.status.value if hasattr(report.status, "value") else str(report.status),
    }, indent=2))


if __name__ == "__main__":
    main()