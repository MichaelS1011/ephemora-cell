#!/usr/bin/env python3
"""Deterministic execution research (verification only, no engine change).

Extends `benchmarks/determinism_probe.py` along the distinction that probe does
not cover: the existing probe reports `fuel_consumed` and wall time only, so it
demonstrates *fuel* determinism but never compares the *result bytes*. This
script keeps the two properties separate and measures each explicitly:

  A. result equality   — output-bytes digest + status, identical across runs?
  B. fuel determinism  — fuel_consumed spread across runs (measured on its own;
                         identical fuel is NOT read back as identical output)

Reuse over reimplementation: same tool, same config, same real Engine — no new
replay mechanism, no runtime-profile change, no extra WASM features.

The environment line reports the ACTUAL wasmtime version from installed
distribution metadata, because the older probe hard-coded a stale "47.0.1"
label while the release line moved to a 49.0.0 pin.

Run with the project venv (the freeze-baseline interpreter), never a stray one:

    python benchmarks/determinism_research.py [N]
"""

from __future__ import annotations

import hashlib
import importlib.metadata as md
import json
import platform
import statistics
import subprocess
import sys
from pathlib import Path

REPO = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(REPO))

from ephemora_cell import WASIConfig, WASISandbox

# Reuse the established determinism workload (also cited in docs/performance.md).
TOOLS = {
    "echo": REPO / "ephemora_cell_mcp" / "tools" / "echo.wasm",
}
STDIN = json.dumps({"params": {"greeting": "probe"}})
N = int(sys.argv[1]) if len(sys.argv) > 1 else 11

# One fixed config — identical for every run so the only variable is the run.
CONFIG = WASIConfig(max_memory_mb=128, max_fuel=2_000_000, timeout_seconds=30)


def _env() -> dict:
    def _git(*a: str) -> str:
        try:
            return subprocess.run(
                ["git", *a], cwd=REPO, capture_output=True, text=True, check=True
            ).stdout.strip()
        except Exception:
            return ""

    try:
        wasmtime_ver = md.version("wasmtime")
    except Exception as exc:  # pragma: no cover
        wasmtime_ver = f"unavailable ({type(exc).__name__})"
    return {
        "commit": _git("rev-parse", "HEAD"),
        "branch": _git("rev-parse", "--abbrev-ref", "HEAD"),
        "python": platform.python_version(),
        "wasmtime_dist": wasmtime_ver,
        "platform": f"{platform.system()} {platform.release()}",
        "machine": platform.machine(),
        "config": {
            "max_memory_mb": CONFIG.max_memory_mb,
            "max_fuel": CONFIG.max_fuel,
            "timeout_seconds": CONFIG.timeout_seconds,
        },
    }


def measure(name: str, tool: Path) -> dict:
    box = WASISandbox(CONFIG)
    runs: list[dict] = []
    for _ in range(N):
        report = box.run(str(tool), stdin_data=STDIN)
        stdout = report.stdout or ""
        digest = hashlib.sha256(stdout.encode("utf-8", "replace")).hexdigest()
        status = (
            report.status.value
            if hasattr(report.status, "value")
            else str(report.status)
        )
        runs.append(
            {
                "output_sha256": digest,
                "status": status,
                "fuel_consumed": report.fuel_consumed,
                "stdout_len": len(stdout),
            }
        )

    fuels = [r["fuel_consumed"] for r in runs]
    out_digests = {r["output_sha256"] for r in runs}
    statuses = {r["status"] for r in runs}

    return {
        "tool": name,
        "runs": N,
        # A — result equality (output bytes + status), judged on its own terms
        "result_determinism": {
            "distinct_output_digests": len(out_digests),
            "output_identical_across_runs": len(out_digests) == 1,
            "distinct_statuses": len(statuses),
            "status_identical_across_runs": len(statuses) == 1,
            "output_sha256": sorted(out_digests)[0] if len(out_digests) == 1 else None,
        },
        # B — fuel determinism, measured separately (NOT a proxy for A)
        "fuel_determinism": {
            "fuels": fuels,
            "fuel_spread": max(fuels) - min(fuels),
            "fuel_median": statistics.median(fuels),
            "fuel_identical_across_runs": len(set(fuels)) == 1,
        },
        "per_run": runs,
    }


def main() -> None:
    env = _env()
    results = {}
    for name, tool in TOOLS.items():
        if not tool.exists():
            results[name] = {"skipped": f"{tool.name} not found"}
            continue
        results[name] = measure(name, tool)

    payload = {
        "title": "Deterministic execution research — result vs fuel, separated",
        "measured": True,
        "environment": env,
        "method": "same tool + same config + same stdin, N back-to-back runs "
        "on one interpreter via the real in-process Engine",
        "scope_note": "This measures a DETERMINISTIC guest (echo). It does NOT "
        "exercise guest reads of clock_time_get / random_get, which "
        "the WASI surface exposes; those are classified separately as "
        "host-controlled non-determinism sources, see this research record.",
        "results": results,
    }
    print(json.dumps(payload, indent=2, sort_keys=True))


if __name__ == "__main__":
    main()
