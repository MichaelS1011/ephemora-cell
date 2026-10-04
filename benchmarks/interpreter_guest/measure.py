#!/usr/bin/env python3
# Ephemora Cell — interpreter-guest measurement (ADR-009 Tier 2)
"""Measure what a BYO interpreter guest actually costs the cell.

Part A (measured): wasi-python 3.10 as the guest — per-call latency
in-process and isolated, fuel per workload, the memory cap the interpreter
needs, and what the default profile does to the same run.

Part B (measured): the same workload class in Docker (python:3.12-slim,
`python3 -c pass`), same machine, same session, same rule as
competitive_benchmark.measure_docker_baseline.

Part C (derived): the interpreter profile's budgets against the measurements.

Pre-declared expectation (written before the run, per benchmarks/
methodology.md): the interpreter's own startup dominates a call, so an
isolated interpreter boot should land in the same order of magnitude as a
Docker Python run — NOT in the sub-millisecond band the cell claims for
compiled modules. If the measurement contradicts that, the measurement wins.

Usage:
    python benchmarks/interpreter_guest/measure.py
    EPHEMORA_BYO_PYTHON=/path/to/python3.10.wasm python benchmarks/interpreter_guest/measure.py
"""

from __future__ import annotations

import json
import os
import shutil
import statistics
import subprocess
import sys
import time
from dataclasses import replace
from pathlib import Path

REPO = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(REPO))

from ephemora_cell import ExecutionStatus, WASISandbox, get_profile  # noqa: E402

DEFAULT_GUEST = Path.home() / ".cache/ephemora-byo/opt/wasi-python"
COLD_BASE = Path.home() / ".cache/ephemora-byo-cold"
TARBALL = Path.home() / ".cache/ephemora-byo/wasi-python-3.10.tgz"
DEST = REPO / "benchmarks/results/2026-10-02"
GUEST_SHA256 = "8e40bfb538b390c1e8b652f4b4369d83d3fd6d1af6b3111631ad80bf0c5a0a02"
GUEST_SOURCE = (
    "https://github.com/singlestore-labs/python-wasi/releases/download/"
    "v3.10-alpha/wasi-python-3.10.tgz"
)

# Guest-side workloads, all CPython startup + a decreasing amount of user
# work. "boot" is the cell-side equivalent of Docker's `python3 -c pass`.
WORKLOADS = {
    "boot": ["-c", "pass"],
    "print": ["-c", "print('hello')"],
    "stdlib": ["-c", "import json; print(json.dumps({'a': [1, 2, 3]}))"],
    "compute": ["-c", "print(sum(range(200000)))"],
}

INPROCESS_RUNS = 25
ISOLATED_RUNS = 15
DOCKER_RUNS = 25
# Boots to measure on a freshly extracted tree before declaring it unprimed
# (see measure_cold_vs_warm — the tree reached its steady boot cost inside
# this many boots when measured).
BOOT_PRIMING_RUNS = 12
MEMORY_STEPS_MB = (64, 128, 256, 512, 1024, 2048)


def _guest_paths() -> tuple[Path, Path] | None:
    root = Path(os.environ.get("EPHEMORA_BYO_PYTHON_ROOT", DEFAULT_GUEST))
    wasm = root / "bin/python3.10.wasm"
    stdlib = root / "lib/python3.10"
    if not wasm.is_file() or not stdlib.is_dir():
        return None
    return wasm, stdlib


def _importer_sha256(path: Path) -> str:
    import hashlib

    h = hashlib.sha256()
    with path.open("rb") as f:
        for chunk in iter(lambda: f.read(1 << 20), b""):
            h.update(chunk)
    return h.hexdigest()


def _stats(samples: list[float], extra: dict) -> dict:
    ordered = sorted(samples)
    return {
        "measured": True,
        "count": len(ordered),
        "mean_ms": round(statistics.fmean(ordered), 3),
        "median_ms": round(statistics.median(ordered), 3),
        "p95_ms": round(ordered[min(len(ordered) - 1, int(0.95 * len(ordered)))], 3),
        "min_ms": round(ordered[0], 3),
        "max_ms": round(ordered[-1], 3),
        **extra,
    }


def _measure_runs(
    sandbox: WASISandbox,
    wasm: str,
    args: list[str],
    *,
    isolated: bool,
    runs: int,
) -> dict:
    latencies: list[float] = []
    fuels: list[int] = []
    statuses: dict[str, int] = {}
    last_stderr = ""
    for _ in range(runs):
        start = time.perf_counter()
        result = sandbox.run(wasm, args=args, use_subprocess=isolated)
        latencies.append((time.perf_counter() - start) * 1000)
        key = result.status.value
        statuses[key] = statuses.get(key, 0) + 1
        last_stderr = result.stderr or ""
        if result.fuel_consumed is not None:
            fuels.append(result.fuel_consumed)
        if result.status is not ExecutionStatus.SUCCESS:
            break
    if statuses.get("success", 0) != runs:
        return {
            "measured": True,
            "count": runs,
            "statuses": statuses,
            "stderr_tail": last_stderr[-300:],
        }
    return _stats(
        latencies,
        {
            "fuel_mean": round(statistics.fmean(fuels)) if fuels else None,
            "fuel_max": max(fuels) if fuels else None,
            "statuses": statuses,
        },
    )


def measure_cell(wasm: Path, stdlib: Path) -> dict:
    """Latency + fuel per workload, both execution paths."""
    # The interpreter reads its stdlib through a preopen mapped to the path
    # CPython was configured with — this build has no embedded stdlib.
    # Fuel is deliberately far above any profile here: the measurement must
    # report the guest's true cost, and a truncated run reports nothing.
    config = replace(
        get_profile("interpreter"),
        max_fuel=2_000_000_000,
        allow_dirs=(f"{stdlib}::{stdlib_guest_path(stdlib)}",),
    )
    out: dict = {
        "profile_used": _config_public(config),
        "profile_shipped": _config_public(get_profile("interpreter")),
        "fuel_note": "max_fuel is raised above the shipped profile for "
        "measurement only — a truncated run reports no fuel at all",
    }
    sandbox = WASISandbox(config=config)
    try:
        for name, args in WORKLOADS.items():
            out[name] = {
                "in_process": _measure_runs(
                    sandbox, str(wasm), args, isolated=False, runs=INPROCESS_RUNS
                ),
                "isolated": _measure_runs(
                    sandbox, str(wasm), args, isolated=True, runs=ISOLATED_RUNS
                ),
            }
    finally:
        sandbox.cleanup()

    # What the default profile does to the same guest — the blocker, stated
    # as a measurement instead of an argument.
    default_sandbox = WASISandbox(config=replace(get_profile("default")))
    try:
        res = default_sandbox.run(str(wasm), args=WORKLOADS["boot"])
        out["default_profile_boot"] = {
            "measured": True,
            "status": res.status.value,
            "fuel_consumed": res.fuel_consumed,
            "stderr_tail": (res.stderr or "")[-200:],
        }
    finally:
        default_sandbox.cleanup()
    return out


def stdlib_guest_path(stdlib: Path) -> str:
    """The guest-side path CPython-WASI looks its stdlib up under."""
    return "/opt/wasi-python/lib/python3.10"


def measure_memory_breakpoint(wasm: Path, stdlib: Path) -> dict:
    """Lowest memory cap the interpreter boots under (in-process)."""
    results: dict = {}
    for mb in MEMORY_STEPS_MB:
        config = replace(
            get_profile("interpreter"),
            max_memory_mb=mb,
            allow_dirs=(f"{stdlib}::{stdlib_guest_path(stdlib)}",),
        )
        sandbox = WASISandbox(config=config)
        try:
            res = sandbox.run(str(wasm), args=WORKLOADS["boot"])
        finally:
            sandbox.cleanup()
        results[f"{mb}_mb"] = {
            "status": res.status.value,
            "fuel_consumed": res.fuel_consumed,
        }
        if res.status is ExecutionStatus.SUCCESS:
            results["first_cap_mib"] = mb
            break
    return results


def measure_cold_vs_warm() -> dict | None:
    """Boots on a freshly extracted stdlib tree until fuel stops falling.

    This build ships sources only: CPython compiles every imported module on
    first use and WRITES the .pyc back into its preopened stdlib. Each boot
    caches a few more modules, so boot fuel falls run by run until the tree is
    primed and the boot reaches its steady cost — the measured sequence is the
    record of that. A writable preopen also means the guest modified its own
    library tree, which belongs in the record next to the latency numbers.
    """
    if not TARBALL.is_file():
        return None
    shutil.rmtree(COLD_BASE, ignore_errors=True)
    COLD_BASE.mkdir(parents=True, exist_ok=True)
    subprocess.run(["tar", "-xzf", str(TARBALL), "-C", str(COLD_BASE)], timeout=300)
    wasm = COLD_BASE / "opt/wasi-python/bin/python3.10.wasm"
    stdlib = COLD_BASE / "opt/wasi-python/lib/python3.10"
    if not wasm.is_file() or not stdlib.is_dir():
        return None
    before = len(list(stdlib.rglob("*.pyc")))
    config = replace(
        get_profile("interpreter"),
        max_fuel=2_000_000_000,
        allow_dirs=(f"{stdlib}::{stdlib_guest_path(stdlib)}",),
    )
    sandbox = WASISandbox(config=config)
    out: dict = {}
    try:
        for index in range(BOOT_PRIMING_RUNS):
            label = "cold" if index == 0 else f"warm_{index + 1}"
            start = time.perf_counter()
            result = sandbox.run(str(wasm), args=WORKLOADS["boot"])
            out[label] = {
                "measured": True,
                "wall_ms": round((time.perf_counter() - start) * 1000, 1),
                "status": result.status.value,
                "fuel_consumed": result.fuel_consumed,
            }
    finally:
        sandbox.cleanup()
    # All boots are measured, not stopped at the first near-repeat: the curve
    # falls slowly and two adjacent values can sit within 2 % of each other
    # long before the tree is primed. Primed = within 2 % of the last boot.
    fuels = [
        out[key]["fuel_consumed"]
        for key in out
        if isinstance(out[key], dict) and out[key].get("fuel_consumed")
    ]
    if fuels:
        steady = fuels[-1]
        out["primed_at_run"] = next(
            (
                i + 1
                for i, fuel in enumerate(fuels)
                if abs(fuel - steady) < 0.02 * steady
            ),
            None,
        )
        out["steady_fuel"] = steady
    after = len(list(stdlib.rglob("*.pyc")))
    out["pyc_files_in_preopen"] = {
        "before": before,
        "after": after,
        "written_by_guest": after - before,
    }
    return out


def measure_docker() -> dict | None:
    """Same rule as competitive_benchmark.measure_docker_baseline."""
    if shutil.which("docker") is None:
        return None
    try:
        warm = subprocess.run(
            ["docker", "run", "--rm", "python:3.12-slim", "python3", "-c", "pass"],
            capture_output=True,
            timeout=300,
        )
        if warm.returncode != 0:
            return None
        times = []
        for _ in range(DOCKER_RUNS):
            start = time.perf_counter()
            run = subprocess.run(
                [
                    "docker",
                    "run",
                    "--rm",
                    "python:3.12-slim",
                    "python3",
                    "-c",
                    "pass",
                ],
                capture_output=True,
                timeout=120,
            )
            times.append((time.perf_counter() - start) * 1000)
            if run.returncode != 0:
                return None
    except (subprocess.TimeoutExpired, OSError):
        return None
    return _stats(
        times, {"command": "docker run --rm python:3.12-slim python3 -c pass"}
    )


def _config_public(config) -> dict:
    return {
        "max_memory_mb": config.max_memory_mb,
        "max_fuel": config.max_fuel,
        "timeout_seconds": config.timeout_seconds,
        "max_wasm_bytes": config.max_wasm_bytes,
        "allow_fsync": config.allow_fsync,
        "io_cpu_seconds": config.io_cpu_seconds,
        "io_budget_bytes": config.io_budget_bytes,
    }


def main() -> int:
    guest = _guest_paths()
    result: dict = {
        "date": "2026-10-02",
        "host": "macOS arm64 (this machine)",
        "wasmtime": None,
        "guest": None,
        "cell": None,
        "memory_breakpoint": None,
        "cold_vs_warm": None,
        "docker": None,
    }
    from importlib.metadata import version as _pkg_version

    try:
        result["wasmtime"] = _pkg_version("wasmtime")
    except Exception:
        result["wasmtime"] = "unknown"
    if guest is None:
        result["guest"] = {
            "measured": False,
            "reason": f"no wasi-python guest at {DEFAULT_GUEST} — set EPHEMORA_BYO_PYTHON_ROOT",
        }
        print(json.dumps(result, indent=2))
        return 2
    wasm, stdlib = guest
    digest = _importer_sha256(wasm)
    result["guest"] = {
        "measured": True,
        "binary": "wasi-python 3.10 (CPython-WASI)",
        "sha256": digest,
        "sha256_matches_pin": digest == GUEST_SHA256,
        "size_bytes": wasm.stat().st_size,
        "source": GUEST_SOURCE,
        "stdlib_preopen_guest_path": stdlib_guest_path(stdlib),
        "note": "this build has no embedded stdlib: encodings lives in the "
        "preopened lib/python3.10 directory",
    }
    result["cell"] = measure_cell(wasm, stdlib)
    result["memory_breakpoint"] = measure_memory_breakpoint(wasm, stdlib)
    result["cold_vs_warm"] = measure_cold_vs_warm()
    result["docker"] = measure_docker()
    DEST.mkdir(parents=True, exist_ok=True)
    out = DEST / "interpreter_guest.json"
    out.write_text(json.dumps(result, indent=2) + "\n", encoding="utf-8")
    print(json.dumps(result, indent=2))
    print(f"wrote {out.relative_to(REPO)}", file=sys.stderr)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
