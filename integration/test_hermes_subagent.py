"""Hermes-style subagent isolation (end-to-end).

Uses existing benchmark workloads to simulate a Hermes subagent that
generates code, then executes it in Ephemora Cell isolation.

Modules (from benchmarks/workloads/):
  code_review — benign computation (SUCCESS)
  exploit — imports blocked WASI function (BLOCK)
  plugin_chain with low fuel — resource exhaustion (FUEL_EXHAUSTED)

Usage:
    python integration/test_hermes_subagent.py
    python integration/test_hermes_subagent.py --json
"""
from __future__ import annotations
import hashlib
import json
import sys
import uuid
from datetime import datetime, timezone
from pathlib import Path

sys.path.insert(0, str(Path(__file__).parent.parent))
from ephemora_cell import WASISandbox, WASIConfig

WORKLOADS = Path(__file__).parent.parent / "benchmarks" / "workloads"


def module_hash(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()[:16]


def run_module(name: str, wasm_path: Path, max_fuel: int) -> dict:
    ts = datetime.now(timezone.utc).isoformat()
    mhash = module_hash(wasm_path)

    config = WASIConfig(max_fuel=max_fuel, timeout_seconds=5, max_memory_mb=16)
    sandbox = WASISandbox(config=config)

    try:
        result = sandbox.run(str(wasm_path))
        return {
            "module": name,
            "timestamp": ts,
            "module_hash": mhash,
            "status": result.status.value,
            "exit_code": result.exit_code,
            "elapsed_ms": round(result.elapsed_ms, 2),
            "fuel_consumed": result.fuel_consumed,
            "stdout": result.stdout[:200],
            "blocked": result.status.value != "success",
        }
    except Exception as e:
        return {
            "module": name,
            "timestamp": ts,
            "module_hash": mhash,
            "status": "ERROR",
            "exit_code": None,
            "elapsed_ms": None,
            "fuel_consumed": None,
            "error": str(e)[:200],
            "blocked": True,
        }
    finally:
        sandbox.cleanup()


def main():
    json_out = "--json" in sys.argv
    request_id = str(uuid.uuid4())[:8]

    modules = [
        # Benign — simple transform (always succeeds with 100K fuel)
        ("benign", "data_transform.wasm", 100_000),
        # Malware — exploit module imports blocked functions
        ("malware", "exploit.wasm", 100_000),
        # Resource heavy — plugin_chain with limited fuel (exhausts on loop)
        ("resource_heavy", "plugin_chain.wasm", 20_000),
    ]

    results = []

    if not json_out:
        print(f"Hermes Subagent Isolation (request: {request_id})")
        print("=" * 60)

    for name, wasm_file, fuel in modules:
        wasm_path = WORKLOADS / wasm_file
        if not wasm_path.exists():
            print(f"  [{name}] SKIP (not found: {wasm_path})", file=sys.stderr)
            continue

        if not json_out:
            print(f"  [{name}] isolating (fuel={fuel}) ... ", end="", flush=True)

        r = run_module(name, wasm_path, fuel)
        results.append(r)

        if not json_out:
            icon = "OK" if r["status"] == "success" else "BLK"
            print(f"{icon} {r['status']} ({r['elapsed_ms']}ms)")

    total = len(results)
    blocked = sum(1 for r in results if r["blocked"])

    report = {
        "test": "hermes_subagent_isolation",
        "request_id": request_id,
        "timestamp": datetime.now(timezone.utc).isoformat(),
        "total_modules": total,
        "passed": total - blocked,
        "blocked": blocked,
        "ephemora_cell_only": True,
        "notes": "Ephemora Cell isolates only — execution isolation",
        "results": results,
    }

    if json_out:
        print(json.dumps(report, indent=2))
    else:
        print(f"\n{'=' * 60}")
        print(f"Result: {total - blocked}/{total} passed, {blocked}/{total} blocked")
        print(f"Mode: Ephemora Cell isolation only (execution isolation, no full pipeline)")
        print("=" * 60)


if __name__ == "__main__":
    main()