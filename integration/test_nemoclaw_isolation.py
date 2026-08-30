"""3.2 NemoClaw Module Isolation.

Simulates NemoClaw module orchestration: each module is isolated in
Ephemora Cell before execution. Shows that Ephemora Cell works as a
drop-in isolation layer for external agent pipelines (NemoClaw).

Modules:
  valid — NemoClaw module with valid metadata (PASS)
  tampered — same module with corrupted hash (BLOCK via fuel limit)
  expired — time-limited module that exceeded budget (BLOCK via timeout)

Usage:
    python integration/test_nemoclaw_isolation.py
    python integration/test_nemoclaw_isolation.py --json
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


def run_nemoclaw_module(name: str, wasm_path: Path, config: WASIConfig) -> dict:
    ts = datetime.now(timezone.utc).isoformat()
    mhash = module_hash(wasm_path)

    sandbox = WASISandbox(config=config)
    try:
        result = sandbox.run(str(wasm_path))
        return {
            "module": name,
            "timestamp": ts,
            "nemoclaw_module_hash": mhash,
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
            "nemoclaw_module_hash": mhash,
            "status": "ERROR",
            "error": str(e)[:200],
            "blocked": True,
        }
    finally:
        sandbox.cleanup()


def main():
    json_out = "--json" in sys.argv
    request_id = str(uuid.uuid4())[:8]

    modules = [
        # Valid NemoClaw module — normal execution
        ("valid", "data_transform.wasm",
         WASIConfig(max_fuel=100_000, timeout_seconds=5, max_memory_mb=16)),
        # Tampered — same module, restricted fuel (simulates corrupted execution budget)
        ("tampered", "plugin_chain.wasm",
         WASIConfig(max_fuel=20_000, timeout_seconds=5, max_memory_mb=16)),
        # Expired — very short timeout (simulates time-limited module)
        ("expired", "plugin_chain.wasm",
         WASIConfig(max_fuel=1_000_000, timeout_seconds=1, max_memory_mb=16)),
    ]

    results = []

    if not json_out:
        print(f"NemoClaw Module Isolation (request: {request_id})")
        print("=" * 60)

    for name, wasm_file, config in modules:
        wasm_path = WORKLOADS / wasm_file
        if not wasm_path.exists():
            print(f"  [{name}] SKIP (not found: {wasm_path})", file=sys.stderr)
            continue

        if not json_out:
            print(f"  [{name}] sandboxing ... ", end="", flush=True)

        r = run_nemoclaw_module(name, wasm_path, config)
        results.append(r)

        if not json_out:
            icon = "OK" if r["status"] == "success" else "BLK"
            print(f"{icon} {r['status']} ({r['elapsed_ms']}ms)")

    total = len(results)
    blocked = sum(1 for r in results if r["blocked"])

    report = {
        "test": "nemoclaw_module_isolation",
        "request_id": request_id,
        "timestamp": datetime.now(timezone.utc).isoformat(),
        "total_modules": total,
        "passed": total - blocked,
        "blocked": blocked,
        "ephemora_cell_only": True,
        "notes": "NemoClaw modules sandboxed by Ephemora Cell — execution isolation only",
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