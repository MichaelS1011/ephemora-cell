#!/usr/bin/env python3
"""B5 — limits enforcement through the Engine and the MCP channel.

Proves the Cell enforces its three resource limits deterministically:
  * memhog   -> memory limit (max_memory_mb) -> MEMORY_EXCEEDED / guest error
  * hugeout  -> stdout byte-budget (10 KB, ENOSPC) -> capture stays <= ~10 KB
  * busy     -> fuel metering (max_fuel) -> FUEL_EXHAUSTED with fuel report

Each guest runs (a) directly through WASISandbox and (b) as an MCP tool
through ephemora-cell-mcp (tools/call + _meta.execution). 3 repetitions each
to confirm determinism.

Run: .venv/bin/python benchmarks/pocs/limits_poc/run_limits_poc.py
"""

from __future__ import annotations

import json
import subprocess
import sys
from pathlib import Path

REPO = Path(__file__).resolve().parent.parent.parent.parent
sys.path.insert(0, str(REPO))

from ephemora_cell import WASIConfig, WASISandbox  # noqa: E402

GUESTS = REPO / "benchmarks" / "pocs" / "limits_poc" / "guests" / "target" / "wasm32-wasip1" / "release"
MCP_BIN = REPO / ".venv" / "bin" / "ephemora-cell-mcp"
N = 3


def engine_run(wasm: Path, **overrides) -> dict:
    config = WASIConfig(**overrides)
    sb = WASISandbox(config)
    results = []
    for _ in range(N):
        r = sb.run(str(wasm))
        results.append({
            "status": r.status.value if hasattr(r.status, "value") else str(r.status),
            "exit_code": r.exit_code,
            "stdout_len": len(r.stdout),
            "stdout_tail": r.stdout[-120:],
            "fuel_consumed": r.fuel_consumed,
            "elapsed_ms": round(r.elapsed_ms, 2),
        })
    return results


def mcp_run(tool_dir: Path, tool_name: str, arguments: dict) -> list[dict]:
    results = []
    for _ in range(N):
        p = subprocess.Popen(
            [str(MCP_BIN), "--tools-dir", str(tool_dir)],
            stdin=subprocess.PIPE, stdout=subprocess.PIPE,
            stderr=subprocess.DEVNULL, text=True, bufsize=1)

        def rpc(method, params=None, rid=1):
            msg = {"jsonrpc": "2.0", "id": rid, "method": method}
            if params:
                msg["params"] = params
            p.stdin.write(json.dumps(msg) + "\n")
            p.stdin.flush()
            while True:
                line = p.stdout.readline()
                if not line:
                    return None
                m = json.loads(line)
                if m.get("id") == rid:
                    return m

        rpc("initialize", {"protocolVersion": "2025-06-18", "capabilities": {},
                           "clientInfo": {"name": "limits", "version": "1"}})
        rpc("notifications/initialized")
        r = rpc("tools/call", {"name": tool_name, "arguments": arguments})
        meta = (r.get("result", {}).get("_meta", {}) or {}).get("execution", {})
        results.append({
            "tool": tool_name,
            "meta_status": meta.get("status"),
            "fuel_consumed": meta.get("fuel_consumed"),
            "elapsed_ms": meta.get("elapsed_ms"),
            "wasmtime": meta.get("security_baseline", {}).get("wasmtime_version"),
        })
        p.terminate()
    return results


def main() -> None:
    out = {}
    print("== B5 limits enforcement (3 runs each) ==")

    for guest, label in [("memhog", "memory"), ("hugeout", "output"), ("busy", "fuel")]:
        print(f"\n--- {label} limit: {guest}.wasm (Engine) ---")
        runs = engine_run(GUESTS / f"{guest}.wasm", max_fuel=2_000_000, timeout_seconds=30)
        for r in runs:
            print(" ", r)
        out[f"engine_{guest}"] = runs

    print("\n--- limits as MCP tools (tools/call + _meta.execution) ---")
    import shutil
    tool_dir = REPO / "benchmarks" / "pocs" / "limits_poc" / "mcp_tools"
    tool_dir.mkdir(exist_ok=True)
    for guest in ["memhog", "hugeout", "busy"]:
        shutil.copy(GUESTS / f"{guest}.wasm", tool_dir / f"{guest}.wasm")
        (tool_dir / f"{guest}.json").write_text(json.dumps({
            "name": guest,
            "description": f"B5 {guest} limits probe",
            "input_schema": {"type": "object", "properties": {}},
        }))
    for guest in ["memhog", "hugeout", "busy"]:
        print(f"  {guest} via MCP:")
        for r in mcp_run(tool_dir, guest, {}):
            print("   ", r)
        out[f"mcp_{guest}"] = mcp_run(tool_dir, guest, {})

    (Path(__file__).parent / "results.json").write_text(json.dumps(out, indent=2))
    print(f"\nresults -> {Path(__file__).parent / 'results.json'}")


if __name__ == "__main__":
    main()