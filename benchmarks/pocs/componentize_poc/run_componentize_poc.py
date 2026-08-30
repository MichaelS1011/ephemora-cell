#!/usr/bin/env python3
"""Ephemora Cell — Componentize PoC driver.

Runs lifted preview1->WASI-0.2 components (built by build_modules.py)
through ComponentSandbox / run_wasm(abi="auto") and checks:

  1. stdout/stderr capture through the custom sink (adapter path)
  2. args + env passthrough
  3. fuel exhaustion on a lifted infinite loop
  4. epoch timeout on the same loop
  5. Store.set_limits memory limit on a lifted memory.grow loop
  6. preopen allowlist behavior (filesystem via the adapter)
  7. entry-point naming: wasi:cli/run@0.2.3 exports vs direct `run`
  8. startup overhead vs the native Rust wasm32-wasip2 fixture (hello02)

Run from the repo root:

    .venv/bin/python benchmarks/pocs/componentize_poc/run_componentize_poc.py
"""
from __future__ import annotations

import json
import os
import statistics
import sys

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__)))))
from ephemora_cell import (
    ComponentSandbox,
    ExecutionStatus,
    WASIConfig,
    WASISandbox,
    run_wasm,
)

HERE = os.path.dirname(os.path.abspath(__file__))
REPO = os.path.dirname(os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__)))))
RESULTS = os.path.join(HERE, "results.json")

P1_PRINT = os.path.join(HERE, "p1_print_lifted.wasm")
P1_LOOP = os.path.join(HERE, "p1_loop_lifted.wasm")
P1_GROW = os.path.join(HERE, "p1_grow_lifted.wasm")
RUST_FS = os.path.join(HERE, "rust_fs_lifted.wasm")
HELLO02 = os.path.join(REPO, "tests", "fixtures", "hello02.wasm")

FUEL_FULL = 50_000_000


def status_name(r) -> str:
    return str(r.status).split(".")[1].lower()


def run_comp(path: str, config: WASIConfig, *, args=None, stdin_data=None):
    s = ComponentSandbox(config)
    r = s.run(path, args=args, stdin_data=stdin_data)
    s.cleanup()
    return r


def median_comp(path: str, config: WASIConfig, *, args=None, n: int = 7) -> dict:
    times = []
    last = None
    for _ in range(n):
        r = run_comp(path, config, args=args)
        times.append(r.elapsed_ms)
        last = r
    return {
        "status": status_name(last),
        "exit_code": last.exit_code,
        "stdout": last.stdout.strip(),
        "stderr": (last.stderr or "")[:220],
        "elapsed_ms_median": round(statistics.median(times), 2),
        "elapsed_ms_min": round(min(times), 2),
        "fuel_consumed": last.fuel_consumed,
    }


def scenario_1_output_capture() -> dict:
    out = {}
    # Hand-written preview1 wat module whose _start calls proc_exit(0).
    r = run_comp(P1_PRINT, WASIConfig(max_fuel=FUEL_FULL))
    out["p1_print_lifted"] = {
        "status": status_name(r), "exit_code": r.exit_code,
        "stdout": r.stdout.strip(), "stderr": (r.stderr or "")[:220],
        "elapsed_ms": round(r.elapsed_ms, 2),
    }
    # Rust wasip1 module (returns from _start normally, no proc_exit).
    r = run_comp(RUST_FS, WASIConfig(max_fuel=FUEL_FULL))
    out["rust_fs_lifted"] = {
        "status": status_name(r), "exit_code": r.exit_code,
        "stdout": r.stdout.strip(), "stderr": (r.stderr or "")[:220],
        "elapsed_ms": round(r.elapsed_ms, 2),
    }
    # run_wasm(abi="auto") dispatch on a lifted component.
    r = run_wasm(P1_PRINT, max_fuel=FUEL_FULL)
    out["auto_dispatch_lifted"] = {
        "status": status_name(r), "stdout": r.stdout.strip(),
        "stderr": (r.stderr or "")[:220],
    }
    return out


def scenario_2_args_env() -> dict:
    out = {}
    target = os.path.join(os.path.expanduser("~"), f".t12_cp_preopen_{os.getpid()}")
    import shutil
    shutil.rmtree(target, ignore_errors=True)
    os.mkdir(target)
    try:
        r = run_comp(
            RUST_FS,
            WASIConfig(max_fuel=FUEL_FULL, allow_dirs=(target,),
                       allow_env=(("EPHEMORA_TEST", "42"),)),
            args=[target],
        )
        out["rust_fs_args_env_preopen"] = {
            "status": status_name(r),
            "stdout": r.stdout.strip(),
            "stderr": (r.stderr or "")[:220],
            "exit_code": r.exit_code,
        }
        out["file_written"] = os.path.exists(os.path.join(target, "out.txt"))
        if out["file_written"]:
            out["file_content"] = open(os.path.join(target, "out.txt")).read().strip()
    finally:
        shutil.rmtree(target, ignore_errors=True)
    return out


def scenario_3_fuel() -> dict:
    out = {}
    r = run_comp(P1_LOOP, WASIConfig(max_fuel=50_000))
    out["lifted_fuel_exhausted"] = {
        "status": status_name(r), "stderr": (r.stderr or "")[:220],
        "elapsed_ms": round(r.elapsed_ms, 2),
    }
    return out


def scenario_4_epoch_timeout() -> dict:
    out = {}
    r = run_comp(P1_LOOP, WASIConfig(max_fuel=None, timeout_seconds=1))
    out["lifted_epoch_timeout"] = {
        "status": status_name(r), "stderr": (r.stderr or "")[:220],
        "elapsed_ms": round(r.elapsed_ms, 2),
    }
    return out


def scenario_5_memory_limit() -> dict:
    out = {}
    r = run_comp(P1_GROW, WASIConfig(max_fuel=FUEL_FULL, max_memory_mb=2))
    out["lifted_memory_limit_2mb"] = {
        "status": status_name(r), "stderr": (r.stderr or "")[:220],
        "elapsed_ms": round(r.elapsed_ms, 2),
    }
    r = run_comp(P1_GROW, WASIConfig(max_fuel=FUEL_FULL, max_memory_mb=128))
    out["lifted_memory_no_limit"] = {
        "status": status_name(r), "stderr": (r.stderr or "")[:220],
        "elapsed_ms": round(r.elapsed_ms, 2),
    }
    return out


def scenario_6_preopen_allowlist() -> dict:
    out = {}
    import shutil
    target = os.path.join(os.path.expanduser("~"), f".t12_cp_denied_{os.getpid()}")
    shutil.rmtree(target, ignore_errors=True)
    os.mkdir(target)
    try:
        r = run_comp(RUST_FS, WASIConfig(max_fuel=FUEL_FULL), args=[target])
        out["no_preopen_denied"] = {
            "status": status_name(r),
            "stdout": r.stdout.strip(),
            "stderr": (r.stderr or "")[:220],
            "file_written": os.path.exists(os.path.join(target, "out.txt")),
        }
    finally:
        shutil.rmtree(target, ignore_errors=True)
    return out


def scenario_7_entry_points() -> dict:
    """Export names of each lifted artifact + the native fixture."""
    import wasmtime
    from wasmtime import component as _component
    out = {}
    for label, path in [("p1_print_lifted", P1_PRINT), ("rust_fs_lifted", RUST_FS),
                        ("hello02_native", HELLO02)]:
        eng = wasmtime.Engine()
        comp = _component.Component.from_file(eng, path)
        exports = [str(n) for n in comp.type.exports(eng)]
        out[label] = {
            "exports": exports,
            "has_wasi_cli_run": any(n.startswith("wasi:cli/run@") for n in exports),
            "has_direct_run": any(n == "run" for n in exports),
        }
    return out


def scenario_8_startup_overhead() -> dict:
    """Startup overhead: lifted wat + lifted Rust vs native wasip2 fixture."""
    out = {}
    for label, path in [("hello02_native", HELLO02),
                        ("p1_print_lifted", P1_PRINT),
                        ("rust_fs_lifted", RUST_FS)]:
        m = median_comp(path, WASIConfig(max_fuel=FUEL_FULL), n=7)
        out[label] = {
            "status": m["status"],
            "elapsed_ms_median": m["elapsed_ms_median"],
            "elapsed_ms_min": m["elapsed_ms_min"],
            "stdout": m["stdout"][:60],
        }
    return out


def main() -> None:
    print("=" * 72)
    print("Ephemora Cell — Componentize PoC")
    print("=" * 72)

    results = {"tooling": {
        "wasm-tools": "1.255.0",
        "adapter": "wasi_snapshot_preview1.command.wasm (wasmtime v34.0.0 release)",
        "lift_cmd": "wasm-tools component new <module.wasm> --adapt "
                    "wasi_snapshot_preview1.command.wasm -o <lifted>.wasm",
    }}

    print("\n[1] Output capture through the adapter")
    s = scenario_1_output_capture()
    results["scenario_1_output_capture"] = s
    for k, v in s.items():
        print(f"  {k}: {v.get('status')}  stdout={v.get('stdout')!r}")

    print("\n[2] Args / env / preopen passthrough (lifted Rust wasip1)")
    s = scenario_2_args_env()
    results["scenario_2_args_env"] = s
    print(f"  status={s['rust_fs_args_env_preopen']['status']} "
          f"file_written={s['file_written']} content={s.get('file_content')!r}")
    print(f"  stdout={s['rust_fs_args_env_preopen']['stdout']!r}")

    print("\n[3] Fuel exhaustion (lifted infinite loop)")
    s = scenario_3_fuel()
    results["scenario_3_fuel"] = s
    print(f"  {s['lifted_fuel_exhausted']['status']}: "
          f"{s['lifted_fuel_exhausted']['stderr'][:80]}")

    print("\n[4] Epoch timeout (lifted infinite loop)")
    s = scenario_4_epoch_timeout()
    results["scenario_4_epoch_timeout"] = s
    print(f"  {s['lifted_epoch_timeout']['status']}: "
          f"{s['lifted_epoch_timeout']['stderr'][:80]}")

    print("\n[5] Memory limit (lifted memory.grow loop)")
    s = scenario_5_memory_limit()
    results["scenario_5_memory_limit"] = s
    for k, v in s.items():
        print(f"  {k}: {v['status']}  {v['stderr'][:80]}")

    print("\n[6] Preopen allowlist (deny by default)")
    s = scenario_6_preopen_allowlist()
    results["scenario_6_preopen_allowlist"] = s
    print(f"  {s['no_preopen_denied']['status']}  "
          f"file_written={s['no_preopen_denied']['file_written']}")

    print("\n[7] Entry-point naming")
    s = scenario_7_entry_points()
    results["scenario_7_entry_points"] = s
    for k, v in s.items():
        print(f"  {k}: run_export={[e for e in v['exports'] if 'run' in e]}")

    print("\n[8] Startup overhead (median of 7, sandbox-inclusive)")
    s = scenario_8_startup_overhead()
    results["scenario_8_startup_overhead"] = s
    base = s["hello02_native"]["elapsed_ms_median"]
    for k, v in s.items():
        ratio = v["elapsed_ms_median"] / base if base else 0
        print(f"  {k}: {v['elapsed_ms_median']} ms  ({ratio:.2f}x vs native)")

    with open(RESULTS, "w") as f:
        json.dump(results, f, indent=2)
    print(f"\nresults written to {RESULTS}")


if __name__ == "__main__":
    main()
