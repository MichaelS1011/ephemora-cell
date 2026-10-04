#!/usr/bin/env python3
"""Why the sync blockade refuses CALLS, not IMPORTS — measured.

The original P1 #12 blockade rejected a module that IMPORTED fd_datasync,
which is why CPython-WASI could not run without an opt-in. This harness
establishes, against the pinned guest and the shipped posture, that the
import is not the harm:

  1. the guest really does import fd_datasync / fd_sync / fd_psync,
  2. it boots and works behind the full call-layer trap set, on a cold AND a
     warm stdlib tree (the cold tree is where .pyc writing happens, i.e. the
     only plausible reason a Python build would sync at all),
  3. nothing in the configuration had to be opened for that to work.

That is the evidence behind the interpreter profile shipping with
`allow_fsync=False` — budgets raised, no sync exception. If a future guest
here reports "blocked by sandbox", it is a guest that actually syncs, and the
answer is the documented opt-in, not a weakened default.

Run:  .venv/bin/python benchmarks/interpreter_guest/probe_datasync.py
"""

from __future__ import annotations

import shutil
import sys
import tempfile
from dataclasses import replace
from pathlib import Path

REPO = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(REPO))

from benchmarks.interpreter_guest.measure import (  # noqa: E402
    _guest_paths,
    stdlib_guest_path,
)
from ephemora_cell import ExecutionStatus, WASISandbox, get_profile  # noqa: E402
from ephemora_cell.wasi_runtime import SYNC_CALL_TRAPS  # noqa: E402

# boot = the Cell equivalent of Docker's `python3 -c pass`. import_json pulls
# a stdlib module, which is the path that writes __pycache__/*.pyc into the
# preopen; the third workload writes through the scratch dir.
PROBES = {
    "boot": ["-c", "pass"],
    "import_json": ["-c", "import json; print(json.dumps({'ok': True}))"],
    "write_file": [
        "-c",
        "f=open('/sandbox/probe.txt','w'); f.write('x'); f.flush(); print('wrote')",
    ],
}


def _imports_of(wasm: Path) -> set[str]:
    """WASI import names the guest links against."""
    import wasmtime

    engine = wasmtime.Engine()
    mod = wasmtime.Module.from_file(engine, str(wasm))
    return {imp.name for imp in mod.imports if imp.module == "wasi_snapshot_preview1"}


def _run(wasm: str, stdlib: Path, label: str, args: list[str]) -> dict:
    # The shipped interpreter profile, unmodified — allow_fsync False. Fuel is
    # the one exception: a truncated run would prove nothing about syncs.
    config = replace(
        get_profile("interpreter"),
        max_fuel=2_000_000_000,
        allow_dirs=(f"{stdlib}::{stdlib_guest_path(stdlib)}",),
    )
    assert config.allow_fsync is False, "profile must ship closed"
    sandbox = WASISandbox(config=config)
    try:
        res = sandbox.run(wasm, args=args)
    finally:
        sandbox.cleanup()
    refused = "blocked by sandbox" in (res.stderr or "")
    verdict = (
        "SYNCED (refused)"
        if refused
        else (
            "never synced" if res.status is ExecutionStatus.SUCCESS else "other error"
        )
    )
    print(f"  {label:<14} {res.status.value:<8} fuel={res.fuel_consumed}  -> {verdict}")
    if verdict == "other error":
        print(f"      stderr: {(res.stderr or '').strip()[-200:]}")
    return {"label": label, "status": res.status.value, "verdict": verdict}


def _strip_pyc(tree: Path) -> int:
    removed = 0
    for cache in list(tree.rglob("__pycache__")):
        shutil.rmtree(cache, ignore_errors=True)
        removed += 1
    return removed


def main() -> int:
    paths = _guest_paths()
    if paths is None:
        print("no pinned guest found — set EPHEMORA_BYO_PYTHON_ROOT", file=sys.stderr)
        return 2
    wasm, stdlib = paths

    print(
        f"guest: {wasm.name} ({wasm.stat().st_size} bytes), shipped profile: interpreter"
    )
    print(f"sync calls trapped by default: {', '.join(SYNC_CALL_TRAPS)}")

    imports = _imports_of(wasm)
    synced = sorted(name for name in SYNC_CALL_TRAPS if name in imports)
    print(f"guest imports among them: {synced or 'none'}")
    if not synced:
        print("  guest imports no sync symbol — the blockade is not its problem")

    print("\n[A] warm tree (primed)")
    warm = [_run(str(wasm), stdlib, name, args) for name, args in PROBES.items()]

    print("\n[B] cold tree (all __pycache__ removed — the .pyc writing path)")
    with tempfile.TemporaryDirectory(prefix="probe-cold-") as tmp:
        cold = Path(tmp) / "python3.10"
        shutil.copytree(stdlib, cold)
        print(f"  stripped {_strip_pyc(cold)} __pycache__ dirs")
        cold_runs = [_run(str(wasm), cold, name, args) for name, args in PROBES.items()]

    runs = warm + cold_runs
    failed = [r for r in runs if r["verdict"] != "never synced"]
    print("\nErgebnis:")
    if not failed:
        print("  Der Gast läuft unter der unveränderten, geschlossenen Sync-Wand.")
        print("  Import ist kein Angriffspunkt; refused wird der Aufruf.")
        return 0
    print(f"  {len(failed)} Lauf/Läufe wurden nicht erfolgreich beendet:")
    for r in failed:
        print(f"    {r['label']}: {r['verdict']} ({r['status']})")
    return 1


if __name__ == "__main__":
    raise SystemExit(main())
