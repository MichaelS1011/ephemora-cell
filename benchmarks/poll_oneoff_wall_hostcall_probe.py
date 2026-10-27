#!/usr/bin/env python3
"""Is the OUTER wall-timeout enforced even when the guest is busy
inside a SINGLE, non-returning hostcall (preview1 `poll_oneoff`)?

Background (preview1 `poll_oneoff` host-work observation, kept separate from the
preview0 GHSA-j366): the preview1 `poll_oneoff` host
work is wall-bounded, NOT fuel-bounded (measured: flat fuel / growing
wall). The open question for a worker-isolated run is whether the deadline still
fires when the guest never returns to a WASM safepoint — the case where an
epoch interrupt physically cannot land.

Mechanism under test (process_executor.py): the worker path bounds the run with
`subprocess.communicate(timeout=max(timeout_seconds+5, 5))` and, on expiry,
`proc.kill()` — a SIGKILL the OS delivers even to a thread blocked inside a
native hostcall. The in-process path only interrupts at epoch safepoints, so a
truly blocking hostcall would NOT be caught there; but `_isolation_gate` forces
untrusted/unknown code onto the worker path, so the guarantee holds where it
matters.

Design: a guest issues ONE `poll_oneoff` with a far-future clock subscription so
the single hostcall blocks essentially forever. We run it ONLY on the mandatory
worker path (never in-process — that could hang) and assert the outer wall kills
and reaps it at the deadline. The whole test is additionally wrapped in an
outer subprocess timeout so a broken containment can never hang this harness.

Run: .venv/bin/python benchmarks/poll_oneoff_wall_hostcall_probe.py
Exit 0 = outer wall enforced during a blocking hostcall (contained + reaped).
Exit 1 = not contained (STOP-CONDITION candidate -> escalate, do not merge).
"""

from __future__ import annotations

import json
import os
import subprocess
import sys
import tempfile
from datetime import date
from pathlib import Path

REPO = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(REPO))

import wasmtime

WAT_BLOCKING_POLL = """
(module
  (import "wasi_snapshot_preview1" "poll_oneoff"
    (func $poll (param i32 i32 i32 i32) (result i32)))
  (memory (export "memory") 1)
  (func (export "_start")
    ;; one 48-byte subscription at offset 0:
    ;;   u_tag (clock) = 0 @8, clock_id @16 = 0,
    ;;   clock_timeout (u64 ns, absolute monotonic) @24 = ~146 years -> never ready
    (i64.store (i32.const 8) (i64.const 0))
    (i32.store (i32.const 16) (i32.const 0))
    (i64.store (i32.const 24) (i64.const 4611686018427387904))
    (i32.store (i32.const 32) (i32.const 0))
    ;; poll(subs=0, events=512, nsubs=1, nready_out=64) -> blocks in the hostcall
    (drop (call $poll (i32.const 0) (i32.const 512) (i32.const 1) (i32.const 64)))))
"""

TIMEOUT_SECONDS = 2  # worker process deadline = max(2+5, 5) = 7 s


def _write_blocking_wasm() -> str:
    # mkstemp, not the deprecated mktemp: the name is created atomically with
    # O_EXCL, so no other process can win the race to that path between the
    # guess and the write (CWE-377).
    fd, path = tempfile.mkstemp(suffix=".wasm")
    os.close(fd)
    Path(path).write_bytes(wasmtime.wat2wasm(WAT_BLOCKING_POLL))
    return path


# Child: run the blocking guest on the mandatory worker path and report.
CHILD = r"""
import json, sys, time
sys.path.insert(0, {repo!r})
from ephemora_cell import WASIConfig, WASISandbox
cfg = WASIConfig(max_memory_mb=64, max_fuel=10_000_000_000,
                 timeout_seconds={to}, allow_dirs=())
sb = WASISandbox(config=cfg)
t0 = time.monotonic()
r = sb.run({wasm!r}, use_subprocess=True, trust="untrusted")
wall = (time.monotonic() - t0) * 1000
print(json.dumps({{"status": r.status.value, "wall_ms": round(wall, 1),
                   "fuel": r.fuel_consumed, "stderr": (r.stderr or "")[:120]}}))
"""


def main() -> int:
    wasm = _write_blocking_wasm()
    verdicts: dict[str, bool] = {}
    detail: dict[str, object] = {}
    try:
        # Outer safety net: if containment were broken and the sandbox.run hung,
        # this subprocess timeout reaps the CHILD (and its worker) instead of
        # hanging the harness. Generously above the 7 s inner deadline.
        proc = subprocess.run(
            [
                sys.executable,
                "-c",
                CHILD.format(repo=str(REPO), to=TIMEOUT_SECONDS, wasm=wasm),
            ],
            capture_output=True,
            text=True,
            timeout=30,
        )
        outer_harness_fired = False
    except subprocess.TimeoutExpired:
        outer_harness_fired = True
        proc = None

    if outer_harness_fired:
        verdicts["worker_run_returned"] = False
        verdicts["outer_wall_killed_hostcall"] = False
        detail["note"] = "sandbox.run did not return within 30 s -> NOT contained"
        result = None
    else:
        verdicts["worker_run_returned"] = proc.returncode == 0
        try:
            result = json.loads(proc.stdout.strip().splitlines()[-1])
        except Exception:
            result = {"raw": proc.stdout[-200:], "err": proc.stderr[-200:]}
        detail["run"] = result
        if isinstance(result, dict) and "status" in result:
            status = result["status"].lower()
            wall = result["wall_ms"]
            # Terminated by the wall (not a fuel/epoch trap, not a normal finish).
            verdicts["terminated_by_wall_timeout"] = "timeout" in status
            # It was STILL busy when killed: wall landed at/after the ~7 s inner
            # deadline rather than returning instantly (proves the kill interrupted
            # a blocked hostcall, not a quick guest exit).
            verdicts["blocked_in_hostcall_at_kill"] = wall >= 6500 and wall < 30000
            # Fuel did not cause the end (host work is not fuel-priced).
            verdicts["not_a_fuel_trap"] = status != "out_of_fuel"
            verdicts["worker_reaped_no_hang"] = proc.returncode == 0
    verdicts["outer_wall_killed_hostcall"] = all(
        v
        for k, v in verdicts.items()
        if k not in ("outer_wall_killed_hostcall", "worker_run_returned")
    ) and verdicts.get("worker_run_returned", False)

    ok = bool(verdicts.get("outer_wall_killed_hostcall"))
    out = {
        "probe": "poll_oneoff_wall_hostcall",
        "engine": "wasmtime-py 49.0.0 (native v49.0.0)",
        "advisory_context": "preview1 poll_oneoff (separated from GHSA-j366 preview0)",
        "config": {"timeout_seconds": TIMEOUT_SECONDS, "worker_deadline_s": 7},
        "verdicts": verdicts,
        "detail": detail,
        "pass": ok,
    }
    results_dir = REPO / "benchmarks" / "results" / date.today().isoformat()
    results_dir.mkdir(parents=True, exist_ok=True)
    ev = results_dir / "poll_oneoff_wall_hostcall.json"
    ev.write_text(json.dumps(out, indent=2))
    print(json.dumps(out, indent=2))
    print(f"\nEvidence -> {ev}")
    print(
        "VERDICT:",
        (
            "PASS (outer wall enforced during blocking hostcall)"
            if ok
            else "FAIL (not contained)"
        ),
    )
    return 0 if ok else 1


if __name__ == "__main__":
    raise SystemExit(main())
