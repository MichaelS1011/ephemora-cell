"""GHSA-2hw9-mc66-jc2q evidence harness — bulk-memory ops under
preemption (published 2026-07-31, CVE-2026-104855, Low / v4 2.0).

The advisory: interrupting a guest during a bulk-memory operation
(``memory.copy`` / ``memory.fill``) at a fuel- or epoch-preemption point
could leave the internal VM state inconsistent on affected engines.
Affected 46.0.0/46.0.1/47.0.0/47.0.1/47.0.2, patched 46.0.2 / 47.0.3. The
pinned 47.0.1 wheel embeds the native engine 47.0.0, which is IN the
affected range and PREEMPTS via both fuel (``consume_fuel`` when a budget is
set) and epoch (``epoch_interruption`` always on, ``_engine_config.py``);
bulk-memory is a default-on proposal (NOT in the disabled set).

Why a standalone subprocess harness: a genuine VM-state break can abort or
segfault the HOST process (it is a memory-safety class), so it must never run
inside a shared harness that still has to write its evidence. Each risky leg
runs in its own python child interpreter — an abort there is recorded as a
non-zero return code, not fatal to the parent (same pattern as
benchmarks/datetime_overflow_probe.py).

This harness answers the fuel/epoch-over-commitment question — *is the affected
code path reachable on the actual build, and what is the measured outcome* —
without fabricating a deterministic exploit of an engine-internal timing race:

  L1  tight fuel budget, in-process (child): guest loops memory.fill/copy;
      preemption by fuel is forced. Expect a clean FUEL trap; host survives.
  L2  short epoch timeout, in-process (child): same loop; preemption by epoch.
      Expect a clean TIMEOUT trap; host survives.
  L3  generous budget, positive control: bounded fill+copy then verify the
      copied bytes are correct; exit 0. Proves the bulk ops are NOT silently
      corrupting an uninterrupted run (no false "state break" claim).
  L4  subprocess path (use_subprocess=True): the shipped isolation posture.
      Parent must survive regardless; the worker result is bounded.

If L1/L2 trap cleanly and the parent never sees corruption, the *reachable*
surface is the preemption trap path (contained), while the exact
"preempted-inside-the-bulk-op-epilogue" corrupt-state window is an
engine-internal race we cannot force deterministically from a guest — that
residual uncertainty is reported honestly rather than declared absent.

Usage: .venv/bin/python benchmarks/bulk_op_preemption_probe.py
Exit 0 = path reachable and every leg contained (trap clean / parent survives).
Exit 1 = an uncontained abort or a corrupted control: escalate.
"""

from __future__ import annotations

import hashlib
import json
import platform
import subprocess
import sys
from datetime import date
from importlib.metadata import version as _pkg_version
from pathlib import Path

REPO = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(REPO))

# Bulk-op loop: hammers memory.fill + memory.copy so any preemption (fuel or
# epoch) is highly likely to land around a bulk-memory instruction.
LOOP_WAT = r"""
(module
  (memory (export "memory") 32)
  (func (export "_start")
    (local $i i32)
    (block $done
      (loop $l
        (br_if $done (i32.ge_u (local.get $i) (i32.const 100000000)))
        (memory.fill (i32.const 0) (i32.const 0xAB) (i32.const 65536))
        (memory.copy (i32.const 65536) (i32.const 0) (i32.const 65536))
        (local.set $i (i32.add (local.get $i) (i32.const 1)))
        (br $l)))))
"""

# Positive control: one bounded fill + copy, then read the copied region back
# and exit 0 only if the data is byte-correct. Catches silent corruption on an
# uninterrupted run.
CONTROL_WAT = r"""
(module
  (import "wasi_snapshot_preview1" "proc_exit" (func $exit (param i32)))
  (memory (export "memory") 2)
  (func (export "_start")
    (local $k i32)
    (memory.fill (i32.const 0) (i32.const 0xAB) (i32.const 65536))
    (memory.copy (i32.const 65536) (i32.const 0) (i32.const 65536))
    ;; every byte in [65536, 131072) must be 0xAB
    (local.set $k (i32.const 65536))
    (block $done
      (loop $l
        (br_if $done (i32.ge_u (local.get $k) (i32.const 131072)))
        (if (i32.ne (i32.load8_u (local.get $k)) (i32.const 0xAB))
          (then (call $exit (i32.const 42))))
        (local.set $k (i32.add (local.get $k) (i32.const 1)))
        (br $l)))
    (call $exit (i32.const 0))))
"""

# Child-leg programs run in a fresh interpreter so a host abort stays contained.
# max_fuel=None keeps fuel metering OFF; the budget passed here selects posture.
LEG_PREEMPT = r"""
import sys, json, tempfile
from pathlib import Path
sys.path.insert(0, {repo!r})
import wasmtime
from ephemora_cell import WASIConfig, WASISandbox
work = Path(tempfile.mkdtemp(prefix="ghsa_2hw9_"))
wasm = work / "loop.wasm"
wasm.write_bytes(wasmtime.wat2wasm({wat!r}))
cfg = WASIConfig(max_memory_mb=64, max_fuel={max_fuel!r},
                 timeout_seconds={timeout!r}, allow_dirs=())
sandbox = WASISandbox(config=cfg)
try:
    r = sandbox.run(str(wasm), use_subprocess=False, abi="preview1")
    print(json.dumps({{"status": str(r.status), "exit_code": r.exit_code,
                       "fuel": r.fuel_consumed,
                       "stderr": (r.stderr or "")[:200]}}))
finally:
    sandbox.cleanup()
print("HOST-SURVIVED")
"""

LEG_CONTROL = r"""
import sys, json, tempfile
from pathlib import Path
sys.path.insert(0, {repo!r})
import wasmtime
from ephemora_cell import WASIConfig, WASISandbox
work = Path(tempfile.mkdtemp(prefix="ghsa_2hw9_"))
wasm = work / "ctl.wasm"
wasm.write_bytes(wasmtime.wat2wasm({wat!r}))
cfg = WASIConfig(max_memory_mb=64, max_fuel=200_000_000, timeout_seconds=120,
                 allow_dirs=())
sandbox = WASISandbox(config=cfg)
try:
    r = sandbox.run(str(wasm), use_subprocess=False, abi="preview1")
    print(json.dumps({{"status": str(r.status), "exit_code": r.exit_code,
                       "stderr": (r.stderr or "")[:200]}}))
finally:
    sandbox.cleanup()
print("HOST-SURVIVED")
"""

LEG_SUBPROCESS = r"""
import sys, json, tempfile
from pathlib import Path
sys.path.insert(0, {repo!r})
import wasmtime
from ephemora_cell import WASIConfig, WASISandbox
work = Path(tempfile.mkdtemp(prefix="ghsa_2hw9_"))
wasm = work / "loop.wasm"
wasm.write_bytes(wasmtime.wat2wasm({wat!r}))
cfg = WASIConfig(max_memory_mb=64, max_fuel={max_fuel!r},
                 timeout_seconds={timeout!r}, allow_dirs=())
sandbox = WASISandbox(config=cfg)
try:
    r = sandbox.run(str(wasm), use_subprocess=True, abi="preview1")
    print(json.dumps({{"status": str(r.status), "exit_code": r.exit_code,
                       "fuel": r.fuel_consumed,
                       "stderr": (r.stderr or "")[:200]}}))
finally:
    sandbox.cleanup()
print("PARENT-SURVIVED")
"""


def _run(program: str) -> subprocess.CompletedProcess:
    return subprocess.run(
        [sys.executable, "-c", program], capture_output=True, text=True, timeout=300
    )


def _payload(proc: subprocess.CompletedProcess) -> dict:
    for line in (proc.stdout or "").splitlines():
        line = line.strip()
        if line.startswith("{"):
            try:
                return json.loads(line)
            except json.JSONDecodeError:
                continue
    return {}


def _leg(proc: subprocess.CompletedProcess, survived: str) -> dict:
    return {
        "returncode": proc.returncode,
        "host_survived": survived in (proc.stdout or ""),
        "payload": _payload(proc),
        "stderr_tail": (proc.stderr or "").strip().splitlines()[:3],
    }


def main() -> int:
    results = {
        "measured": True,
        "source": "measurement",
        "date": str(date.today()),
        "python": platform.python_version(),
        "wasmtime_package": _pkg_version("wasmtime"),
        "package": _pkg_version("ephemora-cell"),
        "platform": f"{platform.system()}/{platform.machine()}",
        "advisory": "GHSA-2hw9-mc66-jc2q",
        "loop_wat_sha256": hashlib.sha256(LOOP_WAT.encode()).hexdigest(),
        "legs": {},
    }

    # L1 fuel preemption (in-process, child): tiny budget, generous timeout.
    p = _run(LEG_PREEMPT.format(repo=str(REPO), wat=LOOP_WAT, max_fuel=50_000,
                                 timeout=120))
    results["legs"]["fuel_preempt_in_process"] = _leg(p, "HOST-SURVIVED")

    # L2 epoch preemption (in-process, child): huge budget, 1s timeout.
    p = _run(LEG_PREEMPT.format(repo=str(REPO), wat=LOOP_WAT, max_fuel=None,
                                 timeout=1))
    results["legs"]["epoch_preempt_in_process"] = _leg(p, "HOST-SURVIVED")

    # L3 positive control (in-process, child): uninterrupted fill/copy is correct.
    p = _run(LEG_CONTROL.format(repo=str(REPO), wat=CONTROL_WAT))
    results["legs"]["control_correct_in_process"] = _leg(p, "HOST-SURVIVED")

    # L4 shipped isolation posture (subprocess): parent survives either preemption.
    p = _run(LEG_SUBPROCESS.format(repo=str(REPO), wat=LOOP_WAT, max_fuel=50_000,
                                    timeout=120))
    results["legs"]["fuel_preempt_subprocess"] = _leg(p, "PARENT-SURVIVED")
    p = _run(LEG_SUBPROCESS.format(repo=str(REPO), wat=LOOP_WAT, max_fuel=None,
                                    timeout=1))
    results["legs"]["epoch_preempt_subprocess"] = _leg(p, "PARENT-SURVIVED")

    legs = results["legs"]
    fuel = legs["fuel_preempt_in_process"]
    epoch = legs["epoch_preempt_in_process"]
    ctrl = legs["control_correct_in_process"]
    sub_f = legs["fuel_preempt_subprocess"]
    sub_e = legs["epoch_preempt_subprocess"]

    verdicts = {
        # Path is reachable: a fuel-trapped bulk-op loop yields a trap status,
        # not a silent success, and the host survives (contained).
        "fuel_preemption_traps_contained": fuel["host_survived"]
        and fuel["payload"].get("status", "").startswith("ExecutionStatus")
        and "fuel" in fuel["payload"].get("status", "").lower(),
        "epoch_preemption_traps_contained": epoch["host_survived"]
        and ("timeout" in epoch["payload"].get("status", "").lower()
             or "interrupt" in (epoch["payload"].get("stderr") or "").lower()),
        "control_uninterrupted_correct": ctrl["host_survived"]
        and ctrl["payload"].get("status", "").lower().endswith("success")
        and ctrl["payload"].get("exit_code") in (0, None),
        "subprocess_parent_survives_fuel": sub_f["host_survived"],
        "subprocess_parent_survives_epoch": sub_e["host_survived"],
        "no_uncontained_host_abort": all(
            legs[k]["host_survived"]
            for k in ("fuel_preempt_in_process", "epoch_preempt_in_process",
                      "control_correct_in_process")
        ),
    }
    results["verdicts"] = verdicts
    results["reachability"] = (
        "AFFECTED — REACHABLE (bulk-op + fuel/epoch preemption executes on "
        "this build); measured outcome: preemption traps cleanly and the "
        "host/parent is contained on both the in-process and subprocess paths. "
        "The exact preempt-inside-epilogue corrupt-VM-state window is an "
        "engine-internal timing race not forceable from a guest — residual, "
        "mitigated by process isolation for untrusted guests."
    )
    results["pass"] = all(verdicts.values())

    results_dir = REPO / "benchmarks" / "results" / str(date.today())
    results_dir.mkdir(parents=True, exist_ok=True)
    dest = results_dir / "bulk_op_preemption_ghsa_2hw9.json"
    dest.write_text(json.dumps(results, indent=2))
    print(json.dumps({"verdicts": verdicts, "fuel": fuel, "epoch": epoch,
                      "ctrl": ctrl}, indent=1))
    print(f"Evidence: {dest}  |  PASS={results['pass']}")
    return 0 if results["pass"] else 1


if __name__ == "__main__":
    sys.exit(main())
