"""GHSA-j2g9-4prp-pf6h evidence harness — wasmtime-wasi filesystem datetime
overflow (published 2026-09-24, no CVE assigned).

The advisory: a guest-supplied filesystem timestamp whose seconds+nanoseconds
record overflows Rust's ``Duration::new`` panics the host (wasip1/2/3
``set-times`` surfaces; Moderate, CVSS 6.2, availability only). Patched in
36.0.16 / 48.0.3 / 49.0.1 — there is NO patched 47.x release, so the pinned
47.0.1 is affected by version range.

Why this is a standalone harness and not part of mcp_cve_replay.py: the
in-process reproduction ABORTS the host process (Rust panic -> SIGABRT), so
it cannot run inside a shared harness that still has to write its evidence.
Each leg runs in its own python subprocess here; an abort is recorded, not
fatal. The probe component is benchmarks/component_probes/times_probe.wasm
(rebuild via component_probes/rebuild.sh).

Legs (measured on the pinned engine):
  1. wasip1 fd_filestat_set_times / path_filestat_set_times with scalar
     u64::MAX nanosecond timestamps (WAT probe, built at run time) — the
     advisory's preview1 surface. NOT reproducible on 47.0.1: the host
     converts the single-u64 value without overflow (errno 0 / 44), no
     panic. The panicking shape is the wasip2 Datetime record (separate
     seconds + nanoseconds fields).
  2. component (wasip2) descriptor.set-times with
     NewTimestamp::Timestamp(Datetime { seconds: u64::MAX, nanoseconds:
     1_000_000_000 }), IN-PROCESS (Cell's default posture) — REPRODUCED:
     host process aborts (SIGABRT, "overflow in Duration::new"). Fuel,
     epoch timeout and memory caps do not apply: the panic happens inside
     the host call.
  3. the same call with NewTimestamp::Now (positive control, in-process) —
     must SUCCEED, proving the preopen grant and set-times rights are fine
     and only the overflowing datetime panics.
  4. the overflow call on the subprocess path (use_subprocess=True) —
     contained: the worker dies, the parent survives with a clean ERROR.

Evidence: benchmarks/results/<date>/datetime_overflow_ghsa_j2g9.json.

Usage: python benchmarks/datetime_overflow_probe.py
"""

from __future__ import annotations

import hashlib
import json
import platform
import subprocess
import sys
import tempfile
from datetime import date
from importlib.metadata import version as _pkg_version
from pathlib import Path

REPO = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(REPO))

TIMES_PROBE = REPO / "benchmarks" / "component_probes" / "times_probe.wasm"

# Preview1 scalar-timestamp probes (advisory's wasip1 surface). fst_flags:
# ATIM=1, ATIM_NOW=2, MTIM=4, MTIM_NOW=8. fd 3 is the /sandbox preopen
# (the only one granted in this config). i64.const -1 == u64::MAX.
WASIP1_VECTORS = {
    "fd_filestat_set_times(atim=u64max, ATIM)": (
        "fd_filestat_set_times",
        "(i32.const 3) (i64.const -1) (i64.const 0) (i32.const 1)",
        "(param i32 i64 i64 i32)",
    ),
    "fd_filestat_set_times(atim=mtim=u64max, ATIM|MTIM)": (
        "fd_filestat_set_times",
        "(i32.const 3) (i64.const -1) (i64.const -1) (i32.const 5)",
        "(param i32 i64 i64 i32)",
    ),
    "fd_filestat_set_times(u64max, ATIM_NOW|MTIM_NOW)": (
        "fd_filestat_set_times",
        "(i32.const 3) (i64.const -1) (i64.const -1) (i32.const 10)",
        "(param i32 i64 i64 i32)",
    ),
    "path_filestat_set_times(u64max, ATIM)": (
        "path_filestat_set_times",
        "(i32.const 3) (i32.const 0) (i32.const 900) (i32.const 0) "
        "(i64.const -1) (i64.const 0) (i32.const 1)",
        "(param i32 i32 i32 i32 i64 i64 i32)",
    ),
}

WASIP1_WAT = r"""
(module
  (import "wasi_snapshot_preview1" "{fname}" (func $t {sig} (result i32)))
  (import "wasi_snapshot_preview1" "fd_write" (func $fd_write (param i32 i32 i32 i32) (result i32)))
  (import "wasi_snapshot_preview1" "proc_exit" (func $exit (param i32)))
  (memory (export "memory") 1)
  (func $put3 (param $ptr i32) (param $v i32)
    (i32.store8 (local.get $ptr) (i32.add (i32.const 48)
      (i32.rem_u (i32.div_u (local.get $v) (i32.const 100)) (i32.const 10))))
    (i32.store8 (i32.add (local.get $ptr) (i32.const 1)) (i32.add (i32.const 48)
      (i32.rem_u (i32.div_u (local.get $v) (i32.const 10)) (i32.const 10))))
    (i32.store8 (i32.add (local.get $ptr) (i32.const 2)) (i32.add (i32.const 48)
      (i32.rem_u (i32.div_u (local.get $v) (i32.const 10)) (i32.const 10)))))
  (func $say (param $ptr i32) (param $len i32)
    (i32.store (i32.const 700) (local.get $ptr))
    (i32.store (i32.const 704) (local.get $len))
    (drop (call $fd_write (i32.const 1) (i32.const 700) (i32.const 1) (i32.const 708))))
  (func (export "_start")
    (local $e i32)
    (local.set $e (call $t {args}))
    (call $say (i32.const 800) (i32.const 6))
    (call $put3 (i32.const 806) (local.get $e))
    (call $say (i32.const 800) (i32.const 9))
    (call $exit (i32.const 0)))
)
"""

# child-leg programs (run in a fresh interpreter so a host abort stays
# contained and is observable as a return code)
LEG_INPROCESS = r"""
import sys, json, tempfile
sys.path.insert(0, {repo!r})
from ephemora_cell import WASIConfig
from ephemora_cell.wasi_02 import ComponentSandbox
allow = tempfile.mkdtemp(prefix="ghsa_j2g9_")
sandbox = ComponentSandbox(config=WASIConfig(allow_dirs=(allow,), max_fuel=1_000_000))
try:
    r = sandbox.run({probe!r}, args={args!r})
    print(json.dumps({{"status": str(r.status), "exit_code": r.exit_code,
                       "stdout": (r.stdout or "")[:120],
                       "stderr": (r.stderr or "")[:200]}}))
finally:
    sandbox.cleanup()
print("HOST-SURVIVED")
"""

LEG_SUBPROCESS = r"""
import sys, json, tempfile
sys.path.insert(0, {repo!r})
from ephemora_cell import WASIConfig, WASISandbox
allow = tempfile.mkdtemp(prefix="ghsa_j2g9_")
sandbox = WASISandbox(config=WASIConfig(allow_dirs=(allow,), max_fuel=1_000_000))
try:
    r = sandbox.run({probe!r}, use_subprocess=True, abi="auto")
    print(json.dumps({{"status": str(r.status), "exit_code": r.exit_code,
                       "stderr": (r.stderr or "")[:300]}}))
finally:
    sandbox.cleanup()
print("PARENT-SURVIVED")
"""


def _run_leg(program: str) -> subprocess.CompletedProcess:
    return subprocess.run(
        [sys.executable, "-c", program],
        capture_output=True,
        text=True,
        timeout=300,
    )


def _leg_result(proc: subprocess.CompletedProcess) -> dict:
    panic = "overflow in Duration::new" in (proc.stderr or "")
    return {
        "returncode": proc.returncode,
        "panic_in_stderr": panic,
        "aborted": proc.returncode != 0,
        "stdout_tail": (proc.stdout or "").strip().splitlines()[-1:],
        "stderr_tail": (proc.stderr or "").strip().splitlines()[:2],
    }


def _leg_json(proc: subprocess.CompletedProcess) -> dict | None:
    """The containment legs print the ExecutionResult as one JSON line."""
    for line in (proc.stdout or "").splitlines():
        line = line.strip()
        if line.startswith("{"):
            try:
                return json.loads(line)
            except json.JSONDecodeError:
                continue
    return None


def wasip1_leg() -> dict:
    """Preview1 scalar-timestamp surface: measure, do not trust."""
    import wasmtime

    from ephemora_cell import WASIConfig, WASISandbox

    out = {}
    for name, (fname, args, sig) in WASIP1_VECTORS.items():
        wat = WASIP1_WAT.format(fname=fname, args=args, sig=sig)
        work = Path(tempfile.mkdtemp(prefix="ghsa_j2g9_p1_"))
        wasm = work / "vec.wasm"
        wasm.write_bytes(wasmtime.wat2wasm(wat))
        sandbox = WASISandbox(config=WASIConfig(max_fuel=1_000_000))
        try:
            r = sandbox.run(str(wasm), use_subprocess=False, abi="auto")
            errno_txt = (r.stdout or "").strip()[-3:]
            out[name] = {
                "status": str(r.status),
                "errno": errno_txt,
                "panic": "panicked" in (r.stderr or ""),
                "host_survived": True,
            }
        finally:
            sandbox.cleanup()
    return out


def component_legs() -> dict:
    probe = str(TIMES_PROBE)
    legs = {}

    # 2: overflow set-times, in-process (Cell default posture) — expect abort
    proc = _run_leg(LEG_INPROCESS.format(repo=str(REPO), probe=probe, args=[]))
    legs["component_set_times_overflow_in_process"] = _leg_result(proc)

    # 3: positive control (NewTimestamp::Now) — expect success, host survives
    proc = _run_leg(LEG_INPROCESS.format(repo=str(REPO), probe=probe, args=["control"]))
    ctrl = _leg_result(proc)
    ctrl["stdout_tail"] = (proc.stdout or "").strip().splitlines()[-1:]
    ctrl["expected_set_times_ok"] = "SET-TIMES:OK" in (proc.stdout or "")
    legs["component_set_times_control_in_process"] = ctrl

    # 4: overflow set-times on the subprocess path — expect containment
    proc = _run_leg(LEG_SUBPROCESS.format(repo=str(REPO), probe=probe))
    sub = _leg_result(proc)
    payload = _leg_json(proc) or {}
    sub["run_status"] = payload.get("status")
    sub["worker_crashed"] = "worker crashed" in (payload.get("stderr") or "")
    sub["panic_in_result_stderr"] = "overflow in Duration::new" in (
        payload.get("stderr") or ""
    )
    sub["parent_survived"] = proc.returncode == 0 and "PARENT-SURVIVED" in (
        proc.stdout or ""
    )
    legs["component_set_times_overflow_subprocess"] = sub
    return legs


def main() -> int:
    results = {
        "measured": True,
        "source": "measurement",
        "date": str(date.today()),
        "python": platform.python_version(),
        "wasmtime": _pkg_version("wasmtime"),
        "package": _pkg_version("ephemora-cell"),
        "platform": f"{platform.system()}/{platform.machine()}",
        "advisory": "GHSA-j2g9-4prp-pf6h",
        "probe_sha256": hashlib.sha256(TIMES_PROBE.read_bytes()).hexdigest(),
        "legs": {},
    }
    results["legs"]["wasip1_scalar_timestamps"] = wasip1_leg()
    results["legs"].update(component_legs())

    legs = results["legs"]
    p1 = legs["wasip1_scalar_timestamps"]
    overflow = legs["component_set_times_overflow_in_process"]
    control = legs["component_set_times_control_in_process"]
    contained = legs["component_set_times_overflow_subprocess"]

    verdicts = {
        "wasip1_not_reproducible": all(
            not v["panic"] for v in p1.values()
        ),
        "component_in_process_aborts": overflow["aborted"] and overflow["panic_in_stderr"],
        "control_succeeds": control.get("expected_set_times_ok", False),
        "subprocess_path_contains": (
            contained.get("parent_survived", False)
            and contained.get("worker_crashed", False)
            and contained.get("panic_in_result_stderr", False)
            and contained.get("run_status") == "ExecutionStatus.ERROR"
        ),
    }
    results["verdicts"] = verdicts
    results["pass"] = all(verdicts.values())

    results_dir = REPO / "benchmarks" / "results" / str(date.today())
    results_dir.mkdir(parents=True, exist_ok=True)
    dest = results_dir / "datetime_overflow_ghsa_j2g9.json"
    dest.write_text(json.dumps(results, indent=2))
    print(json.dumps(verdicts, indent=1))
    print(f"Evidence: {dest}  |  PASS={results['pass']}")
    return 0 if results["pass"] else 1


if __name__ == "__main__":
    sys.exit(main())
