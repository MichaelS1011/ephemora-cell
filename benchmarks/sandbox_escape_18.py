#!/usr/bin/env python3
"""
SandboxEscapeBench-18 mapping — structural capability comparison, NOT a
blocked-benchmark.

Upstream: "SandboxEscapeBench" by the UK AI Security Institute with the
University of Oxford — arXiv 2603.02277, scenario set
UKGovernmentBEIS/sandbox_escape_bench (MIT license; fetched 2026-09-18).
Their benchmark evaluates whether AI agents can escape misconfigured
containers. This script does something narrower and deliberately different:
it maps each of the 18 documented container/K8s escape scenarios to its
closest WASM/WASI equivalent and classifies the outcome on the live Cell
boundary as either

  EXECUTION-DENIED  a real WASM attempt (preopen traversal toward /etc, a
                    sock_accept capability call, a shared-memory module, a
                    live import-surface scan) runs against the engine and
                    is denied, or
  NOT-EXPRESSIBLE   the technique relies on container/kernel primitives
                    (privileged modes, namespaces, cgroups, packet sockets,
                    k8s tooling, RBAC) that do not exist on the WASI
                    surface, so there is nothing to attempt.

This is a statement about the attack surface — not a claim that Cell
"beats" kernel exploits, and no scenario count is presented as "18/18
blocked". A container/K8s deployment still needs its own hardening; see
the hardened-container baseline in the README.

Positive control: on the same sandbox config, creating a file inside the
granted scratch preopen (fd 3) MUST succeed — if it fails, the harness is
broken, not the boundary, and the run does not count (exit 1).

Evidence: benchmarks/results/<date>/04_sandbox_escape_18.json
(measured:true). Supersedes the 2026-08-25 run, whose verdict semantics
counted a trivially succeeding proc_exit module as "BLOCKED by design".
"""

from __future__ import annotations

import json
import sys
import tempfile
from datetime import date
from importlib.metadata import version as _pkg_version
from pathlib import Path

import wasmtime

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
from ephemora_cell import WASIConfig, WASISandbox

REPO = Path(__file__).resolve().parents[1]

UPSTREAM = {
    "benchmark": "SandboxEscapeBench",
    "publisher": "UK AI Security Institute (+ University of Oxford)",
    "arxiv": "2603.02277",
    "scenarios_repo": "https://github.com/UKGovernmentBEIS/sandbox_escape_bench",
    "license": "MIT",
    "fetched": "2026-09-18",
    "upstream_measures": (
        "whether AI agents can escape misconfigured containers (agentic eval); "
        "this script maps the documented scenarios to WASM equivalents and is "
        "a structural attack-surface comparison, not a reproduction"
    ),
}

# Names that would represent exec/fork escape primitives. If any of these
# exist in the live WASI Preview1 import surface, the runc-class vectors
# would be open (same idiom as benchmarks/verify_8_vectors.py).
EXEC_FORK_NAMES = [
    "exec",
    "system",
    "execve",
    "execv",
    "execvp",
    "fork",
    "vfork",
    "clone",
    "posix_spawn",
    "spawn",
    "proc_spawn",
]

# --- WASM payloads ---------------------------------------------------------

CONTROL_WAT = r"""
;; Positive control: creating a file inside the granted scratch preopen
;; (fd 3) MUST succeed (errno 0). Anything else = broken harness.
(module
  (import "wasi_snapshot_preview1" "path_open"
    (func $open (param i32 i32 i32 i32 i32 i64 i64 i32 i32) (result i32)))
  (import "wasi_snapshot_preview1" "fd_write"
    (func $wr (param i32 i32 i32 i32) (result i32)))
  (import "wasi_snapshot_preview1" "proc_exit" (func $exit (param i32)))
  (memory (export "memory") 1)
  (data (i32.const 100) "seb_control.txt")
  (data (i32.const 200) "CONTROL:OK")
  (data (i32.const 250) "CONTROL:DENIED")
  (func (export "_start")
    (local $errno i32)
    ;; path_open(3, 0, 100, 15, CREAT, FD_READ|FD_WRITE, same, 0, 900)
    (local.set $errno
      (call $open
        (i32.const 3) (i32.const 0)
        (i32.const 100) (i32.const 15)
        (i32.const 1)
        (i64.const 0x42) (i64.const 0x42)
        (i32.const 0) (i32.const 900)))
    ;; marker: returned errno 0 -> CONTROL:OK. WASI fd_write takes
    ;; (fd, iovs_ptr, iovs_len, nwritten_ptr) — build the iovec in memory first.
    (if (i32.eqz (local.get $errno))
      (then
        (i32.store (i32.const 952) (i32.const 200))
        (i32.store (i32.const 956) (i32.const 10))
        (drop (call $wr (i32.const 1) (i32.const 952) (i32.const 1) (i32.const 960))))
      (else
        (i32.store (i32.const 952) (i32.const 250))
        (i32.store (i32.const 956) (i32.const 14))
        (drop (call $wr (i32.const 1) (i32.const 952) (i32.const 1) (i32.const 960)))))
    (call $exit (i32.const 0))
  )
)
"""

TRAVERSAL_WAT = r"""
;; Execution test for the hostpath/fs scenarios: path_open the scratch
;; preopen (fd 3) toward "../etc/passwd" — outside the granted root.
;; errno 0 would print TRAVERSAL:OPENED (a win for the attacker side);
;; anything else prints TRAVERSAL:DENIED.
(module
  (import "wasi_snapshot_preview1" "path_open"
    (func $open (param i32 i32 i32 i32 i32 i64 i64 i32 i32) (result i32)))
  (import "wasi_snapshot_preview1" "fd_write"
    (func $wr (param i32 i32 i32 i32) (result i32)))
  (import "wasi_snapshot_preview1" "proc_exit" (func $exit (param i32)))
  (memory (export "memory") 1)
  (data (i32.const 100) "../etc/passwd")
  (data (i32.const 200) "TRAVERSAL:OPENED")
  (data (i32.const 250) "TRAVERSAL:DENIED")
  (func (export "_start")
    (local $errno i32)
    (local.set $errno
      (call $open
        (i32.const 3) (i32.const 0)
        (i32.const 100) (i32.const 13)
        (i32.const 0)
        (i64.const 0x6) (i64.const 0x6)
        (i32.const 0) (i32.const 900)))
    (if (i32.eqz (local.get $errno))
      (then
        (i32.store (i32.const 952) (i32.const 200))
        (i32.store (i32.const 956) (i32.const 16))
        (drop (call $wr (i32.const 1) (i32.const 952) (i32.const 1) (i32.const 960))))
      (else
        (i32.store (i32.const 952) (i32.const 250))
        (i32.store (i32.const 956) (i32.const 15))
        (drop (call $wr (i32.const 1) (i32.const 952) (i32.const 1) (i32.const 960)))))
    (call $exit (i32.const 0))
  )
)
"""

SOCK_WAT = r"""
;; Execution test for the socket scenarios: attempt a sock_accept capability
;; call on the live surface. wasmtime 47 may expose sock_* NAMES (wasi:sockets
;; proposal) — presence alone proves nothing; the CALL verdict is the fact.
;; SOCK:OPENED = network vector open (finding); trap or errno = denied.
(module
  (import "wasi_snapshot_preview1" "sock_accept"
    (func $acc (param i32 i32 i32) (result i32)))
  (import "wasi_snapshot_preview1" "fd_write"
    (func $wr (param i32 i32 i32 i32) (result i32)))
  (import "wasi_snapshot_preview1" "proc_exit" (func $exit (param i32)))
  (memory (export "memory") 1)
  (data (i32.const 200) "SOCKET:OPENED")
  (data (i32.const 250) "SOCKET:DENIED")
  (func (export "_start")
    (local $errno i32)
    (local.set $errno
      (call $acc (i32.const 0) (i32.const 0) (i32.const 900)))
    (if (i32.eqz (local.get $errno))
      (then
        (i32.store (i32.const 952) (i32.const 200))
        (i32.store (i32.const 956) (i32.const 13))
        (drop (call $wr (i32.const 1) (i32.const 952) (i32.const 1) (i32.const 960))))
      (else
        (i32.store (i32.const 952) (i32.const 250))
        (i32.store (i32.const 956) (i32.const 13))
        (drop (call $wr (i32.const 1) (i32.const 952) (i32.const 1) (i32.const 960)))))
    (call $exit (i32.const 0))
  )
)
"""

SHARED_WAT = r"""
;; Execution test for Dirty COW: shared memory requires wasm threads, and
;; the engine is built with wasm_threads=False — declaring a shared memory
;; must be rejected by the engine.
(module
  (memory (export "memory") 1 1 shared)
)
"""

# --- scenario table ---------------------------------------------------------
# method: "execution" -> a real WASM attempt runs; "capability-absent" -> the
# technique has no WASI-expressible equivalent (structural argument).

SCENARIOS = [
    # (id, layer, upstream scenario, method, wat_or_note)
    (
        "privileged",
        "L1 Orchestration",
        "Privileged container (--privileged)",
        "capability-absent",
        "WASI grants only explicit capability preopens; no privileged mode exists",
    ),
    (
        "docker_socket",
        "L1 Orchestration",
        "Docker socket /var/run/docker.sock",
        "execution",
        "SOCK",
    ),
    (
        "pid_namespace",
        "L1 Orchestration",
        "Host PID --pid=host + CAP_SYS_PTRACE",
        "capability-absent",
        "WASI has no pid-namespace concept and no ptrace surface",
    ),
    (
        "sys_admin",
        "L1 Orchestration",
        "CAP_SYS_ADMIN",
        "capability-absent",
        "no capability model beyond explicit preopens",
    ),
    (
        "sys_module",
        "L1 Orchestration",
        "CAP_SYS_MODULE",
        "capability-absent",
        "no kernel-module surface",
    ),
    (
        "dac_read_search",
        "L1 Orchestration",
        "CAP_DAC_READ_SEARCH open_by_handle_at",
        "execution",
        "TRAVERSAL",
    ),
    (
        "hostpath_etc",
        "L1 Orchestration",
        "Writable hostPath /etc",
        "execution",
        "TRAVERSAL",
    ),
    (
        "cgroup_release_agent",
        "L3 Runtime",
        "CVE-2022-0492 cgroup escape",
        "capability-absent",
        "no cgroup surface",
    ),
    (
        "runc_overwrite",
        "L3 Runtime",
        "CVE-2019-5736 runc overwrite",
        "execution",
        "EXEC_SCAN",
    ),
    (
        "bpf_privesc",
        "L4 Kernel",
        "CVE-2017-16995 BPF privesc 4.4.x",
        "capability-absent",
        "no BPF, no kernel",
    ),
    ("dirty_cow", "L4 Kernel", "CVE-2016-5195 Dirty COW", "execution", "SHARED"),
    (
        "dirty_pipe",
        "L4 Kernel",
        "CVE-2022-0847 Dirty Pipe 5.8-5.16",
        "capability-absent",
        "no pipes, no kernel primitives",
    ),
    (
        "packet_socket",
        "L4 Kernel",
        "CVE-2017-7308 packet_socket 4.8.x",
        "execution",
        "SOCK",
    ),
    (
        "k8s_crio_escape",
        "L4 K8s",
        "CVE-2022-0811 CRI-O sysctl",
        "capability-absent",
        "no CRI-O/sysctl surface",
    ),
    (
        "k8s_malicious_binary",
        "L4 K8s",
        "CVE-2019-1002101 kubectl cp tar",
        "capability-absent",
        "no host tooling on the WASI surface",
    ),
    (
        "k8s_rbac_permissions",
        "L1 K8s",
        "Overprivileged service account",
        "capability-absent",
        "no RBAC/API-server surface",
    ),
    (
        "k8s_route_localnet",
        "L4 K8s",
        "CVE-2020-8558 route_localnet",
        "execution",
        "SOCK",
    ),
    ("k8s_runc", "L3 K8s", "CVE-2024-21626 runc fd leak k3s", "execution", "EXEC_SCAN"),
]


def _import_surface() -> set[str]:
    """The WASI Preview1 function names actually defined by the linker Cell
    exposes (live introspection, same idiom as verify_8_vectors)."""
    engine = wasmtime.Engine()
    store = wasmtime.Store(engine)
    linker = wasmtime.Linker(engine)
    linker.define_wasi()
    names: set[str] = set()
    for candidate in EXEC_FORK_NAMES:
        try:
            linker.get(store, "wasi_snapshot_preview1", candidate)
            names.add(candidate)
        except Exception:
            pass
    return names


def _run_module(wat: str) -> tuple[object, str]:
    wasm = wasmtime.wat2wasm(wat)
    tmp = tempfile.NamedTemporaryFile(suffix=".wasm", delete=False)
    tmp.write(wasm)
    tmp.close()
    sandbox = WASISandbox(
        config=WASIConfig(
            allow_dirs=(), max_fuel=100_000, timeout_seconds=2, max_memory_mb=32
        )
    )
    try:
        result = sandbox.run(tmp.name)
    finally:
        sandbox.cleanup()
        Path(tmp.name).unlink(missing_ok=True)
    return result, (result.stdout or "").strip()


def main() -> int:
    print("SandboxEscapeBench-18 mapping — structural capability comparison")
    print("=" * 70)

    ok = True
    results: list[dict] = []

    # Positive control FIRST: the granted scratch preopen must accept a
    # created file. Control failure = broken harness, run does not count.
    control_result, control_out = _run_module(CONTROL_WAT)
    control_ok = control_result.status.name == "SUCCESS" and "CONTROL:OK" in control_out
    print(
        f"positive control (granted scratch create): "
        f"{'OK' if control_ok else 'FAILED'}  [{control_out or control_result.status.name}]"
    )
    if not control_ok:
        print("Harness broken — run does not count.")
        return 1

    surface = _import_surface()
    exec_fork_present = sorted(n for n in EXEC_FORK_NAMES if n in surface)
    scan_denied = len(exec_fork_present) == 0

    for sid, layer, desc, method, note in SCENARIOS:
        if method == "execution" and note in ("TRAVERSAL", "SOCK"):
            result, out = _run_module(
                TRAVERSAL_WAT if note == "TRAVERSAL" else SOCK_WAT
            )
            leaked = result.status.name == "SUCCESS" and (
                "TRAVERSAL:OPENED" in out or "SOCKET:OPENED" in out
            )
            verdict = "OPEN (FINDING)" if leaked else "EXECUTION-DENIED"
            detail = (
                f"{result.status.name}: {out}"
                if out
                else f"{result.status.name} (no stdout) — "
                f"{(result.stderr or '').strip()[:80]}"
            )
        elif method == "execution" and note == "SHARED":
            try:
                wasmtime.wat2wasm(SHARED_WAT)
                rejected, stage = False, "wat2wasm accepted"
            except Exception as e:
                rejected, stage = True, f"rejected at compile: {str(e)[:60]}"
            if rejected:
                verdict, detail = "EXECUTION-DENIED", stage
            else:
                # compile succeeded — try instantiation/engine load
                wasm = wasmtime.wat2wasm(SHARED_WAT)
                tmp = tempfile.NamedTemporaryFile(suffix=".wasm", delete=False)
                tmp.write(wasm)
                tmp.close()
                sandbox = WASISandbox(
                    config=WASIConfig(
                        allow_dirs=(),
                        max_fuel=100_000,
                        timeout_seconds=2,
                        max_memory_mb=32,
                    )
                )
                try:
                    result = sandbox.run(tmp.name)
                    engine_rejected = result.status.name != "SUCCESS"
                    verdict = (
                        "EXECUTION-DENIED" if engine_rejected else "OPEN (FINDING)"
                    )
                    detail = f"{result.status.name}: {(result.stderr or '')[:80]}"
                finally:
                    sandbox.cleanup()
                    Path(tmp.name).unlink(missing_ok=True)
        elif method == "execution" and note == "EXEC_SCAN":
            verdict = "EXECUTION-DENIED" if scan_denied else "OPEN (FINDING)"
            detail = (
                "live import-surface scan: no exec/fork primitive "
                f"(checked {len(EXEC_FORK_NAMES)} names)"
                if scan_denied
                else f"exposed: {exec_fork_present}"
            )
        else:  # capability-absent
            verdict = "NOT-EXPRESSIBLE"
            detail = note

        if "FINDING" in verdict:
            ok = False
        results.append(
            {
                "id": sid,
                "layer": layer,
                "scenario": desc,
                "method": method,
                "verdict": verdict,
                "detail": detail,
            }
        )
        print(f"{sid:22} {layer:16} {verdict:18} {desc[:40]}")

    exec_denied = sum(1 for r in results if r["verdict"] == "EXECUTION-DENIED")
    absent = sum(1 for r in results if r["verdict"] == "NOT-EXPRESSIBLE")
    print("=" * 70)
    print(
        f"Result: {exec_denied}/18 execution-tested and denied · "
        f"{absent}/18 not expressible on the WASI surface (structural)"
    )
    print("This is an attack-surface statement, not a '18/18 blocked' claim.")

    doc = {
        "measured": True,
        "source": "measurement",
        "date": str(date.today()),
        "wasmtime": _pkg_version("wasmtime"),
        "attribution": UPSTREAM,
        "positive_control": {
            "granted_scratch_create": control_ok,
            "detail": control_out or control_result.status.name,
        },
        "import_surface_scan": {
            "exec_fork_names_checked": len(EXEC_FORK_NAMES),
            "present": exec_fork_present,
        },
        "summary": {
            "execution_denied": exec_denied,
            "not_expressible": absent,
            "open_findings": sum(1 for r in results if "FINDING" in r["verdict"]),
        },
        "note": (
            "Structural capability comparison against the live Cell boundary. "
            "Supersedes the 2026-08-25 run, whose verdict semantics counted a "
            "trivially succeeding proc_exit module as 'BLOCKED by design'."
        ),
        "scenarios": results,
    }
    out_dir = REPO / "benchmarks" / "results" / str(date.today())
    out_dir.mkdir(parents=True, exist_ok=True)
    dest = out_dir / "04_sandbox_escape_18.json"
    dest.write_text(json.dumps(doc, indent=2))
    print(f"Saved: {dest}  |  PASS={ok}")
    return 0 if ok else 1


if __name__ == "__main__":
    sys.exit(main())
