"""Classify the eight documented attack vectors against the shipped sandbox.

Every vector is exercised through ``ephemora_cell.WASISandbox`` with a real
module -- never a docs-only assumption and never a scan of a vanilla
``wasmtime.Linker`` standing in for the product. The verdict vocabulary is
fixed, and a refusal is only called a block when a guard actually ran:

  BLOCKED BY POLICY
      An enforced guard refused the operation (capability table, sync trap,
      env allowlist, canonical preopen check), and a positive control shows
      the same operation succeeding when the capability is granted.

  REJECTED AS UNSUPPORTED
      The module or import is structurally outside the exposed ABI/proposal
      policy: WASI Preview1 has no exec/fork/socket-create imports, and the
      engine is built with ``wasm_threads=False`` so shared memories fail at
      validation. An independent control proves the payload itself is valid
      (a benign Preview1 import links and runs; the same bytes compile and
      instantiate under a threads-enabled engine).

  INVALID TEST
      The harness could not construct a valid probe, or its own positive
      control failed for a reason that makes the verdict uninterpretable.

  VULNERABLE
      The attack reached its goal (spawn/socket/sync/FS/env/threads).

  NOT VERIFIED
      Inconclusive: a refusal happened for an unrelated reason, a runtime
      gate refused to run guests, or the evidence does not distinguish the
      cases above.

Consequences for the eight vectors:

  * 1-3 (shell, fork, network) are REJECTED AS UNSUPPORTED, not "blocked":
    the capability does not exist in the WASI Preview1 import surface the
    sandbox exposes. A module importing it is refused at instantiation with
    an unknown-import error; a benign Preview1 import instantiates and runs
    through the same sandbox in the same run.
  * 7 (threading) is REJECTED AS UNSUPPORTED at module validation because
    the product engine sets ``wasm_threads=False``. The same shared-memory +
    atomics module compiles and instantiates on a threads-enabled engine,
    which proves the refusal is the proposal policy and not a broken payload.
  * 4-6 and 8 are BLOCKED BY POLICY and each carries a positive control:
    ``allow_fsync=True`` releases fd_sync/fd_datasync, a real file inside a
    granted preopen opens and reads, and ``allow_env`` with one variable
    makes the guest see exactly one variable.

Exit code 0 only when no vector is VULNERABLE, NOT VERIFIED, or INVALID TEST.
The older "8/8 blocked" summary counted vector 7's parse refusal as a block;
this harness never does, and the report keeps BLOCKED BY POLICY and REJECTED
AS UNSUPPORTED as separate counts.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import shutil
import sys
import tempfile
import time
from collections import Counter
from dataclasses import replace
from pathlib import Path

import wasmtime

from ephemora_cell import WASIConfig, WASISandbox
from ephemora_cell.runtime_qualification import (
    reported_runtime_version,
    runtime_qualification,
    unqualified_runtime_allowed,
)

# =====================================================================
# Verdict vocabulary
# =====================================================================

BLOCKED_BY_POLICY = "BLOCKED BY POLICY"
REJECTED_AS_UNSUPPORTED = "REJECTED AS UNSUPPORTED"
INVALID_TEST = "INVALID TEST"
VULNERABLE = "VULNERABLE"
NOT_VERIFIED = "NOT VERIFIED"

FAILING_CLASSIFICATIONS = {VULNERABLE, NOT_VERIFIED, INVALID_TEST}

# =====================================================================
# Vector 1-3 probe names. Signatures are the WASI Preview1-shaped ones a
# guest would declare. Absence is proven by instantiating a real module
# through WASISandbox -- if a name were defined, the module would link.
# =====================================================================

SHELL_NAMES = {
    "exec": "i32 i32 i32",
    "system": "i32",
    "execve": "i32 i32 i32",
    "execv": "i32 i32",
    "execvp": "i32 i32",
    "posix_spawn": "i32 i32 i32 i32",
    "spawn": "i32 i32",
}
FORK_NAMES = {
    "fork": "",
    "vfork": "",
    "clone": "i32 i32",
    "posix_spawn": "i32 i32 i32 i32",
    "spawn": "i32 i32",
    "proc_spawn": "i32 i32",
}
NETWORK_CREATION_NAMES = {
    "sock_open": "i32 i32 i32 i32",
    "sock_bind": "i32 i32 i32",
    "sock_connect": "i32 i32 i32",
    "sock_listen": "i32 i32",
    "socket": "i32 i32 i32",
    "connect": "i32 i32 i32",
    "bind": "i32 i32 i32",
    "listen": "i32 i32",
    "accept": "i32 i32 i32",
}


def _probe_wat(name: str, params: str) -> str:
    """A module that imports `name` and does nothing else.

    It instantiates only if the sandbox linker defines the import; otherwise
    wasmtime reports an unknown import. That is the difference between a
    capability that exists and one the ABI never had.
    """
    params_wat = " ".join("(param i32)" for _ in params.split())
    return f"""(module
  (import "wasi_snapshot_preview1" "{name}" (func $probe
    {params_wat} (result i32)))
  (memory (export "memory") 1)
  (func (export "_start"))
)"""


#: Benign control: proc_exit exists in Preview1 and must link and run.
BENIGN_IMPORT_WAT = r"""(module
  (import "wasi_snapshot_preview1" "proc_exit" (func $exit (param i32)))
  (memory (export "memory") 1)
  (func (export "_start")
    i32.const 0 call $exit
  )
)"""


def _sock_accept_wat() -> str:
    """Call a handle-only socket op on the preopened sandbox dir (fd 3).

    WASI Preview1 exposes sock_accept, but no creation/connect call. This
    probe shows a handle op cannot bootstrap a socket from a directory fd.
    """
    return r"""(module
  (import "wasi_snapshot_preview1" "sock_accept" (func $sa
    (param i32 i32 i32) (result i32)))
  (import "wasi_snapshot_preview1" "proc_exit" (func $exit (param i32)))
  (memory (export "memory") 1)
  (func (export "_start")
    i32.const 3 i32.const 0 i32.const 100 call $sa call $exit
  )
)"""


# =====================================================================
# Real execution payloads (vectors 4-8)
# =====================================================================

#: Vector 4 — every sync entry point the Cell refuses. All three are trapped
#: at the CALL layer; importing them is legal on purpose, because every
#: wasm32-wasi Zig binary imports fd_sync and CPython-WASI imports fd_datasync
#: without ever calling either. The module calls the sync on fd 3 (the
#: preopened sandbox dir) and would exit 0 if the call returned.
SYNC_NAMES = ("fd_sync", "fd_datasync", "fd_psync")

SYNC_CALL_WAT = r"""(module
  (import "wasi_snapshot_preview1" "%(name)s" (func $s (param i32) (result i32)))
  (import "wasi_snapshot_preview1" "proc_exit" (func $exit (param i32)))
  (memory (export "memory") 1)
  (func (export "_start")
    i32.const 3 call $s drop
    i32.const 0 call $exit
  )
)"""


def sync_call_wat(name: str) -> str:
    return SYNC_CALL_WAT % {"name": name}


def _path_open_wat(target: str) -> str:
    """WASM that path_open()s `target` on the preopen dirfd (3) and exits
    with the returned errno (0 = opened, non-zero = refused)."""
    n = len(target)
    # Stack order is (fd, dirflags, path_ptr, path_len, oflags, rights_base,
    # rights_inheriting, fdflags, opened_fd): path ptr = 0, len = n. Rights
    # are requested FOR THE NEW FILE DESCRIPTOR: FD_READ (0x2) | FD_SEEK
    # (0x4) = 0x6 — file-appropriate; PATH_OPEN is held by the preopened
    # dirfd, never requested per-file.
    return f"""(module
  (import "wasi_snapshot_preview1" "path_open" (func $po
    (param i32 i32 i32 i32 i32 i64 i64 i32 i32) (result i32)))
  (import "wasi_snapshot_preview1" "proc_exit" (func $exit (param i32)))
  (memory (export "memory") 1)
  (data (i32.const 0) "{target}")
  (func (export "_start")
    (local $err i32)
    ;; dirfd=3, dirflags=0, path=0 (ptr), len={n}, oflags=0 (open existing),
    ;; rights=FD_READ|FD_SEEK (0x6), inheriting=0, fdflags=0, opened_fd=100
    i32.const 3 i32.const 0 i32.const 0 i32.const {n} i32.const 0
    i64.const 6 i64.const 0 i32.const 0 i32.const 100
    call $po local.set $err
    local.get $err call $exit
  )
)"""


def _read_file_wat(target: str) -> str:
    """Open `target` in the preopen, fd_read at least one byte, exit 0.

    This is the positive control for vectors 5 and 6: the same probe that the
    attack uses, with the file placed inside the granted directory, must
    succeed. Opening alone would prove less; reading proves the grant is real.
    """
    n = len(target)
    return f"""(module
  (import "wasi_snapshot_preview1" "path_open" (func $po
    (param i32 i32 i32 i32 i32 i64 i64 i32 i32) (result i32)))
  (import "wasi_snapshot_preview1" "fd_read" (func $fr
    (param i32 i32 i32 i32) (result i32)))
  (import "wasi_snapshot_preview1" "proc_exit" (func $exit (param i32)))
  (memory (export "memory") 1)
  (data (i32.const 0) "{target}")
  (func (export "_start")
    (local $err i32) (local $fd i32) (local $n i32)
    ;; path_open(dirfd=3, path=0/len={n}, rights=FD_READ|FD_SEEK)
    i32.const 3 i32.const 0 i32.const 0 i32.const {n} i32.const 0
    i64.const 6 i64.const 0 i32.const 0 i32.const 100
    call $po local.set $err
    local.get $err i32.eqz if else local.get $err call $exit end
    ;; iovec at 128: buf=256, len=32; nread at 140
    i32.const 128 i32.const 256 i32.store
    i32.const 132 i32.const 32 i32.store
    i32.const 100 i32.load local.set $fd
    local.get $fd i32.const 128 i32.const 1 i32.const 140 call $fr local.set $err
    local.get $err i32.eqz if else local.get $err call $exit end
    i32.const 140 i32.load local.set $n
    local.get $n i32.eqz if i32.const 1 call $exit end
    i32.const 0 call $exit
  )
)"""


#: Vector 7 — shared memory AND an atomic RMW, so the payload exercises both
#: the threads proposal's shared memory and its atomics. The product engine
#: (wasm_threads=False) refuses it at validation; a threads-enabled engine
#: must compile and instantiate the same bytes.
SHARED_MEM_ATOMICS_WAT = r"""(module
  (memory (export "memory") 1 2 shared)
  (func (export "bump") (result i32)
    i32.const 0 i32.const 1 i32.atomic.rmw.add)
)"""


#: Vector 8 — exit 0 iff environ_sizes_get reports exactly `expected` vars.
ENV_COUNT_WAT = r"""(module
  (import "wasi_snapshot_preview1" "environ_sizes_get"
    (func $es (param i32 i32) (result i32)))
  (import "wasi_snapshot_preview1" "proc_exit" (func $exit (param i32)))
  (memory (export "memory") 1)
  (func (export "_start")
    (local $err i32)
    i32.const 100 i32.const 104 call $es local.set $err
    local.get $err i32.eqz if else local.get $err call $exit end
    i32.const 100 i32.load i32.const %(expected)d i32.eq
    if (result i32)
      i32.const 0
    else
      i32.const 99
    end
    call $exit
  )
)"""


def env_count_wat(expected: int) -> str:
    return ENV_COUNT_WAT % {"expected": expected}


# =====================================================================
# Helpers
# =====================================================================


def compile_wat(wat: str) -> Path:
    wasm = wasmtime.wat2wasm(wat)
    tmp = tempfile.NamedTemporaryFile(suffix=".wasm", delete=False)
    tmp.write(wasm)
    tmp.close()
    return Path(tmp.name)


def run_attack(wasm_path: Path, config: WASIConfig):
    sandbox = WASISandbox(config=config)
    try:
        result = sandbox.run(str(wasm_path))
        return {
            "status": result.status.value,
            "exit_code": result.exit_code,
            "stderr": (result.stderr or "")[:400],
            "guest_exit_observed": bool(result.guest_exit_observed),
            "execution_mode": result.execution_mode,
            "abi": result.abi,
            "effective_preopens": list(result.effective_preopens),
        }
    except Exception as e:
        return {
            "status": "exception",
            "exit_code": None,
            "stderr": "",
            "error": f"{type(e).__name__}: {e}"[:400],
        }
    finally:
        sandbox.cleanup()


def run_wat(wat: str, config: WASIConfig):
    path = compile_wat(wat)
    try:
        return run_attack(path, config)
    finally:
        path.unlink(missing_ok=True)


def _result_text(result: dict) -> str:
    return " ".join(
        part for part in (result.get("stderr", ""), result.get("error", "")) if part
    )


def _errno_name(code: int | None) -> str | None:
    # WASI Preview1 errno values encountered by these probes.
    return {
        0: "success",
        8: "BADF",
        44: "NOENT",
        54: "NOTDIR",
        63: "PERM",
        76: "NOTCAPABLE",
        57: "NOTSOCK",
        32: "LOOP",
    }.get(code)


DEFAULT = WASIConfig(
    max_fuel=1_000_000, timeout_seconds=5, max_memory_mb=32, allow_dirs=(), allow_env=()
)


def _probe_imports(names: dict[str, str]) -> dict:
    outcomes = {}
    for name, params in names.items():
        result = run_wat(_probe_wat(name, params), DEFAULT)
        text = _result_text(result).lower()
        if result["status"] == "success":
            outcome = "present"
        elif "unknown import" in text or "has not been defined" in text:
            outcome = "absent"
        elif "incompatible import type" in text:
            # The symbol exists with another signature: the capability is
            # exposed even though this probe could not call it.
            outcome = "present-wrong-signature"
        else:
            outcome = "unclear"
        outcomes[name] = {
            "outcome": outcome,
            "status": result["status"],
            "stderr": result.get("stderr", ""),
            "error": result.get("error"),
        }
    return outcomes


def _import_vector(number: int, key: str, title: str, names: dict[str, str]):
    outcomes = _probe_imports(names)
    control = run_wat(BENIGN_IMPORT_WAT, DEFAULT)
    control_ok = control["status"] == "success" and control["exit_code"] == 0
    present = [n for n, o in outcomes.items() if o["outcome"].startswith("present")]
    unclear = [n for n, o in outcomes.items() if o["outcome"] == "unclear"]
    absent = [n for n, o in outcomes.items() if o["outcome"] == "absent"]

    if present:
        classification = VULNERABLE
        guard = (
            "none: the linker defines "
            + ", ".join(sorted(present))
            + " (an import probe instantiated)"
        )
    elif unclear:
        classification = NOT_VERIFIED
        guard = "linker import resolution was inconclusive for " + ", ".join(
            sorted(unclear)
        )
    elif not control_ok:
        classification = INVALID_TEST
        guard = (
            "harness control failed: a benign Preview1 import did not "
            "instantiate/run through the same sandbox"
        )
    else:
        classification = REJECTED_AS_UNSUPPORTED
        guard = (
            "WASI Preview1 linker: no "
            + title.split("/")[0].strip().lower()
            + " import is defined; instantiation refused as unknown import"
        )

    return {
        "vector": number,
        "key": key,
        "name": title,
        "classification": classification,
        "reached_guard": guard,
        "controls": {
            "benign_preview1_import_instantiates_and_runs": control_ok,
            "benign_control_status": control["status"],
            "benign_control_exit_code": control["exit_code"],
        },
        "evidence": {
            "imports_absent": sorted(absent),
            "imports_present": sorted(present),
            "imports_unclear": sorted(unclear),
            "probes": outcomes,
        },
    }


def _vector(number, key, name, classification, guard, controls, evidence):
    return {
        "vector": number,
        "key": key,
        "name": name,
        "classification": classification,
        "reached_guard": guard,
        "controls": controls,
        "evidence": evidence,
    }


# =====================================================================
# Vectors
# =====================================================================


def vector_shell() -> dict:
    return _import_vector(1, "shell_access", "Shell / exec", SHELL_NAMES)


def vector_fork() -> dict:
    return _import_vector(2, "fork", "Fork", FORK_NAMES)


def vector_network() -> dict:
    result = _import_vector(3, "network", "Network / socket", NETWORK_CREATION_NAMES)
    handle = run_wat(_sock_accept_wat(), DEFAULT)
    handle_errno = handle.get("exit_code")
    result["evidence"]["handle_only_sock_accept"] = {
        "status": handle["status"],
        "errno": handle_errno,
        "errno_name": _errno_name(handle_errno),
        "stderr": handle.get("stderr", ""),
    }
    if result["classification"] == REJECTED_AS_UNSUPPORTED:
        if handle["status"] == "success":
            result["classification"] = VULNERABLE
            result["reached_guard"] = (
                "sock_accept returned success on a directory fd; a socket "
                "was obtained without a creation/connect import"
            )
        else:
            result["reached_guard"] = (
                "WASI Preview1 linker: no socket creation/connect import is "
                "defined; instantiation refused as unknown import; the only "
                "handle op reachable (sock_accept) fails on a directory fd "
                f"with errno {handle_errno} "
                f"({_errno_name(handle_errno) or 'unknown'})"
            )
    result["controls"]["handle_only_op_cannot_bootstrap_socket"] = (
        handle["status"] != "success"
    )
    return result


def vector_fsync() -> dict:
    attack = {}
    for name in SYNC_NAMES:
        attack[name] = run_wat(sync_call_wat(name), DEFAULT)

    allow = replace(DEFAULT, allow_fsync=True)
    controls = {}
    for name in SYNC_NAMES:
        controls[name] = run_wat(sync_call_wat(name), allow)

    def trapped(result: dict) -> bool:
        return result["status"] != "success" and (
            "fsync" in _result_text(result).lower()
            or "blocked" in _result_text(result).lower()
        )

    all_trapped = all(trapped(r) for r in attack.values())
    released = (
        controls["fd_sync"]["status"] == "success"
        and controls["fd_sync"]["exit_code"] == 0
        and controls["fd_datasync"]["status"] == "success"
        and controls["fd_datasync"]["exit_code"] == 0
    )
    leaked = [n for n, r in attack.items() if r["status"] == "success"]

    if leaked:
        classification = VULNERABLE
        guard = "none: sync call returned to the guest for " + ", ".join(leaked)
    elif not all_trapped:
        classification = NOT_VERIFIED
        guard = "sync calls did not consistently reach a trap"
    elif not released:
        classification = NOT_VERIFIED
        guard = (
            "allow_fsync=True did not release fd_sync/fd_datasync; the "
            "blockade cannot be attributed to the policy switch"
        )
    else:
        classification = BLOCKED_BY_POLICY
        guard = (
            "linker shadow trap: fd_sync/fd_datasync/fd_psync raise "
            "'fsync/fdatasync blocked by sandbox' at the call layer"
        )

    return _vector(
        4,
        "fsync",
        "fsync / fdatasync / psync",
        classification,
        guard,
        {
            "allow_fsync_fd_sync": controls["fd_sync"],
            "allow_fsync_fd_datasync": controls["fd_datasync"],
            "allow_fsync_fd_psync_still_trapped": (
                controls["fd_psync"]["status"] != "success"
            ),
            "allow_fsync_releases_sync_calls": released,
        },
        {
            "deny_allow_fsync_false": attack,
            "fd_psync_note": (
                "Preview1 has no fd_psync; the Cell's shim stays trapped even "
                "with allow_fsync=True by design"
            ),
        },
    )


def vector_host_fs() -> dict:
    attack = run_wat(_path_open_wat("/etc/passwd"), DEFAULT)

    control_dir = Path(tempfile.mkdtemp(prefix="ephemora_s5_preopen_"))
    try:
        (control_dir / "allowed.txt").write_text("this is allowed")
        control = run_wat(
            _read_file_wat("allowed.txt"),
            replace(DEFAULT, allow_dirs=(str(control_dir),)),
        )
    finally:
        shutil.rmtree(control_dir, ignore_errors=True)

    control_ok = control["status"] == "success" and control["exit_code"] == 0
    opened = attack["status"] == "success" or attack.get("exit_code") == 0

    if opened:
        classification = VULNERABLE
        guard = "none: path_open('/etc/passwd') opened with no preopen"
    elif attack["status"] == "error" and attack.get("exit_code") not in (0, None):
        if control_ok:
            classification = BLOCKED_BY_POLICY
            guard = (
                "WASI capability table: no preopen contains /etc/passwd; "
                f"path_open refused with errno {attack['exit_code']} "
                f"({_errno_name(attack['exit_code']) or 'unknown'})"
            )
        else:
            classification = NOT_VERIFIED
            guard = (
                "attack refused, but the granted-preopen read control failed; "
                "the refusal cannot be attributed to the capability table"
            )
    else:
        classification = NOT_VERIFIED
        guard = "host-FS probe did not produce an interpretable refusal"

    return _vector(
        5,
        "host_fs",
        "Host FS (/etc/passwd)",
        classification,
        guard,
        {"read_file_in_preopen": control},
        {
            "attack_target": "/etc/passwd",
            "attack_errno": attack.get("exit_code"),
            "attack_errno_name": _errno_name(attack.get("exit_code")),
            "attack": attack,
            "positive_control_read_succeeds": control_ok,
        },
    )


def vector_symlink() -> dict:
    safe_tmp = Path(tempfile.mkdtemp(prefix="ephemora_s5_symlink_"))
    try:
        base = Path(tempfile.mkdtemp(prefix="base_", dir=str(safe_tmp)))
        secret_dir = Path(tempfile.mkdtemp(prefix="secret_", dir=str(safe_tmp)))
        secret = secret_dir / "secret.txt"
        secret.write_text("SECRET-PASSWORD-12345")
        link = base / "escape_link"
        try:
            link.symlink_to(secret)
        except OSError as e:
            return _vector(
                6,
                "symlink",
                "Symlink escape",
                NOT_VERIFIED,
                f"host cannot create the probe symlink: {e}",
                {"real_file_in_preopen_reads": False},
                {"symlink_supported": False},
            )

        (base / "allowed.txt").write_text("this is allowed")
        cfg = replace(DEFAULT, allow_dirs=(str(base),))
        control = run_wat(_read_file_wat("allowed.txt"), cfg)
        attack = run_wat(_read_file_wat("escape_link"), cfg)
        control_ok = control["status"] == "success" and control["exit_code"] == 0
        opened = attack["status"] == "success" or attack.get("exit_code") == 0

        if opened:
            classification = VULNERABLE
            guard = "none: the symlink target outside the preopen was opened"
        elif control_ok:
            classification = BLOCKED_BY_POLICY
            guard = (
                "preopen capability boundary (wasmtime dirfd resolution): "
                "symlink target resolves outside the granted directory; "
                f"path_open refused with errno {attack.get('exit_code')} "
                f"({_errno_name(attack.get('exit_code')) or 'unknown'})"
            )
        else:
            classification = NOT_VERIFIED
            guard = (
                "symlink attack refused, but the real-file-in-preopen control "
                "failed; the refusal cannot be attributed to the path check"
            )

        return _vector(
            6,
            "symlink",
            "Symlink escape",
            classification,
            guard,
            {"read_file_in_preopen": control},
            {
                "symlink_supported": True,
                "symlink_target": str(secret),
                "attack_errno": attack.get("exit_code"),
                "attack_errno_name": _errno_name(attack.get("exit_code")),
                "attack": attack,
                "positive_control_read_succeeds": control_ok,
            },
        )
    finally:
        shutil.rmtree(safe_tmp, ignore_errors=True)


def _threads_enabled_control(wasm_bytes: bytes) -> dict:
    """Compile/instantiate the same bytes on a threads-enabled engine.

    This is the independent control for vector 7: it proves the module is
    valid Wasm and that the product's refusal is the proposal policy. The
    task requires compilation; instantiation is attempted as a stronger
    control, and ``shared_memory`` is enabled because wasmtime's Python
    ``Config`` gates shared-memory instantiation separately.
    """
    control = {"threads_enabled_engine_compiles": False}
    try:
        config = wasmtime.Config()
        config.wasm_threads = True
        try:
            config.shared_memory = True
        except AttributeError:
            control["shared_memory_knob"] = "unavailable"
        engine = wasmtime.Engine(config)
        module = wasmtime.Module(engine, wasm_bytes)
        control["threads_enabled_engine_compiles"] = True
        try:
            store = wasmtime.Store(engine)
            linker = wasmtime.Linker(engine)
            instance = linker.instantiate(store, module)
            bump = instance.exports(store).get("bump")
            control["threads_enabled_engine_instantiates"] = True
            control["atomic_rmw_result"] = (
                bump(store) if isinstance(bump, wasmtime.Func) else None
            )
        except Exception as e:
            control["threads_enabled_engine_instantiates"] = False
            control["instantiation_error"] = f"{type(e).__name__}: {e}"[:300]
    except Exception as e:
        control["compilation_error"] = f"{type(e).__name__}: {e}"[:300]
    return control


def vector_threading() -> dict:
    wasm_bytes = wasmtime.wat2wasm(SHARED_MEM_ATOMICS_WAT)
    path = Path(tempfile.NamedTemporaryFile(suffix=".wasm", delete=False).name)
    path.write_bytes(wasm_bytes)
    try:
        attack = run_attack(path, DEFAULT)
    finally:
        path.unlink(missing_ok=True)

    control = _threads_enabled_control(wasm_bytes)
    control["same_bytes_sha256"] = hashlib.sha256(wasm_bytes).hexdigest()
    text = _result_text(attack).lower()
    policy_refusal = ("threads must be enabled" in text) or (
        "shared memor" in text and "parse" in text
    )

    if attack["status"] == "success":
        classification = VULNERABLE
        guard = "none: the product engine accepted a shared-memory/atomics module"
    elif not policy_refusal:
        classification = NOT_VERIFIED
        guard = "module rejected, but not by the threads proposal policy"
    elif not control["threads_enabled_engine_compiles"]:
        classification = INVALID_TEST
        guard = (
            "harness control failed: the same bytes do not compile on a "
            "threads-enabled engine, so the payload is not a valid probe"
        )
    else:
        classification = REJECTED_AS_UNSUPPORTED
        guard = (
            "engine proposal policy: Config.wasm_threads=False; module "
            "rejected at validation before instantiation"
        )

    return _vector(
        7,
        "threading",
        "Multi-threading (shared memory + atomics)",
        classification,
        guard,
        control,
        {
            "product_refusal": attack,
            "refusal_treated_as_parse_or_validation": policy_refusal,
            "payload": "shared memory 1 2 shared + i32.atomic.rmw.add",
        },
    )


def vector_env() -> dict:
    attack = run_wat(env_count_wat(0), DEFAULT)
    control = run_wat(
        env_count_wat(1),
        replace(DEFAULT, allow_env=(("EPHEMORA_S5_CONTROL", "present"),)),
    )
    attack_ok = attack["status"] == "success" and attack["exit_code"] == 0
    control_ok = control["status"] == "success" and control["exit_code"] == 0

    if attack_ok and control_ok:
        classification = BLOCKED_BY_POLICY
        guard = (
            "WASI environment allowlist: allow_env=() forwards zero variables "
            "(environ_sizes_get returns 0); allow_env with one variable "
            "returns exactly 1"
        )
    elif attack["status"] == "error" and attack.get("exit_code") == 99:
        classification = VULNERABLE
        guard = (
            "none: guest saw a non-zero environment variable count with allow_env=()"
        )
    elif not control_ok and attack_ok:
        classification = NOT_VERIFIED
        guard = (
            "allow_env=() showed zero variables, but the allow_env grant "
            "control did not show exactly one"
        )
    else:
        classification = NOT_VERIFIED
        guard = "environment probes did not produce an interpretable result"

    return _vector(
        8,
        "env",
        "Environment variables",
        classification,
        guard,
        {
            "allow_env_one_variable": control,
            "one_variable_visible": control_ok,
        },
        {
            "allow_env_empty": attack,
            "empty_env_count_zero": attack_ok,
            "control_variable": "EPHEMORA_S5_CONTROL=present",
        },
    )


# =====================================================================
# Report / CLI
# =====================================================================


def _not_verified_report(reason: str) -> list[dict]:
    names = [
        (1, "shell_access", "Shell / exec"),
        (2, "fork", "Fork"),
        (3, "network", "Network / socket"),
        (4, "fsync", "fsync / fdatasync / psync"),
        (5, "host_fs", "Host FS (/etc/passwd)"),
        (6, "symlink", "Symlink escape"),
        (7, "threading", "Multi-threading (shared memory + atomics)"),
        (8, "env", "Environment variables"),
    ]
    return [
        _vector(
            number,
            key,
            name,
            NOT_VERIFIED,
            "runtime qualification gate refused guest execution",
            {},
            {"refusal": reason},
        )
        for number, key, name in names
    ]


def _summary(vectors: list[dict], runtime: dict) -> dict:
    counts = Counter(v["classification"] for v in vectors)
    failing = [
        v["key"] for v in vectors if v["classification"] in FAILING_CLASSIFICATIONS
    ]
    return {
        "total": len(vectors),
        "classification_counts": {
            BLOCKED_BY_POLICY: counts.get(BLOCKED_BY_POLICY, 0),
            REJECTED_AS_UNSUPPORTED: counts.get(REJECTED_AS_UNSUPPORTED, 0),
            VULNERABLE: counts.get(VULNERABLE, 0),
            NOT_VERIFIED: counts.get(NOT_VERIFIED, 0),
            INVALID_TEST: counts.get(INVALID_TEST, 0),
        },
        "blocked_by_policy": counts.get(BLOCKED_BY_POLICY, 0),
        "rejected_as_unsupported": counts.get(REJECTED_AS_UNSUPPORTED, 0),
        "vulnerable": counts.get(VULNERABLE, 0),
        "not_verified": counts.get(NOT_VERIFIED, 0),
        "invalid_test": counts.get(INVALID_TEST, 0),
        "failing_vectors": failing,
        "disposition": "FAIL" if failing else "PASS",
        "runtime_gate_refused": not runtime.get("qualified")
        and not runtime.get("unqualified_allowed"),
        "note": (
            "BLOCKED BY POLICY counts an enforced guard with a positive "
            "control; REJECTED AS UNSUPPORTED counts a structural ABI/proposal "
            "refusal (unknown import, wasm_threads=False validation). Parse "
            "refusals are never counted as blocks."
        ),
    }


def _print_table(vectors: list[dict]) -> None:
    print("\n" + "=" * 78)
    print(f"{'#':<2} {'Vector':<40} {'Classification':<24} Guard")
    print("-" * 78)
    for v in vectors:
        print(f"{v['vector']:<2} {v['name'][:40]:<40} {v['classification']:<24}")
        print(f"   guard: {v['reached_guard'][:140]}")
    print("=" * 78)


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(
        description="Classify the eight documented attack vectors."
    )
    parser.add_argument(
        "--json",
        dest="json_path",
        default="/tmp/ephemora_cell-8-vector-verify.json",
        help="write the commit-ready JSON report here",
    )
    args = parser.parse_args(argv)

    qualified, qualification = runtime_qualification()
    allowed = unqualified_runtime_allowed()
    runtime = {
        "wasmtime_version": reported_runtime_version(),
        "qualified": qualified,
        "qualification": qualification,
        "unqualified_allowed": allowed,
        "python": sys.version.split()[0],
    }

    print("=" * 78)
    print("Ephemora Cell 8-Vector Attack Classification (live WASISandbox)")
    print("=" * 78)
    print(f"Runtime: {qualification}")
    if not qualified and allowed:
        print(
            "WARNING: EPHEMORA_ALLOW_UNQUALIFIED_RUNTIME is set; these verdicts "
            "describe this engine, not the audited build."
        )

    if not qualified and not allowed:
        # Every WASISandbox.run would return the same gate refusal. Running the
        # probes anyway would misread that refusal as a capability verdict
        # (vector 8 would look "leaked" merely because the run never started).
        vectors = _not_verified_report(qualification)
    else:
        vectors = [
            vector_shell(),
            vector_fork(),
            vector_network(),
            vector_fsync(),
            vector_host_fs(),
            vector_symlink(),
            vector_threading(),
            vector_env(),
        ]

    summary = _summary(vectors, runtime)
    _print_table(vectors)
    counts = summary["classification_counts"]
    print(
        "Summary: "
        f"{counts[BLOCKED_BY_POLICY]} BLOCKED BY POLICY, "
        f"{counts[REJECTED_AS_UNSUPPORTED]} REJECTED AS UNSUPPORTED, "
        f"{counts[VULNERABLE]} VULNERABLE, "
        f"{counts[NOT_VERIFIED]} NOT VERIFIED, "
        f"{counts[INVALID_TEST]} INVALID TEST "
        f"({summary['total']} vectors dispositioned)"
    )
    print(f"Disposition: {summary['disposition']}")
    if summary["failing_vectors"]:
        print("Failing vectors: " + ", ".join(summary["failing_vectors"]))

    report = {
        "schema": "ephemora-cell/attack-vector-classification/v1",
        "timestamp": time.strftime("%Y-%m-%dT%H:%M:%S%z"),
        "harness": "benchmarks/verify_8_vectors.py",
        "runtime": runtime,
        "vectors": vectors,
        "summary": summary,
    }
    json_path = Path(args.json_path)
    json_path.parent.mkdir(parents=True, exist_ok=True)
    json_path.write_text(json.dumps(report, indent=2), encoding="utf-8")
    print(f"\nFull report: {json_path}")

    return 1 if summary["failing_vectors"] else 0


if __name__ == "__main__":
    sys.exit(main())
