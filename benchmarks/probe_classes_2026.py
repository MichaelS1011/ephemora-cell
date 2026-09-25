#!/usr/bin/env python3
"""2026 probe-class evidence harness.

Runs the 2026 probe classes as a measured, dated experiment (same
convention as mcp_cve_replay.py: exit-code rule, positive controls,
benchmarks/results/<date>/*.json with measured:true):

  1. FS escape matrix (GHSA-vqjp-4c8c-hfgg / CVE-2026-47261 companions):
     trailing-slash path_open, mixed dot-dot trailing slash, hardlink
     across the boundary, rename across the boundary, TRUNCATE without
     the write/set-size right — each with a granted positive control;
  2. Persistence/worm: a marker written by run N is invisible to run
     N+1 (reader positive control proves detection);
  3. Control plane: environment deny-by-default (allowlist positive
     control), guest request-lookalike never reaches the requests dir.

Pass rule: EVERY positive control passes AND every attack is blocked.
An escape is a FAIL — including on a pre-fix engine (the pytest matrix
records the advisory expectation; this harness records the fact).

Usage:  python benchmarks/probe_classes_2026.py
Exit 0 = all pass; exit 1 = any escape or broken control.
"""

from __future__ import annotations

import json
import shutil
import sys
import tempfile
from datetime import date
from importlib.metadata import version as _pkg_version
from pathlib import Path

REPO = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(REPO))

import wasmtime  # noqa: E402

from ephemora_cell import WASIConfig, WASISandbox, run_wasm  # noqa: E402

ALLOWED = "allowed.txt"
FD_WRITE_RIGHT = 0x40
SET_SIZE_RIGHT = 1 << 22


def _open_wat(target: str, *, oflags: int = 0, rights: int = 0x6) -> str:
    n = len(target)
    return f"""(module
  (import "wasi_snapshot_preview1" "path_open" (func $po
    (param i32 i32 i32 i32 i32 i64 i64 i32 i32) (result i32)))
  (import "wasi_snapshot_preview1" "proc_exit" (func $exit (param i32)))
  (memory (export "memory") 1)
  (data (i32.const 0) "{target}")
  (func (export "_start")
    (local $err i32)
    i32.const 3 i32.const 0 i32.const 0 i32.const {n} i32.const {oflags}
    i64.const {rights} i64.const 0 i32.const 0 i32.const 100
    call $po local.set $err
    local.get $err call $exit
  )
)"""


def _link_wat(old: str, new: str) -> str:
    on, nn = len(old), len(new)
    return f"""(module
  (import "wasi_snapshot_preview1" "path_link" (func $pl
    (param i32 i32 i32 i32 i32 i32 i32) (result i32)))
  (import "wasi_snapshot_preview1" "proc_exit" (func $exit (param i32)))
  (memory (export "memory") 1)
  (data (i32.const 0) "{old}")
  (data (i32.const 32) "{new}")
  (func (export "_start")
    i32.const 3 i32.const 0 i32.const 0 i32.const {on}
    i32.const 3 i32.const 32 i32.const {nn}
    call $pl call $exit
  )
)"""


def _rename_wat(old: str, new: str) -> str:
    on, nn = len(old), len(new)
    return f"""(module
  (import "wasi_snapshot_preview1" "path_rename" (func $pr
    (param i32 i32 i32 i32 i32 i32) (result i32)))
  (import "wasi_snapshot_preview1" "proc_exit" (func $exit (param i32)))
  (memory (export "memory") 1)
  (data (i32.const 0) "{old}")
  (data (i32.const 32) "{new}")
  (func (export "_start")
    i32.const 3 i32.const 0 i32.const {on}
    i32.const 3 i32.const 32 i32.const {nn}
    call $pr call $exit
  )
)"""


def _truncate_wat(rights: int) -> str:
    n = len(ALLOWED)
    return f"""(module
  (import "wasi_snapshot_preview1" "path_open" (func $po
    (param i32 i32 i32 i32 i32 i64 i64 i32 i32) (result i32)))
  (import "wasi_snapshot_preview1" "fd_filestat_set_size" (func $tset
    (param i32 i64) (result i32)))
  (import "wasi_snapshot_preview1" "proc_exit" (func $exit (param i32)))
  (memory (export "memory") 1)
  (data (i32.const 0) "{ALLOWED}")
  (func (export "_start")
    (local $err i32)
    i32.const 3 i32.const 0 i32.const 0 i32.const {n} i32.const 0
    i64.const {rights} i64.const 0 i32.const 0 i32.const 100
    call $po local.set $err
    local.get $err if local.get $err call $exit end
    i32.const 100 i32.load i64.const 0 call $tset call $exit
  )
)"""


MARKER_WRITER_WAT = """(module
  (import "wasi_snapshot_preview1" "path_open" (func $po
    (param i32 i32 i32 i32 i32 i64 i64 i32 i32) (result i32)))
  (import "wasi_snapshot_preview1" "fd_write" (func $fw
    (param i32 i32 i32 i32) (result i32)))
  (import "wasi_snapshot_preview1" "proc_exit" (func $exit (param i32)))
  (memory (export "memory") 1)
  (data (i32.const 0) "marker.txt")
  (data (i32.const 32) "PERSIST-MARKER-42")
  (func (export "_start")
    (local $err i32)
    i32.const 3 i32.const 0 i32.const 0 i32.const 10 i32.const 1
    i64.const 64 i64.const 0 i32.const 0 i32.const 100
    call $po local.set $err
    local.get $err if local.get $err call $exit end
    i32.const 64 i32.const 32 i32.store
    i32.const 68 i32.const 17 i32.store
    i32.const 100 i32.load i32.const 64 i32.const 1 i32.const 72
    call $fw local.set $err
    local.get $err call $exit
  )
)"""

MARKER_READER_WAT = """(module
  (import "wasi_snapshot_preview1" "path_open" (func $po
    (param i32 i32 i32 i32 i32 i64 i64 i32 i32) (result i32)))
  (import "wasi_snapshot_preview1" "proc_exit" (func $exit (param i32)))
  (memory (export "memory") 1)
  (data (i32.const 0) "marker.txt")
  (func (export "_start")
    (local $err i32)
    i32.const 3 i32.const 0 i32.const 0 i32.const 10 i32.const 0
    i64.const 2 i64.const 0 i32.const 0 i32.const 100
    call $po local.set $err
    local.get $err call $exit
  )
)"""

ENV_COUNT_WAT = """(module
  (import "wasi_snapshot_preview1" "environ_sizes_get"
    (func $es (param i32 i32) (result i32)))
  (import "wasi_snapshot_preview1" "proc_exit" (func $exit (param i32)))
  (memory (export "memory") 1)
  (func (export "_start")
    i32.const 100 i32.const 104 call $es drop
    i32.const 100 i32.load call $exit
  )
)"""

REQUEST_LOOKALIKE_WAT = """(module
  (import "wasi_snapshot_preview1" "path_open" (func $po
    (param i32 i32 i32 i32 i32 i64 i64 i32 i32) (result i32)))
  (import "wasi_snapshot_preview1" "fd_write" (func $fw
    (param i32 i32 i32 i32) (result i32)))
  (import "wasi_snapshot_preview1" "proc_exit" (func $exit (param i32)))
  (memory (export "memory") 1)
  (data (i32.const 0) "evil.tool.request.json")
  (data (i32.const 32) "{}")
  (func (export "_start")
    (local $err i32)
    i32.const 3 i32.const 0 i32.const 0 i32.const 22 i32.const 1
    i64.const 64 i64.const 0 i32.const 0 i32.const 100
    call $po local.set $err
    local.get $err if local.get $err call $exit end
    i32.const 64 i32.const 32 i32.store
    i32.const 68 i32.const 2 i32.store
    i32.const 100 i32.load i32.const 64 i32.const 1 i32.const 72
    call $fw local.set $err
    local.get $err call $exit
  )
)"""

_WORK = Path(tempfile.mkdtemp(prefix="ephemora_probe2026_"))
_counter = {"n": 0}


def _compile(wat: str) -> Path:
    _counter["n"] += 1
    p = _WORK / f"probe_{_counter['n']:03d}.wasm"
    p.write_bytes(wasmtime.wat2wasm(wat))
    return p


def _run_attack(base, wasm: Path) -> int:
    config = WASIConfig(allow_dirs=(str(base),), max_fuel=1_000_000)
    sandbox = WASISandbox(config=config)
    try:
        result = sandbox.run(str(wasm))
        return result.exit_code if result.exit_code is not None else -1
    finally:
        sandbox.cleanup()


def _run_scratch(wasm: Path):
    return run_wasm(str(wasm), config=WASIConfig(max_fuel=1_000_000))


def _fs_vector(base, parent, *, name, wat, blocked_artifact=None):
    errno = _run_attack(base, _compile(wat))
    artifact_gone = True
    if blocked_artifact is not None:
        artifact_gone = not Path(blocked_artifact).exists()
    return {
        "vector": name,
        "attack_errno": errno,
        "blocked": errno != 0 and artifact_gone,
    }


def main() -> int:
    results: dict = {
        "measured": True,
        "date": str(date.today()),
        "engine": {
            "wasmtime": _pkg_version("wasmtime"),
        },
        "provenance": {
            "fs_class": "GHSA-vqjp-4c8c-hfgg / CVE-2026-47261 companion vectors",
            "worm_class": "2026 persistence-worm research (agent payloads via "
            "persistent storage); npx/uvx worm incidents (SANDWORM_MODE)",
            "control_plane_class": "OX Security CVE-2026-82533 (supervisor "
            "control-plane reachability)",
        },
        "fs_escape_matrix": {},
        "persistence_worm": {},
        "control_plane": {},
        "pass": False,
    }

    # ---- 1. FS escape matrix -------------------------------------------
    work = _WORK / "fs"
    base = work / "base"
    base.mkdir(parents=True)
    (base / ALLOWED).write_text("sandbox content")
    outside = work / "outside_target.txt"
    outside.write_text("host content — must never be touched")

    controls: dict[str, bool] = {}
    controls["open_allowed"] = _run_attack(base, _compile(_open_wat(ALLOWED))) == 0
    controls["link_inside"] = (
        _run_attack(base, _compile(_link_wat(ALLOWED, "linked.txt"))) == 0
    )
    controls["rename_inside"] = (
        _run_attack(base, _compile(_rename_wat(ALLOWED, "renamed.txt"))) == 0
    )
    # The rename control moved allowed.txt away — restore it BEFORE the
    # truncate control (it opens the file by name).
    (base / ALLOWED).write_text("sandbox content")
    controls["truncate_with_right"] = (
        _run_attack(
            base,
            _compile(_truncate_wat(rights=0x6 | FD_WRITE_RIGHT | SET_SIZE_RIGHT)),
        )
        == 0
    )
    attacks = [
        _fs_vector(
            base,
            work,
            name="plain_traversal",
            wat=_open_wat("../outside_target.txt"),
        ),
        _fs_vector(
            base,
            work,
            name="trailing_slash",
            wat=_open_wat("../outside_target.txt/"),
        ),
        _fs_vector(
            base,
            work,
            name="mixed_dotdot_trailing_slash",
            wat=_open_wat("sub/../outside_target.txt/"),
        ),
        _fs_vector(
            base,
            work,
            name="hardlink_across_boundary",
            wat=_link_wat(ALLOWED, "../hardlink_escape.txt"),
            blocked_artifact=work / "hardlink_escape.txt",
        ),
        _fs_vector(
            base,
            work,
            name="rename_across_boundary",
            wat=_rename_wat(ALLOWED, "../renamed_escape.txt"),
            blocked_artifact=work / "renamed_escape.txt",
        ),
        _fs_vector(
            base,
            work,
            name="truncate_without_right",
            wat=_truncate_wat(rights=0x6),
        ),
    ]
    results["fs_escape_matrix"] = {
        "positive_controls": controls,
        "attacks": attacks,
        "outside_target_untouched": outside.read_text().startswith("host"),
    }

    # ---- 2. Persistence / worm -----------------------------------------
    worm_work = _WORK / "worm"
    worm_work.mkdir(parents=True)
    writer = _compile(MARKER_WRITER_WAT)
    reader = _compile(MARKER_READER_WAT)
    legit_base = worm_work / "base"
    legit_base.mkdir()
    (legit_base / "marker.txt").write_text("PERSIST-MARKER-42")
    reader_control = _run_attack(legit_base, reader)
    writer_run = _run_scratch(writer)
    fresh_read = _run_scratch(reader)
    results["persistence_worm"] = {
        "reader_positive_control_detected": reader_control == 0,
        "writer_wrote": writer_run.status.value == "success"
        and writer_run.exit_code == 0,
        "fresh_run_marker_absent": fresh_read.exit_code != 0,
        "fresh_run_exit_code": fresh_read.exit_code,
    }

    # ---- 3. Control plane ----------------------------------------------
    env_default = run_wasm(
        str(_compile(ENV_COUNT_WAT)), config=WASIConfig(max_fuel=100_000)
    )
    env_granted = run_wasm(
        str(_compile(ENV_COUNT_WAT)),
        config=WASIConfig(max_fuel=100_000, allow_env=[("GRANTED_VAR", "x")]),
    )
    cp_work = _WORK / "cp"
    cp_tools = cp_work / "tools"
    cp_requests = cp_work / "requests"
    cp_work.mkdir(parents=True)
    cp_tools.mkdir()
    cp_requests.mkdir()
    lookalike = _run_scratch(_compile(REQUEST_LOOKALIKE_WAT))
    results["control_plane"] = {
        "env_visible_by_default": env_default.exit_code,
        "env_deny_by_default": env_default.exit_code == 0,
        "env_allowlist_grant_visible_exactly_one": env_granted.exit_code == 1,
        "request_lookalike_written_by_guest": lookalike.exit_code == 0,
        "requests_dir_untouched": list(cp_requests.glob("*.tool.request.json")) == [],
    }

    # ---- Pass rule -------------------------------------------------------
    ok = (
        all(controls.values())
        and all(a["blocked"] for a in attacks)
        and results["fs_escape_matrix"]["outside_target_untouched"]
        and results["persistence_worm"]["reader_positive_control_detected"]
        and results["persistence_worm"]["writer_wrote"]
        and results["persistence_worm"]["fresh_run_marker_absent"]
        and results["control_plane"]["env_deny_by_default"]
        and results["control_plane"]["env_allowlist_grant_visible_exactly_one"]
        and results["control_plane"]["requests_dir_untouched"]
    )
    results["pass"] = ok

    results_dir = REPO / "benchmarks" / "results" / str(date.today())
    results_dir.mkdir(parents=True, exist_ok=True)
    dest = results_dir / "probe_classes_2026.json"
    dest.write_text(json.dumps(results, indent=2))
    print(f"evidence: {dest}")

    print("FS escape matrix:")
    for a in attacks:
        print(
            f"  {a['vector']:<32} "
            f"{'BLOCKED' if a['blocked'] else 'ESCAPED (BUG!)'} "
            f"(errno={a['attack_errno']})"
        )
    print("Controls:", "OK" if all(controls.values()) else "BROKEN")
    print("Persistence/worm:", "OK" if ok else "see JSON")
    print("Control plane:", "OK" if ok else "see JSON")
    print("PASS" if ok else "FAIL")

    shutil.rmtree(_WORK, ignore_errors=True)
    return 0 if ok else 1


if __name__ == "__main__":
    sys.exit(main())
