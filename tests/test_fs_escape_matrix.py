"""FS escape matrix — trailing-slash / hardlink / rename / TRUNCATE vectors.

The four companion vectors of GHSA-vqjp-4c8c-hfgg (CVE-2026-47261,
CVSS 7.5): wasmtime-wasi ``open_at`` mishandles trailing slashes, and the
same FS layer carries the hardlink / rename-across-boundary / TRUNCATE-
without-write-right companion classes. The preopen test matrix promised
in SECURITY.md ("will gain trailing-slash/hardlink/rename/TRUNCATE
vectors with positive controls") lives here.

Expectation handling is honest to the advisory timeline:

* the upstream fix ships in 47.0.4 — which has **no PyPI wheels yet**,
  so the pinned engine (47.0.1) is treated as exposed;
* the four ATTACK tests are ``xfail(strict=False)`` while the engine is
  pre-fix: an actual escape (errno 0 / host-visible artifact) is
  reported xfail, an already-blocked vector is reported xpass — both
  green, neither silent;
* at the M2 engine upgrade (>= 48.0.3) the xfail markers flip to strict
  asserts and every vector must be denied with controls granted;
* the POSITIVE CONTROLS are never xfail: a failing control means this
  harness is broken, not the sandbox (suite control convention).

**Measured 2026-09-25 (wasmtime 47.0.1, macOS arm64):** all four attack
vectors report XPASS — through Cell's preopen grant path the
trailing-slash, hardlink, rename and TRUNCATE escapes do NOT reproduce
on the pinned engine (the advisory shapes target wasmtime-wasi
``open_at`` semantics that Cell's granted-preopen configuration does not
reach, mirroring the fuel-amplification PoC result recorded in
SECURITY.md). The advisory remains authoritative: the markers stay
until the M2 upgrade re-runs this matrix on the patched engine.

Conventions reused from benchmarks/verify_8_vectors.py: the audit-
corrected ``path_open`` stack order (path POINTER and LENGTH pushed
correctly — the pre-2026-09-12 harness bug is not reintroduced) and
dirfd 3 = first allow_dir preopen (the runtime preopens allow_dirs
before the ``/sandbox`` scratch dir).
"""

from __future__ import annotations

import atexit
import os
import shutil
import sys
import tempfile
from importlib.metadata import version as _pkg_version
from pathlib import Path

sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))

import pytest
import wasmtime

from ephemora_cell import WASIConfig, WASISandbox

# ---------------------------------------------------------------------------
# Advisory gate
# ---------------------------------------------------------------------------


def _wasmtime_version_tuple() -> tuple[int, ...]:
    parts: list[int] = []
    for chunk in _pkg_version("wasmtime").split(".")[:3]:
        digits = "".join(c for c in chunk if c.isdigit())
        parts.append(int(digits) if digits else 0)
    return tuple(parts)


_FS_ADVISORY_PATCHED = _wasmtime_version_tuple() >= (47, 0, 4)

_XFAIL_FS = pytest.mark.xfail(
    condition=not _FS_ADVISORY_PATCHED,
    strict=False,
    reason=(
        "GHSA-vqjp-4c8c-hfgg / CVE-2026-47261: FS escape class is unfixed "
        "on the pinned engine (upstream fix in 47.0.4, no PyPI wheels yet); "
        "flips to strict-green at the M2 engine upgrade"
    ),
)

# ---------------------------------------------------------------------------
# WAT generators (audit-corrected: dirfd=3, path ptr+len pushed, errno out)
# ---------------------------------------------------------------------------

_ALLOWED = "allowed.txt"


def _open_wat(target: str, *, oflags: int = 0, rights: int = 0x6) -> str:
    """path_open `target` on the preopen dirfd and exit with the errno."""
    n = len(target)
    return f"""(module
  (import "wasi_snapshot_preview1" "path_open" (func $po
    (param i32 i32 i32 i32 i32 i64 i64 i32 i32) (result i32)))
  (import "wasi_snapshot_preview1" "proc_exit" (func $exit (param i32)))
  (memory (export "memory") 1)
  (data (i32.const 0) "{target}")
  (func (export "_start")
    (local $err i32)
    ;; dirfd=3, dirflags=0, path=0, len={n}, oflags={oflags},
    ;; rights={rights}, inheriting=0, fdflags=0, opened_fd=100
    i32.const 3 i32.const 0 i32.const 0 i32.const {n} i32.const {oflags}
    i64.const {rights} i64.const 0 i32.const 0 i32.const 100
    call $po local.set $err
    local.get $err call $exit
  )
)"""


def _link_wat(old: str, new: str) -> str:
    """path_link old -> new on dirfd 3; exit with the errno."""
    on, nn = len(old), len(new)
    return f"""(module
  (import "wasi_snapshot_preview1" "path_link" (func $pl
    (param i32 i32 i32 i32 i32 i32 i32) (result i32)))
  (import "wasi_snapshot_preview1" "proc_exit" (func $exit (param i32)))
  (memory (export "memory") 1)
  (data (i32.const 0) "{old}")
  (data (i32.const 32) "{new}")
  (func (export "_start")
    ;; old_fd=3, flags=0, old=0/{on}, new_fd=3, new=32/{nn}
    i32.const 3 i32.const 0 i32.const 0 i32.const {on}
    i32.const 3 i32.const 32 i32.const {nn}
    call $pl call $exit
  )
)"""


def _rename_wat(old: str, new: str) -> str:
    """path_rename old -> new on dirfd 3; exit with the errno."""
    on, nn = len(old), len(new)
    return f"""(module
  (import "wasi_snapshot_preview1" "path_rename" (func $pr
    (param i32 i32 i32 i32 i32 i32) (result i32)))
  (import "wasi_snapshot_preview1" "proc_exit" (func $exit (param i32)))
  (memory (export "memory") 1)
  (data (i32.const 0) "{old}")
  (data (i32.const 32) "{new}")
  (func (export "_start")
    ;; old_fd=3, old=0/{on}, new_fd=3, new=32/{nn}
    i32.const 3 i32.const 0 i32.const {on}
    i32.const 3 i32.const 32 i32.const {nn}
    call $pr call $exit
  )
)"""


# fd_filestat_set_size = 1<<22 (0x400000); FD_READ|FD_SEEK = 0x6.
_SET_SIZE_RIGHT = 1 << 22


def _truncate_wat(*, rights: int) -> str:
    """Open allowed.txt with `rights`, then fd_filestat_set_size(fd, 0).

    Exits with the path_open errno if the open fails, otherwise with the
    truncate errno — 0 only when BOTH succeeded.
    """
    n = len(_ALLOWED)
    return f"""(module
  (import "wasi_snapshot_preview1" "path_open" (func $po
    (param i32 i32 i32 i32 i32 i64 i64 i32 i32) (result i32)))
  (import "wasi_snapshot_preview1" "fd_filestat_set_size" (func $tset
    (param i32 i64) (result i32)))
  (import "wasi_snapshot_preview1" "proc_exit" (func $exit (param i32)))
  (memory (export "memory") 1)
  (data (i32.const 0) "{_ALLOWED}")
  (func (export "_start")
    (local $err i32)
    i32.const 3 i32.const 0 i32.const 0 i32.const {n} i32.const 0
    i64.const {rights} i64.const 0 i32.const 0 i32.const 100
    call $po local.set $err
    local.get $err if
      local.get $err call $exit
    end
    ;; path_open's last arg is a POINTER: the real fd is stored at
    ;; address 100 — load it before calling fd_filestat_set_size.
    i32.const 100 i32.load i64.const 0 call $tset call $exit
  )
)"""


# ---------------------------------------------------------------------------
# Harness
# ---------------------------------------------------------------------------


def _compile(wat: str):
    """Compile a probe module into a hygienic scratch dir (mkdtemp +
    process-exit cleanup — never Path.home(), never repo pollution)."""
    global _PROBE_DIR
    if _PROBE_DIR is None:
        _PROBE_DIR = Path(tempfile.mkdtemp(prefix="ephemora_fsmatrix_"))
        atexit.register(shutil.rmtree, _PROBE_DIR, ignore_errors=True)
    wasm = _PROBE_DIR / f"probe_{len(list(_PROBE_DIR.iterdir())):04d}.wasm"
    wasm.write_bytes(wasmtime.wat2wasm(wat))
    return wasm


_PROBE_DIR: Path | None = None


def _run_attack(base, wasm) -> int:
    """Run a probe with allow_dirs=(base,); return the guest exit code
    (the WASI errno for path_* probes)."""
    config = WASIConfig(allow_dirs=(str(base),), max_fuel=1_000_000)
    sandbox = WASISandbox(config=config)
    try:
        result = sandbox.run(str(wasm))
        assert result.status is not None
        return result.exit_code if result.exit_code is not None else -1
    finally:
        sandbox.cleanup()


@pytest.fixture()
def fs_env(tmp_path):
    """base/ (the preopen) with allowed.txt; the PARENT is the escape
    target region and holds outside_target.txt with known content."""
    base = tmp_path / "base"
    base.mkdir()
    (base / _ALLOWED).write_text("sandbox content")
    outside = tmp_path / "outside_target.txt"
    outside.write_text("host content — must never be touched")
    return base, tmp_path


# ---------------------------------------------------------------------------
# Vector 1 — trailing-slash path_open across the preopen boundary
# ---------------------------------------------------------------------------


class TestTrailingSlashOpen:
    def test_positive_control_plain_open_works(self, fs_env):
        base, _parent = fs_env
        errno = _run_attack(base, _compile(_open_wat(_ALLOWED)))
        assert errno == 0, "harness broken: plain open of allowed.txt failed"

    def test_plain_traversal_blocked_everywhere(self, fs_env):
        """Baseline (no trailing slash): dot-dot traversal must be blocked
        on EVERY engine, patched or not — strict by design."""
        base, _parent = fs_env
        errno = _run_attack(base, _compile(_open_wat("../outside_target.txt")))
        assert errno != 0, "plain traversal escaped — this is not advisory-"
        "conditional and must never happen"

    @_XFAIL_FS
    def test_trailing_slash_traversal_blocked(self, fs_env):
        """The advisory class: a trailing slash on a traversal path must
        not bypass the preopen boundary."""
        base, parent = fs_env
        errno = _run_attack(base, _compile(_open_wat("../outside_target.txt/")))
        assert errno != 0, "trailing-slash traversal opened outside the sandbox"
        # Belt and suspenders: the outside artifact must be untouched.
        assert (parent / "outside_target.txt").read_text().startswith("host")

    @_XFAIL_FS
    def test_mixed_dotdot_trailing_slash_blocked(self, fs_env):
        base, parent = fs_env
        (base / "sub").mkdir()
        errno = _run_attack(base, _compile(_open_wat("sub/../outside_target.txt/")))
        assert errno != 0, "mixed dot-dot + trailing-slash open escaped"
        assert (parent / "outside_target.txt").read_text().startswith("host")


# ---------------------------------------------------------------------------
# Vector 2 — hardlink across the preopen boundary
# ---------------------------------------------------------------------------


class TestHardlinkEscape:
    def test_positive_control_link_inside_sandbox(self, fs_env):
        base, _parent = fs_env
        errno = _run_attack(base, _compile(_link_wat(_ALLOWED, "linked.txt")))
        assert errno == 0, "harness broken: in-sandbox link failed"
        assert (base / "linked.txt").exists()

    @_XFAIL_FS
    def test_hardlink_across_boundary_blocked(self, fs_env):
        base, parent = fs_env
        errno = _run_attack(
            base, _compile(_link_wat(_ALLOWED, "../hardlink_escape.txt"))
        )
        assert errno != 0, "hardlink crossed the preopen boundary"
        assert not (parent / "hardlink_escape.txt").exists()


# ---------------------------------------------------------------------------
# Vector 3 — rename across the preopen boundary
# ---------------------------------------------------------------------------


class TestRenameEscape:
    def test_positive_control_rename_inside_sandbox(self, fs_env):
        base, _parent = fs_env
        errno = _run_attack(base, _compile(_rename_wat(_ALLOWED, "renamed.txt")))
        assert errno == 0, "harness broken: in-sandbox rename failed"
        assert (base / "renamed.txt").exists()

    @_XFAIL_FS
    def test_rename_across_boundary_blocked(self, fs_env):
        base, parent = fs_env
        errno = _run_attack(
            base, _compile(_rename_wat(_ALLOWED, "../renamed_escape.txt"))
        )
        assert errno != 0, "rename moved a file across the preopen boundary"
        # The sandbox copy must still be there — nothing moved out.
        assert (base / _ALLOWED).exists()


# ---------------------------------------------------------------------------
# Vector 4 — TRUNCATE without the write/set-size right
# ---------------------------------------------------------------------------


class TestTruncateWithoutWriteRight:
    def test_positive_control_truncate_with_right(self, fs_env):
        base, _parent = fs_env
        # fd_write (1<<6) is required too: without it wasmtime opens the
        # file read-only and even a GRANTED set_size fails (EINVAL from
        # ftruncate on a read-only fd) — that would be a broken control,
        # not a defense.
        errno = _run_attack(
            base,
            _compile(_truncate_wat(rights=0x6 | 0x40 | _SET_SIZE_RIGHT)),
        )
        assert errno == 0, "harness broken: granted truncate failed"

    @_XFAIL_FS
    def test_truncate_without_right_blocked(self, fs_env):
        """An fd opened WITHOUT fd_filestat_set_size (and without
        fd_write) must not be able to truncate the file."""
        base, _parent = fs_env
        errno = _run_attack(base, _compile(_truncate_wat(rights=0x6)))
        assert errno != 0, "truncated a file through a read-only fd"
        assert (base / _ALLOWED).read_text() == "sandbox content"
