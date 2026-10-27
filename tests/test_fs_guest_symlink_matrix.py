"""S2 — filesystem / WASI capability matrix with REAL guest operations.

Every filesystem operation in this module is a genuine WASI preview1 call made
by the guest through the shipped :class:`ephemora_cell.WASISandbox` product
path. The host only performs host-authority setup (creating sentinel files,
swapping the preopen directory, chmod), never the attack itself: links are
created by the guest with ``path_symlink``, never planted by Python.

The harness reuses the audit-corrected conventions of
``tests/test_fs_escape_matrix.py`` and ``tests/test_security.py``:

* dirfd ``3`` is the FIRST ``allow_dir`` preopen (the runtime preopens the
  allowed dirs before the ``/sandbox`` scratch dir; with no allowed dir left,
  fd 3 is ``/sandbox``);
* the nine-argument ``path_open`` stack order is preserved (i32 dirfd,
  dirflags, path POINTER, path LENGTH, oflags, i64 rights, i64 inheriting,
  fdflags, opened-fd POINTER);
* ``path_symlink(old_ptr, old_len, fd, new_ptr, new_len)`` is used to create
  each link inside the preopen.

Behaviour is measured against the qualified wasmtime 49.0.4 line on macOS
arm64 (2026-10-23). Guest reports are emitted as tagged bytes on stdout
(``L<errno>`` per link, ``O<errno>`` for path_open, ``R<errno>N<n>D<byte>``
after a successful read, ``X`` end) so the exact errno is recorded in the
failure message instead of being collapsed into a boolean.

Case map (all eight required cases are genuinely reached):

1. guest-created relative symlink to an outside file -> path_open refused
   (``EPERM``; ``ENOTCAPABLE`` is accepted as the other capability denial),
   outside sentinel unchanged. Positive control: the same guest creates an
   in-preopen symlink and reads it (also case 3).
2. guest-created A -> B -> outside chain -> path_open A refused. Positive
   control: the same two-hop chain pointing inside opens.
3. guest-created symlink to a real inside file -> path_open + fd_read work
   (positive control for 1/2/4).
4. trailing slash through a guest-created symlink to an outside DIRECTORY ->
   refused, sentinel unchanged. Positive control: the same trailing-slash
   open through a guest-created symlink to a real inside directory succeeds.
5. host replaces the preopen directory with a symlink to a forbidden outside
   directory between ``WASISandbox(...)`` and ``run()``. The swap is a real
   filesystem rename/symlink, never a patched ``_canonicalize``. In the
   unmodified product the run-time canonical filter refuses the entry; a
   companion test bypasses that EARLIER filter (test-local monkeypatch only)
   so the swap genuinely reaches the grant-time TOCTOU revalidation, which
   skips the preopen with a ``RuntimeWarning``. In both shapes the guest
   cannot open the outside sentinel (fd 3 falls back to ``/sandbox``).
   Scope note (verified separately, 2026-10-23): the revalidation is a
   canonical DENYLIST check, not path-identity binding. A real swap to
   another canonically ALLOWED directory (e.g. a sibling temp dir) is
   granted without a warning and the guest can read it. That matches the
   documented "allow_dirs are explicitly granted, trusted" model but is
   narrower than SECURITY.md's unqualified sentence "a swap ... is skipped
   with a warning"; it is reported as a claim-scope finding, not encoded
   here as a passing security expectation.
6. invalid WASI parameters: bad dirfd (``EBADF``), path pointer outside
   linear memory (trap, host stays alive), path length outside linear memory
   (errno/trap), and a fd opened without ``FD_WRITE`` (``fd_write`` errno).
   Positive controls with valid parameters follow each invalid call.
7. mutation control: with the run-time filter made permissive AND grant-time
   revalidation disabled, the SAME real swap lets the guest read the outside
   sentinel — proving the boundary is enforced by that code. ``monkeypatch``
   restores both, and a third fresh run is blocked again.
8. permission revocation mid-operation IS TESTED deterministically: the guest
   creates ``ready`` with real WASI calls, polls for ``go``, and the host
   chmods the target to 000 after observing ``ready`` but before creating
   ``go``. The subsequent real ``path_open`` gets ``EACCES``; the control run
   (no chmod) reads the file.

Runs use ``trust="trusted"`` (the sanctioned in-process fast path) because the
host-side coordination thread and the monkeypatch mutation controls must act
on the same process. The preopen filter/grant code under test is identical on
the isolated-worker path, and the case-5 swap is visible on the filesystem to
either path.
"""

from __future__ import annotations

import atexit
import os
import shutil
import sys
import tempfile
import threading
import time
from pathlib import Path

sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))

import pytest
import wasmtime

from ephemora_cell import ExecutionStatus, WASIConfig, WASISandbox
from ephemora_cell.execution_report import TRUST_TRUSTED

# WASI preview1 errno values observed on the qualified 49.0.4 line.
_EPERM = 63
_ENOTCAPABLE = 76
_EBADF = 8
_EACCES = 2

# Tags used in the guest's stdout report.
_T_LINK = 76  # 'L'
_T_OPEN = 79  # 'O'
_T_READ = 82  # 'R'
_T_NREAD = 78  # 'N'
_T_DATA = 68  # 'D'
_T_END = 88  # 'X'


# ---------------------------------------------------------------------------
# WAT generators (audit-corrected stack order: dirfd=3, path ptr+len pushed)
# ---------------------------------------------------------------------------


class _Data:
    """Allocate guest strings at 32-byte-aligned linear-memory addresses."""

    def __init__(self) -> None:
        self.lines: list[str] = []
        self._next = 0

    def add(self, value: str) -> tuple[int, int]:
        assert '"' not in value and "\\" not in value, value
        assert self._next + max(len(value), 1) < 400, "string table overflow"
        addr = self._next
        self.lines.append(f'  (data (i32.const {addr}) "{value}")')
        self._next += 32
        return addr, len(value)


def _symlink_open_wat(
    links: list[tuple[str, str]],
    target: str,
    *,
    follow: bool = True,
    rights: int = 2,
    oflags: int = 0,
    dirfd: int = 3,
    path_override: tuple[int, int] | None = None,
    read: bool = True,
) -> str:
    """Create ``links`` (old, new) with path_symlink, then path_open target.

    Emits ``L<errno>`` per link, ``O<errno>`` for the open, and — after a
    successful open — ``R<errno>N<nread>D<first-byte>``. Exits 0 so a normal
    guest return cannot be confused with a refused operation.
    """
    data = _Data()
    ops: list[tuple[int, int, int, int]] = []
    for old, new in links:
        old_ptr, old_len = data.add(old)
        new_ptr, new_len = data.add(new)
        ops.append((old_ptr, old_len, new_ptr, new_len))
    if path_override is None:
        target_ptr, target_len = data.add(target)
    else:
        target_ptr, target_len = path_override

    link_code = "\n".join(f"""    (call $put8 (i32.const {_T_LINK}))
    (call $put8 (call $ps (i32.const {op}) (i32.const {ol})
      (i32.const 3) (i32.const {np}) (i32.const {nl})))""" for op, ol, np, nl in ops)

    read_code = ""
    if read:
        read_code = f"""        (i32.store (i32.const 4100) (i32.const 512))
        (i32.store (i32.const 4104) (i32.const 16))
        (local.set $e (call $fr (local.get $fd) (i32.const 4100)
          (i32.const 1) (i32.const 4116)))
        (call $put8 (i32.const {_T_READ}))
        (call $put8 (local.get $e))
        (call $put8 (i32.const {_T_NREAD}))
        (call $put8 (i32.load (i32.const 4116)))
        (call $put8 (i32.const {_T_DATA}))
        (call $put8 (i32.load8_u (i32.const 512)))"""

    return f"""(module
  (import "wasi_snapshot_preview1" "path_open" (func $po
    (param i32 i32 i32 i32 i32 i64 i64 i32 i32) (result i32)))
  (import "wasi_snapshot_preview1" "path_symlink" (func $ps
    (param i32 i32 i32 i32 i32) (result i32)))
  (import "wasi_snapshot_preview1" "fd_read" (func $fr
    (param i32 i32 i32 i32) (result i32)))
  (import "wasi_snapshot_preview1" "fd_write" (func $fw
    (param i32 i32 i32 i32) (result i32)))
  (import "wasi_snapshot_preview1" "proc_exit" (func $exit (param i32)))
  (memory (export "memory") 1)
{chr(10).join(data.lines)}
  (func $put8 (param $b i32)
    (i32.store8 (i32.const 4096) (local.get $b))
    (i32.store (i32.const 4100) (i32.const 4096))
    (i32.store (i32.const 4104) (i32.const 1))
    (drop (call $fw (i32.const 1) (i32.const 4100) (i32.const 1)
      (i32.const 4108))))
  (func (export "_start")
    (local $e i32) (local $fd i32)
{link_code}
    (call $put8 (i32.const {_T_OPEN}))
    (local.set $e (call $po (i32.const {dirfd})
      (i32.const {1 if follow else 0}) (i32.const {target_ptr})
      (i32.const {target_len}) (i32.const {oflags}) (i64.const {rights})
      (i64.const 0) (i32.const 0) (i32.const 4112)))
    (call $put8 (local.get $e))
    (if (i32.eqz (local.get $e))
      (then
        (local.set $fd (i32.load (i32.const 4112)))
{read_code}
      ))
    (call $put8 (i32.const {_T_END}))
    (call $exit (i32.const 0))
  )
)"""


def _open_write_wat(path: str, *, rights: int) -> str:
    """Open `path` on dirfd 3 with `rights`, then fd_write one byte.

    Emits ``O<errno>`` and, when the open succeeded, ``W<errno>``.
    """
    data = _Data()
    path_ptr, path_len = data.add(path)
    write_ptr, write_len = data.add("W")
    return f"""(module
  (import "wasi_snapshot_preview1" "path_open" (func $po
    (param i32 i32 i32 i32 i32 i64 i64 i32 i32) (result i32)))
  (import "wasi_snapshot_preview1" "fd_write" (func $fw
    (param i32 i32 i32 i32) (result i32)))
  (import "wasi_snapshot_preview1" "proc_exit" (func $exit (param i32)))
  (memory (export "memory") 1)
{chr(10).join(data.lines)}
  (func $put8 (param $b i32)
    (i32.store8 (i32.const 4096) (local.get $b))
    (i32.store (i32.const 4100) (i32.const 4096))
    (i32.store (i32.const 4104) (i32.const 1))
    (drop (call $fw (i32.const 1) (i32.const 4100) (i32.const 1)
      (i32.const 4108))))
  (func (export "_start")
    (local $e i32) (local $fd i32)
    (call $put8 (i32.const {_T_OPEN}))
    (local.set $e (call $po (i32.const 3) (i32.const 1)
      (i32.const {path_ptr}) (i32.const {path_len}) (i32.const 0)
      (i64.const {rights}) (i64.const 0) (i32.const 0)
      (i32.const 4112)))
    (call $put8 (local.get $e))
    (if (i32.eqz (local.get $e))
      (then
        (local.set $fd (i32.load (i32.const 4112)))
        (i32.store (i32.const 4100) (i32.const {write_ptr}))
        (i32.store (i32.const 4104) (i32.const {write_len}))
        (local.set $e (call $fw (local.get $fd) (i32.const 4100)
          (i32.const 1) (i32.const 4108)))
        (call $put8 (i32.const 87))
        (call $put8 (local.get $e))))
    (call $put8 (i32.const {_T_END}))
    (call $exit (i32.const 0))
  )
)"""


def _revocation_wat() -> str:
    """Create ``ready`` and signal, poll for ``go``, then open ``secret.txt``.

    The host observes ``ready``, may chmod ``secret.txt`` to 000, then creates
    ``go``. The guest's next real path_open therefore happens strictly after
    the revocation. Exits 0 on completion; emits ``O<errno>`` (+ read report).
    """
    return f"""(module
  (import "wasi_snapshot_preview1" "path_open" (func $po
    (param i32 i32 i32 i32 i32 i64 i64 i32 i32) (result i32)))
  (import "wasi_snapshot_preview1" "fd_read" (func $fr
    (param i32 i32 i32 i32) (result i32)))
  (import "wasi_snapshot_preview1" "fd_write" (func $fw
    (param i32 i32 i32 i32) (result i32)))
  (import "wasi_snapshot_preview1" "fd_close" (func $fc
    (param i32) (result i32)))
  (import "wasi_snapshot_preview1" "proc_exit" (func $exit (param i32)))
  (memory (export "memory") 1)
  (data (i32.const 0) "ready")
  (data (i32.const 32) "go")
  (data (i32.const 64) "secret.txt")
  (data (i32.const 96) "R")
  (func $put8 (param $b i32)
    (i32.store8 (i32.const 4096) (local.get $b))
    (i32.store (i32.const 4100) (i32.const 4096))
    (i32.store (i32.const 4104) (i32.const 1))
    (drop (call $fw (i32.const 1) (i32.const 4100) (i32.const 1)
      (i32.const 4108))))
  (func (export "_start")
    (local $e i32) (local $fd i32) (local $i i32)
    ;; Signal readiness: path_open("ready", O_CREAT, rights=READ|WRITE).
    (local.set $e (call $po (i32.const 3) (i32.const 0) (i32.const 0)
      (i32.const 5) (i32.const 1) (i64.const 66) (i64.const 0)
      (i32.const 0) (i32.const 4112)))
    (if (i32.ne (local.get $e) (i32.const 0))
      (then (call $put8 (i32.const 67)) (call $put8 (local.get $e))
        (call $exit (i32.const 91))))
    (local.set $fd (i32.load (i32.const 4112)))
    (i32.store (i32.const 4100) (i32.const 96))
    (i32.store (i32.const 4104) (i32.const 1))
    (drop (call $fw (local.get $fd) (i32.const 4100) (i32.const 1)
      (i32.const 4108)))
    (drop (call $fc (local.get $fd)))
    ;; Bounded poll for the host's "go" marker (300k iterations).
    (block $found
      (loop $l
        (local.set $e (call $po (i32.const 3) (i32.const 0) (i32.const 32)
          (i32.const 2) (i32.const 0) (i64.const 2) (i64.const 0)
          (i32.const 0) (i32.const 4112)))
        (if (i32.eqz (local.get $e))
          (then
            (drop (call $fc (i32.load (i32.const 4112))))
            (br $found)))
        (local.set $i (i32.add (local.get $i) (i32.const 1)))
        (br_if $found (i32.ge_u (local.get $i) (i32.const 300000)))
        (br $l)))
    (if (i32.ge_u (local.get $i) (i32.const 300000))
      (then (call $put8 (i32.const 84)) (call $exit (i32.const 92))))
    ;; Revocation has happened (or not, in the control) before this call.
    (call $put8 (i32.const {_T_OPEN}))
    (local.set $e (call $po (i32.const 3) (i32.const 1) (i32.const 64)
      (i32.const 10) (i32.const 0) (i64.const 2) (i64.const 0)
      (i32.const 0) (i32.const 4112)))
    (call $put8 (local.get $e))
    (if (i32.eqz (local.get $e))
      (then
        (local.set $fd (i32.load (i32.const 4112)))
        (i32.store (i32.const 4100) (i32.const 512))
        (i32.store (i32.const 4104) (i32.const 16))
        (local.set $e (call $fr (local.get $fd) (i32.const 4100)
          (i32.const 1) (i32.const 4116)))
        (call $put8 (i32.const {_T_READ}))
        (call $put8 (local.get $e))
        (call $put8 (i32.const {_T_NREAD}))
        (call $put8 (i32.load (i32.const 4116)))
        (call $put8 (i32.const {_T_DATA}))
        (call $put8 (i32.load8_u (i32.const 512)))))
    (call $put8 (i32.const {_T_END}))
    (call $exit (i32.const 0))
  )
)"""


# ---------------------------------------------------------------------------
# Harness
# ---------------------------------------------------------------------------


def _compile(wat: str) -> Path:
    """Compile a probe into a hygienic scratch dir (mkdtemp + atexit)."""
    global _PROBE_DIR
    if _PROBE_DIR is None:
        _PROBE_DIR = Path(tempfile.mkdtemp(prefix="ephemora_s2_guest_"))
        atexit.register(shutil.rmtree, _PROBE_DIR, ignore_errors=True)
    wasm = _PROBE_DIR / f"probe_{len(list(_PROBE_DIR.iterdir())):04d}.wasm"
    wasm.write_bytes(wasmtime.wat2wasm(wat))
    return wasm


_PROBE_DIR: Path | None = None


def _sandbox(base: Path, *, max_fuel: int = 5_000_000) -> WASISandbox:
    """Construct the product sandbox with `base` as the first allow_dir."""
    return WASISandbox(
        config=WASIConfig(
            allow_dirs=(str(base),),
            max_fuel=max_fuel,
            timeout_seconds=20,
        )
    )


def _run(base: Path, wasm: Path, *, max_fuel: int = 5_000_000):
    """Run a probe through the real WASISandbox path (in-process trust)."""
    sandbox = _sandbox(base, max_fuel=max_fuel)
    try:
        return sandbox.run(
            str(wasm),
            trust=TRUST_TRUSTED,
            use_engine_pool=False,
        )
    finally:
        sandbox.cleanup()


def _assert_guest_ran(result) -> None:
    assert result.status is ExecutionStatus.SUCCESS, (
        f"guest did not run: status={result.status} exit={result.exit_code} "
        f"stderr={result.stderr[:400]!r}"
    )


def _parse_symlink_open(stdout: str, link_count: int, expects_read: bool) -> dict:
    """Parse the tagged guest report; record every errno in the message."""
    raw = stdout.encode("utf-8")
    pos = 0
    links: list[int] = []
    for index in range(link_count):
        assert raw[pos : pos + 1] == bytes(
            [_T_LINK]
        ), f"missing L tag for link {index} in guest report {raw!r}"
        links.append(raw[pos + 1])
        pos += 2
    assert raw[pos : pos + 1] == bytes(
        [_T_OPEN]
    ), f"missing O tag in guest report {raw!r}"
    report = {
        "links": links,
        "open": raw[pos + 1],
        "read": None,
        "nread": None,
        "data": None,
    }
    pos += 2
    if report["open"] == 0 and expects_read:
        assert raw[pos : pos + 1] == bytes([_T_READ]), f"missing R: {raw!r}"
        report["read"] = raw[pos + 1]
        pos += 2
        assert raw[pos : pos + 1] == bytes([_T_NREAD]), f"missing N: {raw!r}"
        report["nread"] = raw[pos + 1]
        pos += 2
        assert raw[pos : pos + 1] == bytes([_T_DATA]), f"missing D: {raw!r}"
        report["data"] = raw[pos + 1]
        pos += 2
    assert raw[pos : pos + 1] == bytes(
        [_T_END]
    ), f"missing X end marker in guest report {raw!r}"
    return report


def _probe(
    base: Path,
    wat: str,
    *,
    link_count: int,
    expects_read: bool = True,
    max_fuel: int = 5_000_000,
):
    result = _run(base, _compile(wat), max_fuel=max_fuel)
    _assert_guest_ran(result)
    return result, _parse_symlink_open(result.stdout, link_count, expects_read)


def _open_errno_byte(stdout: str) -> int | None:
    """Return the byte after the O tag, or None if the guest trapped first."""
    raw = stdout.encode("utf-8")
    index = raw.find(bytes([_T_OPEN]))
    if index < 0 or index + 1 >= len(raw):
        return None
    return raw[index + 1]


def _parse_open_write(stdout: str) -> dict:
    raw = stdout.encode("utf-8")
    assert raw[0:1] == bytes([_T_OPEN]), f"missing O: {raw!r}"
    report = {"open": raw[1], "write": None}
    pos = 2
    if report["open"] == 0:
        assert raw[pos : pos + 1] == b"W", f"missing W: {raw!r}"
        report["write"] = raw[pos + 1]
        pos += 2
    assert raw[pos : pos + 1] == bytes([_T_END]), f"missing X: {raw!r}"
    return report


def _forbidden_swap_dir() -> Path:
    """A writable directory the product's canonical policy forbids.

    On macOS ``/var/tmp`` canonicalizes to ``/private/var/tmp``; ``/private``
    is on ``FORBIDDEN_CANONICAL`` while only ``/private/tmp`` and
    ``/private/var/folders`` are excepted. The test user can still create and
    remove a sentinel there, so the swap target is REAL and writable — no
    patched ``_canonicalize`` is involved anywhere.
    """
    if sys.platform != "darwin":
        pytest.skip("forbidden writable swap target is macOS-specific")
    path = Path(tempfile.mkdtemp(prefix="ephemora_s2_forbidden_", dir="/var/tmp"))
    canon = os.path.realpath(path)
    if not canon.startswith("/private/var/tmp/"):
        shutil.rmtree(path, ignore_errors=True)
        pytest.skip(f"/var/tmp does not resolve under /private/var/tmp: {canon}")
    return path


def _swap_preopen_with_symlink(base: Path, outside: Path) -> None:
    """Replace the preopen directory with a symlink to `outside` (real FS)."""
    for child in sorted(base.iterdir()):
        if child.is_dir():
            shutil.rmtree(child)
        else:
            child.unlink()
    base.rmdir()
    base.symlink_to(outside, target_is_directory=True)


def _make_swapped_sandbox(root: Path, name: str):
    """Construct before the swap; return (base, outside, sandbox, sentinel)."""
    base = root / name / "base"
    base.mkdir(parents=True)
    (base / "allowed.txt").write_text("sandbox content")
    outside = _forbidden_swap_dir()
    sentinel = outside / "sentinel.txt"
    sentinel.write_text("FORBIDDEN-OUTSIDE-SENTINEL")
    sandbox = _sandbox(base)  # validates the SAFE path, like a real operator
    _swap_preopen_with_symlink(base, outside)
    return base, outside, sandbox, sentinel


# ---------------------------------------------------------------------------
# Case 1 — guest-created relative symlink to an outside sentinel
# ---------------------------------------------------------------------------


class TestGuestCreatedSymlinkToOutside:
    def test_guest_symlink_to_outside_is_refused(self, tmp_path):
        # Positive control: the exact same guest creates an in-preopen symlink
        # and reads it (a broken harness cannot pass this).
        control = tmp_path / "control"
        control.mkdir()
        (control / "inside.txt").write_text("INSIDE-CONTROL")
        _, ctrl = _probe(
            control,
            _symlink_open_wat([("inside.txt", "inside_link")], "inside_link"),
            link_count=1,
        )
        assert ctrl["links"] == [0], "control: path_symlink failed"
        assert ctrl["open"] == 0, f"control: open errno {ctrl['open']}"
        assert ctrl["data"] == ord("I"), f"control: read {ctrl['data']}"

        base = tmp_path / "base"
        base.mkdir()
        outside = tmp_path / "outside"
        outside.mkdir()
        sentinel = outside / "sentinel.txt"
        sentinel.write_text("OUTSIDE-SENTINEL-CONTENT")

        _, report = _probe(
            base,
            _symlink_open_wat(
                [("../outside/sentinel.txt", "escape")],
                "escape",
            ),
            link_count=1,
        )
        assert report["links"] == [0], (
            f"guest could not create the link via path_symlink: "
            f"errno {report['links']}"
        )
        link = base / "escape"
        assert link.is_symlink(), "guest link does not exist on the host"
        assert os.readlink(link) == "../outside/sentinel.txt"
        assert report["open"] in (_EPERM, _ENOTCAPABLE), (
            f"outside symlink open returned errno {report['open']}, expected a "
            "capability denial (EPERM=63 or ENOTCAPABLE=76)"
        )
        assert report["read"] is None, "a read happened after a refused open"
        assert sentinel.read_text() == "OUTSIDE-SENTINEL-CONTENT"


# ---------------------------------------------------------------------------
# Case 2 — guest-created A -> B -> outside chain
# ---------------------------------------------------------------------------


class TestAbsoluteGuestPath:
    def test_absolute_host_path_is_refused_even_with_a_preopen(self, tmp_path):
        base = tmp_path / "base"
        base.mkdir()
        (base / "inside.txt").write_text("INSIDE-ABSOLUTE")
        # Positive control: a relative path inside the granted preopen works.
        control = _run(
            base, _compile(_open_write_wat("inside.txt", rights=2)), max_fuel=2_000_000
        )
        assert _open_errno_byte(control.stdout) in (0, None), control.stdout
        # Attack: absolute host path is not relative to dirfd 3.
        attack = _run(
            base, _compile(_open_write_wat("/etc/passwd", rights=2)), max_fuel=2_000_000
        )
        errno = _open_errno_byte(attack.stdout)
        assert errno in (
            _EPERM,
            _ENOTCAPABLE,
        ), f"absolute path open returned errno {errno}, expected capability denial"


class TestGuestSymlinkChain:
    def test_two_hop_chain_to_outside_is_refused(self, tmp_path):
        # Positive control: the same two-hop shape pointing inside opens.
        control = tmp_path / "control"
        control.mkdir()
        (control / "inside.txt").write_text("INSIDE-CHAIN")
        _, ctrl = _probe(
            control,
            _symlink_open_wat(
                [("inside.txt", "link_b"), ("link_b", "link_a")],
                "link_a",
            ),
            link_count=2,
        )
        assert ctrl["links"] == [0, 0], "control: path_symlink chain failed"
        assert ctrl["open"] == 0, f"control: open errno {ctrl['open']}"
        assert ctrl["data"] == ord("I")

        base = tmp_path / "base"
        base.mkdir()
        outside = tmp_path / "outside"
        outside.mkdir()
        sentinel = outside / "sentinel.txt"
        sentinel.write_text("CHAIN-SENTINEL")

        _, report = _probe(
            base,
            _symlink_open_wat(
                [("../outside/sentinel.txt", "link_b"), ("link_b", "link_a")],
                "link_a",
            ),
            link_count=2,
        )
        assert report["links"] == [
            0,
            0,
        ], f"guest could not create both links: errnos {report['links']}"
        assert os.readlink(base / "link_a") == "link_b"
        assert os.readlink(base / "link_b") == "../outside/sentinel.txt"
        assert report["open"] in (_EPERM, _ENOTCAPABLE), (
            f"chained symlink open returned errno {report['open']}, expected a "
            "capability denial"
        )
        assert report["read"] is None
        assert sentinel.read_text() == "CHAIN-SENTINEL"


# ---------------------------------------------------------------------------
# Case 3 — guest-created symlink to a real inside file (positive control)
# ---------------------------------------------------------------------------


class TestGuestSymlinkInside:
    def test_guest_symlink_to_inside_file_opens_and_reads(self, tmp_path):
        base = tmp_path / "base"
        base.mkdir()
        (base / "inside.txt").write_text("INSIDE-CONTENT")
        _, report = _probe(
            base,
            _symlink_open_wat([("inside.txt", "inside_link")], "inside_link"),
            link_count=1,
        )
        assert report["links"] == [0], "path_symlink failed"
        assert os.readlink(base / "inside_link") == "inside.txt"
        assert report["open"] == 0, f"inside symlink open errno {report['open']}"
        assert report["read"] == 0, f"fd_read errno {report['read']}"
        assert report["nread"] and report["nread"] > 0
        assert report["data"] == ord("I"), f"read byte {report['data']!r}, expected 'I'"


# ---------------------------------------------------------------------------
# Case 4 — trailing slash through a guest-created symlink to outside
# ---------------------------------------------------------------------------


class TestTrailingSlashThroughGuestSymlink:
    def test_trailing_slash_to_outside_directory_is_refused(self, tmp_path):
        base = tmp_path / "base"
        base.mkdir()
        # Positive control: trailing slash through a guest-created symlink to
        # a real inside directory opens (so the refusal below is not a generic
        # "trailing slash is unsupported" result).
        (base / "realdir").mkdir()
        _, ctrl = _probe(
            base,
            _symlink_open_wat([("realdir", "indir")], "indir/", read=False),
            link_count=1,
            expects_read=False,
        )
        assert ctrl["links"] == [0]
        assert (
            ctrl["open"] == 0
        ), f"control: trailing slash to inside dir errno {ctrl['open']}"

        outside_dir = tmp_path / "outside_dir"
        outside_dir.mkdir()
        sentinel = outside_dir / "sentinel.txt"
        sentinel.write_text("OUTSIDE-DIR-SENTINEL")

        _, report = _probe(
            base,
            _symlink_open_wat([("../outside_dir", "outdir")], "outdir/", read=False),
            link_count=1,
            expects_read=False,
        )
        assert report["links"] == [0], "guest could not create outdir link"
        assert os.readlink(base / "outdir") == "../outside_dir"
        assert report["open"] in (_EPERM, _ENOTCAPABLE), (
            f"trailing-slash outside open returned errno {report['open']}, "
            "expected a capability denial"
        )
        assert sentinel.read_text() == "OUTSIDE-DIR-SENTINEL"


# ---------------------------------------------------------------------------
# Case 5 — host swaps the preopen with a symlink before run()
# ---------------------------------------------------------------------------


class TestPreopenSwapBeforeRun:
    def test_real_swap_before_run_is_refused(self, tmp_path):
        # Positive control on an unswapped preopen with the same guest.
        safe = tmp_path / "safe"
        safe.mkdir()
        (safe / "sentinel.txt").write_text("INSIDE-SENTINEL")
        _, ctrl = _probe(
            safe,
            _symlink_open_wat([], "sentinel.txt"),
            link_count=0,
        )
        assert ctrl["open"] == 0, f"control: open errno {ctrl['open']}"
        assert ctrl["data"] == ord("I")

        base = tmp_path / "base"
        base.mkdir()
        (base / "allowed.txt").write_text("sandbox content")
        outside = _forbidden_swap_dir()
        sentinel = outside / "sentinel.txt"
        sentinel.write_text("FORBIDDEN-SENTINEL")
        try:
            # Construct against the SAFE directory, then swap for real.
            sandbox = _sandbox(base)
            _swap_preopen_with_symlink(base, outside)
            try:
                result = sandbox.run(
                    str(_compile(_symlink_open_wat([], "sentinel.txt"))),
                    trust=TRUST_TRUSTED,
                    use_engine_pool=False,
                )
            finally:
                sandbox.cleanup()
            _assert_guest_ran(result)
            report = _parse_symlink_open(result.stdout, 0, True)
            assert result.effective_preopens == (
                "/sandbox",
            ), f"swapped preopen was granted: {result.effective_preopens}"
            assert os.path.realpath(outside) not in result.effective_preopens
            assert (
                report["open"] != 0
            ), "guest opened the outside sentinel after the preopen swap"
            assert report["read"] is None
            assert sentinel.read_text() == "FORBIDDEN-SENTINEL"
        finally:
            shutil.rmtree(outside, ignore_errors=True)

    def test_grant_time_revalidation_refuses_swapped_preopen(
        self, tmp_path, monkeypatch
    ):
        """Isolate the grant-time layer: bypass the earlier run-time filter.

        The swap itself is a REAL filesystem replacement. Bypassing the
        config-time canonical filter (test-local monkeypatch) is what makes
        the swapped entry reach ``_grant_preopens``; the TOCTOU revalidation
        there must still skip it.
        """
        base = tmp_path / "base"
        base.mkdir()
        (base / "allowed.txt").write_text("sandbox content")
        outside = _forbidden_swap_dir()
        sentinel = outside / "sentinel.txt"
        sentinel.write_text("GRANT-REVALIDATION-SENTINEL")
        sandbox = _sandbox(base)
        monkeypatch.setattr(
            WASISandbox,
            "_filter_dangerous_dirs",
            lambda self, dirs: tuple(dirs),
        )
        _swap_preopen_with_symlink(base, outside)
        try:
            with pytest.warns(RuntimeWarning, match="TOCTOU revalidation"):
                result = sandbox.run(
                    str(_compile(_symlink_open_wat([], "sentinel.txt"))),
                    trust=TRUST_TRUSTED,
                    use_engine_pool=False,
                )
            _assert_guest_ran(result)
            report = _parse_symlink_open(result.stdout, 0, True)
            assert result.effective_preopens == ("/sandbox",)
            assert report["open"] != 0
            assert sentinel.read_text() == "GRANT-REVALIDATION-SENTINEL"
        finally:
            sandbox.cleanup()
            shutil.rmtree(outside, ignore_errors=True)


# ---------------------------------------------------------------------------
# Case 6 — invalid WASI parameters
# ---------------------------------------------------------------------------


class TestInvalidWasiParameters:
    def test_bad_dirfd_returns_ebadf_and_host_survives(self, tmp_path):
        base = tmp_path / "base"
        base.mkdir()
        (base / "inside.txt").write_text("INSIDE")
        _, report = _probe(
            base,
            _symlink_open_wat([], "inside.txt", dirfd=999),
            link_count=0,
            expects_read=False,
        )
        assert (
            report["open"] == _EBADF
        ), f"bad dirfd returned errno {report['open']}, expected EBADF=8"
        # Positive control: valid dirfd on the same preopen still works.
        _, ctrl = _probe(base, _symlink_open_wat([], "inside.txt"), link_count=0)
        assert ctrl["open"] == 0
        assert ctrl["data"] == ord("I")

    def test_path_pointer_outside_memory_traps_without_host_crash(self, tmp_path):
        base = tmp_path / "base"
        base.mkdir()
        (base / "inside.txt").write_text("INSIDE")
        result = _run(
            base,
            _compile(
                _symlink_open_wat(
                    [],
                    "inside.txt",
                    path_override=(0x7FFF_FFF0, 16),
                    read=False,
                )
            ),
        )
        trapped = result.status is not ExecutionStatus.SUCCESS
        errno = _open_errno_byte(result.stdout)
        assert trapped or errno not in (None, 0), (
            "out-of-bounds path pointer neither trapped nor returned an errno: "
            f"status={result.status} exit={result.exit_code} "
            f"stdout={result.stdout!r}"
        )
        # Host process is alive and the sandbox still works.
        _, ctrl = _probe(base, _symlink_open_wat([], "inside.txt"), link_count=0)
        assert ctrl["open"] == 0

    def test_path_length_outside_memory_is_errno_or_trap(self, tmp_path):
        base = tmp_path / "base"
        base.mkdir()
        (base / "inside.txt").write_text("INSIDE")
        result = _run(
            base,
            _compile(
                _symlink_open_wat(
                    [],
                    "inside.txt",
                    path_override=(0, 0x7FFF_FFFF),
                    read=False,
                )
            ),
        )
        trapped = result.status is not ExecutionStatus.SUCCESS
        errno = _open_errno_byte(result.stdout)
        assert trapped or errno not in (None, 0), (
            "out-of-bounds path length neither trapped nor returned an errno: "
            f"status={result.status} exit={result.exit_code} "
            f"stdout={result.stdout!r}"
        )
        _, ctrl = _probe(base, _symlink_open_wat([], "inside.txt"), link_count=0)
        assert ctrl["open"] == 0

    def test_missing_write_right_is_denied(self, tmp_path):
        base = tmp_path / "base"
        base.mkdir()
        (base / "inside.txt").write_text("INSIDE")
        result = _run(base, _compile(_open_write_wat("inside.txt", rights=0x6)))
        _assert_guest_ran(result)
        report = _parse_open_write(result.stdout)
        assert report["open"] == 0, f"open without write right errno {report['open']}"
        assert report["write"] not in (
            None,
            0,
        ), "fd_write succeeded on an fd opened without FD_WRITE"
        # Positive control: FD_WRITE in the requested rights makes the same
        # guest write through, and the host sees the byte.
        result = _run(base, _compile(_open_write_wat("inside.txt", rights=0x46)))
        _assert_guest_ran(result)
        report = _parse_open_write(result.stdout)
        assert report["open"] == 0
        assert report["write"] == 0, f"positive control write errno {report['write']}"
        assert (base / "inside.txt").read_text().startswith("W")


# ---------------------------------------------------------------------------
# Case 7 — mutation control: the boundary is enforced by filter/grant code
# ---------------------------------------------------------------------------


def _permissive_grant(wasi_cfg, safe_dirs, sandbox_dir):
    """Mutation: grant every entry without the forbidden-canonical check."""
    granted: list[str] = []
    for entry in safe_dirs:
        host, guest = WASISandbox._split_dir_mapping(entry)
        canon = os.path.realpath(host)
        wasi_cfg.preopen_dir(canon, guest)
        granted.append(canon)
    wasi_cfg.preopen_dir(sandbox_dir, "/sandbox")
    granted.append("/sandbox")
    return tuple(granted)


class TestBoundaryMutationControl:
    def test_mutation_disables_boundary_and_restores(self, tmp_path, monkeypatch):
        wat = _symlink_open_wat([], "sentinel.txt")
        outside_dirs: list[Path] = []
        try:
            # 1. Real product code: the same swap is refused.
            _, outside, sandbox, sentinel = _make_swapped_sandbox(tmp_path, "blocked")
            outside_dirs.append(outside)
            try:
                result = sandbox.run(
                    str(_compile(wat)),
                    trust=TRUST_TRUSTED,
                    use_engine_pool=False,
                )
            finally:
                sandbox.cleanup()
            _assert_guest_ran(result)
            blocked = _parse_symlink_open(result.stdout, 0, True)
            assert result.effective_preopens == ("/sandbox",)
            assert blocked["open"] != 0, "baseline attack was not blocked"

            # 2. Mutation: make the shared filter permissive AND disable the
            #    grant-time revalidation. The SAME real swap now escapes.
            with monkeypatch.context() as m:
                m.setattr(
                    WASISandbox,
                    "_filter_dangerous_dirs",
                    lambda self, dirs: tuple(dirs),
                )
                m.setattr(
                    WASISandbox,
                    "_grant_preopens",
                    staticmethod(_permissive_grant),
                )
                _, outside2, sandbox2, sentinel2 = _make_swapped_sandbox(
                    tmp_path, "mutated"
                )
                outside_dirs.append(outside2)
                try:
                    result2 = sandbox2.run(
                        str(_compile(wat)),
                        trust=TRUST_TRUSTED,
                        use_engine_pool=False,
                    )
                finally:
                    sandbox2.cleanup()
            _assert_guest_ran(result2)
            escaped = _parse_symlink_open(result2.stdout, 0, True)
            assert os.path.realpath(outside2) in result2.effective_preopens, (
                "mutation control did not grant the forbidden directory: "
                f"{result2.effective_preopens}"
            )
            assert (
                escaped["open"] == 0
            ), f"mutation control open errno {escaped['open']}"
            assert escaped["data"] == ord(
                "F"
            ), f"mutation control read {escaped['data']!r}, expected 'F'"
            assert sentinel2.read_text() == "FORBIDDEN-OUTSIDE-SENTINEL"

            # 3. monkeypatch.context() restored the product code: a third
            #    fresh attack is blocked again.
            _, outside3, sandbox3, _ = _make_swapped_sandbox(tmp_path, "restored")
            outside_dirs.append(outside3)
            try:
                result3 = sandbox3.run(
                    str(_compile(wat)),
                    trust=TRUST_TRUSTED,
                    use_engine_pool=False,
                )
            finally:
                sandbox3.cleanup()
            _assert_guest_ran(result3)
            restored = _parse_symlink_open(result3.stdout, 0, True)
            assert result3.effective_preopens == ("/sandbox",)
            assert restored["open"] != 0, "boundary was not restored after mutation"
            assert sentinel.read_text() == "FORBIDDEN-OUTSIDE-SENTINEL"
        finally:
            for path in outside_dirs:
                shutil.rmtree(path, ignore_errors=True)


# ---------------------------------------------------------------------------
# Case 8 — permission revocation between guest readiness and the open
# ---------------------------------------------------------------------------


def _run_with_revocation(base: Path, wasm: Path, *, revoke: bool):
    """Guest signals `ready`; host may chmod 000, then creates `go`."""
    acted = {"done": False}

    def host_side() -> None:
        deadline = time.monotonic() + 15.0
        ready = base / "ready"
        while time.monotonic() < deadline:
            if ready.exists():
                if revoke:
                    os.chmod(base / "secret.txt", 0o000)
                (base / "go").write_text("go")
                acted["done"] = True
                return
            time.sleep(0.001)

    thread = threading.Thread(target=host_side, daemon=True)
    thread.start()
    try:
        result = _run(base, wasm, max_fuel=50_000_000)
    finally:
        thread.join(timeout=20)
        if revoke:
            try:
                os.chmod(base / "secret.txt", 0o600)
            except OSError:
                pass
    assert acted["done"], "host coordination never observed guest readiness"
    return result


class TestPermissionRevocation:
    def test_permission_revoked_mid_operation_denies_open(self, tmp_path):
        if os.geteuid() == 0:
            pytest.skip("root ignores file mode bits; revocation is untestable")
        wasm = _compile(_revocation_wat())

        # Positive control: identical guest, identical coordination, no chmod.
        control = tmp_path / "control"
        control.mkdir()
        (control / "secret.txt").write_text("SECRET")
        result = _run_with_revocation(control, wasm, revoke=False)
        _assert_guest_ran(result)
        ctrl = _parse_symlink_open(result.stdout, 0, True)
        assert ctrl["open"] == 0, f"control open errno {ctrl['open']}"
        assert ctrl["data"] == ord("S"), f"control read {ctrl['data']!r}"

        # Revocation: chmod 000 strictly between the guest's readiness signal
        # and its path_open (the guest polls for the host's `go` marker).
        revoke = tmp_path / "revoke"
        revoke.mkdir()
        (revoke / "secret.txt").write_text("SECRET")
        result = _run_with_revocation(revoke, wasm, revoke=True)
        _assert_guest_ran(result)
        report = _parse_symlink_open(result.stdout, 0, True)
        assert report["open"] != 0, "path_open succeeded after the target was chmod 000"
        assert (
            report["open"] == _EACCES
        ), f"revoked open returned errno {report['open']}, expected EACCES=2"
        assert report["read"] is None
        assert (revoke / "secret.txt").read_text() == "SECRET"
