"""ADR-002: ``io_budget_bytes`` on the COMPONENT path.

Measured 2026-10-16 on the release candidate: a component run with
``io_budget_bytes=1`` wrote 19 bytes into its granted preopen and still came
back SUCCESS with ``io_budget_exceeded=False``. The knob was validated at run
time but never enforced there — the preview1 watcher's scope is the private
``/sandbox`` dir, and a WASI 0.2 component has no mount for it, so the
component path had nothing to watch and ``wasi_02`` referenced
``io_budget_bytes`` nowhere (0 hits).

The wall now covers the directories a component run actually preopens, which
IS its only writable scope. The breach keeps the preview1 form (ERROR, the
``"I/O budget exceeded: guest wrote N bytes ..."`` text, ``io_budget_exceeded``).
Two consequences are deliberate and named, not incidental:

* the comparison is against a baseline taken before the guest starts, so a
  caller-owned directory's pre-existing content is not charged to the guest
  (the preview1 sandbox dir starts empty, which is why the inline watcher may
  compare absolute sizes);
* the poller cannot observe a write that begins and finishes inside one
  interval — the same sampling bound the preview1 path has — so an
  end-of-run sample reports such an overrun as a breach instead of a silent
  success. It DETECTS: the bytes of that run are already on disk.

That end-of-run sample now runs on the preview1 path as well (the preview1
hard-exit budget case). A preview1 guest that wrote over budget and then exited
used to come back
SUCCESS with ``io_budget_exceeded=False`` and ``io_bytes_written=None`` while
up to 12.5 MiB sat in its sandbox dir: ``proc_exit`` raises
``wasmtime.ExitTrap`` — an ``Exception``, not a ``Trap`` — so the run never
reached the byte watcher's success path. ``TestPreview1EndOfRunSample`` pins
that route (in-process and through the worker) plus the controls that must
stay green.

The same end-of-run VERDICT now also runs on the component path's hard-exit
route (the component hard-exit case, measured 2026-10-16). A component that
writes over budget and
then leaves through ``wasi:cli/exit`` (``std::process::exit(0)``, C ``exit()``,
a lifted preview1 module's ``proc_exit``) makes the ``run`` call raise
``"Exited with i32 exit status 0"``; that trap branch returned SUCCESS without
ever comparing the measured bytes against ``io_budget_bytes`` — 65536 B at
budget 1024 came back ``success`` with ``io_budget_exceeded=False`` and the
bytes on disk, in-process AND through the protected worker, while ``fs02.wasm``
(19 B, same grant, budget 1) took the regular route and came back ERROR. The
enforcement depended on the guest's exit path, not on the byte count. The
exit-0 branch now applies the same end-of-run comparison as the regular return
route, after — never instead of — the poller's ``exceeded`` verdict.
``TestComponentExitTrapBudgetRoute`` pins that route, its controls and the
containment.

Negative controls are here next to the positive ones on purpose: an
enforcement that also breaks the legitimate component run would be a
regression, not a fix.
"""

from __future__ import annotations

import os
import shutil
import sys
import tempfile
import threading
import time

import wasmtime

sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))

from ephemora_cell import (
    ComponentSandbox,
    ExecutionStatus,
    WASIConfig,
    WASISandbox,
    run_isolated,
)
from ephemora_cell.wasi_runtime import (
    _drop_nested_dirs,
    _GuestWriteBudget,
)

FIXTURES = os.path.join(os.path.dirname(__file__), "fixtures")
HELLO02 = os.path.join(FIXTURES, "hello02.wasm")
FS02 = os.path.join(FIXTURES, "fs02.wasm")
# Burst-write vector: writes <argv[2]> bytes in ONE std::fs::write and then
# leaves through wasi:cli/exit(0) (hard exit, not a run-return value).
EXITWRITE02 = os.path.join(FIXTURES, "exitwrite02.wasm")

# fs02 writes exactly this into <argv[1]>/out.txt (tests/fixtures/README.md).
PAYLOAD = "pwned-by-component\n"
PAYLOAD_BYTES = len(PAYLOAD.encode())
assert PAYLOAD_BYTES == 19

_SMALL = dict(max_fuel=5_000_000, timeout_seconds=30)

# Bounded write-flood (same shape as tests/test_run_io_budgets.py): opens
# "out.bin" in the FIRST preopen (fd 3) and writes 500 x 8 bytes = 4000 B.
BOUNDED_WRITE_WAT = """
(module
  (import "wasi_snapshot_preview1" "fd_write" (func $fd_write
    (param i32 i32 i32 i32) (result i32)))
  (import "wasi_snapshot_preview1" "path_open" (func $path_open
    (param i32 i32 i32 i32 i32 i64 i64 i32 i32) (result i32)))
  (import "wasi_snapshot_preview1" "proc_exit" (func $proc_exit (param i32)))
  (memory (export "memory") 1)
  (data (i32.const 8) "out.bin")
  (data (i32.const 32) "AAAAAAAA")
  (data (i32.const 64) "\\20\\00\\00\\00\\08\\00\\00\\00")
  (func (export "_start") (local $e i32) (local $i i32)
    i32.const 3 i32.const 0 i32.const 8 i32.const 7 i32.const 1
    i64.const 70 i64.const 70 i32.const 0 i32.const 100
    call $path_open
    local.set $e
    local.get $e
    if i32.const 2 call $proc_exit end
    (loop $l
      i32.const 100 i32.load
      i32.const 64 i32.const 1 i32.const 104
      call $fd_write drop
      local.get $i i32.const 1 i32.add local.set $i
      local.get $i i32.const 500 i32.lt_u
      br_if $l
    )
    i32.const 0
    call $proc_exit
  )
)
"""

PREOPEN_WRITE_BYTES = 500 * 8


def _grant(prefix: str = "ephemora_iob_grant_") -> str:
    return tempfile.mkdtemp(prefix=prefix)


def _write_file(root: str, name: str, size: int) -> None:
    with open(os.path.join(root, name), "wb") as fh:
        fh.write(b"x" * size)


class _Epoch:
    """Records the watcher's interrupt signal (the real one is an Engine)."""

    def __init__(self) -> None:
        self.calls = 0

    def increment_epoch(self) -> None:
        self.calls += 1


class TestComponentByteBudgetEnforced:
    """Regression core: an over-budget component write is never a success."""

    def test_over_budget_write_is_a_breach_not_a_silent_success(self):
        """The measured 2026-10-16 vector, in-process."""
        target = _grant()
        sandbox = ComponentSandbox(
            WASIConfig(allow_dirs=(target,), io_budget_bytes=1, **_SMALL)
        )
        try:
            result = sandbox.run(FS02, args=[target])
            assert result.status is not ExecutionStatus.SUCCESS, (
                "budget=1 with a 19-byte guest write must not report success: "
                f"{result.status}"
            )
            assert result.status is ExecutionStatus.ERROR
            assert "I/O budget exceeded" in result.stderr
            assert result.io_budget_exceeded is True
            assert result.io_bytes_written == PAYLOAD_BYTES
            # Detection, not prevention: the sub-interval write is already on
            # disk when the end-of-run sample catches it.
            with open(os.path.join(target, "out.txt")) as fh:
                assert fh.read() == PAYLOAD
        finally:
            sandbox.cleanup()
            shutil.rmtree(target, ignore_errors=True)

    def test_over_budget_write_is_a_breach_on_the_worker_path(self):
        """The same vector through the disposable worker."""
        target = _grant()
        try:
            config = WASIConfig(allow_dirs=(target,), io_budget_bytes=1, **_SMALL)
            result = run_isolated(FS02, config, args=[target], abi="component")
        finally:
            shutil.rmtree(target, ignore_errors=True)
        assert result["status"] is ExecutionStatus.ERROR
        assert "I/O budget exceeded" in result["stderr"]
        assert result["io_budget_exceeded"] is True
        assert result["io_bytes_written"] == PAYLOAD_BYTES

    def test_a_breach_does_not_take_the_host_process_down(self):
        """Containment: the breach ends the RUN, not the process."""
        target = _grant()
        sandbox = ComponentSandbox(
            WASIConfig(allow_dirs=(target,), io_budget_bytes=1, **_SMALL)
        )
        try:
            assert sandbox.run(FS02, args=[target]).io_budget_exceeded is True
            # The same process still runs a budgeted component normally.
            ok = ComponentSandbox(
                WASIConfig(allow_dirs=(target,), io_budget_bytes=1024 * 1024, **_SMALL)
            )
            try:
                follow_up = ok.run(FS02, args=[target])
            finally:
                ok.cleanup()
            assert follow_up.status is ExecutionStatus.SUCCESS, follow_up.stderr[:200]
        finally:
            sandbox.cleanup()
            shutil.rmtree(target, ignore_errors=True)


class TestComponentByteBudgetPositiveControls:
    """A sufficient budget must leave the component run exactly as before."""

    def test_default_budget_leaves_a_normal_component_run_alone(self):
        target = _grant()
        sandbox = ComponentSandbox(WASIConfig(allow_dirs=(target,), **_SMALL))
        try:
            result = sandbox.run(FS02, args=[target])
            assert result.status is ExecutionStatus.SUCCESS, result.stderr[:200]
            assert result.io_budget_exceeded is False
            # The component path used to report None here for every run; the
            # ADR-002 receipt now carries the guest's byte count.
            assert result.io_bytes_written == PAYLOAD_BYTES
            with open(os.path.join(target, "out.txt")) as fh:
                assert fh.read() == PAYLOAD
        finally:
            sandbox.cleanup()
            shutil.rmtree(target, ignore_errors=True)

    def test_generous_explicit_budget_runs_clean(self):
        target = _grant()
        sandbox = ComponentSandbox(
            WASIConfig(allow_dirs=(target,), io_budget_bytes=1024 * 1024, **_SMALL)
        )
        try:
            result = sandbox.run(FS02, args=[target])
            assert result.status is ExecutionStatus.SUCCESS, result.stderr[:200]
            assert result.io_budget_exceeded is False
            assert result.io_bytes_written == PAYLOAD_BYTES
        finally:
            sandbox.cleanup()
            shutil.rmtree(target, ignore_errors=True)

    def test_none_disables_the_wall_on_the_component_path(self):
        """None means unlimited — and must report no measurement, not zero."""
        target = _grant()
        sandbox = ComponentSandbox(
            WASIConfig(allow_dirs=(target,), io_budget_bytes=None, **_SMALL)
        )
        try:
            result = sandbox.run(FS02, args=[target])
            assert result.status is ExecutionStatus.SUCCESS, result.stderr[:200]
            assert result.io_budget_exceeded is False
            assert result.io_bytes_written is None
        finally:
            sandbox.cleanup()
            shutil.rmtree(target, ignore_errors=True)

    def test_no_grant_means_no_writable_scope_and_no_breach(self):
        """Nothing is preopened: budget=1 cannot fire on a write that cannot
        happen. Guards against a watcher that trips on the module itself."""
        sandbox = ComponentSandbox(WASIConfig(io_budget_bytes=1, **_SMALL))
        try:
            result = sandbox.run(HELLO02)
            assert result.status is ExecutionStatus.SUCCESS, result.stderr[:200]
            assert result.io_budget_exceeded is False
        finally:
            sandbox.cleanup()

    def test_pre_existing_grant_content_is_not_charged_to_the_guest(self):
        """Baseline semantics: a caller-owned directory that already holds
        data must not breach a small budget by merely existing."""
        target = _grant()
        _write_file(target, "seed.bin", 64 * 1024)
        sandbox = ComponentSandbox(
            WASIConfig(allow_dirs=(target,), io_budget_bytes=1024, **_SMALL)
        )
        try:
            result = sandbox.run(FS02, args=[target])
            assert result.status is ExecutionStatus.SUCCESS, result.stderr[:200]
            assert result.io_budget_exceeded is False
            assert result.io_bytes_written == PAYLOAD_BYTES
        finally:
            sandbox.cleanup()
            shutil.rmtree(target, ignore_errors=True)


# One 64 KiB write (not a flood): it begins and finishes well inside the 100 ms
# poll interval — exactly the blind spot the end-of-run sample closes. The
# iovec at offset 64 is {ptr=1024, len=NBR*65536} for the multi-write cases.
ONE_BIG_WRITE_WAT = """
(module
  (import "wasi_snapshot_preview1" "fd_write" (func $fd_write
    (param i32 i32 i32 i32) (result i32)))
  (import "wasi_snapshot_preview1" "path_open" (func $path_open
    (param i32 i32 i32 i32 i32 i64 i64 i32 i32) (result i32)))
  (import "wasi_snapshot_preview1" "proc_exit" (func $proc_exit (param i32)))
  (memory (export "memory") 4)
  (data (i32.const 8) "out.bin")
  (data (i32.const 64) "\\00\\04\\00\\00\\00\\00\\01\\00")
  (func (export "_start") (local $e i32) (local $i i32)
    i32.const 3 i32.const 0 i32.const 8 i32.const 7 i32.const 1
    i64.const 70 i64.const 70 i32.const 0 i32.const 100
    call $path_open
    local.set $e
    local.get $e
    if i32.const 2 call $proc_exit end
    (loop $l
      i32.const 100 i32.load
      i32.const 64 i32.const 1 i32.const 200
      call $fd_write drop
      local.get $i i32.const 1 i32.add local.set $i
      local.get $i i32.const NBR i32.lt_u
      br_if $l
    )
    i32.const 0
    call $proc_exit
  )
)
"""

BIG_WRITE_BYTES = 65536


def _p1_wasm(tmp_path, writes: int, chunk: int = BIG_WRITE_BYTES):
    """One write of ``chunk`` bytes, repeated ``writes`` times, then exit 0."""
    import struct

    vec = struct.pack("<II", 1024, chunk)
    wat = ONE_BIG_WRITE_WAT.replace(
        "\\00\\04\\00\\00\\00\\00\\01\\00",
        "".join(f"\\{byte:02x}" for byte in vec),
    ).replace("NBR", str(writes))
    wasm = tmp_path / f"p1_{writes}x{chunk}.wasm"
    wasm.write_bytes(wasmtime.wat2wasm(wat))
    return str(wasm)


def _sandbox_bytes(sandbox: WASISandbox) -> int:
    total = 0
    for root, _dirs, files in os.walk(sandbox._sandbox_dir):
        for name in files:
            total += os.path.getsize(os.path.join(root, name))
    return total


class TestPreview1EndOfRunSample:
    """The preview1 path measures the sandbox dir end-of-run too.

    Before the fix a guest that wrote over budget and then exited reported
    SUCCESS/exceeded=False; ``proc_exit`` raises ``wasmtime.ExitTrap``, which is
    an ``Exception`` but NOT a ``Trap``, so the run never reached the watcher's
    success path.
    """

    def test_sub_interval_overrun_is_a_breach_not_a_silent_success(self, tmp_path):
        """The measured 2026-10-16 vector, in-process: 64 KiB in ONE write,
        budget 1024 -> ERROR (was: SUCCESS, 64 KiB on disk, io_bytes None)."""
        wasm = _p1_wasm(tmp_path, 1)
        sandbox = WASISandbox(config=WASIConfig(io_budget_bytes=1024, **_SMALL))
        try:
            result = sandbox.run(wasm, trust="trusted")
            on_disk = _sandbox_bytes(sandbox)
        finally:
            sandbox.cleanup()
        assert result.status is ExecutionStatus.ERROR, result.status
        assert result.io_budget_exceeded is True
        assert "I/O budget exceeded" in result.stderr
        assert result.io_bytes_written == BIG_WRITE_BYTES
        # Detection, not prevention: the sub-interval bytes are already on disk.
        assert on_disk == BIG_WRITE_BYTES

    def test_repeated_sub_interval_writes_are_a_breach(self, tmp_path):
        """A loop of the same write must not slip under the sample either.

        The pin is the attribution, not a write count: the poller may land
        inside the loop (100 ms interval) and interrupt it, so how many of the
        20 writes complete is load-dependent — measured on 3.13 in a loaded
        suite run: 19 chunks landed but were reported as 19, never as 20 or as
        a stale poller value. What the product promises is that the number it
        reports IS the end-of-run size of the sandbox dir once the guest has
        stopped, and that any overrun is a breach whatever ended the run.
        """
        wasm = _p1_wasm(tmp_path, 20)
        sandbox = WASISandbox(config=WASIConfig(io_budget_bytes=1024, **_SMALL))
        try:
            result = sandbox.run(wasm, trust="trusted")
            on_disk = _sandbox_bytes(sandbox)
        finally:
            sandbox.cleanup()
        assert result.status is ExecutionStatus.ERROR, result.status
        assert result.io_budget_exceeded is True
        assert "I/O budget exceeded" in result.stderr
        # attribution: reported == what is actually on disk, not a poller guess
        assert result.io_bytes_written == on_disk
        # a breach means bytes above the budget, and at least one whole write
        assert result.io_bytes_written > 1024
        assert result.io_bytes_written >= BIG_WRITE_BYTES

    def test_sub_interval_overrun_is_a_breach_on_the_worker_path(self, tmp_path):
        """The same vector through the disposable worker."""
        wasm = _p1_wasm(tmp_path, 1)
        result = run_isolated(
            wasm, WASIConfig(io_budget_bytes=1024, **_SMALL), abi="preview1"
        )
        assert result["status"] is ExecutionStatus.ERROR, result["status"]
        assert result["io_budget_exceeded"] is True
        assert "I/O budget exceeded" in result["stderr"]
        assert result["io_bytes_written"] == BIG_WRITE_BYTES

    def test_default_budget_leaves_a_small_write_a_success(self, tmp_path):
        """Negative control, preview1: with the default budget a 19-byte write
        of the same shape stays SUCCESS and unflagged."""
        wasm = _p1_wasm(tmp_path, 1, chunk=19)
        sandbox = WASISandbox(config=WASIConfig(**_SMALL))
        try:
            result = sandbox.run(wasm, trust="trusted")
        finally:
            sandbox.cleanup()
        assert result.status is ExecutionStatus.SUCCESS, result.stderr[:200]
        assert result.io_budget_exceeded is False

    def test_a_write_exactly_at_the_budget_is_not_a_breach(self, tmp_path):
        """Boundary control: "over the wall" is strictly ``>``; a write landing
        exactly on io_budget_bytes must not be escalated by the sample."""
        wasm = _p1_wasm(tmp_path, 1)
        sandbox = WASISandbox(
            config=WASIConfig(io_budget_bytes=BIG_WRITE_BYTES, **_SMALL)
        )
        try:
            result = sandbox.run(wasm, trust="trusted")
        finally:
            sandbox.cleanup()
        assert result.status is ExecutionStatus.SUCCESS, result.stderr[:200]
        assert result.io_budget_exceeded is False

    def test_a_preview1_breach_does_not_take_the_host_process_down(self, tmp_path):
        """Containment: the breach ends the RUN; the same host process still
        serves a budgeted preview1 run afterwards."""
        wasm = _p1_wasm(tmp_path, 1)
        sandbox = WASISandbox(config=WASIConfig(io_budget_bytes=1024, **_SMALL))
        try:
            assert sandbox.run(wasm, trust="trusted").io_budget_exceeded is True
        finally:
            sandbox.cleanup()
        ok = WASISandbox(config=WASIConfig(io_budget_bytes=1024 * 1024, **_SMALL))
        try:
            follow_up = ok.run(wasm, trust="trusted")
        finally:
            ok.cleanup()
        assert follow_up.status is ExecutionStatus.SUCCESS, follow_up.stderr[:200]

    def test_budget_none_stays_a_hard_off_switch_on_preview1(self, tmp_path):
        """``None`` = unlimited: no watcher, no end-of-run sample, no walk."""
        wasm = _p1_wasm(tmp_path, 1)
        sandbox = WASISandbox(config=WASIConfig(io_budget_bytes=None, **_SMALL))
        try:
            result = sandbox.run(wasm, trust="trusted")
        finally:
            sandbox.cleanup()
        assert result.status is ExecutionStatus.SUCCESS, result.stderr[:200]
        assert result.io_budget_exceeded is False


class TestPreview1ScopeUnchanged:
    """The preview1 path keeps its own behaviour and its own scope."""

    def test_preview1_preopen_write_is_still_out_of_scope(self, tmp_path):
        """Scope control for the UNCHANGED path: ADR-002 v1 covers /sandbox,
        so 4000 bytes written into a PREOPEN are not an io_budget breach on
        preview1. The component fix must not have widened this path."""
        wasm = tmp_path / "preopen_write.wasm"
        wasm.write_bytes(wasmtime.wat2wasm(BOUNDED_WRITE_WAT))
        target = _grant()
        try:
            sandbox = WASISandbox(
                config=WASIConfig(allow_dirs=(target,), io_budget_bytes=1, **_SMALL)
            )
            try:
                result = sandbox.run(str(wasm))
            finally:
                sandbox.cleanup()
            assert result.status is ExecutionStatus.SUCCESS, result.stderr[:200]
            assert result.io_budget_exceeded is False
            written = os.path.getsize(os.path.join(target, "out.bin"))
            assert written == PREOPEN_WRITE_BYTES
        finally:
            shutil.rmtree(target, ignore_errors=True)


class TestWatcherMechanics:
    """The shared poller: delta accounting, dedup, interrupt, lifecycle."""

    def test_counts_only_the_guest_delta(self):
        root = _grant()
        try:
            _write_file(root, "seed.bin", 4096)
            watcher = _GuestWriteBudget(_Epoch(), (root,), 10**9, threading.Event())
            assert watcher._baseline == 4096
            _write_file(root, "guest.bin", 128)
            assert watcher.sample() == 128
        finally:
            shutil.rmtree(root, ignore_errors=True)

    def test_deleted_files_never_report_negative_writes(self):
        root = _grant()
        try:
            _write_file(root, "seed.bin", 4096)
            watcher = _GuestWriteBudget(_Epoch(), (root,), 10**9, threading.Event())
            os.remove(os.path.join(root, "seed.bin"))
            assert watcher.sample() == 0
        finally:
            shutil.rmtree(root, ignore_errors=True)

    def test_nested_grant_is_not_double_counted(self):
        """A grant carrying a dir and its child must not count bytes twice —
        that would breach the wall at half its declared value."""
        root = _grant()
        try:
            nested = os.path.join(root, "sub")
            os.makedirs(nested)
            _write_file(nested, "f.bin", 1024)
            assert _drop_nested_dirs((root, nested)) == (root,)
            watcher = _GuestWriteBudget(
                _Epoch(), (root, nested), 10**9, threading.Event()
            )
            assert watcher._baseline == 1024
        finally:
            shutil.rmtree(root, ignore_errors=True)

    def test_sustained_overrun_raises_the_epoch(self):
        """The interrupt is the preview1 one: engine.increment_epoch()."""
        root = _grant()
        stop = threading.Event()
        try:
            _write_file(root, "seed.bin", 4096)
            epoch = _Epoch()
            watcher = _GuestWriteBudget(epoch, (root,), 1024, stop)
            watcher.start()
            _write_file(root, "guest.bin", 2048)
            deadline = time.monotonic() + 10
            while epoch.calls == 0 and time.monotonic() < deadline:
                time.sleep(0.02)
            assert epoch.calls == 1, "watcher never interrupted the guest"
            assert watcher.exceeded is True
        finally:
            stop.set()
            shutil.rmtree(root, ignore_errors=True)

    def test_finish_joins_the_poller_and_reports_the_end_delta(self):
        """Resource contract: no poller thread survives the run, and the
        count published at the end is the end-of-run truth."""
        root = _grant()
        try:
            watcher = _GuestWriteBudget(_Epoch(), (root,), 10**9, threading.Event())
            watcher.start()
            assert watcher._thread is not None
            _write_file(root, "guest.bin", 256)
            assert watcher.finish() == 256
            assert not watcher._thread.is_alive(), "poller thread leaked"
        finally:
            shutil.rmtree(root, ignore_errors=True)

    def test_no_writable_dir_spawns_no_thread(self):
        watcher = _GuestWriteBudget(_Epoch(), (), 10**9, threading.Event())
        watcher.start()
        assert watcher._thread is None
        assert watcher.finish() == 0


# Burst size for the component hard-exit case: 64x the budget used in the
# probe vectors that accompany it.
BURST_BYTES = 65536


def _dir_bytes(root: str) -> int:
    """Sum of all file sizes under ``root`` (the watcher's own measure)."""
    total = 0
    for base, _dirs, files in os.walk(root):
        for name in files:
            total += os.path.getsize(os.path.join(base, name))
    return total


class TestComponentExitTrapBudgetRoute:
    """The byte wall also gates the exit-status-0 trap route.

    ``wasi:cli/exit`` makes the guest's ``run`` call raise
    ``"Exited with i32 exit status 0"``. That trap branch returned
    ``ExecutionStatus.SUCCESS`` with ``io_bytes_written=<measured>`` but WITHOUT
    the ``written > limit`` comparison — so a single over-budget burst followed
    by ``exit(0)`` was attested as ``success`` /
    ``io_budget_exceeded=False`` (65536 B at budget 1024 = 64x, bytes on disk),
    in-process and through the worker. ``exitwrite02.wasm`` reproduces that
    route: one ``std::fs::write`` of ``<argv[2]>`` bytes, then
    ``std::process::exit(0)`` (tests/fixtures/README.md).
    """

    def test_exit0_over_budget_write_is_a_breach_not_a_silent_success(self):
        """The measured burst-write vector, in-process: 65536 B, budget 1024."""
        target = _grant()
        sandbox = ComponentSandbox(
            WASIConfig(allow_dirs=(target,), io_budget_bytes=1024, **_SMALL)
        )
        try:
            result = sandbox.run(EXITWRITE02, args=[target, str(BURST_BYTES)])
            on_disk = _dir_bytes(target)
        finally:
            sandbox.cleanup()
            shutil.rmtree(target, ignore_errors=True)
        assert result.status is ExecutionStatus.ERROR, (
            "an over-budget burst that exits through wasi:cli/exit(0) must not "
            f"report success: {result.status}"
        )
        assert result.io_budget_exceeded is True
        assert "I/O budget exceeded" in result.stderr
        assert result.io_bytes_written == BURST_BYTES
        # Detection, not prevention: the sub-interval burst is already on disk
        # when the end-of-run sample judges it.
        assert on_disk == BURST_BYTES

    def test_exit0_small_over_budget_write_is_a_breach(self):
        """19 B at budget 1 — the ``exit02``-shaped vector. Same byte count and
        same grant as the ``fs02`` regular-route control below, so the only
        difference between ERROR and (before the fix) SUCCESS is the exit path.
        """
        target = _grant()
        sandbox = ComponentSandbox(
            WASIConfig(allow_dirs=(target,), io_budget_bytes=1, **_SMALL)
        )
        try:
            result = sandbox.run(EXITWRITE02, args=[target, str(PAYLOAD_BYTES)])
        finally:
            sandbox.cleanup()
            shutil.rmtree(target, ignore_errors=True)
        assert result.status is ExecutionStatus.ERROR, result.status
        assert result.io_budget_exceeded is True
        assert "I/O budget exceeded" in result.stderr
        assert result.io_bytes_written == PAYLOAD_BYTES

    def test_exit0_over_budget_write_is_a_breach_on_the_worker_path(self):
        """The same vector through the disposable worker (the path ADR-015
        forces for untrusted input)."""
        target = _grant()
        try:
            config = WASIConfig(allow_dirs=(target,), io_budget_bytes=1024, **_SMALL)
            result = run_isolated(
                EXITWRITE02, config, args=[target, str(BURST_BYTES)], abi="component"
            )
        finally:
            shutil.rmtree(target, ignore_errors=True)
        assert result["status"] is ExecutionStatus.ERROR, result["status"]
        assert result["io_budget_exceeded"] is True
        assert "I/O budget exceeded" in result["stderr"]
        assert result["io_bytes_written"] == BURST_BYTES

    def test_default_budget_leaves_the_exit0_route_a_success(self):
        """Positive control: the default budget (64 MiB) must leave the
        hard-exit route exactly as before — success, unflagged, byte count
        reported."""
        target = _grant()
        sandbox = ComponentSandbox(WASIConfig(allow_dirs=(target,), **_SMALL))
        try:
            result = sandbox.run(EXITWRITE02, args=[target, str(BURST_BYTES)])
        finally:
            sandbox.cleanup()
            shutil.rmtree(target, ignore_errors=True)
        assert result.status is ExecutionStatus.SUCCESS, result.stderr[:200]
        assert result.io_budget_exceeded is False
        assert result.io_bytes_written == BURST_BYTES

    def test_a_write_exactly_at_the_budget_on_the_exit0_route_is_not_a_breach(self):
        """Boundary control: "over the wall" is strictly ``>`` — a burst that
        lands exactly on ``io_budget_bytes`` must not be escalated by the
        end-of-run verdict of the exit-0 route either."""
        target = _grant()
        sandbox = ComponentSandbox(
            WASIConfig(allow_dirs=(target,), io_budget_bytes=BURST_BYTES, **_SMALL)
        )
        try:
            result = sandbox.run(EXITWRITE02, args=[target, str(BURST_BYTES)])
        finally:
            sandbox.cleanup()
            shutil.rmtree(target, ignore_errors=True)
        assert result.status is ExecutionStatus.SUCCESS, result.stderr[:200]
        assert result.io_budget_exceeded is False
        assert result.io_bytes_written == BURST_BYTES

    def test_an_exit0_breach_does_not_take_the_host_process_down(self):
        """Containment: the breach ends the RUN, not the process — the same host
        process still serves a clean budgeted run afterwards."""
        target = _grant()
        sandbox = ComponentSandbox(
            WASIConfig(allow_dirs=(target,), io_budget_bytes=1024, **_SMALL)
        )
        try:
            assert (
                sandbox.run(
                    EXITWRITE02, args=[target, str(BURST_BYTES)]
                ).io_budget_exceeded
                is True
            )
        finally:
            sandbox.cleanup()
            shutil.rmtree(target, ignore_errors=True)
        follow_dir = _grant()
        ok = ComponentSandbox(
            WASIConfig(allow_dirs=(follow_dir,), io_budget_bytes=1024 * 1024, **_SMALL)
        )
        try:
            follow_up = ok.run(EXITWRITE02, args=[follow_dir, str(BURST_BYTES)])
        finally:
            ok.cleanup()
            shutil.rmtree(follow_dir, ignore_errors=True)
        assert follow_up.status is ExecutionStatus.SUCCESS, follow_up.stderr[:200]
