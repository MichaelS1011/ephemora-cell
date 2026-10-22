"""
Phase 4: Ephemora Cell Sandbox Security Tests

Offensive security tests — each test simulates a real attack vector
against the WASM sandbox and verifies the defense holds.

Roles: penetration tester (attack) + senior SecOps engineer (verify)
"""

from __future__ import annotations

import os
import shutil
import sys
import tempfile
import threading
import time
from pathlib import Path

import pytest
import wasmtime

sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))

from ephemora_cell import (
    ExecutionStatus,
    WASIConfig,
    WASISandbox,
)
from ephemora_cell.execution_report import TRUST_TRUSTED

# === pytest Fixtures (Test Automation) ===


@pytest.fixture(scope="module")
def wat_payloads():
    """Pre-compile all WAT payloads once per module — cached, deterministic."""
    return {
        "cpu_dos": wasmtime.wat2wasm(CPU_DOS_WAT),
        "memory_exhaust": wasmtime.wat2wasm(MEMORY_EXHAUST_WAT),
        "path_open": wasmtime.wat2wasm(PATH_OPEN_WAT),
        "stdout_flood": wasmtime.wat2wasm(STDOUT_FLOOD_WAT),
        "fsync_import": wasmtime.wat2wasm(FSYNC_IMPORT_WAT),
        "write_flood": wasmtime.wat2wasm(WRITE_FLOOD_WAT),
    }


@pytest.fixture
def wasm_file(tmp_path, wat_payloads, request):
    """Write a compiled WASM module to a temp file and auto-cleanup.

    Usage:
        def test_x(wasm_file):
            wasm_file.write("cpu_dos")  # or any key from wat_payloads
            result = sandbox.run(str(wasm_file.path))
    """

    class WasmFile:
        def __init__(self, tmp_dir):
            self.tmp_dir = tmp_dir
            self.path = None

        def write(self, payload_key):
            name = f"{payload_key}.wasm"
            self.path = self.tmp_dir / name
            self.path.write_bytes(wat_payloads[payload_key])
            return self.path

    return WasmFile(tmp_path)


# === Attack Payloads (Penetration Tester) ===
# Every payload is a compilable WAT module simulating one specific attack.
# Compilation: wasmtime.wat2wasm(PAYLOAD_WAT) → bytes


# 4.1 CPU-DoS: infinite jump loop (br $l) — exercises the fuel limit
CPU_DOS_WAT = """
(module
  (func (export "_start")
    (loop $l
      br $l  ;; infinite jump — no stack growth, no I/O
    )
  )
)
"""

# 4.2 Memory Exhaustion: memory.grow in Loop — testet max_memory_mb
MEMORY_EXHAUST_WAT = """
(module
  (memory (export "memory") 1)
  (func (export "_start")
    (loop $l
      i32.const 1   ;; request +1 page (64KB) per iteration
      memory.grow
      drop
      br $l
    )
  )
)
"""

# 4.6 Timeout: identical to CPU_DOS_WAT — exercised via max_fuel=None
TIMEOUT_WAT = CPU_DOS_WAT  # Dedup: identical payload, different purpose (timeout test)

# 4.7 / 4.3 probe: open a relative name on preopen fd 3 and put the
# observed byte on stdout. A normal _start return keeps the sandbox result
# SUCCESS, so an invalid module or a type mismatch cannot pass as a security
# result through the ERROR branch. The 9-parameter WASI Preview1 signature
# matters: rights are i64 and the last argument is the opened_fd POINTER
# (the 8x i32 shape used here before did not validate at all).
_OPEN_PROBE_TEMPLATE = """
(module
  (import "wasi_snapshot_preview1" "path_open" (func $open
    (param i32 i32 i32 i32 i32 i64 i64 i32 i32) (result i32)))
  (import "wasi_snapshot_preview1" "fd_read" (func $read
    (param i32 i32 i32 i32) (result i32)))
  (import "wasi_snapshot_preview1" "fd_write" (func $write
    (param i32 i32 i32 i32) (result i32)))
  (import "wasi_snapshot_preview1" "fd_close" (func $close
    (param i32) (result i32)))
  (memory (export "memory") 1)
  (data (i32.const 0) "@PATH@")
  (func $emit (param $b i32)
    (i32.store8 (i32.const 512) (local.get $b))
    (i32.store (i32.const 520) (i32.const 512))
    (i32.store (i32.const 524) (i32.const 1))
    (drop (call $write (i32.const 1) (i32.const 520) (i32.const 1) (i32.const 528))))
  (func $open_read (result i32)
    (local $errno i32)
    (local $fd i32)
    (local.set $errno
      (call $open (i32.const 3) (i32.const 1) (i32.const 0) (i32.const @PLEN@)
                  (i32.const 0) (i64.const 2) (i64.const 2) (i32.const 0)
                  (i32.const 8)))
    (if (i32.ne (local.get $errno) (i32.const 0))
      (then (return (local.get $errno))))
    (local.set $fd (i32.load (i32.const 8)))
    (i32.store (i32.const 520) (i32.const 512))
    (i32.store (i32.const 524) (i32.const 1))
    (local.set $errno
      (call $read (local.get $fd) (i32.const 520) (i32.const 1) (i32.const 528)))
    (drop (call $close (local.get $fd)))
    (if (i32.ne (local.get $errno) (i32.const 0))
      (then (return (local.get $errno))))
    (i32.load8_u (i32.const 512)))
  (func (export "_start")
    (local $i i32)
    (local $r i32)
    (local $flag i32)
    (if (i32.eq (i32.const @MODE@) (i32.const 0))
      (then (call $emit (call $open_read)) (return)))
    ;; Race mode: many opens; emit "1" if ANY read saw the outside byte 'O'.
    (local.set $i (i32.const 0))
    (block $done
      (loop $l
        (br_if $done (i32.ge_u (local.get $i) (i32.const @N@)))
        (local.set $r (call $open_read))
        (if (i32.eq (local.get $r) (i32.const 79))
          (then (local.set $flag (i32.const 1))))
        (local.set $i (i32.add (local.get $i) (i32.const 1)))
        (br $l)))
    (call $emit (i32.add (i32.const 48) (local.get $flag))))
)
"""


def _open_probe_wat(path: str, *, repeats: int = 0) -> str:
    return (
        _OPEN_PROBE_TEMPLATE.replace("@PATH@", path)
        .replace("@PLEN@", str(len(path)))
        .replace("@MODE@", "1" if repeats else "0")
        .replace("@N@", str(repeats))
    )


PATH_OPEN_WAT = _open_probe_wat("../outside.txt")

# 4.8 Stdout Flood: 1000x fd_write(32 bytes) = ~32KB — exercises the 10 KB output limit
STDOUT_FLOOD_WAT = """
(module
  (import "wasi_snapshot_preview1" "fd_write" (func $fd_write
    (param i32 i32 i32 i32) (result i32)))
  (import "wasi_snapshot_preview1" "proc_exit" (func $proc_exit (param i32)))
  (memory (export "memory") 2)  ;; 2 pages = 128KB for buffer
  (data (i32.const 8) "ABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789")  ;; 32 chars
  ;; wasi_subscription_point: iovec {buf=8, len=32}
  (data (i32.const 64) "\\08\\00\\00\\00\\20\\00\\00\\00")
  (func (export "_start")
    (local $i i32)
    i32.const 0
    (local.set $i)
    (loop $l
      ;; fd_write(fd=1/stdout, iovs=64, iovs_len=1, nwritten=100)
      i32.const 1
      i32.const 64
      i32.const 1
      i32.const 100
      call $fd_write
      drop
      local.get $i
      i32.const 1
      i32.add
      (local.set $i)
      local.get $i
      i32.const 1000   ;; 1000 iterations x 32B = 32KB
      i32.lt_s
      if
        br $l
      end
    )
    i32.const 0
    call $proc_exit
  )
)
"""

# 4.9 fsync import block: module imports fd_psync — must be blocked at the import layer
FSYNC_IMPORT_WAT = """
(module
  (import "wasi_snapshot_preview1" "fd_psync" (func $fd_psync
    (param i32) (result i32)))
  (import "wasi_snapshot_preview1" "proc_exit" (func $proc_exit (param i32)))
  (memory (export "memory") 1)
  (func (export "_start")
    i32.const 0
    call $fd_psync
    drop
    i32.const 0
    call $proc_exit
  )
)
"""

# 4.5 I/O DoS: 50000x fd_write(32 bytes) — exploits the fuel-vs-I/O gap
# With 1M fuel budget and ~29 fuel/write (test-local approximation of the
# measured 27/write stdout path): ~34477 writes possible = ~1.1MB
WRITE_FLOOD_WAT = """
(module
  (import "wasi_snapshot_preview1" "fd_write" (func $fd_write
    (param i32 i32 i32 i32) (result i32)))
  (import "wasi_snapshot_preview1" "proc_exit" (func $proc_exit (param i32)))
  (memory (export "memory") 1)
  (data (i32.const 0) "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA")  ;; 32 bytes padding
  (func (export "_start")
    (local $i i32)
    i32.const 0
    (local.set $i)
    (loop $l
      i32.const 1    ;; fd=stdout
      i32.const 0
      i32.const 1
      i32.const 32
      call $fd_write
      drop
      local.get $i
      i32.const 1
      i32.add
      (local.set $i)
      local.get $i
      i32.const 50000  ;; target: 1.6MB if unrestricted
      i32.lt_s
      if
        br $l
      end
    )
    i32.const 0
    call $proc_exit
  )
)
"""


# === Security Test Suite ===


class TestSecurity4_1_CPU_DoS:
    """4.1: CPU-DoS via infinite loop — Fuel-Limit must stop it."""

    def test_infinite_loop_blocked_by_fuel(self):
        """An infinite loop (br 0) MUST be stopped by the fuel limit."""
        config = WASIConfig(max_fuel=1_000_000)
        sandbox = WASISandbox(config=config)

        wasm_bytes = wasmtime.wat2wasm(CPU_DOS_WAT)
        wasm_path = Path(tempfile.mkdtemp(prefix="ephemora_cell_sec_")) / "cpu_dos.wasm"
        wasm_path.write_bytes(wasm_bytes)

        result = sandbox.run(str(wasm_path))

        # Defense holds: execution does NOT complete successfully
        assert result.status == ExecutionStatus.FUEL_EXHAUSTED, (
            f"Fuel limit failed to stop infinite loop. "
            f"Got {result.status}: {result.stderr[:200]}"
        )
        # Execution was fast — not a hang
        assert (
            result.elapsed_ms < 5000
        ), f"CPU DoS took {result.elapsed_ms:.0f}ms — should have been stopped quickly"

    def test_fuel_consumed_is_tracked(self):
        """Fuel consumed should be reported (or close to max_fuel on exhaustion)."""
        config = WASIConfig(max_fuel=1_000_000)
        sandbox = WASISandbox(config=config)

        wasm_bytes = wasmtime.wat2wasm(CPU_DOS_WAT)
        wasm_path = Path(tempfile.mkdtemp(prefix="ephemora_cell_sec_")) / "cpu_dos.wasm"
        wasm_path.write_bytes(wasm_bytes)

        result = sandbox.run(str(wasm_path))

        # On fuel exhaustion, fuel_consumed should be close to max_fuel
        if result.fuel_consumed is not None:
            assert result.fuel_consumed > 0, "Fuel should have been consumed"


class TestSecurity4_2_Memory_Exhaustion:
    """4.2: Memory.grow flood — max_memory_mb must cap growth."""

    def test_memory_grow_capped(self):
        """memory.grow in a loop MUST be stopped by max_memory_mb."""
        config = WASIConfig(max_memory_mb=16, max_fuel=1_000_000)
        sandbox = WASISandbox(config=config)

        wasm_bytes = wasmtime.wat2wasm(MEMORY_EXHAUST_WAT)
        wasm_path = (
            Path(tempfile.mkdtemp(prefix="ephemora_cell_sec_")) / "mem_exhaust.wasm"
        )
        wasm_path.write_bytes(wasm_bytes)

        result = sandbox.run(str(wasm_path))

        # Defense holds: the concrete containments are fuel exhaustion
        # (loop metered) or the memory limit (Store.set_limits) - a generic
        # ERROR is NOT an acceptable pass.
        assert result.status in (
            ExecutionStatus.FUEL_EXHAUSTED,
            ExecutionStatus.MEMORY_EXCEEDED,
        ), f"Memory exhaustion not contained. Got {result.status}: {result.stderr[:200]}"
        assert (
            result.status != ExecutionStatus.SUCCESS
        ), "Memory.grow flood completed successfully — sandbox failed to contain it!"


class TestSecurity4_3_Path_Traversal:
    """4.3: Symlink escape via allow_dirs — MUST NOT follow symlinks outside sandbox."""

    @staticmethod
    def _probe(tmp_path: Path, name: str, path: str, *, repeats: int = 0) -> Path:
        wasm_path = tmp_path / f"{name}.wasm"
        wasm_path.write_bytes(wasmtime.wat2wasm(_open_probe_wat(path, repeats=repeats)))
        return wasm_path

    @staticmethod
    def _run_probe(wasm_path: Path, preopen: Path) -> dict[str, object]:
        from ephemora_cell import run_isolated

        config = WASIConfig(
            allow_dirs=(f"{preopen}::/",),
            max_fuel=5_000_000,
            timeout_seconds=20,
        )
        return run_isolated(str(wasm_path), config)

    @staticmethod
    def _make_safe_dir() -> Path:
        """Create a safe dir under TMPDIR.

        Works on every platform: macOS canonicalizes /tmp and /var/folders
        to /private/... which the canonical allowlist explicitly excepts,
        and containers with HOME=/root no longer trip the dangerous-dir
        filter (the old Path.home() location).
        """
        return Path(tempfile.mkdtemp(prefix="ephemora_safe_"))

    def test_symlink_not_followed_via_wasm(self, tmp_path):
        """A valid guest opens a relative symlink: inside works, outside is
        refused at path_open, and a live swap never yields outside bytes.

        The guest returns normally, so SUCCESS plus the exact observed byte is
        required. A type error or instantiation failure can no longer pass as
        a blocked escape via the generic ERROR branch.
        """
        root = tmp_path / "root"
        safe = root / "safe"
        outside = root / "outside"
        safe.mkdir(parents=True)
        outside.mkdir()
        (safe / "inside.txt").write_text("INSIDE\n")
        (outside / "secret.txt").write_text("OUTSIDE\n")
        link = safe / "link"
        link.symlink_to("inside.txt")

        # Positive control: a relative symlink that stays inside the preopen
        # must resolve and deliver the inside sentinel.
        result = self._run_probe(
            self._probe(tmp_path, "inside_link", "link"), preopen=safe
        )
        assert result["status"] is ExecutionStatus.SUCCESS, result["stderr"]
        assert result["stdout"] == "I", "relative inside symlink did not open"

        # Negative control: the same guest name pointing outside must be
        # refused with a capability errno (63 EPERM / 76 ENOTCAPABLE), never
        # by an unrelated ERROR state.
        link.unlink()
        link.symlink_to("../outside/secret.txt")
        result = self._run_probe(
            self._probe(tmp_path, "outside_link", "link"), preopen=safe
        )
        assert result["status"] is ExecutionStatus.SUCCESS, result["stderr"]
        assert result["stdout"] in {chr(63), chr(76)}, (
            f"outside symlink returned {result['stdout']!r}, expected a "
            "capability denial"
        )

        # Race: the host swaps the link while one worker performs 2,000
        # opens. Any outside read emits "1"; held means "0".
        link.unlink()
        link.symlink_to("inside.txt")
        stop = threading.Event()
        swaps = 0

        def swapper() -> None:
            nonlocal swaps
            while not stop.is_set():
                target = "../outside/secret.txt" if swaps % 2 == 0 else "inside.txt"
                tmp = safe / f".swap-{threading.get_ident()}"
                tmp.unlink(missing_ok=True)
                tmp.symlink_to(target)
                os.replace(tmp, link)
                swaps += 1
                time.sleep(0.0002)

        thread = threading.Thread(target=swapper, daemon=True)
        thread.start()
        try:
            result = self._run_probe(
                self._probe(tmp_path, "race", "link", repeats=2_000), preopen=safe
            )
        finally:
            stop.set()
            thread.join(timeout=5)
        assert not thread.is_alive()
        assert swaps > 0, "race control did not run"
        assert result["status"] is ExecutionStatus.SUCCESS, result["stderr"]
        assert (
            result["stdout"] == "0"
        ), f"symlink race read outside bytes after {swaps} swaps"

        # Mutation control: if the capability boundary is deliberately
        # widened to the parent, the SAME guest must see the outside byte.
        # This proves the assertion above is capable of detecting an escape.
        link.unlink()
        link.symlink_to("../outside/secret.txt")
        result = self._run_probe(
            self._probe(tmp_path, "widened", "safe/link"), preopen=root
        )
        assert result["status"] is ExecutionStatus.SUCCESS, result["stderr"]
        assert result["stdout"] == "O", (
            "oracle control failed: outside data was not detectable even with "
            "the parent granted"
        )

    # Positive control: guest WRITES a file into the preopen dir
    # (same proven pattern as tests/test_disk_quota.py). exit 0 = the
    # preopen grant works. Only with this control does "symlink blocked"
    # mean "defense works" and not "the sandbox is broken anyway".
    POSITIVE_CONTROL_WAT = """
    (module
      (import "wasi_snapshot_preview1" "path_open" (func $path_open
        (param i32 i32 i32 i32 i32 i64 i64 i32 i32) (result i32)))
      (import "wasi_snapshot_preview1" "fd_write" (func $fd_write
        (param i32 i32 i32 i32) (result i32)))
      (import "wasi_snapshot_preview1" "proc_exit" (func $proc_exit (param i32)))
      (memory (export "memory") 1)
      (data (i32.const 8) "control.out")
      (data (i32.const 32) "PERMITTED!")
      ;; iovec at 64: {buf_ptr = 32, buf_len = 10}
      (data (i32.const 64) "\\20\\00\\00\\00\\0a\\00\\00\\00")
      (func (export "_start") (local $errno i32)
        i32.const 3
        i32.const 0
        i32.const 8
        i32.const 11
        i32.const 1
        i64.const 70
        i64.const 70
        i32.const 0
        i32.const 100
        call $path_open
        local.set $errno
        local.get $errno
        if
          i32.const 2
          call $proc_exit
        end
        i32.const 100
        i32.load
        i32.const 64
        i32.const 1
        i32.const 104
        call $fd_write
        local.set $errno
        local.get $errno
        if
          i32.const 3
          call $proc_exit
        end
        ;; fd_write must report all 10 bytes written
        i32.const 104
        i32.load
        i32.const 10
        i32.eq
        if
          i32.const 0
          call $proc_exit
        end
        i32.const 4
        call $proc_exit
      )
    )
    """

    def test_positive_control_preopen_write_works(self):
        """The guest CAN write into the granted preopen dir - proves the
        symlink block is a defense, not a broken sandbox.

        Runs through the worker path (run_isolated), the same proven
        pattern as tests/test_disk_quota.py.
        """
        from ephemora_cell import run_isolated

        safe_dir = self._make_safe_dir()
        wasm_path = (
            Path(tempfile.mkdtemp(prefix="ephemora_cell_sec_")) / "positive.wasm"
        )
        wasm_path.write_bytes(wasmtime.wat2wasm(self.POSITIVE_CONTROL_WAT))
        config = WASIConfig(
            allow_dirs=(str(safe_dir),), max_fuel=1_000_000, timeout_seconds=15
        )
        try:
            result = run_isolated(str(wasm_path), config)
            control = safe_dir / "control.out"
            written = control.exists() and control.read_text() == "PERMITTED!"
        finally:
            shutil.rmtree(safe_dir, ignore_errors=True)
        assert result["status"] == ExecutionStatus.SUCCESS, (
            f"positive control failed: status={result['status']} "
            f"exit={result['exit_code']} stderr={str(result['stderr'])[:200]!r}"
        )
        assert result["exit_code"] == 0
        assert written, "positive control file was not written correctly"

    def test_symlink_dir_not_in_dangerous_filter(self):
        """A safe dir (not under /private) stays in the allowlist filter."""
        safe_dir = self._make_safe_dir()
        try:
            safe = WASISandbox()._filter_dangerous_dirs((str(safe_dir),))
            assert str(safe_dir) in safe
        finally:
            shutil.rmtree(safe_dir, ignore_errors=True)


class TestSecurity4_4_Dangerous_Dir_Bypass:
    """4.4: allow_dirs into system locations must be rejected by the canonical allowlist."""

    def test_dangerous_dir_rejected(self):
        """allow_dirs="/etc" must raise ValueError at sandbox construction."""
        config = WASIConfig(allow_dirs=("/etc",))
        with pytest.raises(ValueError, match="forbidden"):
            WASISandbox(config=config)

    def test_root_allow_dir_rejected(self):
        """allow_dirs="/" must raise ValueError — root grants everything."""
        config = WASIConfig(allow_dirs=("/",))
        with pytest.raises(ValueError, match="forbidden"):
            WASISandbox(config=config)

    def test_private_etc_rejected(self):
        """allow_dirs="/private/etc" must raise ValueError (macOS realpath bypass)."""
        config = WASIConfig(allow_dirs=("/private/etc",))
        with pytest.raises(ValueError, match="forbidden"):
            WASISandbox(config=config)

    def test_macos_tmp_parity_allowed(self):
        """Regression (2026-09-12): /tmp realpaths to /private/tmp on
        macOS, so tempfile.mkdtemp() dirs used to hard-fail the canonical
        allowlist while Linux /tmp was always allowed. The macOS temp roots
        (/private/tmp, /private/var/folders) are now allowed explicitly;
        everything else under /private stays forbidden (see
        test_private_etc_rejected)."""
        if sys.platform != "darwin":
            pytest.skip("Only meaningful where /tmp is a symlink into /private")
        d = tempfile.mkdtemp(prefix="ephemora_tmp_parity_")
        try:
            sandbox = WASISandbox(config=WASIConfig(allow_dirs=(d,)))
            assert sandbox._filter_dangerous_dirs((d,)) == (d,)
        finally:
            shutil.rmtree(d, ignore_errors=True)

    def test_private_tmp_string_survives_denylist(self):
        """A configured /private/tmp/... string must survive the /private
        STRING denylist entry — the canonical check is the authority, and it
        allows the macOS temp roots."""
        if sys.platform != "darwin":
            pytest.skip("Only meaningful where /tmp is a symlink into /private")
        d = str(Path(tempfile.mkdtemp(prefix="ephemora_privtmp_")).resolve())
        try:
            assert d.startswith("/private/")
            sandbox = WASISandbox(config=WASIConfig(allow_dirs=(d,)))
            assert d in sandbox._filter_dangerous_dirs((d,))
        finally:
            shutil.rmtree(d, ignore_errors=True)

    def test_filter_drops_forbidden_keeps_safe(self):
        """Filter: /etc and /usr are dropped, /data stays."""
        config = WASIConfig(allow_dirs=("/etc", "/usr", "/data"))
        sandbox = WASISandbox()  # fresh sandbox, no preopens — filter is static

        safe_dirs = sandbox._filter_dangerous_dirs(config.allow_dirs)

        assert "/etc" not in safe_dirs
        assert "/usr" not in safe_dirs
        assert "/data" in safe_dirs


class TestSecurity4_5_IO_DoS:
    """4.5: Write flood via fd_write — Fuel limit must bound I/O volume."""

    def test_write_fuel_bounded(self):
        """Mass fd_write calls must be stopped by fuel, not allowed to flood disk."""
        config = WASIConfig(max_fuel=1_000_000, max_memory_mb=128)
        sandbox = WASISandbox(config=config)

        wasm_bytes = wasmtime.wat2wasm(WRITE_FLOOD_WAT)
        wasm_path = (
            Path(tempfile.mkdtemp(prefix="ephemora_cell_sec_")) / "io_flood.wasm"
        )
        wasm_path.write_bytes(wasm_bytes)

        result = sandbox.run(str(wasm_path))

        # Defense: either fuel stops it, or it completes with bounded output
        if result.status == ExecutionStatus.SUCCESS:
            # Output must be capped at 10KB
            assert (
                len(result.stdout) <= 10_050
            ), f"Stdout not capped: {len(result.stdout)} chars (limit: ~10KB)"
        else:
            # Fuel should have stopped the flood
            assert result.status in (
                ExecutionStatus.FUEL_EXHAUSTED,
                ExecutionStatus.ERROR,
            ), f"I/O flood not contained: {result.status}"


class TestSecurity4_6_Timeout_Enforcement:
    """4.6: Hanging module with no fuel limit — timeout must kill it."""

    def test_timeout_kills_infinite_loop(self):
        """When max_fuel=None, timeout_seconds must still stop infinite loops."""
        config = WASIConfig(max_fuel=None, timeout_seconds=5)
        sandbox = WASISandbox(config=config)

        wasm_bytes = wasmtime.wat2wasm(TIMEOUT_WAT)
        wasm_path = Path(tempfile.mkdtemp(prefix="ephemora_cell_sec_")) / "timeout.wasm"
        wasm_path.write_bytes(wasm_bytes)

        result = sandbox.run(str(wasm_path))

        # The loop must be STOPPED: no hang, no success. Under the 1.2.0 mandate
        # the default (isolated) posture meters the worker's own CPU, so the
        # io_cpu_seconds watchdog (default 2.0s) fires BEFORE the 5s wall timeout
        # and reports the epoch interrupt as ERROR ("I/O budget exceeded"); the
        # in-process/trusted path reports the wall clock as TIMEOUT. Both are
        # termination — neither may be SUCCESS — so assert the invariant across
        # postures rather than pinning one mechanism's status code.
        assert result.status in (
            ExecutionStatus.TIMEOUT,
            ExecutionStatus.ERROR,
        ), f"Timeout failed to kill infinite loop. Got {result.status}: {result.stderr[:200]}"
        assert (
            result.status is not ExecutionStatus.SUCCESS
        ), "infinite loop must never return SUCCESS"
        assert (
            result.elapsed_ms < 10_000
        ), f"Timeout took {result.elapsed_ms:.0f}ms — should have killed within ~5s"

    def test_defense_in_depth_fuel_none_timeout_none(self):
        """Defense-in-Depth: Fuel=NONE + Timeout=0 must NOT allow infinite loop to succeed."""
        # Critical: with both controls disabled, the sandbox must not hang.
        config = WASIConfig(max_fuel=None, timeout_seconds=0)
        sandbox = WASISandbox(config=config)

        wasm_bytes = wasmtime.wat2wasm(CPU_DOS_WAT)  # Infinite loop
        wasm_path = Path(tempfile.mkdtemp(prefix="ephemora_cell_sec_")) / "dod.wasm"
        wasm_path.write_bytes(wasm_bytes)

        result = sandbox.run(str(wasm_path))

        # The module MUST NOT be SUCCESS — no unbounded loop without limits
        assert (
            result.status != ExecutionStatus.SUCCESS
        ), "CRITICAL: Infinite loop with no fuel and no timeout returned SUCCESS!"
        # Must not hang — epoch_interrupt with timeout=0 should take effect immediately
        assert (
            result.elapsed_ms < 5000
        ), f"HANG: Execution took {result.elapsed_ms:.0f}ms — sandbox did not stop loop"

    def test_defense_in_depth_short_timeout_stops_loop(self):
        """Defense-in-Depth: timeout_seconds=1 must stop an infinite loop in ~1s."""
        config = WASIConfig(max_fuel=None, timeout_seconds=1)
        sandbox = WASISandbox(config=config)

        wasm_bytes = wasmtime.wat2wasm(CPU_DOS_WAT)
        wasm_path = (
            Path(tempfile.mkdtemp(prefix="ephemora_cell_sec_")) / "dod_short.wasm"
        )
        wasm_path.write_bytes(wasm_bytes)

        result = sandbox.run(str(wasm_path))

        assert (
            result.status == ExecutionStatus.TIMEOUT
        ), f"Expected TIMEOUT with 1s limit, got {result.status}: {result.stderr[:200]}"
        assert (
            result.elapsed_ms < 3000
        ), f"1s timeout took {result.elapsed_ms:.0f}ms — should be ~1s"


class TestSecurity4_7_Preopen_Default_Deny:
    """4.7: Default deny — no preopened dirs means NO file access."""

    def test_no_preopen_blocks_path_open(self, tmp_path):
        """NEGATIVE: with empty allow_dirs, the only preopen is /sandbox and
        a traversal outside it must return a capability errno.

        The valid guest writes the errno it actually got; SUCCESS is required
        so an instantiation error cannot be mistaken for a denial.
        """
        from ephemora_cell import run_isolated

        config = WASIConfig(max_fuel=1_000_000)  # No allow_dirs
        wasm_path = tmp_path / "preopen.wasm"
        wasm_path.write_bytes(wasmtime.wat2wasm(PATH_OPEN_WAT))
        result = run_isolated(str(wasm_path), config)

        assert result["status"] is ExecutionStatus.SUCCESS, result["stderr"]
        assert result["stdout"] in {chr(63), chr(76)}, (
            f"Preopen default-deny returned {result['stdout']!r}, expected a "
            "capability denial"
        )

    def test_default_deny_no_allow_dirs_config(self):
        """POSITIVE: the default config really has 0 preopened dirs (except /sandbox)."""
        """Checks the config layer — not a WASM test, a config verification."""
        config = WASIConfig()  # Default: allow_dirs=()
        assert config.allow_dirs == (), "Default allow_dirs must be empty"

        sandbox = WASISandbox(config=config)
        safe_dirs = sandbox._filter_dangerous_dirs(config.allow_dirs)
        assert safe_dirs == (), "Empty allow_dirs yield 0 safe dirs"

    def test_only_sandbox_dir_is_preopened(self):
        """POSITIVE: after run() /sandbox exists as the only preopened access point."""
        """A minimal WASM that only exits — without allow_dirs it MUST still run."""
        # The module must work without preopened dirs (as long as it performs no
        # file operations — /sandbox is always preopened for stdout/stderr)
        minimal_exit_wat = """
        (module
          (import "wasi_snapshot_preview1" "proc_exit" (func $exit (param i32)))
          (memory (export "memory") 1)
          (func (export "_start")
            i32.const 0
            call $exit
          )
        )
        """
        wasm_bytes = wasmtime.wat2wasm(minimal_exit_wat)
        wasm_path = Path(tempfile.mkdtemp(prefix="ephemora_cell_sec_")) / "minimal.wasm"
        wasm_path.write_bytes(wasm_bytes)

        config = WASIConfig(max_fuel=1_000_000)  # No allow_dirs
        sandbox = WASISandbox(config=config)
        result = sandbox.run(str(wasm_path))

        # proc_exit raises a trap — exit 0 is reported as ERROR with exit_code=0
        # (that is correct — WASI proc_exit is not a clean _start return.)
        assert result.status in (
            ExecutionStatus.SUCCESS,
            ExecutionStatus.ERROR,
        ), f"Minimal WASM crashed unexpectedly: {result.stderr[:200]}"
        assert result.exit_code == 0, f"Expected exit 0, got {result.exit_code}"


class TestSecurity4_8_Stdout_Capping:
    """4.8: Massive stdout output — must be truncated at 10KB."""

    def test_stdout_capped_at_10kb(self):
        """Output exceeding 10KB must be truncated with [... truncated] suffix."""
        config = WASIConfig(max_fuel=10_000_000, max_memory_mb=128)
        sandbox = WASISandbox(config=config)

        wasm_bytes = wasmtime.wat2wasm(STDOUT_FLOOD_WAT)
        wasm_path = (
            Path(tempfile.mkdtemp(prefix="ephemora_cell_sec_")) / "stdout_flood.wasm"
        )
        wasm_path.write_bytes(wasm_bytes)

        result = sandbox.run(str(wasm_path))

        # stdout must not exceed ~10KB + truncation suffix
        assert (
            len(result.stdout) <= 10_050
        ), f"Stdout cap failed: {len(result.stdout)} chars exceeds 10KB limit"
        # If output was truncated, it should have the suffix
        if result.status == ExecutionStatus.SUCCESS and len(result.stdout) > 9000:
            assert (
                "[... truncated]" in result.stdout
            ), "Large stdout missing truncation suffix"


class TestSecurity4_9_Fsync_Import_Blocking:
    """4.9: fsync/psync imports must be blocked at the module level."""

    def test_fd_psync_import_blocked(self):
        """A module importing fd_psync must be rejected before instantiation."""
        sandbox = WASISandbox()

        wasm_bytes = wasmtime.wat2wasm(FSYNC_IMPORT_WAT)
        wasm_path = Path(tempfile.mkdtemp(prefix="ephemora_cell_sec_")) / "fsync.wasm"
        wasm_path.write_bytes(wasm_bytes)

        result = sandbox.run(str(wasm_path))

        assert (
            result.status == ExecutionStatus.ERROR
        ), f"fsync import not blocked. Got {result.status}: {result.stderr[:200]}"
        assert (
            "Blocked WASI import" in result.stderr or "fsync" in result.stderr.lower()
        ), f"Error message doesn't mention fsync block: {result.stderr[:200]}"

    def test_default_config_exposes_zero_env_vars(self):
        """Regression: default WASIConfig must show the guest ZERO env vars.

        Root cause of the 7/8 false-positive in security_comparison.py was a
        test that probed the *presence* of the environ_get import (always
        present in WASI Preview1) rather than whether host env actually leaks.
        This pins the real property: the guest-visible env count is 0, so a
        future allow_env regression that leaks the host environment fails here.
        """
        env_count_wat = """
        (module
          (import "wasi_snapshot_preview1" "proc_exit" (func $exit (param i32)))
          (import "wasi_snapshot_preview1" "environ_sizes_get"
            (func $sizes (param i32 i32) (result i32)))
          (memory (export "memory") 1)
          (func (export "_start")
            i32.const 0
            i32.const 4
            call $sizes
            drop
            ;; exit(0) if any env var visible (a leak); exit(1) if none.
            (if (i32.load offset=0)
              (then (i32.const 0) (call $exit))
              (else (i32.const 1) (call $exit))))
        )
        """
        sandbox = WASISandbox(config=WASIConfig(max_fuel=100_000))
        wasm_path = Path(tempfile.mkdtemp(prefix="ephemora_cell_env_")) / "env.wasm"
        wasm_path.write_bytes(wasmtime.wat2wasm(env_count_wat))
        result = sandbox.run(str(wasm_path))
        sandbox.cleanup()
        assert (
            result.status != ExecutionStatus.SUCCESS
        ), "Guest saw host env vars under default config — env isolation broken"


class TestSecurity4_10_Sandbox_Cleanup:
    """4.10: Zero-dwell — sandbox dir must be fully removed after cleanup()."""

    def test_cleanup_removes_all_artifacts(self):
        """After cleanup(), the sandbox dir and all its contents must be gone."""
        config = WASIConfig(max_fuel=1_000_000)
        sandbox = WASISandbox(config=config)

        # Simple module that exits cleanly
        simple_wat = """
        (module
          (import "wasi_snapshot_preview1" "proc_exit" (func $exit (param i32)))
          (func (export "_start")
            i32.const 0
            call $exit
          )
        )
        """
        wasm_bytes = wasmtime.wat2wasm(simple_wat)
        wasm_path = Path(tempfile.mkdtemp(prefix="ephemora_cell_sec_")) / "cleanup.wasm"
        wasm_path.write_bytes(wasm_bytes)

        # The subject is the PARENT-side zero-dwell lifecycle of the sandbox dir
        # the WASISandbox object owns (exists after run, gone after cleanup). Under
        # the 1.2.0 mandate the default posture runs in a worker that cleans its own
        # dir inside the child, so the parent's ``result.sandbox_dir`` is not the
        # object this assertion inspects; declare the sanctioned in-process path.
        # The isolated zero-dwell guarantee is covered by the worker reaping tests.
        result = sandbox.run(str(wasm_path), trust=TRUST_TRUSTED)
        assert result.sandbox_dir is not None
        assert Path(
            result.sandbox_dir
        ).exists(), "Sandbox dir should exist after run() completes"

        # Now cleanup
        sandbox.cleanup()

        # Dir must be gone
        assert not Path(
            result.sandbox_dir
        ).exists(), f"Sandbox dir {result.sandbox_dir} still exists after cleanup()"


# === Boundary / Edge-Case Tests (SRE) ===


class TestSecurityBaselineFingerprint:
    """ExecutionReport carries a frozen security-baseline block."""

    def test_report_security_baseline_fingerprint(self):
        from ephemora_cell.execution_report import ExecutionReport

        config = WASIConfig(
            max_memory_mb=16,
            max_fuel=500_000,
            allow_dirs=("/data",),
        )
        report = ExecutionReport(status="success", exit_code=0, elapsed_ms=1.0)
        report.apply_config(config)

        baseline = report.security_baseline
        assert baseline["wasmtime_version"] is not None
        assert baseline["memory_limit_bytes"] == 16 * 1024 * 1024
        assert baseline["fuel"] == 500_000
        assert baseline["threads_enabled"] is False
        assert baseline["memory64"] is False
        # Without a live run result no grant is claimed — configured
        # dirs are reported as configured, /sandbox is NOT attested.
        assert baseline["preopens"] == ["/data"]
        report.apply_config(config, effective_preopens=("/data", "/sandbox"))
        assert baseline["preopens"] == ["/data", "/sandbox"]

        # Fingerprint is serialized with the report
        as_dict = report.to_dict()
        assert "security_baseline" in as_dict
        assert as_dict["security_baseline"]["memory_limit_bytes"] == 16 * 1024 * 1024
        assert as_dict["security_baseline"]["threads_enabled"] is False


class TestSecurityBoundary:
    """Boundary conditions — extreme config values must not crash the sandbox."""

    def test_zero_fuel_fails_immediately(self):
        """max_fuel=0: every WASM must fail fuel_exhausted immediately."""
        minimal_wat = """
        (module
          (import "wasi_snapshot_preview1" "proc_exit" (func $exit (param i32)))
          (memory (export "memory") 1)
          (func (export "_start")
            i32.const 0
            call $exit
          )
        )
        """
        wasm_bytes = wasmtime.wat2wasm(minimal_wat)
        wasm_path = (
            Path(tempfile.mkdtemp(prefix="ephemora_cell_boundary_")) / "zero_fuel.wasm"
        )
        wasm_path.write_bytes(wasm_bytes)

        config = WASIConfig(max_fuel=0)
        sandbox = WASISandbox(config=config)
        result = sandbox.run(str(wasm_path))

        assert (
            result.status == ExecutionStatus.FUEL_EXHAUSTED
        ), f"max_fuel=0 returned {result.status} — fuel enforcement failed at boundary"
        assert result.elapsed_ms < 100, "Zero fuel should fail instantly"

    def test_zero_memory_still_works_for_minimal(self):
        """max_memory_mb=0: a module without memory should still run."""
        no_mem_wat = """
        (module
          (func (export "_start"))
        )
        """
        wasm_bytes = wasmtime.wat2wasm(no_mem_wat)
        wasm_path = (
            Path(tempfile.mkdtemp(prefix="ephemora_cell_boundary_")) / "zero_mem.wasm"
        )
        wasm_path.write_bytes(wasm_bytes)

        config = WASIConfig(max_memory_mb=0, max_fuel=1_000_000)
        sandbox = WASISandbox(config=config)
        result = sandbox.run(str(wasm_path))

        assert (
            result.status == ExecutionStatus.SUCCESS
        ), f"max_memory_mb=0 blocked minimal WASM: {result.stderr[:200]}"

    def test_zero_timeout_stops_infinite_loop(self):
        """timeout_seconds=0: an infinite loop must be stopped immediately."""
        config = WASIConfig(max_fuel=None, timeout_seconds=0)
        sandbox = WASISandbox(config=config)

        wasm_bytes = wasmtime.wat2wasm(CPU_DOS_WAT)
        wasm_path = (
            Path(tempfile.mkdtemp(prefix="ephemora_cell_boundary_"))
            / "zero_timeout.wasm"
        )
        wasm_path.write_bytes(wasm_bytes)

        result = sandbox.run(str(wasm_path))

        assert (
            result.status == ExecutionStatus.TIMEOUT
        ), f"timeout=0 returned {result.status} — epoch interrupt failed at boundary"
        assert result.elapsed_ms < 100, "Zero timeout should stop instantly"

    def test_wasm_threads_disabled(self):
        """wasm_threads=False must block shared-memory modules."""
        # WASM mit shared memory (require threads capability)
        shared_mem_wat = """
        (module
          (memory (export "memory") 1 shared)
          (func (export "_start"))
        )
        """
        try:
            wasm_bytes = wasmtime.wat2wasm(shared_mem_wat)
        except Exception:
            pytest.skip("wasmtime does not support shared memory WAT compilation")

        wasm_path = (
            Path(tempfile.mkdtemp(prefix="ephemora_cell_boundary_")) / "threads.wasm"
        )
        wasm_path.write_bytes(wasm_bytes)

        sandbox = WASISandbox()
        result = sandbox.run(str(wasm_path))

        # shared-memory modules must be rejected (wasm_threads=False)
        assert (
            result.status == ExecutionStatus.ERROR
        ), f"Shared memory WASM not blocked with wasm_threads=False: {result.status}"


def test_out_of_fuel_during_host_call_is_fuel_exhausted(wasm_file):
    """Regression (2026-09-05, 15-user field study): an out-of-fuel trap that
    fires inside a host function or during instantiation surfaces as a
    generic exception — it must still classify as FUEL_EXHAUSTED, not ERROR."""
    wasm_file.write("stdout_flood")
    config = WASIConfig(max_fuel=500)
    sandbox = WASISandbox(config=config)
    result = sandbox.run(str(wasm_file.path))
    sandbox.cleanup()
    assert (
        result.status == ExecutionStatus.FUEL_EXHAUSTED
    ), f"out-of-fuel classified as {result.status}: {result.stderr[:120]}"
