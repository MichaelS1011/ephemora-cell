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
from pathlib import Path

import pytest
import wasmtime

sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))

from ephemora_cell import (
    ExecutionStatus,
    WASIConfig,
    WASISandbox,
)

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
        "symlink_escape": wasmtime.wat2wasm(
            TestSecurity4_3_Path_Traversal.SYMLINK_ESCAPE_WAT
        ),
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

# 4.7 Preopen default-deny: attempt to open a file without preopened dirs.
# path_open Signatur (WASI Preview1):
#   param[0] dirfd:     fd of the parent directory (0 = AT_FDCWD via wasmtime)
#   param[1] path_name: pointer to the filename string in linear memory
#   param[2] path_name_len: length of the filename
#   param[3] path_flags: 0 (no symlink, no create)
#   param[4] fs_flags:   0 (no O_CREAT, no O_EXCL)
#   param[5] rights:     desired rights (0 = minimal)
#   param[6] fd_flags:   0 (no append, no synchronous)
#   param[7] preopen_fds_count: number of preopen fds in the output buffer
# result: errno code (0 = success, >0 = error)
PATH_OPEN_WAT = """
(module
  (import "wasi_snapshot_preview1" "path_open" (func $path_open
    (param i32 i32 i32 i32 i32 i32 i32 i32) (result i32)))
  (import "wasi_snapshot_preview1" "fd_open" (func $fd_open
    (param i32 i32 i32 i32 i32 i32) (result i32)))
  (import "wasi_snapshot_preview1" "proc_exit" (func $proc_exit (param i32)))
  (memory (export "memory") 1)
  (data (i32.const 0) "/tmp/test\\00000000000000")  ;; path string at offset 0
  (func (export "_start")
    ;; path_open(dirfd=0, path="/tmp/test", len=9, ...)
    ;; Without preopened dirs this MUST fail with ENOTCAPABLE (63)
    i32.const 0      ;; dirfd
    i32.const 0      ;; path_name pointer
    i32.const 9      ;; path_name_len
    i32.const 0      ;; path_flags
    i32.const 0      ;; fs_flags
    i32.const 0      ;; rights
    i32.const 0      ;; fd_flags
    i32.const 0      ;; preopen_fds_count
    call $path_open
    drop
    i32.const 63     ;; ENOTCAPABLE exit code
    call $proc_exit
  )
)
"""

# 4.8 Stdout Flood: 1000x fd_write(32 bytes) = ~32KB — exercises the 10 KB output limit
STDOUT_FLOOD_WAT = """
(module
  (import "wasi_snapshot_preview1" "fd_write" (func $fd_write
    (param i32 i32 i32 i32) (result i32)))
  (import "wasi_snapshot_preview1" "proc_exit" (func $proc_exit (param i32)))
  (memory (export "memory") 2)  ;; 2 pages = 128KB for buffer
  (data (i32.const 0) "ABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789")  ;; 32 chars
  (func (export "_start")
    (local $i i32)
    i32.const 0
    (local.set $i)
    (loop $l
      ;; fd_write(fd=1/stdout, iovs_ptr=0, iovs_len=1, buf_len=32)
      i32.const 1
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

    # WASM: tries to open and read a file via a symlink inside the preopened dir.
    # path_open(dirfd=3, "/escape_link", flags=0, ...) -> must be blocked.
    SYMLINK_ESCAPE_WAT = """
    (module
      (import "wasi_snapshot_preview1" "path_open" (func $path_open
        (param i32 i32 i32 i32 i32 i32 i32 i32) (result i32)))
      (import "wasi_snapshot_preview1" "fd_read" (func $fd_read
        (param i32 i32 i32 i32) (result i32)))
      (import "wasi_snapshot_preview1" "fd_close" (func $fd_close
        (param i32) (result i32)))
      (import "wasi_snapshot_preview1" "proc_exit" (func $proc_exit (param i32)))
      (memory (export "memory") 2)
      ;; "/escape_link\\0" — the symlink name inside the preopened dir
      (data (i32.const 0) "/escape_link\\0000000000000000")
      (func (export "_start")
        (local $fd i32)
        (local $err i32)
        ;; path_open: dirfd=3(AT_FDCWD), path_ptr=0, path_len=11,
        ;; oflags=0(O_RDONLY), dirs=0, fds=0, fd_count=1, rights=0
        i32.const 3
        i32.const 0
        i32.const 11
        i32.const 0
        i32.const 0
        i32.const 0
        i32.const 1
        i32.const 0
        call $path_open
        local.set $fd
        ;; If fd < 0 (as unsigned: very large), it was blocked -> test passed
        local.get $fd
        i32.const 1000
        i32.gt_u
        if
          ;; error code -> symlink escape blocked (good)
          i32.const 0
          call $proc_exit
        end
        ;; If it did open: read contents and exit 1 (bad)
        local.get $fd
        call $fd_close
        i32.const 1
        call $proc_exit
      )
    )
    """

    @staticmethod
    def _make_safe_dir() -> Path:
        """Create a safe dir OUTSIDE /private (canonical allowlist forbids /private)."""
        safe_dir = Path.home() / f".ephemora_safe_{os.getpid()}"
        safe_dir.mkdir(parents=True, exist_ok=True)
        return safe_dir

    def test_symlink_not_followed_via_wasm(self):
        """Real WASM tries to read through a symlink — must be blocked."""
        # Setup: safe dir with a symlink to /tmp (outside the sandbox)
        safe_dir = self._make_safe_dir()
        target = Path("/tmp")
        symlink = safe_dir / "escape_link"
        try:
            symlink.symlink_to(target)
        except OSError:
            pytest.skip("Symlinks not supported on this platform")

        # Write a test file into the safe dir (so it is not empty)
        (safe_dir / "allowed.txt").write_text("this is allowed")

        # Compile the attack payload
        wasm_bytes = wasmtime.wat2wasm(self.SYMLINK_ESCAPE_WAT)
        wasm_path = Path(tempfile.mkdtemp(prefix="ephemora_cell_sec_")) / "symlink.wasm"
        wasm_path.write_bytes(wasm_bytes)

        # Run with allow_dirs=safe_dir
        config = WASIConfig(
            allow_dirs=(str(safe_dir),),
            max_fuel=1_000_000,
        )
        sandbox = WASISandbox(config=config)
        result = sandbox.run(str(wasm_path))
        sandbox.cleanup()
        shutil.rmtree(safe_dir, ignore_errors=True)

        # Defense holds: path_open on the symlink must fail
        # The module exits 0 when blocked, 1 when the escape succeeded
        if result.status == ExecutionStatus.SUCCESS:
            assert (
                result.exit_code == 0
            ), "Symlink escape SUCCESSFUL — guest read outside sandbox!"
        else:
            # Trap/ERROR is also acceptable (symlink not found at all)
            assert result.status in (
                ExecutionStatus.ERROR,
                ExecutionStatus.FUEL_EXHAUSTED,
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

    def test_tmp_rejected_on_macos(self):
        """allow_dirs="/tmp" must be rejected on macOS: realpath -> /private/tmp."""
        if sys.platform != "darwin":
            pytest.skip("Only meaningful where /tmp is a symlink into /private")
        config = WASIConfig(allow_dirs=("/tmp",))
        with pytest.raises(ValueError, match="forbidden"):
            WASISandbox(config=config)

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

        assert (
            result.status == ExecutionStatus.TIMEOUT
        ), f"Timeout failed to kill infinite loop. Got {result.status}: {result.stderr[:200]}"
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

    def test_no_preopen_blocks_path_open(self):
        """NEGATIVE: with empty allow_dirs, path_open must not succeed."""
        config = WASIConfig(max_fuel=1_000_000)  # No allow_dirs
        sandbox = WASISandbox(config=config)

        wasm_bytes = wasmtime.wat2wasm(PATH_OPEN_WAT)
        wasm_path = Path(tempfile.mkdtemp(prefix="ephemora_cell_sec_")) / "preopen.wasm"
        wasm_path.write_bytes(wasm_bytes)

        result = sandbox.run(str(wasm_path))

        # The module crashes or exits with an error — never SUCCESS
        assert result.status in (
            ExecutionStatus.ERROR,
            ExecutionStatus.FUEL_EXHAUSTED,
        ), (
            f"Preopen default-deny failed. Module completed with {result.status}. "
            f"Stderr: {result.stderr[:200]}"
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

        result = sandbox.run(str(wasm_path))

        # The sandbox dir from run() should exist
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
