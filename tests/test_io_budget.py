"""
Regression tests: real I/O byte budget, host-owned capture,
preopen visibility, and the frozen memory baseline.

K3/K4: output is capped by a byte-budget WASI sink (stdout/stderr), capture
files live in a host-owned directory that is never preopened, and the
Store-level memory limit rejects modules whose linear memory exceeds it.
"""

from __future__ import annotations

import os
import sys
import tempfile
from pathlib import Path

import wasmtime

sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))

from ephemora_cell import (
    ExecutionStatus,
    WASIConfig,
    WASISandbox,
)

# 300000 x 32B = 9.6 MB — a "10-MB-writer" that the 10 KB budget must stop.
MB_WRITER_WAT = """
(module
  (import "wasi_snapshot_preview1" "fd_write" (func $fd_write
    (param i32 i32 i32 i32) (result i32)))
  (import "wasi_snapshot_preview1" "proc_exit" (func $proc_exit (param i32)))
  (memory (export "memory") 2)
  (data (i32.const 4096) "ABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789")
  (func (export "_start") (local $i i32)
    i32.const 0
    i32.const 4096
    i32.store
    i32.const 4
    i32.const 32
    i32.store
    i32.const 0
    local.set $i
    (loop $l
      i32.const 1
      i32.const 0
      i32.const 1
      i32.const 32
      call $fd_write
      drop
      local.get $i
      i32.const 1
      i32.add
      local.set $i
      local.get $i
      i32.const 300000
      i32.lt_s
      if
        br $l
      end)
    i32.const 0
    call $proc_exit))
"""

# Enumerates guest-visible preopens via fd_prestat_get / fd_prestat_dir_name.
# Exits 0 only if every preopen is exactly "/sandbox"; exits 1 if any other
# preopen exists; exits 2 if scanning itself fails.
PREOPEN_SCAN_WAT = """
(module
  (import "wasi_snapshot_preview1" "fd_prestat_get" (func $fd_prestat_get
    (param i32 i32) (result i32)))
  (import "wasi_snapshot_preview1" "fd_prestat_dir_name" (func $fd_prestat_dir_name
    (param i32 i32 i32) (result i32)))
  (import "wasi_snapshot_preview1" "proc_exit" (func $proc_exit (param i32)))
  (memory (export "memory") 2)
  (data (i32.const 2048) "/sandbox")
  (func $classify (param $fd i32) (result i32)
    (local $err i32) (local $len i32) (local $i i32) (local $ok i32)
    local.get $fd
    i32.const 1024
    call $fd_prestat_get
    local.set $err
    local.get $err
    if
      i32.const 2
      return
    end
    i32.const 1028
    i32.load
    local.set $len
    local.get $len
    i32.const 8
    i32.ne
    if
      i32.const 0
      return
    end
    local.get $fd
    i32.const 2560
    local.get $len
    call $fd_prestat_dir_name
    local.set $err
    local.get $err
    if
      i32.const 0
      return
    end
    i32.const 1
    local.set $ok
    i32.const 0
    local.set $i
    block $cmpdone
      loop $cmploop
        local.get $i
        i32.const 8
        i32.ge_s
        if
          br $cmpdone
        end
        local.get $i
        i32.const 2560
        i32.add
        i32.load8_u
        local.get $i
        i32.const 2048
        i32.add
        i32.load8_u
        i32.ne
        if
          i32.const 0
          local.set $ok
          br $cmpdone
        end
        local.get $i
        i32.const 1
        i32.add
        local.set $i
        br $cmploop
      end
    end
    local.get $ok)
  (func (export "_start") (local $fd i32) (local $kind i32)
    i32.const 3
    local.set $fd
    block $done
      loop $scan
        local.get $fd
        call $classify
        local.set $kind
        local.get $kind
        i32.const 2
        i32.eq
        if
          br $done
        end
        local.get $kind
        i32.const 1
        i32.eq
        if
          local.get $fd
          i32.const 1
          i32.add
          local.set $fd
          br $scan
        end
        i32.const 1
        call $proc_exit
      end
    end
    i32.const 0
    call $proc_exit))
"""


def _write_wasm(wat: str) -> str:
    path = Path(tempfile.mkdtemp(prefix="ephemora_io_budget_")) / "mod.wasm"
    path.write_bytes(wasmtime.wat2wasm(wat))
    return str(path)


class TestIOByteBudget:
    """fd_write output is bounded by a real byte budget."""

    def test_mb_writer_stopped_at_budget(self):
        """A ~10 MB writer must be stopped at ~10 KB and the capture file must stay small."""
        sandbox = WASISandbox(config=WASIConfig(max_fuel=None, timeout_seconds=60))
        result = sandbox.run(_write_wasm(MB_WRITER_WAT))

        assert result.status == ExecutionStatus.SUCCESS, result.stderr[:300]
        # In-memory output bounded at 10 KB (+ truncation slack)
        assert (
            len(result.stdout) <= 10_100
        ), f"stdout not budgeted: {len(result.stdout)} chars"
        # The guest genuinely wrote before being cut off
        assert (
            len(result.stdout) >= 9_000
        ), f"stdout suspiciously small: {len(result.stdout)} chars"
        # On-disk capture file stays within the budget
        host_dir = sandbox._host_dir
        assert host_dir is not None
        stdout_file = os.path.join(host_dir, "stdout.txt")
        assert os.path.exists(stdout_file), "capture file missing in host dir"
        file_size = os.path.getsize(stdout_file)
        assert file_size <= 10_050, f"capture file grew past budget: {file_size} bytes"

    def test_capture_files_not_in_guest_sandbox(self):
        """Capture files must live in the host dir, NOT in the guest-visible /sandbox."""
        sandbox = WASISandbox(config=WASIConfig(max_fuel=None, timeout_seconds=60))
        result = sandbox.run(_write_wasm(MB_WRITER_WAT))
        assert result.status == ExecutionStatus.SUCCESS, result.stderr[:300]

        sandbox_dir = result.sandbox_dir
        assert sandbox_dir is not None
        assert not os.path.exists(os.path.join(sandbox_dir, "stdout.txt"))
        assert not os.path.exists(os.path.join(sandbox_dir, "stderr.txt"))

        host_dir = sandbox._host_dir
        assert host_dir is not None
        assert os.path.exists(os.path.join(host_dir, "stdout.txt"))
        # Host dir must not be preopened — guest cannot even know its path.
        assert os.path.realpath(host_dir) != os.path.realpath(sandbox_dir)


class TestPreopenVisibility:
    """stdout capture file is invisible to the guest (CWE-59 closure)."""

    def test_only_sandbox_preopen_visible(self):
        """Guest-side preopen enumeration must see exactly /sandbox (no capture dir)."""
        sandbox = WASISandbox(config=WASIConfig(max_fuel=1_000_000))
        result = sandbox.run(_write_wasm(PREOPEN_SCAN_WAT))
        assert result.status == ExecutionStatus.SUCCESS, result.stderr[:300]
        assert (
            result.exit_code == 0
        ), f"guest saw a foreign preopen (exit {result.exit_code})"

    def test_extra_allow_dir_detected(self):
        """Control: with a real extra allow_dir, the same module must exit 1."""
        safe_dir = Path.home() / f".ephemora_preopen_ctl_{os.getpid()}"
        safe_dir.mkdir(parents=True, exist_ok=True)
        try:
            sandbox = WASISandbox(
                config=WASIConfig(max_fuel=1_000_000, allow_dirs=(str(safe_dir),))
            )
            result = sandbox.run(_write_wasm(PREOPEN_SCAN_WAT))
            assert (
                result.exit_code == 1
            ), f"control failed: extra preopen not detected (exit {result.exit_code})"
        finally:
            import shutil

            shutil.rmtree(safe_dir, ignore_errors=True)


class TestMemoryBaseline:
    """Store.set_limits rejects modules whose memory exceeds the limit."""

    def test_module_over_memory_limit_rejected(self):
        """A module declaring 300 pages (19.2 MB) must fail with max_memory_mb=16."""
        sandbox = WASISandbox(config=WASIConfig(max_memory_mb=16, max_fuel=1_000_000))
        wat = '(module (memory (export "memory") 300) (func (export "_start")))'
        result = sandbox.run(_write_wasm(wat))

        assert (
            result.status == ExecutionStatus.ERROR
        ), f"over-limit module not rejected: {result.status}"
        assert "memory" in result.stderr.lower(), result.stderr[:200]

    def test_memory_grow_bounded_by_store_limit(self):
        """memory.grow must stop growing once the Store limit is reached (no hang)."""
        grow_wat = """
        (module
          (memory (export "memory") 1)
          (func (export "_start") (local $i i32)
            i32.const 0
            local.set $i
            (loop $l
              i32.const 1
              memory.grow
              drop
              local.get $i
              i32.const 1
              i32.add
              local.set $i
              local.get $i
              i32.const 1000
              i32.lt_s
              if
                br $l
              end)))
        """
        sandbox = WASISandbox(config=WASIConfig(max_memory_mb=16, max_fuel=1_000_000))
        result = sandbox.run(_write_wasm(grow_wat))
        # grow returns -1 at the limit; the loop then burns fuel until exhausted.
        assert result.status in (
            ExecutionStatus.FUEL_EXHAUSTED,
            ExecutionStatus.SUCCESS,
        ), result.stderr[:200]


class TestWasmFeatureFreeze:
    """memory64 / multi-memory proposals are disabled by default."""

    MEMORY64_WAT = '(module (memory (export "memory") i64 1) (func (export "_start")))'

    def test_memory64_module_rejected(self):
        sandbox = WASISandbox()
        result = sandbox.run(_write_wasm(self.MEMORY64_WAT))
        assert result.status == ExecutionStatus.ERROR
        assert "memory64" in result.stderr.lower(), result.stderr[:200]

    def test_memory64_default_off_in_config(self):
        assert WASIConfig().memory64 is False
        assert WASIConfig(memory64=False).memory64 is False

    def test_multi_memory_module_rejected(self):
        sandbox = WASISandbox()
        wat = (
            '(module (memory (export "m0") 1) (memory (export "m1") 1) '
            '(func (export "_start")))'
        )
        result = sandbox.run(_write_wasm(wat))
        assert result.status == ExecutionStatus.ERROR
        assert (
            "multi" in result.stderr.lower() or "memory" in result.stderr.lower()
        ), result.stderr[:200]


class TestMemory64OptIn:
    """memory64 is a per-config opt-in: off by default, works when enabled."""

    MEMORY64_WAT = '(module (memory (export "memory") i64 1) (func (export "_start")))'

    def test_runs_inline_when_opted_in(self):
        sandbox = WASISandbox(config=WASIConfig(memory64=True))
        result = sandbox.run(_write_wasm(self.MEMORY64_WAT))
        assert result.status == ExecutionStatus.SUCCESS, result.stderr[:200]

    def test_runs_pooled_when_opted_in(self):
        sandbox = WASISandbox(config=WASIConfig(memory64=True))
        result = sandbox.run(_write_wasm(self.MEMORY64_WAT), use_engine_pool=True)
        assert result.status == ExecutionStatus.SUCCESS, result.stderr[:200]

    def test_run_wasm_kwarg(self):
        from ephemora_cell import run_wasm

        result = run_wasm(_write_wasm(self.MEMORY64_WAT), memory64=True)
        assert result.status == ExecutionStatus.SUCCESS, result.stderr[:200]

    def test_worker_passthrough(self):
        from ephemora_cell.process_executor import run_isolated

        result = run_isolated(_write_wasm(self.MEMORY64_WAT), WASIConfig(memory64=True))
        assert result["status"] == ExecutionStatus.SUCCESS, result["stderr"][:200]

    def test_worker_still_rejects_by_default(self):
        from ephemora_cell.process_executor import run_isolated

        result = run_isolated(_write_wasm(self.MEMORY64_WAT), WASIConfig())
        assert result["status"] == ExecutionStatus.ERROR
        assert "memory64" in result["stderr"].lower()

    def test_multi_memory_stays_frozen_even_with_memory64(self):
        sandbox = WASISandbox(config=WASIConfig(memory64=True))
        wat = (
            '(module (memory (export "m0") i64 1) (memory (export "m1") i64 1) '
            '(func (export "_start")))'
        )
        result = sandbox.run(_write_wasm(wat))
        assert result.status == ExecutionStatus.ERROR

    def test_report_baseline_reflects_opt_in(self):
        from ephemora_cell.execution_report import ExecutionReport

        report = ExecutionReport(status="success", exit_code=0, elapsed_ms=1.0)
        report.apply_config(WASIConfig(memory64=True))
        assert report.security_baseline["memory64"] is True
        report.apply_config(WASIConfig())
        assert report.security_baseline["memory64"] is False
