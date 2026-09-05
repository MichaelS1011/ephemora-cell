"""ADR-002: run-level I/O budgets (io_cpu_seconds, io_budget_bytes).

Fuel meters guest compute, not host work (benchmarks/io_dos/). These
tests prove the per-run walls break the attack at the BUDGET, not at
the host: a write flood is stopped by io_budget_bytes, a zero-byte
stat flood by io_cpu_seconds, and None disables each wall explicitly.
"""

from __future__ import annotations

import os
import sys
import threading
import time
from pathlib import Path

import wasmtime

sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))

from ephemora_cell import ExecutionStatus, WASIConfig, WASISandbox, run_isolated

# Opens "out.bin" (O_CREAT) in the first preopen (fd 3) and writes 8-byte
# chunks in an infinite loop. With allow_dirs=() the only preopen is
# /sandbox, so the bytes-wall watcher sees the file.
WRITE_FLOOD_WAT = """
(module
  (import "wasi_snapshot_preview1" "fd_write" (func $fd_write
    (param i32 i32 i32 i32) (result i32)))
  (import "wasi_snapshot_preview1" "path_open" (func $path_open
    (param i32 i32 i32 i32 i32 i64 i64 i32 i32) (result i32)))
  (import "wasi_snapshot_preview1" "proc_exit" (func $halt (param i32)))
  (memory (export "memory") 1)
  (data (i32.const 8) "out.bin")
  (data (i32.const 32) "AAAAAAAA")
  (data (i32.const 64) "\\20\\00\\00\\00\\08\\00\\00\\00")
  (func (export "_start") (local $e i32)
    i32.const 3 i32.const 0 i32.const 8 i32.const 7 i32.const 1
    i64.const 70 i64.const 70 i32.const 0 i32.const 100
    call $path_open
    local.set $e
    local.get $e
    if i32.const 2 call $halt end
    (loop $l
      i32.const 100 i32.load
      i32.const 64 i32.const 1 i32.const 104
      call $fd_write drop
      br $l
    )
  )
)
"""

# Zero-byte stat flood: fd_filestat_get on the preopen fd in an infinite
# loop — 3 fuel/call, ~9.7us real host FS work per call, no bytes
# (measured 2026-08; may shift with wasmtime versions).
STAT_FLOOD_WAT = """
(module
  (import "wasi_snapshot_preview1" "fd_filestat_get" (func $fstat
    (param i32 i32) (result i32)))
  (memory (export "memory") 1)
  (func (export "_start")
    (loop $l
      i32.const 3 i32.const 512 call $fstat drop
      br $l
    )
  )
)
"""

# Same write-flood shape as WRITE_FLOOD_WAT but with a bounded loop and a
# clean exit, for the None-disables positive controls.
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


def _write_module(datadir: Path, name: str, wat: str) -> Path:
    path = datadir / name
    path.write_bytes(wasmtime.wat2wasm(wat))
    return path


class TestBytesBudget:
    def test_write_flood_breaks_at_budget_worker_path(self, tmp_path):
        """Worker path: the flood dies at io_budget_bytes, not at the host."""
        wasm = _write_module(tmp_path, "flood.wasm", WRITE_FLOOD_WAT)
        budget = 64 * 1024
        config = WASIConfig(
            max_fuel=None,
            timeout_seconds=30,
            io_budget_bytes=budget,
        )
        t0 = time.monotonic()
        result = run_isolated(str(wasm), config)
        wall = time.monotonic() - t0
        assert result["status"] == ExecutionStatus.ERROR
        assert "I/O budget exceeded" in result["stderr"]
        assert result["io_budget_exceeded"] is True
        assert result["io_bytes_written"] is not None
        # poll overshoot is bounded (100ms scan interval, ~1.4MB/s max rate)
        assert result["io_bytes_written"] <= budget + 512 * 1024
        assert wall < 15, f"budget did not stop the run early: {wall:.1f}s"

    def test_write_flood_breaks_at_budget_in_process(self, tmp_path):
        """In-process path: the sandbox-dir byte wall works there too."""
        wasm = _write_module(tmp_path, "flood.wasm", WRITE_FLOOD_WAT)
        config = WASIConfig(max_fuel=500_000_000, io_budget_bytes=32 * 1024)
        sandbox = WASISandbox(config=config)
        try:
            result = sandbox.run(str(wasm))
        finally:
            sandbox.cleanup()
        assert result.status == ExecutionStatus.ERROR
        assert "I/O budget exceeded" in result.stderr
        assert result.io_budget_exceeded is True
        assert result.io_bytes_written is not None

    def test_no_budget_no_breach_message(self, tmp_path):
        """Positive control: bounded writes with None budget run clean."""
        wasm = _write_module(tmp_path, "bounded.wasm", BOUNDED_WRITE_WAT)
        config = WASIConfig(max_fuel=10_000_000, io_budget_bytes=None)
        result = run_isolated(str(wasm), config)
        assert result["status"] == ExecutionStatus.SUCCESS
        assert "I/O budget exceeded" not in result["stderr"]


class TestCpuBudget:
    def test_stat_flood_breaks_at_cpu_budget(self, tmp_path):
        """Zero-byte stat flood (3 fuel/call): only the CPU wall stops it."""
        wasm = _write_module(tmp_path, "statflood.wasm", STAT_FLOOD_WAT)
        config = WASIConfig(
            max_fuel=None,  # no fuel metering at all
            timeout_seconds=30,
            io_cpu_seconds=0.5,
        )
        t0 = time.monotonic()
        result = run_isolated(str(wasm), config)
        wall = time.monotonic() - t0
        assert result["status"] == ExecutionStatus.ERROR
        assert "I/O budget exceeded" in result["stderr"]
        assert "io_cpu_seconds=0.5" in result["stderr"]
        assert 0 < wall < 10, f"cpu budget did not stop the run early: {wall:.1f}s"
        assert result["io_cpu_used_seconds"] is not None

    def test_cpu_budget_none_falls_back_to_timeout(self, tmp_path):
        """None disables the wall: the epoch timeout ends the run instead."""
        wasm = _write_module(tmp_path, "statflood.wasm", STAT_FLOOD_WAT)
        config = WASIConfig(max_fuel=None, timeout_seconds=2, io_cpu_seconds=None)
        t0 = time.monotonic()
        result = run_isolated(str(wasm), config)
        wall = time.monotonic() - t0
        assert result["status"] == ExecutionStatus.TIMEOUT
        assert "I/O budget exceeded" not in result["stderr"]
        assert wall >= 2


class TestValidation:
    def test_invalid_cpu_budget_rejected(self):
        import pytest

        with pytest.raises(ValueError):
            WASISandbox(config=WASIConfig(io_cpu_seconds=0))
        with pytest.raises(ValueError):
            WASISandbox(config=WASIConfig(io_cpu_seconds=-1.0))

    def test_invalid_byte_budget_rejected(self):
        import pytest

        with pytest.raises(ValueError):
            WASISandbox(config=WASIConfig(io_budget_bytes=0))
        with pytest.raises(ValueError):
            WASISandbox(config=WASIConfig(io_budget_bytes=-5))


class TestInProcessInterrupt:
    def test_interrupt_event_ends_run_promptly(self, tmp_path):
        """An external watchdog can interrupt an in-process run via epoch."""
        wasm = _write_module(tmp_path, "statflood.wasm", STAT_FLOOD_WAT)
        config = WASIConfig(max_fuel=None, timeout_seconds=30, io_cpu_seconds=None)
        sandbox = WASISandbox(config=config)
        interrupt = threading.Event()

        def _watchdog():
            time.sleep(0.5)
            interrupt.set()

        threading.Thread(target=_watchdog, daemon=True).start()
        try:
            result = sandbox.run(str(wasm), interrupt_event=interrupt)
        finally:
            sandbox.cleanup()
        assert result.status == ExecutionStatus.TIMEOUT
        assert result.io_bytes_written is not None
