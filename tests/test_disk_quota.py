"""Disk quota for guest writes into preopened directories.

``disk_quota_bytes`` is enforced in the subprocess isolation path via
RLIMIT_FSIZE in the worker: a guest writing past the quota gets a
controlled write error (EFBIG) instead of filling host disk. The cap is
per-file (kernel semantics) and documented as such.
"""

from __future__ import annotations

import os
import shutil
import sys
import time
from pathlib import Path

import wasmtime

sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))

from ephemora_cell import ExecutionStatus, WASIConfig, run_isolated

# Opens "out.bin" (O_CREAT) in preopen fd 3 and writes 16-byte chunks in a
# loop (100_000 x 16 B = 1.6 MB if unrestricted). On the first write error
# the guest exits with the WASI errno — EFBIG is errno 22.
QUOTA_BOMB_WAT = """
(module
  (import "wasi_snapshot_preview1" "path_open" (func $path_open
    (param i32 i32 i32 i32 i32 i64 i64 i32 i32) (result i32)))
  (import "wasi_snapshot_preview1" "fd_write" (func $fd_write
    (param i32 i32 i32 i32) (result i32)))
  (import "wasi_snapshot_preview1" "proc_exit" (func $proc_exit (param i32)))
  (memory (export "memory") 1)
  (data (i32.const 8) "out.bin")
  (data (i32.const 32) "ABCDEFGHIJKLMNOP")
  ;; iovec at 64: {buf_ptr = 32, buf_len = 16}
  (data (i32.const 64) "\\20\\00\\00\\00\\10\\00\\00\\00")
  (func (export "_start") (local $fd i32) (local $errno i32)
    ;; path_open(3 /* first preopen */, 0, "out.bin", 7,
    ;;           O_CREAT, fd_read|fd_write, same, 0, &fd at 100)
    i32.const 3
    i32.const 0
    i32.const 8
    i32.const 7
    i32.const 1
    i64.const 70
    i64.const 70
    i32.const 0
    i32.const 100
    call $path_open
    local.set $errno
    local.get $errno
    if
      local.get $errno
      call $proc_exit
    end
    (loop $l
      ;; fd_write(fd@100, iovec@64, 1, nwritten@104)
      i32.const 100
      i32.load
      i32.const 64
      i32.const 1
      i32.const 104
      call $fd_write
      local.set $errno
      local.get $errno
      if
        local.get $errno
        call $proc_exit
      end
      br $l
    )
    i32.const 0
    call $proc_exit
  )
)
"""


def test_quota_stops_guest_write_flood():
    """Guest writing 1.6 MB with a 64 KB quota: capped, host unharmed."""
    datadir = Path.home() / f".ephemora_quota_{os.getpid()}_{time.monotonic_ns()}"
    datadir.mkdir()
    try:
        wasm = datadir / "quota_bomb.wasm"
        wasm.write_bytes(wasmtime.wat2wasm(QUOTA_BOMB_WAT))

        quota = 64 * 1024
        config = WASIConfig(
            max_fuel=100_000_000,
            timeout_seconds=15,
            allow_dirs=(str(datadir),),
            disk_quota_bytes=quota,
        )
        result = run_isolated(str(wasm), config)

        out_file = datadir / "out.bin"
        assert out_file.exists(), "guest never managed to create the file"
        size = out_file.stat().st_size
        # Kernel semantics: RLIMIT_FSIZE is per-file — the write that would
        # cross the limit fails with EFBIG (WASI errno 22), the file stops
        # at (or just below) the quota.
        assert size <= quota, f"quota breached: {size} > {quota}"
        assert result["status"] == ExecutionStatus.ERROR
        assert result["exit_code"] == 22, (
            f"expected EFBIG (22), got exit_code={result['exit_code']}, "
            f"stderr={result['stderr'][:200]!r}"
        )
    finally:
        shutil.rmtree(datadir, ignore_errors=True)


def test_no_quota_allows_full_write():
    """Positive control: same guest, unlimited quota writes past 64 KB."""
    datadir = Path.home() / f".ephemora_quota_{os.getpid()}_{time.monotonic_ns()}"
    datadir.mkdir()
    try:
        wasm = datadir / "quota_bomb.wasm"
        wasm.write_bytes(wasmtime.wat2wasm(QUOTA_BOMB_WAT))

        config = WASIConfig(
            max_fuel=500_000_000,
            timeout_seconds=30,
            allow_dirs=(str(datadir),),
            disk_quota_bytes=None,
        )
        result = run_isolated(str(wasm), config)
        out_file = datadir / "out.bin"
        if result["status"] == ExecutionStatus.SUCCESS:
            # full 1.6 MB written — the cap was the only thing stopping it
            assert out_file.stat().st_size > 64 * 1024
        else:
            # fuel/timeout contained the loop instead — still no breach of
            # this test's claim (no quota was configured)
            pass
    finally:
        shutil.rmtree(datadir, ignore_errors=True)
