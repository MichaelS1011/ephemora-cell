"""ADR-004: named state across isolated runs (StateStore).

Covers: cap enforcement, session isolation (no leakage), explicit
cleanup, and the 3-run counter demo — three consecutive runs passing a
counter through ``ephemora_state`` imports (get → +1 → set).
"""

from __future__ import annotations

import os
import sys

import pytest
import wasmtime

sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))

from ephemora_cell import ExecutionStatus, WASIConfig, WASISandbox
from ephemora_cell.state import (
    StateCapExceeded,
    StateStore,
)

TRIVIAL_WAT = """
(module
  (import "wasi_snapshot_preview1" "proc_exit" (func $exit (param i32)))
  (memory (export "memory") 1)
  (func (export "_start") i32.const 0 call $exit)
)
"""

COUNTER_WAT = """
(module
  (import "wasi_snapshot_preview1" "proc_exit" (func $exit (param i32)))
  ;; ephemora_state.get(name_ptr, name_len, buf_ptr, buf_len_ptr) -> errno
  (import "ephemora_state" "get" (func $get
    (param i32 i32 i32 i32) (result i32)))
  ;; ephemora_state.set(name_ptr, name_len, val_ptr, val_len) -> errno
  (import "ephemora_state" "set" (func $set
    (param i32 i32 i32 i32) (result i32)))
  (memory (export "memory") 1)
  (data (i32.const 8) "counter")
  (func (export "_start") (local $errno i32) (local $v i64)
    ;; buffer capacity for get: 8 bytes at address 136
    i32.const 136 i32.const 8 i32.store
    ;; read current counter (8-byte little-endian i64) into 128
    i32.const 8 i32.const 7 i32.const 128 i32.const 136
    call $get
    local.set $errno
    local.get $errno
    i32.const 0
    i32.ne
    if
      local.get $errno
      i32.const 3
      i32.ne
      if
        local.get $errno
        call $exit          ;; real error -> exit with errno
      end
      i64.const 0
      local.set $v          ;; ERRNO_NOT_FOUND -> start at 0
    else
      i32.const 128
      i64.load
      local.set $v
    end
    ;; value = value + 1, write back
    local.get $v
    i64.const 1
    i64.add
    local.set $v
    i32.const 128
    local.get $v
    i64.store
    ;; set(name, value, 8)
    i32.const 8 i32.const 7 i32.const 128 i32.const 8
    call $set
    local.set $errno
    local.get $errno
    if
      local.get $errno
      call $exit
    end
    i32.const 0
    call $exit
  )
)
"""

BIG_SET_WAT = """
(module
  (import "wasi_snapshot_preview1" "proc_exit" (func $exit (param i32)))
  (import "ephemora_state" "set" (func $set
    (param i32 i32 i32 i32) (result i32)))
  (memory (export "memory") 1)
  (data (i32.const 8) "big")
  (func (export "_start") (local $errno i32)
    ;; set("big", <0 bytes>, len = 2048 > max_value_bytes) -> cap breach
    i32.const 8 i32.const 3
    i32.const 128 i32.const 2048
    call $set
    local.set $errno
    local.get $errno
    call $exit                       ;; exits with the errno
  )
)
"""

NOT_FOUND_WAT = """
(module
  (import "wasi_snapshot_preview1" "proc_exit" (func $exit (param i32)))
  (import "ephemora_state" "get" (func $get
    (param i32 i32 i32 i32) (result i32)))
  (memory (export "memory") 1)
  (data (i32.const 8) "missing")
  (func (export "_start") (local $errno i32)
    i32.const 8 i32.const 7
    i32.const 128 i32.const 136
    call $get
    local.set $errno
    local.get $errno
    call $exit
  )
)
"""


def _write_module(datadir, name: str, wat: str):
    path = datadir / name
    path.write_bytes(wasmtime.wat2wasm(wat))
    return path


class TestStateStore:
    def test_caps_value_total_entries(self):
        store = StateStore(max_value_bytes=16, max_total_bytes=32, max_entries=2)
        store.set("a", b"x" * 16)
        with pytest.raises(StateCapExceeded):
            store.set("b", b"x" * 17)
        store.set("b", b"y" * 16)
        with pytest.raises(StateCapExceeded):
            store.set("c", b"z")  # max_entries
        with pytest.raises(StateCapExceeded):
            store.set("a", b"x" * 20)  # would breach total (20+16 > 32)
        assert store.total_bytes == 32

    def test_delete_and_clear(self):
        store = StateStore()
        store.set("k", b"v")
        assert store.delete("k") is True
        assert store.delete("k") is False
        assert store.total_bytes == 0
        store.set("k", b"v")
        store.clear()
        assert store.get("k") is None
        assert store.total_bytes == 0

    def test_session_isolation(self):
        a, b = StateStore(), StateStore()
        a.set("secret", b"alpha")
        assert b.get("secret") is None
        assert b.names() == []


class TestStateImports:
    def test_no_state_store_no_imports(self, tmp_path):
        """Without the explicit grant the guest cannot resolve the import."""
        wasm = _write_module(tmp_path, "counter.wasm", COUNTER_WAT)
        sandbox = WASISandbox(config=WASIConfig(max_fuel=1_000_000))
        try:
            result = sandbox.run(str(wasm))
        finally:
            sandbox.cleanup()
        # instantiation fails: ephemora_state imports are not defined
        assert result.status == ExecutionStatus.ERROR

    def test_gate_demo_counter_across_three_runs(self, tmp_path):
        """Three isolated runs passing a counter through state."""
        wasm = _write_module(tmp_path, "counter.wasm", COUNTER_WAT)
        store = StateStore()
        sandbox = WASISandbox(config=WASIConfig(max_fuel=1_000_000))
        try:
            for _ in range(3):
                result = sandbox.run(str(wasm), state_store=store)
                assert result.status == ExecutionStatus.SUCCESS, result.stderr[:200]
                assert result.state_bytes == store.total_bytes
        finally:
            sandbox.cleanup()
        assert store.get("counter") == (3).to_bytes(8, "little")
        assert store.total_bytes == 8

    def test_not_found_errno_visible_to_guest(self, tmp_path):
        wasm = _write_module(tmp_path, "missing.wasm", NOT_FOUND_WAT)
        store = StateStore()
        sandbox = WASISandbox(config=WASIConfig(max_fuel=1_000_000))
        try:
            result = sandbox.run(str(wasm), state_store=store)
        finally:
            sandbox.cleanup()
        # guest exits with errno 3 (not found) -> ERROR with exit_code 3
        assert result.status == ExecutionStatus.ERROR
        assert result.exit_code == 3

    def test_cap_breach_returns_errno_to_guest(self, tmp_path):
        wasm = _write_module(tmp_path, "big.wasm", BIG_SET_WAT)
        store = StateStore(max_value_bytes=1024)
        sandbox = WASISandbox(config=WASIConfig(max_fuel=1_000_000))
        try:
            result = sandbox.run(str(wasm), state_store=store)
        finally:
            sandbox.cleanup()
        assert result.status == ExecutionStatus.ERROR
        assert result.exit_code == 1  # ERRNO_CAP
        assert store.names() == []  # nothing stored

    def test_buffer_too_small_reports_required_len(self, tmp_path):
        """get with a too-small buffer returns errno 4 + required length."""
        store = StateStore()
        store.set("counter", b"12345678")

        wat = """
        (module
          (import "wasi_snapshot_preview1" "proc_exit" (func $exit (param i32)))
          (import "ephemora_state" "get" (func $get
            (param i32 i32 i32 i32) (result i32)))
          (memory (export "memory") 1)
          (data (i32.const 8) "counter")
          (func (export "_start") (local $errno i32)
            i32.const 8 i32.const 7
            i32.const 128 i32.const 136   ;; capacity field = 0 (too small)
            call $get
            local.set $errno
            ;; required length must have been written to 136
            i32.const 136 i32.load
            i32.const 8
            i32.ne
            if i32.const 9 call $exit end
            local.get $errno
            call $exit
          )
        )
        """
        wasm = _write_module(tmp_path, "small.wasm", wat)
        sandbox = WASISandbox(config=WASIConfig(max_fuel=1_000_000))
        try:
            result = sandbox.run(str(wasm), state_store=store)
        finally:
            sandbox.cleanup()
        assert result.status == ExecutionStatus.ERROR
        assert result.exit_code == 4  # ERRNO_BUF_TOO_SMALL (and len==8 checked)
