"""Coverage companion: wasm_inspector basics (was untested)."""

from __future__ import annotations

import os
import sys

import wasmtime

sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))

from ephemora_cell import wasm_inspector

WAT = """
(module
  (import "wasi_snapshot_preview1" "fd_write" (func $w (param i32 i32 i32 i32) (result i32)))
  (memory (export "memory") 2)
  (func (export "_start") nop)
  (global $g i32 (i32.const 0))
)
"""


def test_inspect_module_reports_structure(tmp_path):
    path = tmp_path / "m.wasm"
    path.write_bytes(wasmtime.wat2wasm(WAT))
    info = wasm_inspector.inspect_module(str(path))
    assert info.raw_size > 0
    assert info.wasi_dependent is True
    assert info.has_start is True
    assert info.memory_pages == 2
    assert info.num_functions >= 1
    assert any(i.get("name") == "_start" for i in info.exports)
    assert any("fd_write" in str(i) for i in info.wasi_imports)
    # the inspector flags fd_write as a capped-output risk
    assert any(r.get("name") == "wasi_snapshot_preview1::fd_write" for r in info.risks)


def test_inspect_module_missing_file(tmp_path):
    try:
        wasm_inspector.inspect_module(str(tmp_path / "nope.wasm"))
        raised = False
    except (FileNotFoundError, ValueError, RuntimeError):
        raised = True
    assert raised
