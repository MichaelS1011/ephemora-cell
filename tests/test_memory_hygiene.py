"""Memory hygiene across sequential instances (CVE-2026-34988 class guard).

The wasmtime pooling-allocator leak (CVE-2026-34988: cache-pressure reset
skipped, memory residues visible to the next instance in the same slot) is
not reachable from Cell — the Python binding exposes no allocator selection
at all. This test is the standing guard: if a pooling allocator ever
arrives in the binding (or engine defaults change), a guest that reads its
linear memory before writing must never observe a predecessor's bytes.

Guest A writes a recognizable secret pattern across its whole memory, then
guest B reads every word of its own fresh memory before writing anything —
any residue traps (``unreachable``), so a clean run proves zeroing.
"""

from __future__ import annotations

import os
import sys

sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))

import wasmtime

from ephemora_cell import ExecutionStatus, WASIConfig, WASISandbox, run_wasm

SECRET_WRITER_WAT = r"""
(module
  (memory (export "memory") 1)
  (func (export "_start")
    (local $i i32)
    (loop $w
      (i32.store (local.get $i) (i32.const 0xdeadbeef))
      (local.set $i (i32.add (local.get $i) (i32.const 4)))
      (br_if $w (i32.lt_u (local.get $i) (i32.const 65536)))
    )
  )
)
"""

RESIDUE_READER_WAT = r"""
(module
  (memory (export "memory") 1)
  (func (export "_start")
    (local $i i32)
    (loop $r
      (if (i32.ne (i32.load (local.get $i)) (i32.const 0))
        (then unreachable))
      (local.set $i (i32.add (local.get $i) (i32.const 4)))
      (br_if $r (i32.lt_u (local.get $i) (i32.const 65536)))
    )
  )
)
"""


def _write_modules(tmp_path):
    writer = tmp_path / "secret_writer.wasm"
    reader = tmp_path / "residue_reader.wasm"
    writer.write_bytes(wasmtime.wat2wasm(SECRET_WRITER_WAT))
    reader.write_bytes(wasmtime.wat2wasm(RESIDUE_READER_WAT))
    return writer, reader


def test_no_residues_within_sandbox_instance(tmp_path):
    """Same sandbox, back-to-back runs: the second guest sees only zeros."""
    writer, reader = _write_modules(tmp_path)
    config = WASIConfig(max_fuel=10_000_000, timeout_seconds=10)
    sandbox = WASISandbox(config=config)
    try:
        first = sandbox.run(str(writer))
        assert first.status == ExecutionStatus.SUCCESS, first.stderr
        second = sandbox.run(str(reader))
        assert second.status == ExecutionStatus.SUCCESS, (
            "residues of the previous run observed: " + (second.stderr or "")[:120]
        )
    finally:
        sandbox.cleanup()


def test_no_residues_across_pooled_engine(tmp_path):
    """Different sandboxes sharing the pooled engine: module reuse must not
    carry data — the reader starts from zeroed memory."""
    writer, reader = _write_modules(tmp_path)
    config = WASIConfig(max_fuel=10_000_000, timeout_seconds=10)
    first = run_wasm(str(writer), config=config)
    assert first.status == ExecutionStatus.SUCCESS, first.stderr
    second = run_wasm(str(reader), config=config)
    assert second.status == ExecutionStatus.SUCCESS, (
        "residues observed across pooled runs: " + (second.stderr or "")[:120]
    )
