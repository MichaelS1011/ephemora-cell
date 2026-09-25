"""Persistence / worm probe class (AgentWorm-class, 2026).

Motivation: 2026 worm research (self-propagating agent payloads via
persistent storage — the Anthropic/EPFL persistence demonstration; the
npx/uvx "installation = execution" worm incidents recorded as
SANDWORM_MODE/Shai-Hulud in docs/comparison-mcp-servers.md) makes
cross-run persistence the key worm prerequisite. A worm in Cell's threat
model needs one thing Cell must deny: a place where run N leaves
something run N+1 sees WITHOUT an explicit host grant.

Probes:
* W-1  guest writes a marker into its /sandbox scratch — a FRESH run
  (fresh sandbox dir, same instance or not) must never see it;
* W-1c reader positive control: the reader module detects a marker when
  one IS legitimately present (proves detection, not a broken harness);
* W-2  named state exists ONLY behind the explicit ADR-004 grant —
  covered by tests/test_state.py::test_no_state_store_no_imports
  (referenced, not duplicated).

Memory residue between sequential instances is guarded by
tests/test_memory_hygiene.py (CVE-2026-34988 standing guard).
"""

from __future__ import annotations

import os
import sys

sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))

import wasmtime

from ephemora_cell import ExecutionStatus, WASIConfig, WASISandbox

# Writer: create + write "PERSIST-MARKER-42" into marker.txt on the
# preopen dirfd 3; exit 0 only when the write fully succeeded.
MARKER_WRITER_WAT = """(module
  (import "wasi_snapshot_preview1" "path_open" (func $po
    (param i32 i32 i32 i32 i32 i64 i64 i32 i32) (result i32)))
  (import "wasi_snapshot_preview1" "fd_write" (func $fw
    (param i32 i32 i32 i32) (result i32)))
  (import "wasi_snapshot_preview1" "proc_exit" (func $exit (param i32)))
  (memory (export "memory") 1)
  (data (i32.const 0) "marker.txt")
  (data (i32.const 32) "PERSIST-MARKER-42")
  (func (export "_start")
    (local $err i32)
    ;; path_open marker.txt, oflags=CREAT (1), rights=fd_write (0x40)
    i32.const 3 i32.const 0 i32.const 0 i32.const 10 i32.const 1
    i64.const 64 i64.const 0 i32.const 0 i32.const 100
    call $po local.set $err
    local.get $err if local.get $err call $exit end
    ;; iov[0] = {ptr=32, len=17}; fd_write(fd=mem[100], iov, 1, &n)
    i32.const 64 i32.const 32 i32.store
    i32.const 68 i32.const 17 i32.store
    i32.const 100 i32.load i32.const 64 i32.const 1 i32.const 72
    call $fw local.set $err
    local.get $err call $exit
  )
)"""

# Reader: path_open marker.txt read-only on dirfd 3; exit with the errno
# (0 = the marker IS there — persistence observed; nonzero = absent).
MARKER_READER_WAT = """(module
  (import "wasi_snapshot_preview1" "path_open" (func $po
    (param i32 i32 i32 i32 i32 i64 i64 i32 i32) (result i32)))
  (import "wasi_snapshot_preview1" "proc_exit" (func $exit (param i32)))
  (memory (export "memory") 1)
  (data (i32.const 0) "marker.txt")
  (func (export "_start")
    (local $err i32)
    ;; oflags=0 (existing only), rights=fd_read (0x2)
    i32.const 3 i32.const 0 i32.const 0 i32.const 10 i32.const 0
    i64.const 2 i64.const 0 i32.const 0 i32.const 100
    call $po local.set $err
    local.get $err call $exit
  )
)"""


def _write_probe(tmp_path, wat: str, name: str):
    path = tmp_path / name
    path.write_bytes(wasmtime.wat2wasm(wat))
    return path


def _run(wasm_path, allow_dirs=None):
    config = WASIConfig(
        max_fuel=1_000_000,
        timeout_seconds=10,
        allow_dirs=(allow_dirs,) if allow_dirs else (),
    )
    sandbox = WASISandbox(config=config)
    try:
        return sandbox.run(str(wasm_path))
    finally:
        sandbox.cleanup()


class TestPersistenceWorm:
    def test_writer_writes_marker(self, tmp_path):
        """Writer sanity: the marker lands (proves the probe writes)."""
        writer = _write_probe(tmp_path, MARKER_WRITER_WAT, "writer.wasm")
        result = _run(writer)
        assert result.status is ExecutionStatus.SUCCESS, result.stderr
        assert result.exit_code == 0, result.stderr

    def test_reader_detects_legitimate_marker(self, tmp_path):
        """W-1c reader positive control via a real allow_dir: when the
        marker EXISTS, the reader must see it (detection works)."""
        base = tmp_path / "base"
        base.mkdir()
        (base / "marker.txt").write_text("PERSIST-MARKER-42")
        reader = _write_probe(tmp_path, MARKER_READER_WAT, "reader.wasm")
        result = _run(reader, allow_dirs=str(base))
        assert result.status is ExecutionStatus.SUCCESS, result.stderr
        assert result.exit_code == 0, "harness broken: reader missed the marker"

    def test_fresh_run_sees_no_marker(self, tmp_path):
        """W-1 core probe: run N writes the marker into its scratch —
        run N+1 (fresh sandbox dir) finds NOTHING there."""
        writer = _write_probe(tmp_path, MARKER_WRITER_WAT, "writer.wasm")
        reader = _write_probe(tmp_path, MARKER_READER_WAT, "reader.wasm")
        first = _run(writer)
        assert first.status is ExecutionStatus.SUCCESS, first.stderr
        second = _run(reader)
        # dirfd 3 is the fresh /sandbox scratch: the marker must be gone
        # (path_open fails with ENOENT → non-zero proc_exit, so the run
        # reports a non-SUCCESS status with that errno as exit_code).
        assert second.exit_code != 0, (
            "persistence observed: a later run sees the previous run's "
            "scratch content — worm prerequisite NOT denied"
        )

    def test_same_instance_repeat_run_sees_no_marker(self, tmp_path):
        """Repeat-run on ONE sandbox instance also gets a fresh scratch
        (the leak-guard cleans prior dirs) — no residue channel."""
        writer = _write_probe(tmp_path, MARKER_WRITER_WAT, "writer.wasm")
        reader = _write_probe(tmp_path, MARKER_READER_WAT, "reader.wasm")
        config = WASIConfig(max_fuel=1_000_000, timeout_seconds=10)
        sandbox = WASISandbox(config=config)
        try:
            first = sandbox.run(str(writer))
            assert first.status is ExecutionStatus.SUCCESS, first.stderr
            second = sandbox.run(str(reader))
            assert second.exit_code != 0, "residue channel across repeat runs"
        finally:
            sandbox.cleanup()

    def test_no_state_store_no_state_imports(self, tmp_path):
        """W-2: without the ADR-004 grant the state imports do not exist
        (referenced coverage — the structural negative lives in
        tests/test_state.py::test_no_state_store_no_imports; here as the
        worm-flavored end-to-end probe: a state-importing module fails
        closed)."""
        state_wat = """(module
          (import "ephemora_state" "get" (func $get (param i32 i32 i32) (result i32)))
          (func (export "_start"))
        )"""
        wasm = _write_probe(tmp_path, state_wat, "state_thief.wasm")
        result = _run(wasm)
        assert (
            result.status is not ExecutionStatus.SUCCESS
        ), "state import resolved WITHOUT the ADR-004 grant"
