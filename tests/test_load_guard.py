"""Load-guard and atomic-publication guarantees.

Two properties under test:

1. **Atomic publication** — a producer that dies mid-write never leaves a
   partial file under its final name. Readers (registry scan, server
   re-scan, concurrent calls) see either the old content or the complete
   new content, and a failed publish leaves no ``.tmp`` residue behind.
2. **Consumer load-guard** — a tools/requests file is only ever picked up
   when it is complete, well-formed and stable (see the guard tests
   below; added with the load-guard itself).
"""

from __future__ import annotations

import hashlib
import json
import os
import sys
from pathlib import Path

sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))

import pytest
import wasmtime

from ephemora_cell import ExecutionStatus, WASIConfig, WASISandbox
from ephemora_cell._fsutil import (
    atomic_copyfile,
    atomic_write_bytes,
    atomic_write_json,
    atomic_write_text,
    read_stable_bytes,
)
from ephemora_cell.engine_pool import EnginePool
from ephemora_cell.process_executor import run_isolated
from ephemora_cell_mcp.tool_registry import ToolRegistry

# A minimal, compilable WASI preview1 module (clean _start, exit 0).
HELLO_WAT = '(module (func (export "_start")))'
VARIANT_WAT = '(module (func (export "_start")) (func (export "x")))'


class TestAtomicPublication:
    def test_write_publishes_complete_content(self, tmp_path):
        target = tmp_path / "tool.wasm"
        atomic_write_bytes(target, b"\x00asm\x01\x00\x00\x00")
        assert target.read_bytes() == b"\x00asm\x01\x00\x00\x00"

    def test_text_publishes_decoded_content(self, tmp_path):
        target = tmp_path / "sidecar.json"
        atomic_write_text(target, '{"name": "echo"}\n')
        assert target.read_text(encoding="utf-8") == '{"name": "echo"}\n'

    def test_json_matches_sidecar_convention(self, tmp_path):
        target = tmp_path / "sidecar.json"
        atomic_write_json(target, {"name": "echo"})
        raw = target.read_text(encoding="utf-8")
        # Registry convention: indent=2, ensure_ascii=False, trailing \n.
        assert raw == json.dumps({"name": "echo"}, indent=2, ensure_ascii=False) + "\n"
        assert json.loads(raw) == {"name": "echo"}

    def test_copyfile_publishes_content(self, tmp_path):
        src = tmp_path / "src.wasm"
        src.write_bytes(b"\x00asm-payload")
        dst = tmp_path / "dst.wasm"
        atomic_copyfile(src, dst)
        assert dst.read_bytes() == b"\x00asm-payload"

    def test_failed_publish_keeps_old_content(self, tmp_path, monkeypatch):
        target = tmp_path / "tool.wasm"
        target.write_bytes(b"old-complete-content")

        def _boom(src, dst):
            raise OSError("simulated crash between write and replace")

        monkeypatch.setattr(os, "replace", _boom)
        with pytest.raises(OSError, match="simulated crash"):
            atomic_write_bytes(target, b"new-content")
        # The old content survives; no .tmp residue is left behind.
        assert target.read_bytes() == b"old-complete-content"
        assert list(tmp_path.glob("*.tmp")) == []

    def test_failed_first_publish_leaves_no_target(self, tmp_path, monkeypatch):
        target = tmp_path / "tool.wasm"

        def _boom(src, dst):
            raise OSError("simulated crash before the first publish")

        monkeypatch.setattr(os, "replace", _boom)
        with pytest.raises(OSError, match="simulated crash"):
            atomic_write_bytes(target, b"new-content")
        assert not target.exists()
        assert list(tmp_path.glob("*.tmp")) == []


class TestStableRead:
    def test_settled_file_reads_back(self, tmp_path):
        target = tmp_path / "file.bin"
        target.write_bytes(b"settled")
        assert read_stable_bytes(target) == b"settled"

    def test_missing_file_returns_none(self, tmp_path):
        assert read_stable_bytes(tmp_path / "absent.bin") is None

    def test_changing_file_returns_none(self, tmp_path, monkeypatch):
        """A file whose content differs between two reads is not settled —
        the consumer defers instead of parsing/rejecting a partial file."""
        target = tmp_path / "file.bin"
        target.write_bytes(b"final-content")
        real_read = Path.read_bytes
        calls = {"n": 0}

        def flaky_read(self):
            calls["n"] += 1
            if calls["n"] == 1:
                return b"partial-write"  # producer still streaming
            return real_read(self)

        monkeypatch.setattr(Path, "read_bytes", flaky_read)
        assert read_stable_bytes(target) is None


class TestRegistryLoadGuard:
    """The consumer load-guard in ToolRegistry._build_spec (both modes)."""

    def test_garbage_module_not_registered_legacy_mode(self, tmp_path):
        tools = tmp_path / "tools"
        tools.mkdir()
        (tools / "junk.wasm").write_bytes(b"definitely not a module")
        with pytest.warns(RuntimeWarning, match="load guard"):
            registry = ToolRegistry(tools)
        assert registry.list_tools() == []

    def test_oversize_module_not_registered(self, tmp_path, monkeypatch):
        import ephemora_cell_mcp.tool_registry as tr

        monkeypatch.setattr(tr, "DEFAULT_MAX_WASM_BYTES", 8)
        tools = tmp_path / "tools"
        tools.mkdir()
        (tools / "big.wasm").write_bytes(b"\x00asm" + b"\x00" * 32)
        with pytest.warns(RuntimeWarning, match="load guard"):
            registry = ToolRegistry(tools)
        assert registry.list_tools() == []

    def test_valid_module_registers_legacy_mode(self, tmp_path):
        tools = tmp_path / "tools"
        tools.mkdir()
        (tools / "ok.wasm").write_bytes(wasmtime.wat2wasm(HELLO_WAT))
        registry = ToolRegistry(tools)
        assert [t.name for t in registry.list_tools()] == ["ok"]
        # Legacy mode stays disk-truth: no per-call binding.
        assert registry.get("ok").wasm_sha256 is None

    def test_signed_mode_spec_binds_digest(self, tmp_path):
        pytest.importorskip("cryptography")
        from ephemora_cell_mcp.tool_registry import (
            sign_manifest,
            tool_wasm_sha256,
        )

        tools = tmp_path / "tools"
        tools.mkdir()
        wasm_bytes = wasmtime.wat2wasm(HELLO_WAT)
        (tools / "ok.wasm").write_bytes(wasm_bytes)
        manifest = {"name": "ok", "profile": "llm", "allow_dirs": []}
        manifest["wasm_sha256"] = tool_wasm_sha256(tools / "ok.wasm")
        signed = sign_manifest(manifest, lambda data: b"\x01" * 64)
        (tools / "ok.json").write_text(json.dumps(signed), encoding="utf-8")
        registry = ToolRegistry(tools, manifest_verifier=lambda c, s: True)
        spec = registry.get("ok")
        assert spec is not None
        # Signed mode binds the spec to the verified register-time digest.
        assert spec.wasm_sha256 == hashlib.sha256(wasm_bytes).hexdigest()


class TestPerCallBinding:
    """expected_sha256: executed bytes cannot drift from the digest."""

    def _config(self):
        return WASIConfig(max_fuel=100_000, timeout_seconds=10)

    def test_match_executes(self, tmp_path):
        wasm = tmp_path / "hello.wasm"
        wasm.write_bytes(wasmtime.wat2wasm(HELLO_WAT))
        digest = hashlib.sha256(wasm.read_bytes()).hexdigest()
        sandbox = WASISandbox(config=self._config())
        try:
            result = sandbox.run(str(wasm), expected_sha256=digest)
            assert result.status is ExecutionStatus.SUCCESS, result.stderr
        finally:
            sandbox.cleanup()

    def test_mismatch_rejected(self, tmp_path):
        wasm = tmp_path / "hello.wasm"
        wasm.write_bytes(wasmtime.wat2wasm(HELLO_WAT))
        sandbox = WASISandbox(config=self._config())
        try:
            result = sandbox.run(str(wasm), expected_sha256="ff" * 32)
            assert result.status is ExecutionStatus.ERROR
            assert "hash mismatch" in (result.stderr or "")
        finally:
            sandbox.cleanup()

    def test_mismatch_rejected_via_pooled_engine(self, tmp_path):
        wasm = tmp_path / "hello.wasm"
        wasm.write_bytes(wasmtime.wat2wasm(HELLO_WAT))
        sandbox = WASISandbox(config=self._config())
        try:
            result = sandbox.run(
                str(wasm), use_engine_pool=True, expected_sha256="ee" * 32
            )
            assert result.status is ExecutionStatus.ERROR
            assert "hash mismatch" in (result.stderr or "")
        finally:
            sandbox.cleanup()

    def test_mismatch_rejected_via_subprocess(self, tmp_path):
        wasm = tmp_path / "hello.wasm"
        wasm.write_bytes(wasmtime.wat2wasm(HELLO_WAT))
        report = run_isolated(str(wasm), self._config(), expected_sha256="dd" * 32)
        assert report["status"] is ExecutionStatus.ERROR
        assert "hash mismatch" in report["stderr"]

    def test_match_executes_via_subprocess(self, tmp_path):
        wasm = tmp_path / "hello.wasm"
        wasm.write_bytes(wasmtime.wat2wasm(HELLO_WAT))
        digest = hashlib.sha256(wasm.read_bytes()).hexdigest()
        report = run_isolated(str(wasm), self._config(), expected_sha256=digest)
        assert report["status"] is ExecutionStatus.SUCCESS, report["stderr"]


class TestModuleCacheContentKeyed:
    """EnginePool cache: keyed by content hash — no stat/open race, no
    stale-serve for a mtime-preserving swap."""

    def _pool_and_engine(self):
        pool = EnginePool(max_engines=1)
        engine = pool.engine_for(WASIConfig())
        return pool, engine

    def test_same_bytes_return_same_module_object(self):
        pool, engine = self._pool_and_engine()
        data = wasmtime.wat2wasm(HELLO_WAT)
        first = pool.cached_module_data(engine, data)
        second = pool.cached_module_data(engine, data)
        assert first is second

    def test_different_bytes_compile_distinct_modules(self):
        pool, engine = self._pool_and_engine()
        a = pool.cached_module_data(engine, wasmtime.wat2wasm(HELLO_WAT))
        b = pool.cached_module_data(engine, wasmtime.wat2wasm(VARIANT_WAT))
        assert a is not b


class TestRequestFileDeferral:
    """Unstable request files are deferred, not parsed or rejected."""

    def _server_with_request(self, tmp_path):
        from ephemora_cell_mcp.server import Server
        from ephemora_cell_mcp.tool_registry import TOOL_REQUEST_SUFFIX
        from ephemora_cell_mcp.transport import MemoryTransport

        tools = tmp_path / "tools"
        requests = tmp_path / "requests"
        tools.mkdir()
        requests.mkdir()
        (requests / "widget.tool.request.json".replace("widget.", "widget."))
        request_file = requests / f"widget{TOOL_REQUEST_SUFFIX}"
        request_file.write_text("{}", encoding="utf-8")
        server = Server(
            tools_dir=tools,
            transport=MemoryTransport(),
            tool_requests_dir=requests,
        )
        return server, request_file

    def test_unstable_request_deferred_not_rejected(self, tmp_path, monkeypatch):
        import ephemora_cell_mcp.server as server_mod

        server, request_file = self._server_with_request(tmp_path)
        monkeypatch.setattr(server_mod, "read_stable_bytes", lambda path: None)
        report = server.process_tool_requests()
        assert report["accepted"] == []
        assert report["rejected"] == []
        assert report["pending"] == [request_file.name]
        # Deferred files stay on disk and are retried on the next tick.
        assert request_file.exists()

    def test_no_pending_key_when_nothing_deferred(self, tmp_path, monkeypatch):
        import ephemora_cell_mcp.server as server_mod

        server, _request_file = self._server_with_request(tmp_path)
        monkeypatch.setattr(server_mod, "read_stable_bytes", lambda path: b"{}")
        report = server.process_tool_requests()
        # Report shape unchanged when nothing was deferred (compat).
        assert report == {
            "accepted": [],
            "rejected": [
                {
                    "request": "widget.tool.request.json",
                    "reason": report["rejected"][0]["reason"],
                }
            ],
        }
        assert "pending" not in report
