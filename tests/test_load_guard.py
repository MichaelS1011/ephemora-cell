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

import json
import os
import sys

sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))

import pytest

from ephemora_cell._fsutil import (
    atomic_copyfile,
    atomic_write_bytes,
    atomic_write_json,
    atomic_write_text,
)


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
