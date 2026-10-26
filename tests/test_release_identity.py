"""Tests for the release-identity manifest (scripts/release_identity.py).

The manifest is the answer to "which artifact did you actually test?" — so these
tests pin the properties that make it worth trusting: it names the commit, it
names the bytes, it repeats identically, and it refuses to call a dirty or
labelled build publishable.
"""

from __future__ import annotations

import hashlib
import importlib.util
import json
import re
from pathlib import Path

_ROOT = Path(__file__).resolve().parents[1]
_spec = importlib.util.spec_from_file_location(
    "release_identity", _ROOT / "scripts" / "release_identity.py"
)
assert _spec and _spec.loader
ident = importlib.util.module_from_spec(_spec)
_spec.loader.exec_module(ident)


def _run(tmp_path: Path, *extra: str) -> dict:
    out = tmp_path / "identity.json"
    rc = ident.main(["--dist", str(tmp_path / "dist"), "--out", str(out), *extra])
    assert rc == 0
    return json.loads(out.read_text(encoding="utf-8"))


def test_manifest_binds_commit_and_artifact_bytes(tmp_path: Path) -> None:
    dist = tmp_path / "dist"
    dist.mkdir()
    payload = b"not a real wheel, but real bytes"
    (dist / "ephemora_cell-0.0.0-py3-none-any.whl").write_bytes(payload)

    manifest = _run(tmp_path)
    assert manifest["schema"] == "ephemora-cell/release-identity/1"
    assert re.fullmatch(r"[0-9a-f]{40}", manifest["source"]["commit"])
    assert re.fullmatch(r"[0-9a-f]{40}", manifest["source"]["tree"])
    entry = manifest["artifacts"][0]
    assert entry["name"] == "ephemora_cell-0.0.0-py3-none-any.whl"
    assert entry["bytes"] == len(payload)
    assert entry["sha256"] == hashlib.sha256(payload).hexdigest()
    # The identity string is the human-readable handle an evidence run quotes.
    assert manifest["source"]["commit"][:12] in manifest["identity"]
    assert entry["sha256"][:12] in manifest["identity"]


def test_native_runtime_is_named_by_bytes_not_by_version_range(tmp_path: Path) -> None:
    (tmp_path / "dist").mkdir()
    engine = _run(tmp_path)["native_runtime"]
    if not engine.get("importable"):  # pragma: no cover - env without wasmtime
        return
    assert engine["wasmtime_version"]
    assert engine["native_libraries"]
    for lib in engine["native_libraries"]:
        assert re.fullmatch(r"[0-9a-f]{64}", lib["sha256"])
        assert lib["bytes"] > 0


def test_missing_artifacts_block_publication(tmp_path: Path) -> None:
    manifest = _run(tmp_path)
    assert manifest["publishable"] is False
    assert any("no distribution artifacts" in b for b in manifest["publish_blockers"])


def test_dirty_worktree_blocks_publication(tmp_path: Path) -> None:
    # The repository under test carries uncommitted work during a gate run; the
    # manifest must then refuse the publishable flag rather than imply a clean
    # release identity.
    dist = tmp_path / "dist"
    dist.mkdir()
    (dist / "x-0.0.0.tar.gz").write_bytes(b"tarball")
    manifest = _run(tmp_path)
    if manifest["source"]["worktree_dirty"]:
        assert manifest["publishable"] is False
        assert any("uncommitted" in b for b in manifest["publish_blockers"])


def test_manifest_is_reproducible(tmp_path: Path) -> None:
    dist = tmp_path / "dist"
    dist.mkdir()
    (dist / "ephemora_cell-0.0.0-py3-none-any.whl").write_bytes(b"abc")
    first = json.dumps(_run(tmp_path), sort_keys=True)
    second = json.dumps(_run(tmp_path), sort_keys=True)
    assert first == second


def test_container_block_degrades_honestly_without_an_image(tmp_path: Path) -> None:
    (tmp_path / "dist").mkdir()
    container = _run(tmp_path)["reference_container"]
    assert container["image_ref"] is None
    assert "note" in container
    assert "image_id" not in container


def test_base_image_digest_is_read_from_the_reference_dockerfile(
    tmp_path: Path,
) -> None:
    (tmp_path / "dist").mkdir()
    dockerfile = tmp_path / "Dockerfile"
    digest = "sha256:" + "ab" * 32
    dockerfile.write_text(f"FROM python:3.12-slim@{digest}\n", encoding="utf-8")
    out = tmp_path / "identity.json"
    ident.main(
        [
            "--dist",
            str(tmp_path / "dist"),
            "--image",
            "definitely-not-built:0",
            "--dockerfile",
            str(dockerfile),
            "--out",
            str(out),
        ]
    )
    container = json.loads(out.read_text(encoding="utf-8"))["reference_container"]
    assert container["base_image_digests"] == [digest]
    assert container["base_digest_pinned"] is True
    # An unbuildable ref is recorded as unreachable instead of silently missing.
    assert container["reachable"] is False
