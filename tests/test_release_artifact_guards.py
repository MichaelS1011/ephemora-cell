"""The release-artifact guards must refuse what they say they refuse.

`scripts/release_manifest.py` tells a user that a directory matching the manifest
is the set that was measured, and `scripts/license_matrix.py` tells a
redistribution reviewer that every distribution carries its licence text. Both
statements were wrong in the first version, in ways an independent review found
on 2026-10-20:

* `verify` skipped the three generated files, so a `requirements-release.txt`
  whose pins had been rewritten — the file pip consumes with `--require-hashes` —
  still verified OK.
* `verify` did not check the role set, so a manifest describing four of five
  artifacts plus a deleted wheel was blessed.
* `license_matrix.py` counted `AUTHORS.md` as a licence file, so a wheel with no
  licence text at all passed.

These tests build a small synthetic set (no real artifacts needed) and pin the
refusals. They are acceptance tests for the guard's own promises, not coverage
theatre: each one fails if the corresponding hole comes back.
"""

from __future__ import annotations

import importlib.util
import io
import json
import subprocess
import tarfile
import zipfile
from pathlib import Path

import pytest

REPO = Path(__file__).resolve().parents[1]


def _load(name: str):
    spec = importlib.util.spec_from_file_location(name, REPO / "scripts" / f"{name}.py")
    module = importlib.util.module_from_spec(spec)
    assert spec.loader is not None
    spec.loader.exec_module(module)
    return module


try:
    manifest_mod = _load("release_manifest")
    license_mod = _load("license_matrix")
except FileNotFoundError:  # unpacked sdist: `scripts/` is not shipped there
    pytest.skip("scripts/ is not part of the distribution", allow_module_level=True)

HEAD = subprocess.run(
    ["git", "rev-parse", "HEAD"], cwd=REPO, capture_output=True, text=True, check=True
).stdout.strip()

LICENCE_TEXT = "Business Source License 1.1\n\n" + ("terms " * 60)


def _wheel(path: Path, dist: str, version: str, members: dict[str, bytes]) -> None:
    info = f"{dist.replace('-', '_')}-{version}.dist-info"
    with zipfile.ZipFile(path, "w") as archive:
        archive.writestr(f"{dist.replace('-', '_')}/__init__.py", b"")
        archive.writestr(
            f"{info}/METADATA",
            f"Metadata-Version: 2.4\nName: {dist}\nVersion: {version}\n".encode(),
        )
        for name, data in members.items():
            archive.writestr(f"{info}/{name}", data)


def build_set(root: Path) -> Path:
    root.mkdir(parents=True, exist_ok=True)
    _wheel(
        root / "ephemora_cell-1.0-py3-none-any.whl",
        "ephemora-cell",
        "1.0",
        {"licenses/LICENSE": LICENCE_TEXT.encode()},
    )
    with tarfile.open(root / "ephemora_cell-1.0.tar.gz", "w:gz") as tar:
        data = LICENCE_TEXT.encode()
        info = tarfile.TarInfo("ephemora_cell-1.0/LICENSE")
        info.size = len(data)
        tar.addfile(info, io.BytesIO(data))
    _wheel(
        root / "wasmtime-9.9.9-py3-none-macosx_11_0_arm64.whl",
        "wasmtime",
        "9.9.9",
        {
            "licenses/LICENSE": b"Apache License\n" + b"terms " * 60,
        },
    )
    # the runtime needs exactly one native library for the identity read
    with zipfile.ZipFile(
        root / "wasmtime-9.9.9-py3-none-macosx_11_0_arm64.whl", "a"
    ) as z:
        z.writestr("wasmtime/darwin-aarch64/_libwasmtime.dylib", b"\x00native")
    _wheel(
        root / "ephemora_cell_python_guest-1.0-py3-none-any.whl",
        "ephemora-cell-python-guest",
        "1.0",
        {
            "licenses/LICENSE": LICENCE_TEXT.encode(),
            "licenses/THIRD_PARTY_NOTICES.md": b"Guest notice sha256 " + b"a" * 64,
        },
    )
    with zipfile.ZipFile(
        root / "ephemora_cell_python_guest-1.0-py3-none-any.whl", "a"
    ) as z:
        z.writestr("ephemora_cell_python_guest/guest.wasm", b"guest-bytes")
    _wheel(
        root / "ephemora_cell_javascript_guest-1.0-py3-none-any.whl",
        "ephemora-cell-javascript-guest",
        "1.0",
        {"licenses/LICENSE": LICENCE_TEXT.encode()},
    )
    return root


@pytest.fixture()
def release_set(tmp_path):
    root = build_set(tmp_path / "set")
    assert manifest_mod.main(["write", "--set", str(root), "--commit", HEAD]) == 0
    return root


def test_a_clean_set_verifies(release_set):
    assert manifest_mod.main(["verify", "--set", str(release_set)]) == 0


def test_an_edited_requirements_file_is_refused(release_set):
    """The pin file is what pip enforces; rewriting it must not verify."""
    target = release_set / manifest_mod.REQUIREMENTS_NAME
    original = target.read_text(encoding="utf-8")
    target.write_text(
        original.replace("--hash=sha256:", "--hash=sha256:0"), encoding="utf-8"
    )
    assert manifest_mod.main(["verify", "--set", str(release_set)]) == 1


def test_an_edited_sums_file_is_refused(release_set):
    target = release_set / manifest_mod.SUMS_NAME
    lines = target.read_text(encoding="utf-8").splitlines()
    lines[0] = "0" * 64 + lines[0][64:]
    target.write_text("\n".join(lines) + "\n", encoding="utf-8")
    assert manifest_mod.main(["verify", "--set", str(release_set)]) == 1


def test_a_manifest_missing_a_role_is_refused(release_set):
    """Dropping a guest from the manifest AND from the directory must not pass."""
    manifest_path = release_set / manifest_mod.MANIFEST_NAME
    manifest = json.loads(manifest_path.read_text(encoding="utf-8"))
    dropped = [a for a in manifest["artifacts"] if a["role"] == "guest-javascript"]
    manifest["artifacts"] = [
        a for a in manifest["artifacts"] if a["role"] != "guest-javascript"
    ]
    manifest_path.write_text(json.dumps(manifest, indent=2, sort_keys=True) + "\n")
    (release_set / dropped[0]["name"]).unlink()
    assert manifest_mod.main(["verify", "--set", str(release_set)]) == 1


def test_an_extra_artifact_is_refused(release_set):
    (release_set / "surprise-1.0-py3-none-any.whl").write_bytes(b"x")
    assert manifest_mod.main(["verify", "--set", str(release_set)]) == 1


def test_write_refuses_an_incomplete_set(tmp_path):
    root = build_set(tmp_path / "partial")
    (root / "ephemora_cell_javascript_guest-1.0-py3-none-any.whl").unlink()
    with pytest.raises(SystemExit) as exc:
        manifest_mod.write_manifest(root, HEAD)
    assert "incomplete" in str(exc.value)


def test_a_wheel_with_only_an_authors_file_is_a_gap(tmp_path, capsys):
    """AUTHORS.md is not a licence. This passed an earlier version."""
    root = build_set(tmp_path / "licence")
    wheel = root / "ephemora_cell-1.0-py3-none-any.whl"
    with (
        zipfile.ZipFile(wheel) as src,
        zipfile.ZipFile(tmp_path / "leaky.whl", "w") as dst,
    ):
        for item in src.infolist():
            if item.filename.endswith("licenses/LICENSE"):
                continue
            dst.writestr(item, src.read(item.filename))
        dst.writestr(
            "ephemora_cell-1.0.dist-info/licenses/AUTHORS.md", b"Michael Soppa\n"
        )
    (tmp_path / "leaky.whl").replace(wheel)
    assert license_mod.main(["--set", str(root)]) == 1
    assert "carries no licence file" in capsys.readouterr().out


def test_an_empty_licence_file_is_a_gap(tmp_path, capsys):
    root = build_set(tmp_path / "empty")
    wheel = root / "ephemora_cell-1.0-py3-none-any.whl"
    with (
        zipfile.ZipFile(wheel) as src,
        zipfile.ZipFile(tmp_path / "empty.whl", "w") as dst,
    ):
        for item in src.infolist():
            data = src.read(item.filename)
            if item.filename.endswith("licenses/LICENSE"):
                data = b"\n"
            dst.writestr(item, data)
    (tmp_path / "empty.whl").replace(wheel)
    assert license_mod.main(["--set", str(root)]) == 1
    assert "empty or a placeholder" in capsys.readouterr().out
