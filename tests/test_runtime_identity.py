# SPDX-License-Identifier: BUSL-1.1
# Copyright 2026 Michael Soppa
"""The execution gate follows the exact native file the bindings load.

The first implementation accepted any ``_libwasmtime*`` file under the package
that had the qualified digest. A swapped loaded library plus a qualified backup
copy therefore passed ``doctor``. These tests pin the contract:

* the path is derived exactly as ``wasmtime/_ffi.py`` derives it;
* the verdict is the digest of that file, not of a sibling;
* the gate refuses a mismatch before its import probe;
* a real swapped-dylib run ends in the environment error class, while the same
  unmodified copy still runs (positive control).
"""

from __future__ import annotations

import hashlib
import importlib.metadata as metadata
import json
import os
import platform
import shutil
import subprocess
import sys
from pathlib import Path

import pytest

from ephemora_cell import runtime_qualification as rq

REPO = Path(__file__).resolve().parents[1]
HELLO = REPO / "examples" / "hello.wasm"


def _expected_loader_path(wasmtime_file: str) -> Path:
    sys_platform = "android" if hasattr(sys, "getandroidapilevel") else sys.platform
    if sys_platform in ("linux", "android"):
        libname = "_libwasmtime.so"
    elif sys_platform == "win32":
        libname = "_wasmtime.dll"
    elif sys_platform == "darwin":
        libname = "_libwasmtime.dylib"
    else:
        pytest.skip(f"wasmtime does not support {sys_platform}")
    machine = platform.machine()
    if machine == "AMD64":
        machine = "x86_64"
    if machine in ("arm64", "ARM64"):
        machine = "aarch64"
    return Path(wasmtime_file).resolve().parent / f"{sys_platform}-{machine}" / libname


def test_native_library_path_matches_the_bindings_loader():
    wasmtime = pytest.importorskip("wasmtime")
    assert rq.native_library_path() == _expected_loader_path(wasmtime.__file__)


def test_identity_hashes_the_exact_file():
    wasmtime = pytest.importorskip("wasmtime")
    identity = rq.native_engine_identity()
    assert identity.path == _expected_loader_path(wasmtime.__file__)
    assert identity.path is not None and identity.path.is_file()
    assert identity.sha256 == hashlib.sha256(identity.path.read_bytes()).hexdigest()
    if identity.sha256 != rq.QUALIFIED_ENGINE_SHA256:
        pytest.skip("installed engine is not the qualified build")
    assert identity.match is True


def test_a_layout_change_fails_closed_on_the_qualified_platform(monkeypatch):
    monkeypatch.setattr(rq, "native_library_path", lambda: None)
    monkeypatch.setattr(rq, "qualified_platform", lambda: True)
    assert rq.native_engine_identity().match is False


def test_gate_refuses_a_mismatch_before_the_import_probe(monkeypatch):
    monkeypatch.setattr(rq, "reported_runtime_version", lambda: "49.0.4")
    monkeypatch.setattr(
        rq,
        "native_engine_identity",
        lambda: rq.NativeEngineIdentity(
            Path("/tmp/_libwasmtime.dylib"), "0" * 64, False, "digest differs"
        ),
    )

    def must_not_import():
        raise AssertionError("the gate ran the import probe before deciding")

    monkeypatch.setattr(rq, "import_error", must_not_import)
    ok, why = rq.runtime_qualification()
    assert ok is False
    assert "does not match" in why
    assert rq.UNQUALIFIED_RUNTIME_ENV in why


def test_gate_accepts_a_matching_identity(monkeypatch):
    monkeypatch.setattr(rq, "reported_runtime_version", lambda: "49.0.4")
    monkeypatch.setattr(
        rq,
        "native_engine_identity",
        lambda: rq.NativeEngineIdentity(
            Path("/tmp/_libwasmtime.dylib"),
            rq.QUALIFIED_ENGINE_SHA256,
            True,
            "match",
        ),
    )
    monkeypatch.setattr(rq, "import_error", lambda: None)
    ok, why = rq.runtime_qualification()
    assert ok is True
    assert "native identity verified" in why


def test_gate_off_platform_checks_only_the_line(monkeypatch):
    monkeypatch.setattr(rq, "reported_runtime_version", lambda: "49.0.4")
    monkeypatch.setattr(
        rq,
        "native_engine_identity",
        lambda: rq.NativeEngineIdentity(None, None, None, "no reference"),
    )
    monkeypatch.setattr(rq, "import_error", lambda: None)
    ok, why = rq.runtime_qualification()
    assert ok is True
    assert "native identity verified" not in why


@pytest.mark.skipif(
    not rq.qualified_platform(),
    reason="the exact-file contract is only claimed on the qualified platform",
)
def test_swapped_dylib_is_refused_and_the_unmodified_copy_runs(tmp_path):
    wasmtime = pytest.importorskip("wasmtime")
    installed = rq.native_engine_identity()
    if installed.sha256 != rq.QUALIFIED_ENGINE_SHA256:
        pytest.skip("installed engine is not the qualified build")

    package_dir = Path(wasmtime.__file__).resolve().parent
    dist_info = metadata.distribution("wasmtime")._path
    exact_rel = installed.path.relative_to(package_dir)

    copy = tmp_path / "wasmtime"
    shutil.copytree(package_dir, copy)
    shutil.copytree(dist_info, tmp_path / Path(dist_info).name)
    copied_exact = copy / exact_rel
    original = copied_exact.read_bytes()

    # A qualified backup must not mask the loaded file.
    (copied_exact.parent / (copied_exact.name + ".bak")).write_bytes(original)
    swapped = bytearray(original)
    swapped[len(swapped) // 2] ^= 0xFF
    copied_exact.write_bytes(bytes(swapped))

    env = os.environ.copy()
    env["PYTHONPATH"] = f"{tmp_path}{os.pathsep}{REPO}"
    env.pop(rq.UNQUALIFIED_RUNTIME_ENV, None)
    code = (
        "import sys; from ephemora_cell.cli import main; "
        f"sys.argv = ['ephemora-cell', 'run', {str(HELLO)!r}, '--json']; "
        "raise SystemExit(main())"
    )

    def run_cli() -> subprocess.CompletedProcess[str]:
        return subprocess.run(
            [sys.executable, "-c", code],
            capture_output=True,
            text=True,
            env=env,
            cwd=REPO,
            timeout=120,
        )

    refused = run_cli()
    assert refused.returncode == 4, (refused.stdout, refused.stderr)
    document = json.loads(refused.stdout)
    assert document["error_class"] == "environment"
    assert "does not match" in document["runtime_qualification"]
    assert "status" not in document or document["status"] == "error"

    # Positive control: the same copy, with the original bytes, runs.
    copied_exact.write_bytes(original)
    (copied_exact.parent / (copied_exact.name + ".bak")).unlink()
    accepted = run_cli()
    assert accepted.returncode == 0, (accepted.stdout, accepted.stderr)
    assert json.loads(accepted.stdout)["status"] == "success"
