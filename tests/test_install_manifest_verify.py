# SPDX-License-Identifier: BUSL-1.1
# Copyright 2026 Michael Soppa

"""Release-set integrity: the manifest must reject altered or missing bytes (v1.2).

Runs ``scripts/release_manifest.py verify`` — the same command the release
process uses — against the recorded artifact set, then against a copy whose
bytes were changed. The set lives in the audit tree, so the cases skip where it
is absent.
"""

from __future__ import annotations

import os
import shutil
import subprocess
import sys
from pathlib import Path

sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))

import pytest

REPO = Path(__file__).resolve().parent.parent
RELEASE_SET = Path(os.environ.get("EPHEMORA_RELEASE_SET", REPO / "dist"))
_SCRIPT = REPO / "scripts" / "release_manifest.py"


def _verify(set_dir: Path):
    return subprocess.run(
        [sys.executable, str(_SCRIPT), "verify", "--set", str(set_dir)],
        capture_output=True,
        text=True,
        timeout=300,
        cwd=str(REPO),
    )


@pytest.fixture()
def release_copy(tmp_path):
    if not RELEASE_SET.is_dir():
        pytest.skip("release artifact set not present on this machine")
    target = tmp_path / "set"
    # `verify` describes the distributable set; signatures, the public key and
    # the SBOM live beside it and are checked separately, not by the manifest.
    shutil.copytree(
        RELEASE_SET,
        target,
        ignore=shutil.ignore_patterns("*.sig", "*.pub.pem", "sbom*"),
    )
    return target


def test_the_release_set_matches_its_manifest(release_copy):
    result = _verify(release_copy)
    assert result.returncode == 0, result.stdout + result.stderr
    assert "OK:" in result.stdout


def test_a_tampered_artifact_fails_the_manifest(release_copy):
    wheels = sorted(release_copy.glob("ephemora_cell-*.whl"))
    assert wheels, "expected a core wheel in the set"
    target = wheels[0]
    before = target.stat().st_size
    with open(target, "ab") as handle:
        handle.write(b"\x00")
    assert target.stat().st_size == before + 1  # the mutation is real

    result = _verify(release_copy)
    assert result.returncode == 1, result.stdout + result.stderr
    assert "sha256" in result.stdout


def test_a_missing_file_fails_the_manifest(release_copy):
    os.unlink(release_copy / "SHA256SUMS")
    result = _verify(release_copy)
    assert result.returncode != 0, result.stdout + result.stderr
