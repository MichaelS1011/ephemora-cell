# SPDX-License-Identifier: BUSL-1.1
# Copyright 2026 Michael Soppa

"""License metadata consistency of the release artifacts (v1.2).

Checks what can be checked mechanically on the shipped 1.2.0 artifacts: PEP 639
license metadata, the license documents travelling inside the wheels and the
sdist, and that every third-party wheel in the set is named in the notices. It
does NOT decide redistribution rights — that is the legal step (v1.2).

The artifact set lives in the audit tree, so the cases skip where it is absent.
"""

from __future__ import annotations

import os
import tarfile
import zipfile
from pathlib import Path

import pytest

REPO = Path(__file__).resolve().parent.parent
RELEASE_SET = Path(os.environ.get("EPHEMORA_RELEASE_SET", REPO / "dist"))
pytestmark = pytest.mark.skipif(
    not RELEASE_SET.is_dir(),
    reason="release artifact set not present (set EPHEMORA_RELEASE_SET to a built set)",
)

_THIRD_PARTY = ("certifi", "wasmtime")


def _wheels() -> list[Path]:
    if not RELEASE_SET.is_dir():
        pytest.skip("release artifact set not present on this machine")
    return sorted(RELEASE_SET.glob("*.whl"))


def _metadata(wheel: Path) -> str:
    with zipfile.ZipFile(wheel) as archive:
        name = next(n for n in archive.namelist() if n.endswith(".dist-info/METADATA"))
        return archive.read(name).decode("utf-8", "replace")


def _notice_text() -> str:
    sdist = next(RELEASE_SET.glob("*.tar.gz"))
    with tarfile.open(sdist) as archive:
        member = next(
            n for n in archive.getnames() if n.endswith("THIRD_PARTY_NOTICES.md")
        )
        return archive.extractfile(member).read().decode("utf-8", "replace")


def test_every_wheel_declares_a_license():
    """PEP 639 expression where we build the wheel, legacy field tolerated upstream.

    Our own wheels carry ``License-Expression``; an upstream wheel may still use
    the older ``License:`` field (certifi ships MPL-2.0 that way). Demanding the
    modern field from a third party would fail on metadata we do not own.
    """
    for wheel in _wheels():
        text = _metadata(wheel)
        assert (
            "License-Expression:" in text or "License:" in text
        ), f"{wheel.name} declares no license at all"


def test_the_ephemora_packages_are_busl_licensed():
    checked = 0
    for wheel in _wheels():
        text = _metadata(wheel)
        name = next(line for line in text.splitlines() if line.startswith("Name:"))
        if name.split(":", 1)[1].strip().startswith("ephemora-cell"):
            assert "License-Expression: BUSL-1.1" in text, wheel.name
            checked += 1
    assert checked >= 3  # core + python guest + javascript guest


def test_the_runtime_wheel_keeps_its_upstream_license():
    for wheel in _wheels():
        if wheel.name.startswith("wasmtime-"):
            text = _metadata(wheel)
            assert "Apache-2.0 WITH LLVM-exception" in text, wheel.name


def test_license_documents_travel_inside_the_wheels():
    for wheel in _wheels():
        with zipfile.ZipFile(wheel) as archive:
            names = [n for n in archive.namelist() if "/licenses/" in n]
        assert any(n.endswith("/LICENSE") for n in names), wheel.name


def test_the_sdist_carries_both_license_documents():
    sdist = next(RELEASE_SET.glob("*.tar.gz"))
    with tarfile.open(sdist) as archive:
        names = archive.getnames()
    assert any(n.endswith("/LICENSE") for n in names), names
    assert any(n.endswith("THIRD_PARTY_NOTICES.md") for n in names), names


def test_every_third_party_wheel_in_the_set_is_named_in_the_notices():
    notices = _notice_text().lower()
    wheels = [w.name.lower() for w in _wheels()]
    for package in _THIRD_PARTY:
        assert any(w.startswith(package) for w in wheels), package
        assert package in notices, f"{package} is shipped but not in the notices"
