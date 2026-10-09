"""Project meta invariants — the relicense to BUSL-1.1 (d64b7b9) pinned.

The license changed at the source level; these tests make the resulting
invariants machine-checked instead of remembered:

- every shipped module carries the SPDX header within its first lines,
- no shipped module still announces the old license up front,
- the packaged LICENSE copy is byte-identical to the root one,
- the root LICENSE is the real BUSL-1.1 text with all four parameters,
- pyproject.toml declares BUSL-1.1.
"""

from __future__ import annotations

import os
import sys
from pathlib import Path

sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))

REPO = Path(__file__).resolve().parent.parent
SPDX = "# SPDX-License-Identifier: BUSL-1.1"


def _package_py_files() -> list[Path]:
    files: list[Path] = []
    for package in ("ephemora_cell", "ephemora_cell_mcp"):
        files.extend(sorted((REPO / package).rglob("*.py")))
    assert files, "package discovery found no .py files — paths moved?"
    return files


def test_every_module_carries_spdx_busl_header():
    """Each shipped .py names BUSL-1.1 in its first 3 lines."""
    for path in _package_py_files():
        head = path.read_text(encoding="utf-8", errors="replace").splitlines()[:3]
        assert any(
            line.strip() == SPDX for line in head
        ), f"{path.relative_to(REPO)}: missing '{SPDX}' in its first 3 lines"


def test_no_module_announces_apache_up_front():
    """The license change must not leave stale Apache-2.0 headers in the
    first 5 lines of shipped modules (the Apache conversion terms live in
    the LICENSE text itself — this pins the module headers only)."""
    for path in _package_py_files():
        head = path.read_text(encoding="utf-8", errors="replace").splitlines()[:5]
        assert not any(
            "Apache-2.0" in line for line in head
        ), f"{path.relative_to(REPO)}: first 5 lines still mention Apache-2.0"


def test_packaged_license_is_byte_identical_to_root():
    """ephemera_cell/LICENSE ships inside the wheel — it must never drift
    from the root LICENSE the badge and README point at."""
    root = (REPO / "LICENSE").read_bytes()
    packaged = (REPO / "ephemora_cell" / "LICENSE").read_bytes()
    assert (
        root == packaged
    ), "ephemora_cell/LICENSE differs from the root LICENSE — re-copy it"


def test_root_license_is_busl_1_1_with_all_parameters():
    """The root LICENSE text is the Business Source License 1.1 including
    its four changeable parameters (Licensor, Additional Use Grant,
    Change Date, Change License)."""
    text = (REPO / "LICENSE").read_text(encoding="utf-8")
    assert "Business Source License 1.1" in text
    for parameter in (
        "Licensor:",
        "Additional Use Grant:",
        "Change Date:",
        "Change License:",
    ):
        assert parameter in text, f"LICENSE is missing the {parameter!r} parameter"


def test_pyproject_declares_busl_license():
    """pyproject.toml declares BUSL-1.1 as a PEP 639 SPDX expression (text-level
    check — no tomllib dependency on Python 3.10)."""
    text = (REPO / "pyproject.toml").read_text(encoding="utf-8")
    assert (
        'license = "BUSL-1.1"' in text
    ), 'pyproject.toml must declare license = "BUSL-1.1"'
    # The expression supersedes License classifiers, and setuptools >=77 refuses
    # to build a project that sets both. BUSL-1.1 is not OSI-approved, so the
    # expression is the whole machine-readable claim.
    assert "License ::" not in text, "remove the License classifier"
    # license-files replaces setuptools auto-detection, so naming LICENSE is what
    # keeps the BUSL text in the wheel; the notices file travels with it because
    # the LICENSE appendix points at it.
    assert (
        'license-files = ["LICENSE", "THIRD_PARTY_NOTICES.md"]' in text
    ), "both license documents must be declared as license-files"
    assert (
        REPO / "THIRD_PARTY_NOTICES.md"
    ).is_file(), "the notices file the LICENSE refers to is missing"


def test_changelog_list_structure_is_intact():
    """No bullet may lose its lead-in.

    A `re.split` on a markdown line silently swallowed one sentence here and the
    entry began with `  Three pins, all` — nothing rendered it wrong, nothing
    measured it, and it sat across four commits. Continuation lines of a list item
    are indented by exactly the marker width; a line indented by anything else is
    a broken item.
    """
    text = (REPO / "CHANGELOG.md").read_text(encoding="utf-8")
    broken = []
    for number, line in enumerate(text.splitlines(), start=1):
        stripped = line.lstrip(" ")
        indent = len(line) - len(stripped)
        if not stripped or indent == 0 or stripped.startswith(("#", "|", ">")):
            continue
        if line.startswith("```"):
            continue
        if stripped.startswith(("- ", "* ", "[", "<")) or indent in (2, 4):
            continue
        if stripped[:1].isdigit() and ". " in stripped[:4]:
            continue
        broken.append((number, line[:70]))
    assert broken == [], f"malformed changelog continuation lines: {broken[:8]}"
