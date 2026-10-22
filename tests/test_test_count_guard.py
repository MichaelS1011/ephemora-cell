# SPDX-License-Identifier: BUSL-1.1
# Copyright 2026 Michael Soppa
"""Non-vacuity tests for the test-count guard (``scripts/check_test_count.py``).

The guard is the machine check behind every "N passing / M skipped" claim in
README.md, docs/comparison-mcp-servers.md, SECURITY.md and
docs/security_attack_matrix.md. It runs as a CI gate
(``CHECK_TEST_COUNT_STRICT=1 python scripts/check_test_count.py``), but until
this file nothing checked the checker: a guard whose patterns no longer match
anywhere, or whose input document gets deleted, exits 0 and looks like a passing
gate while verifying nothing. That failure mode is not hypothetical — the guard's
own docstring records a previous soft check that "silently verified nothing" and
was removed rather than left to look like coverage.

Method — and the one trap it has to avoid: the guard derives its repository
root from ``Path(__file__).resolve().parent.parent``. Pointing it at the real
tree with a symlink is INVALID, because ``resolve()`` walks back into the real
checkout and the guard then reads the very documents it is supposed to be
replaced for (this was measured before this file existed). So every case builds
a FARM: a throwaway tree with a COPY of the guard script under
``farm/scripts/``, three collectible tests, and the four documents. ``__file__``
then genuinely resolves to ``farm/``.

Each case runs the guard as a subprocess and reads its exit code — behaviour,
not source text.
"""

from __future__ import annotations

import subprocess
import sys
from pathlib import Path

import pytest

_ROOT = Path(__file__).resolve().parents[1]
GUARD_SOURCE = _ROOT / "scripts" / "check_test_count.py"

#: the farm's own collection — three tests, so ``collected`` is a known number
FARM_TESTS = """
def test_one():
    assert True


def test_two():
    assert True


def test_three():
    assert True
"""


def _docs(passing: int = 3, skipped: int = 0, collected: int = 3) -> dict[str, str]:
    """The four guarded documents, with claims that agree with ``collected``.

    The sentences are the shapes the guard's regexes look for — they are not
    copies of the real documents, and that is the point: a farm claim that
    stopped matching a pattern would make the guard FAIL here instead of
    silently checking nothing.
    """
    return {
        "README.md": (
            "# Farm\n\n"
            "## Testing & Verification\n\n"
            f"The suite reports {passing} tests passing ({skipped} skipped).\n"
            "Stamp every mention from one canonical number.** "
            f"{passing} / {skipped} ({collected} collected)\n"
        ),
        "docs/comparison-mcp-servers.md": (
            f"The guard sees {passing} CI-enforced tests ({skipped} skipped).\n"
            f"The suite comprises {collected} collected tests today\n"
            f"— {passing} passing ({skipped} skipped), measured.\n"
        ),
        "SECURITY.md": (
            f"Release gate: {passing} passing / {skipped} skipped, "
            "no failures tolerated.\n"
        ),
        "docs/security_attack_matrix.md": (
            f"Gate: **{passing} passing / {skipped} skipped** at release.\n"
        ),
    }


def _make_farm(
    tmp_path: Path,
    docs: dict[str, str] | None = None,
    *,
    farm_tests: str = FARM_TESTS,
    with_guard: bool = True,
    with_readme: bool = True,
) -> Path:
    """Build a throwaway repository whose ``scripts/`` holds a real COPY.

    Copying (not symlinking) is what makes ``__file__`` resolve inside the farm;
    the guard's ``REPO`` is then ``farm`` and it can only ever see farm files.
    """
    farm = tmp_path / "farm"
    docs = dict(docs if docs is not None else _docs())
    if not with_readme:
        docs.pop("README.md")
    for rel, text in docs.items():
        target = farm / rel
        target.parent.mkdir(parents=True, exist_ok=True)
        target.write_text(text, encoding="utf-8")
    tests_dir = farm / "tests"
    tests_dir.mkdir(parents=True, exist_ok=True)
    (tests_dir / "test_farm.py").write_text(farm_tests, encoding="utf-8")
    if with_guard:
        scripts = farm / "scripts"
        scripts.mkdir(parents=True, exist_ok=True)
        (scripts / "check_test_count.py").write_text(
            GUARD_SOURCE.read_text(encoding="utf-8"), encoding="utf-8"
        )
    return farm


def _run_guard(farm: Path, strict: bool = False) -> subprocess.CompletedProcess:
    """Execute the FARM copy of the guard, from the farm root."""
    env = {"PATH": "/usr/bin:/bin", "HOME": str(Path.home())}
    if strict:
        env["CHECK_TEST_COUNT_STRICT"] = "1"
    return subprocess.run(
        [sys.executable, str(farm / "scripts" / "check_test_count.py")],
        capture_output=True,
        text=True,
        cwd=str(farm),
        env=env,
        timeout=300,
    )


@pytest.fixture()
def green_farm(tmp_path: Path) -> Path:
    """A farm whose claims match its own collection: the control."""
    farm = _make_farm(tmp_path)
    proc = _run_guard(farm)
    assert proc.returncode == 0, (proc.stdout, proc.stderr)
    return farm


def test_the_farm_guard_resolves_the_farm_not_the_checkout(tmp_path: Path):
    """Method control, and the reason a symlinked farm was invalid: without a
    README.md IN THE FARM the guard must report the farm's missing README — if
    ``resolve()`` had walked back into the real checkout it would find one and
    print a different error.
    """
    farm = _make_farm(tmp_path, with_readme=False)
    proc = _run_guard(farm)
    assert proc.returncode == 1
    assert "README.md not found" in proc.stderr
    assert str(_ROOT) not in proc.stderr, "the guard reached the real checkout"


def test_a_correct_farm_passes_and_says_what_it_checked(green_farm: Path):
    """The positive control: the patterns DO match a well-formed farm, so every
    failure below is a verdict and not a harness artifact.
    """
    proc = _run_guard(green_farm)
    assert proc.returncode == 0, (proc.stdout, proc.stderr)
    assert "3 tests collected" in proc.stdout
    assert "OK: documented test counts match the collection (3 collected)" in (
        proc.stdout
    )


@pytest.mark.parametrize(
    "rel,broken,fragment",
    [
        pytest.param(
            "README.md",
            lambda d: d.__setitem__(
                "README.md",
                d["README.md"].replace("3 tests passing", "4 tests passing"),
            ),
            'README.md "Testing & Verification"',
            id="readme-passing-drift",
        ),
        pytest.param(
            "docs/comparison-mcp-servers.md",
            lambda d: d.__setitem__(
                "docs/comparison-mcp-servers.md",
                d["docs/comparison-mcp-servers.md"]
                .replace("2 CI-enforced", "9 CI-enforced")
                .replace("3 CI-enforced", "9 CI-enforced"),
            ),
            "docs/comparison-mcp-servers.md",
            id="comparison-drift",
        ),
        pytest.param(
            "SECURITY.md",
            lambda d: d.__setitem__(
                "SECURITY.md", d["SECURITY.md"].replace("3 passing", "1459 passing")
            ),
            "SECURITY.md suite claim",
            id="security-md-drift",
        ),
        pytest.param(
            "docs/security_attack_matrix.md",
            lambda d: d.__setitem__(
                "docs/security_attack_matrix.md",
                d["docs/security_attack_matrix.md"].replace("**3", "**1459"),
            ),
            "docs/security_attack_matrix.md gate claim",
            id="attack-matrix-drift",
        ),
    ],
)
def test_a_wrong_documented_number_fails_the_guard(
    tmp_path: Path, rel, broken, fragment
):
    """(a) of the mandate: a stale count must exit non-zero, naming the file.

    The planted wrong numbers are deliberate: 1459 is this repository's real
    count, so a farm that quietly kept reading the real tree would appear to
    PASS — the failure below is what proves the farm is really being read.
    """
    docs = _docs()
    broken(docs)
    farm = _make_farm(tmp_path, docs)
    proc = _run_guard(farm)
    assert proc.returncode == 1, (proc.stdout, proc.stderr)
    assert "FAIL:" in proc.stderr
    assert fragment in proc.stderr
    assert "test-count drift" in proc.stderr


def test_security_md_without_any_count_claim_fails_the_guard(tmp_path: Path):
    """(b) of the mandate: SECURITY.md is where the release count is asserted,
    so a document that stops carrying it must fail — not be skipped.
    """
    docs = _docs()
    docs["SECURITY.md"] = "This document describes the security programme.\n"
    proc = _run_guard(_make_farm(tmp_path, docs))
    assert proc.returncode == 1, (proc.stdout, proc.stderr)
    assert "FAIL:" in proc.stderr
    assert "SECURITY.md suite claim" in proc.stderr
    assert "no 'N passing (M skipped)' claim found" in proc.stderr


def test_attack_matrix_without_any_count_claim_fails_the_guard(tmp_path: Path):
    """The same for the other hand-stamped security document."""
    docs = _docs()
    docs["docs/security_attack_matrix.md"] = "See SECURITY.md.\n"
    proc = _run_guard(_make_farm(tmp_path, docs))
    assert proc.returncode == 1, (proc.stdout, proc.stderr)
    assert "docs/security_attack_matrix.md gate claim" in proc.stderr
    assert "no 'N passing (M skipped)' claim found" in proc.stderr


@pytest.mark.parametrize(
    "rel",
    [
        pytest.param("SECURITY.md", id="SECURITY.md"),
        pytest.param("docs/security_attack_matrix.md", id="attack-matrix"),
    ],
)
def test_deleting_the_document_does_not_silence_the_guard(tmp_path: Path, rel: str):
    """Absence is a gate failure, not a skipped check: this is the hole the
    guard's own contract names, and the ``exists()`` wrapper that would have
    allowed it is what this pins out.
    """
    docs = _docs()
    del docs[rel]
    proc = _run_guard(_make_farm(tmp_path, docs))
    assert proc.returncode == 1, (proc.stdout, proc.stderr)
    assert f"{rel} not found" in proc.stderr
    assert "a gate failure, not a skipped check" in proc.stderr


def test_conflicting_claims_in_one_document_fail_the_guard(tmp_path: Path):
    """Two different numbers in the same file is a documentation bug, and the
    guard refuses to guess which one is real.
    """
    docs = _docs()
    docs["SECURITY.md"] += "Older prose: 2 passing / 1 skipped.\n"
    proc = _run_guard(_make_farm(tmp_path, docs))
    assert proc.returncode == 1, (proc.stdout, proc.stderr)
    assert "CONFLICTING passing/skipped claims" in proc.stderr


def test_the_hard_checks_see_the_sum_not_the_split(tmp_path: Path):
    """Characterization of the guard's OWN stated limit: the hard checks verify
    ``passing + skipped == collected``, so a document that keeps the sum right
    while inventing the split passes. That is documented in the script and is
    deliberately out of scope; this pin keeps the limit visible, and shows the
    sum check itself is not vacuous (5 + 0 fails).
    """
    docs = _docs()
    docs["docs/security_attack_matrix.md"] = "Gate: **2 passing / 1 skipped**.\n"
    proc = _run_guard(_make_farm(tmp_path, docs))
    assert proc.returncode == 0, (proc.stdout, proc.stderr)
    # measured and stated, so nobody later "tightens" this by surprise: the
    # guard cannot see the split, only the sum. 2 + 1 == 3 collected passes.
    assert "OK: documented test counts match" in proc.stdout
    docs["docs/security_attack_matrix.md"] = "Gate: **5 passing / 0 skipped**.\n"
    farm2 = _make_farm(tmp_path / "second", docs)
    proc2 = _run_guard(farm2)
    assert proc2.returncode == 1, (proc2.stdout, proc2.stderr)
    assert "test-count drift" in proc2.stderr


def test_a_collection_that_cannot_run_fails_closed(tmp_path: Path):
    """If ``pytest --collect-only`` cannot produce a total, the guard errors —
    it never treats an unreadable source as agreement.
    """
    farm = _make_farm(tmp_path, farm_tests="def test_broken(:\n")
    proc = _run_guard(farm)
    assert proc.returncode == 1, (proc.stdout, proc.stderr)
    assert "pytest --collect-only failed" in proc.stderr


def test_a_badge_is_a_warning_by_default_and_hard_in_strict_mode(tmp_path: Path):
    """The documented two-mode behaviour of the ONE soft claim, pinned so a
    future mode change is a decision and not an accident.
    """
    docs = _docs()
    docs[
        "README.md"
    ] += "![status](https://img.shields.io/badge/tests-2_passing-green)\n"
    farm = _make_farm(tmp_path, docs)
    default = _run_guard(farm)
    assert default.returncode == 0, (default.stdout, default.stderr)
    assert "WARNING" in default.stdout
    assert "README.md hero badge" in default.stdout
    strict = _run_guard(farm, strict=True)
    assert strict.returncode == 1, (strict.stdout, strict.stderr)
    assert "FAIL: WARNING: README.md hero badge" in strict.stderr
