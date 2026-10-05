# SPDX-License-Identifier: BUSL-1.1
# Copyright 2026 Michael Soppa
"""The sdist must not be able to masquerade as a source checkout.

`tests/conftest.py` skips the repository-inspection modules when a checkout's
inputs are absent, so an unpacked sdist states a boundary instead of producing a
wall of failures. That skip is only worth anything if the predicate tells the two
situations apart — and it did not: once `MANIFEST.in` shipped
`tests/fixtures/*.wasm`, an unpacked sdist satisfied "pyproject.toml + a fixture
binary exists", the skips never fired, and the clean-room container reported 16
failures plus 4 errors from modules reading files no distribution carries
(packaging, not product). These are the pins that keep the two halves honest.
"""

from __future__ import annotations

import importlib.util
from pathlib import Path

TESTS = Path(__file__).resolve().parent
REPO = TESTS.parent

_spec = importlib.util.spec_from_file_location("_tests_conftest", TESTS / "conftest.py")
assert _spec and _spec.loader
_conftest = importlib.util.module_from_spec(_spec)
_spec.loader.exec_module(_conftest)
is_checkout = _conftest.is_checkout
CHECKOUT_ONLY_MODULES = _conftest.CHECKOUT_ONLY_MODULES


def test_this_suite_run_is_recognised_as_a_checkout():
    """Nothing may be skipped here: CI runs in a checkout and must keep every
    gate. If this ever fails, the repository-inspection modules have gone silent
    in exactly the place they are supposed to bite."""
    assert is_checkout(REPO) is True


def test_an_unpacked_sdist_is_not_a_checkout(tmp_path):
    """The regression itself: the fixture binaries and the project file are inside
    the distribution, and that alone must not read as a checkout."""
    (tmp_path / "pyproject.toml").write_text("[project]\nname = 'x'\n")
    fixtures = tmp_path / "tests" / "fixtures"
    fixtures.mkdir(parents=True)
    (fixtures / "hello02.wasm").write_bytes(b"\x00asm\x01\x00\x00\x00")
    assert is_checkout(tmp_path) is False


def test_a_source_export_without_git_is_still_a_checkout(tmp_path):
    """A `git archive` export has no `.git` but does have the repository inputs —
    the predicate must not quietly skip gates for someone building from one."""
    (tmp_path / "docs").mkdir()
    (tmp_path / "scripts").mkdir()
    assert is_checkout(tmp_path) is True


def test_the_distribution_ships_neither_checkout_marker():
    """The other half: if packaging ever starts shipping `docs/` or `scripts/`, the
    predicate above stops separating the two situations and this test says so
    before a container run has to."""
    manifest = (REPO / "MANIFEST.in").read_text(encoding="utf-8")
    shipped = [
        line
        for line in manifest.splitlines()
        if line.strip()
        and not line.lstrip().startswith("#")
        and ("docs/" in line or "scripts/" in line)
    ]
    assert shipped == [], shipped


def test_every_checkout_only_module_exists():
    """A stale name in the skip list is a module that would run in an sdist and
    fail there for the reason this file exists."""
    for name in sorted(CHECKOUT_ONLY_MODULES):
        assert (TESTS / name).is_file(), name
