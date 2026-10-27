# SPDX-License-Identifier: BUSL-1.1
# Copyright 2026 Michael Soppa
"""Shared test-assembly policy.

The suite is written against a SOURCE CHECKOUT, not against an installed
artifact: some of it inspects repository files (`server.json`, `scripts/`,
`LICENSE`, the module sources themselves) and some of it runs the WASM fixtures
under `tests/fixtures/`, which are build inputs for the tests and are not part of
the distribution. `sdist` ships `tests/` because setuptools includes package
data, so an unpacked sdist contains test files whose inputs are missing — and a
naive `pytest` there reports dozens of failures that have nothing to do with the
product.

This module turns that into a stated boundary instead of noise: when the checkout
artifacts are absent, the checkout-only modules are SKIPPED with a reason that
names the cause, and everything that can run from an installed package does run.
No test is skipped here for want of checkout files, so CI keeps its full teeth.

The other kind of environment statement belongs here too: a leg that asserts a
guest is ABSENT cannot run on a host that installed one. Those legs get
``no_packaged_guest`` below and report what they observed instead of failing on
the machine.
"""

from __future__ import annotations

from pathlib import Path

import pytest

TESTS = Path(__file__).resolve().parent
REPO = TESTS.parent

# Modules that read repository files or fixtures that the sdist does not carry.
# The list was assembled by unpacking the sdist into a clean python:3.12-slim
# container and installing it as the only source of the package — which is also
# how the marker above was found to be self-defeating: shipping `tests/fixtures`
# made an unpacked sdist look like a checkout, so these modules ran and failed
# instead of being skipped. `tests/test_checkout_skip_policy.py` pins both halves.
CHECKOUT_ONLY_MODULES = frozenset(
    {
        # repository metadata, scripts and source-text inspection
        "test_project_meta.py",
        "test_policy_agreement.py",
        "test_mcp_config.py",
        "test_watch_upstream.py",
        "test_surface_audit.py",
        "test_tool_signing.py",
        "test_component_probe_fixtures.py",
        "test_cli.py",
        # the test-count guard: it copies scripts/check_test_count.py into a
        # farm, so without scripts/ there is no guard to exercise (and an
        # error here would look like a product failure, not a packaging one)
        "test_test_count_guard.py",
        # ... and so is the guard that keeps this list honest: it reads
        # MANIFEST.in and the directory shape of the repository.
        "test_checkout_skip_policy.py",
    }
)


def is_checkout(repo: Path) -> bool:
    """Is ``repo`` a source checkout rather than an unpacked distribution?

    A checkout is where the REPOSITORY inputs exist, not where the project file
    is. The obvious predicate — `pyproject.toml` plus the `tests/fixtures`
    binaries — is wrong, and was wrong since the sdist started shipping those
    fixtures: an unpacked sdist satisfies it, so the skip below never fired and
    eight repository-inspection modules ran against files no distribution
    carries. What a Python distribution never ships is the repository's own
    documentation and script directories, and a checkout — clone or source
    export — always has both, because that is where the build-and-verify
    instructions live.
    """
    return (repo / "docs").is_dir() and (repo / "scripts").is_dir()


def _in_source_checkout() -> bool:
    return is_checkout(REPO)


def pytest_collection_modifyitems(
    config: pytest.Config, items: list[pytest.Item]
) -> None:
    if _in_source_checkout():
        return
    skip = pytest.mark.skip(
        reason="requires a source checkout: repository metadata or tests/fixtures "
        "binaries are not part of the distribution"
    )
    for item in items:
        path = str(item.fspath)
        if Path(path).name in CHECKOUT_ONLY_MODULES:
            item.add_marker(skip)


#: Environment variables a caller may use to point at a bring-your-own guest.
_BYO_GUEST_VARS = (
    "EPHEMORA_BYO_PYTHON_GUEST",
    "EPHEMORA_BYO_PYTHON_STDLIB",
    "EPHEMORA_BYO_PYTHON_SHA256",
    "EPHEMORA_BYO_JS_GUEST",
    "EPHEMORA_BYO_JS_SHA256",
    "EPHEMORA_PY_COMPONENT_GUEST",
    "EPHEMORA_JS_INTERPRETER_GUEST",
)


@pytest.fixture
def no_packaged_guest(monkeypatch: pytest.MonkeyPatch) -> None:
    """Stand a fail-closed leg aside when this host actually carries the guest.

    Several legs assert that the resolver REFUSES because no packaged language
    guest exists. That is a statement about a machine, and a qualification venv
    built from the release wheelhouse installs exactly those guests — there the
    resolver resolves, the refusal does not happen, and the leg would fail on the
    environment instead of on the contract. So the leg says so and steps aside,
    with the reason naming what it found. The BYO overrides are cleared first,
    because the legs under this fixture test the packaged path, not a pin.
    """
    from ephemora_cell import lang_guest

    for var in _BYO_GUEST_VARS:
        monkeypatch.delenv(var, raising=False)
    for language in ("python", "javascript"):
        try:
            lang_guest.resolve_guest(language)
        except lang_guest.GuestNotInstalled:
            continue
        pytest.skip(
            f"this host carries an installed {language} guest — the resolver's "
            "fail-closed branch is not reachable here (the legs that need it are "
            "the guest-round-trip gates, opted in by EPHEMORA_*_GUEST)"
        )
