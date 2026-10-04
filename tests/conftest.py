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
No test is ever skipped in a real checkout, so CI keeps its full teeth.
"""

from __future__ import annotations

from pathlib import Path

import pytest

TESTS = Path(__file__).resolve().parent
REPO = TESTS.parent

# Modules that read repository files or fixtures that the sdist does not carry.
# Verified by unpacking the 1.1.0 sdist into a clean python:3.12-slim container
# and installing it as the only source of the package.
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
    }
)


def _in_source_checkout() -> bool:
    """A checkout has the project file AND the fixture binaries the suite needs."""
    return (REPO / "pyproject.toml").is_file() and (
        TESTS / "fixtures" / "hello02.wasm"
    ).is_file()


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
