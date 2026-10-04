# SPDX-License-Identifier: BUSL-1.1
# Copyright 2026 Michael Soppa
"""Offline tests for scripts/watch_upstream.py (ADR-009 external gates).

Only the pure detection helpers are exercised here — the network paths are
integration behavior and run when the watcher is invoked manually/CI-side.
"""

from __future__ import annotations

import importlib.util
import pathlib
import sys

import pytest

_SCRIPT = pathlib.Path(__file__).resolve().parents[1] / "scripts" / "watch_upstream.py"


def _load_module():
    spec = importlib.util.spec_from_file_location("watch_upstream", _SCRIPT)
    assert spec is not None and spec.loader is not None
    module = importlib.util.module_from_spec(spec)
    sys.modules["watch_upstream"] = module
    spec.loader.exec_module(module)
    return module


@pytest.fixture(scope="module")
def wu():
    return _load_module()


def test_script_exists_and_matches_adr009_claim():
    # ADR-009 states "A scripts/watch_upstream.py watcher tracks the three
    # external gates" — the file must exist for that sentence to be true.
    assert _SCRIPT.is_file()


def test_wheels_ok_requires_all_platform_markers(wu):
    assert wu.wheels_ok(
        [
            "wasmtime-48.0.3-cp39-macosx_arm64.whl",
            "wasmtime-48.0.3-cp39-manylinux_x86_64.whl",
        ]
    )
    assert not wu.wheels_ok(["wasmtime-48.0.3-cp39-macosx_arm64.whl"])
    assert not wu.wheels_ok(["wasmtime-48.0.3-cp39-manylinux_x86_64.whl"])
    assert not wu.wheels_ok([])


def test_source_exposes_p3(wu):
    assert wu.source_exposes_p3("class Linker:\n    def add_wasip3(self) -> None: ...")
    assert not wu.source_exposes_p3(
        "class Linker:\n    def add_wasip2(self) -> None: ..."
    )
    # The installed binding's surface audit assertion today:
    assert not wu.source_exposes_p3("def add_wasi_http(self) -> None: ...")


def test_source_exposes_gc_limiter(wu):
    assert wu.source_exposes_gc_limiter("class ResourceLimiter: ...")
    assert wu.source_exposes_gc_limiter("wasmtime_component_resource_limiter_new(...)")
    assert not wu.source_exposes_gc_limiter("def set_limits(self, memory): ...")


def test_patch_targets_cover_the_2026_advisory_batch(wu):
    """The first two entries open the M2 gate; the rest are informational.

    The 2026-10-02 wave (GHSA-j366-h8gg-77pm, GHSA-gqmc-89g8-p25r,
    GHSA-96f6-r43r-8c24, RUSTSEC-2026-0324) is patched only from
    48.0.4 / 49.0.2. Naming 48.0.3 / 49.0.1 here — as this list did — would
    have declared the upgrade path open on an engine that still carries the
    uncharged-host-work and readdir-leak classes.
    """
    assert wu.WASMTIME_PATCH_TARGETS[:2] == ("48.0.4", "49.0.2")
    assert wu.WASMTIME_PATCH_TARGETS[2] == "47.0.4"
