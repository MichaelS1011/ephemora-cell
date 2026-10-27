# SPDX-License-Identifier: BUSL-1.1
# Copyright 2026 Michael Soppa
"""Mandatory counter-check for the 2026-10 aarch64 br_table escape.

GHSA-mghf-wjfp-p5xm was fixed in 49.0.4. The qualified build must refuse a
module whose br_table target count exceeds the implementation limit (65520);
a build that accepts it is not the qualified one. The small module is the
positive control: the generator produces valid input, so the refusal above is
about the target count, not about malformed WAT.
"""

from __future__ import annotations

import importlib.metadata

import pytest

wasmtime = pytest.importorskip("wasmtime")

pytestmark = pytest.mark.skipif(
    importlib.metadata.version("wasmtime").split("+")[0] != "49.0.4.post1",
    reason="br_table limit counter-check is pinned to the qualified 49.0.4 build",
)


def _module(targets: int):
    labels = " ".join(["0"] * targets)
    wat = (
        '(module (func (export "f") (param i32) (result i32) '
        "(block (result i32) (i32.const 0) (local.get 0) "
        f"(br_table {labels}))))"
    )
    return wasmtime.Module(wasmtime.Engine(), wasmtime.wat2wasm(wat))


def test_small_br_table_compiles_positive_control():
    module = _module(10)
    assert module is not None


def test_300000_target_module_is_refused_by_the_qualified_build():
    with pytest.raises(Exception, match="implementation limit of 65520"):
        _module(300_000)
