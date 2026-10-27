# SPDX-License-Identifier: BUSL-1.1
# Copyright 2026 Michael Soppa

"""Opt-in qualification of a real, reproducibly-built JavaScript guest.

This is the executable half of ADR-009's language decision for the
JavaScript side: it builds a modern Javy (QuickJS-in-WASM) Preview1 guest from
the pinned recipe (``scripts/build_js_guest.py``) and runs it through the
**isolated** ``lang_js`` adapter, asserting the JSON round-trip executes with
the correct output, and as a negative control that the per-call
``expected_sha256`` module binding is a hard supply-chain gate that refuses a
swapped artifact before it runs.

It is **opt-in** because it needs the native ``javy`` CLI (not a pip/npm
package) on PATH or via ``EPHEMORA_JAVY_BIN``. The default suite must stay
green on hosts without that toolchain — this mirrors the documented
toolchain-skip asymmetry in ``docs/languages.md`` and never runs in the
standard ``pytest`` invocation. Enable explicitly on a provisioned build host
with::

    EPHEMORA_JS_GUEST_QUALIFY=1 pytest tests/test_js_guest.py

Nothing here downloads at Cell run time; the toolchain must already be
installed by the operator, and the guest is built into a temporary path.
"""

from __future__ import annotations

import importlib.util
import os
import shutil
import sys
import tempfile
from pathlib import Path

import pytest

sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))

from ephemora_cell.lang_js import run_javascript_module
from scripts.build_js_guest import (
    GUEST_EXPECTED_OUTPUT,
    GUEST_INPUT,
    JAVY_BIN_ENV,
    build,
)

_HAS_TOOLCHAIN = bool(os.environ.get(JAVY_BIN_ENV)) or shutil.which("javy") is not None
_ENABLED = os.environ.get("EPHEMORA_JS_GUEST_QUALIFY") == "1"
_HAS_RUNTIME = importlib.util.find_spec("wasmtime") is not None

pytestmark = pytest.mark.skipif(
    not (_ENABLED and _HAS_TOOLCHAIN and _HAS_RUNTIME),
    reason=(
        "opt-in heavy gate: requires EPHEMORA_JS_GUEST_QUALIFY=1, the javy CLI "
        f"(PATH or {JAVY_BIN_ENV}) and wasmtime importable (see module docstring)"
    ),
)


def test_js_guest_runs_isolated_and_output_matches() -> None:
    with tempfile.TemporaryDirectory() as tmp:
        out = Path(tmp) / "guest.wasm"
        digest, size = build(out)
        assert size > 100_000, "javy guest should embed a QuickJS runtime"
        result = run_javascript_module(
            str(out), input_json=GUEST_INPUT, expected_sha256=digest
        )
        assert result["status"].endswith(
            "SUCCESS"
        ), f"guest run did not succeed: {result['status']} / {result['stderr']!r}"
        assert result["output"] == GUEST_EXPECTED_OUTPUT


def test_wrong_digest_binding_refuses_before_run() -> None:
    # Negative control: a per-call expected_sha256 that does not match the
    # bytes must fail closed — the guest is never executed, so a swapped
    # artifact cannot reach the (GHSA-32h6-sensitive) runtime at all. The
    # adapter surfaces the sandbox's ERROR result rather than raising.
    with tempfile.TemporaryDirectory() as tmp:
        out = Path(tmp) / "guest.wasm"
        _digest, _size = build(out)
        result = run_javascript_module(
            str(out), input_json=GUEST_INPUT, expected_sha256="0" * 64
        )
        assert not result["status"].endswith("SUCCESS"), result["status"]
        assert result["output"] is None
        assert "hash mismatch" in (result["stderr"] or "").lower()
