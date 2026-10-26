# SPDX-License-Identifier: BUSL-1.1
# Copyright 2026 Michael Soppa

"""Opt-in qualification of a real, reproducibly-built Python component guest.

This is the executable half of ADR-009's language decision for the
Python side: it builds a modern CPython WASI-0.2 component from the pinned
recipe (``scripts/build_python_guest.py``) and runs it through the **isolated**
Cell sandbox, asserting the guest executes with the correct output, and as a
negative control that the per-call ``expected_sha256`` module binding is a hard
supply-chain gate that refuses a swapped artifact before it runs.

It is **opt-in** because the build is heavyweight (an ~18 MB CPython component,
multi-second boot) and needs ``componentize-py`` on PATH. The default suite must
stay green on hosts without that toolchain — this mirrors the documented
toolchain-skip asymmetry in ``docs/languages.md`` and never runs in the standard
``pytest`` invocation. Enable explicitly on a provisioned build host with::

    EPHEMORA_PY_GUEST_QUALIFY=1 pytest tests/test_python_guest.py

Nothing here downloads at Cell run time; the toolchain must already be installed
by the operator, and the guest is built into a temporary path.
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

from ephemora_cell import WASISandbox, get_profile
from ephemora_cell.wasi_runtime import ExecutionStatus
from scripts.build_python_guest import GUEST_EXPECTED_OUTPUT, build

_HAS_TOOLCHAIN = shutil.which("componentize-py") is not None
_ENABLED = os.environ.get("EPHEMORA_PY_GUEST_QUALIFY") == "1"
_HAS_RUNTIME = importlib.util.find_spec("wasmtime") is not None

pytestmark = pytest.mark.skipif(
    not (_ENABLED and _HAS_TOOLCHAIN and _HAS_RUNTIME),
    reason=(
        "opt-in heavy gate: requires EPHEMORA_PY_GUEST_QUALIFY=1, componentize-py on "
        "PATH and wasmtime importable (see module docstring)"
    ),
)


def test_python_guest_runs_isolated_and_output_matches() -> None:
    with tempfile.TemporaryDirectory() as tmp:
        out = Path(tmp) / "guest.wasm"
        digest, size = build(out)
        assert size > 1_000_000, "componentize-py guest should embed a CPython runtime"
        sandbox = WASISandbox(config=get_profile("interpreter"))
        try:
            result = sandbox.run(
                str(out),
                abi="component",
                use_subprocess=True,
                expected_sha256=digest,
            )
            assert (
                result.status is ExecutionStatus.SUCCESS
            ), f"guest run did not succeed: {result.status} / {result.stderr!r}"
            assert (result.stdout or "") == GUEST_EXPECTED_OUTPUT
        finally:
            sandbox.cleanup()


def test_wrong_digest_binding_refuses_before_run() -> None:
    # Negative control: a per-call expected_sha256 that does not match the bytes
    # must fail closed — the guest is never instantiated, so a swapped artifact
    # cannot reach the (GHSA-32h6-sensitive) native component validator.
    with tempfile.TemporaryDirectory() as tmp:
        out = Path(tmp) / "guest.wasm"
        _digest, _size = build(out)
        sandbox = WASISandbox(config=get_profile("interpreter"))
        try:
            result = sandbox.run(
                str(out),
                abi="component",
                use_subprocess=True,
                expected_sha256="0" * 64,
            )
            assert result.status is ExecutionStatus.ERROR
            assert (result.stdout or "") == ""
            assert "hash mismatch" in (result.stderr or "").lower()
        finally:
            sandbox.cleanup()
