# SPDX-License-Identifier: BUSL-1.1
# Copyright 2026 Michael Soppa

"""Installation security: the runtime gate must refuse unqualified engines (v1.2).

"Kein Test führt unbemerkt zu einer unqualifizierten produktiven Runtime." These
cases use *real* interpreter environments recorded by the audit rather than a
mocked identity, because the thing under test is the decision about actual
native bytes. The environments live in the audit tree, so every case skips
cleanly on a machine that does not have them.
"""

from __future__ import annotations

import json
import os
import subprocess
import sys
from pathlib import Path

sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))

import pytest

REPO = Path(__file__).resolve().parent.parent
ECHO_WASM = REPO / "ephemora_cell_mcp" / "tools" / "echo.wasm"

#: Audit environments (see .tmp_gate/audit/): the qualified release env and
#: real unqualified ones. Point EPHEMORA_AUDIT_DIR at another tree when the
#: audit environments live elsewhere; every case skips when they are absent.
_AUDIT = Path(
    os.environ.get(
        "EPHEMORA_AUDIT_DIR",
        Path.home() / "ephemora-cell" / ".tmp_gate" / "audit",
    )
)
QUALIFIED = _AUDIT / "final_closure" / "venv312" / "bin" / "python"
UNQUALIFIED = {
    "49.0.3.post2": _AUDIT / "venvM3.10" / "bin" / "python",
    "49.0.0": Path.home() / "ephemora-cell" / ".venv" / "bin" / "python",
}


def _run(interpreter: Path, *args, env_extra: dict[str, str] | None = None):
    env = dict(os.environ)
    env.pop("EPHEMORA_ALLOW_UNQUALIFIED_RUNTIME", None)
    if env_extra:
        env.update(env_extra)
    return subprocess.run(
        [str(interpreter), "-m", "ephemora_cell.cli", *args],
        capture_output=True,
        text=True,
        timeout=180,
        cwd=str(REPO),
        env=env,
    )


def test_the_qualified_interpreter_runs_a_guest():
    if not QUALIFIED.exists():
        pytest.skip("qualified audit venv not present on this machine")
    result = _run(QUALIFIED, "run", str(ECHO_WASM))
    assert result.returncode == 0, result.stdout + result.stderr
    assert "unqualified runtime" not in result.stderr


@pytest.mark.parametrize("label", sorted(UNQUALIFIED))
def test_an_unqualified_interpreter_is_refused(label):
    interpreter = UNQUALIFIED[label]
    if not interpreter.exists():
        pytest.skip(f"audit venv for wasmtime {label} not present on this machine")
    result = _run(interpreter, "run", str(ECHO_WASM))
    assert result.returncode == 4, result.stdout + result.stderr
    assert "unqualified runtime" in result.stderr


@pytest.mark.parametrize("label", sorted(UNQUALIFIED))
def test_the_escape_hatch_is_explicit_and_stamps_the_record(label):
    """An operator may opt out, but the record must admit what engine ran."""
    interpreter = UNQUALIFIED[label]
    if not interpreter.exists():
        pytest.skip(f"audit venv for wasmtime {label} not present on this machine")
    result = _run(
        interpreter,
        "run",
        str(ECHO_WASM),
        "--json",
        env_extra={"EPHEMORA_ALLOW_UNQUALIFIED_RUNTIME": "1"},
    )
    assert result.returncode == 0, result.stdout + result.stderr
    report = json.loads(result.stdout)
    assert report["unqualified_runtime_allowed"] is True
    # The stamped version is the *unqualified* engine, not the qualified line.
    assert report["security_baseline"]["wasmtime_version"].startswith(label)
