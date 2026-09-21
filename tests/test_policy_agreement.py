"""get-policy vs. enforcement: the reported policy must equal what a real
run attests — the "report and enforcement cannot drift" promise.

Regression for the 2026-09-21 fix: ``policy_for`` previously reported only
the profile's configured ``allow_dirs`` (empty for the default profile),
while every core-module execution additionally grants the ephemeral
sandbox dir as ``/sandbox``. get-policy now attests the same preopen set
the execution witness records, plus the execution topology
(``sandbox_lifecycle``: fresh sandbox per call vs. pooled fast path).
Also guards the package version being single-sourced (a released 1.0.3
wheel once shipped a serverInfo saying 1.0.1).
"""

from __future__ import annotations

import os
import sys
import tomllib
from pathlib import Path

import pytest

sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))

from ephemora_cell_mcp._version import __version__
from ephemora_cell_mcp.engine import CellToolEngine
from ephemora_cell_mcp.tool_registry import ToolRegistry

PACKAGE_TOOLS = Path(__file__).resolve().parent.parent / "ephemora_cell_mcp" / "tools"
ECHO_WASM = PACKAGE_TOOLS / "echo.wasm"


def _engine(pooled: bool = False) -> CellToolEngine:
    return CellToolEngine(pooled=pooled)


def _echo_spec():
    return ToolRegistry(tools_dir=PACKAGE_TOOLS).get("echo")


@pytest.mark.skipif(not ECHO_WASM.is_file(), reason="echo.wasm not built")
def test_policy_preopens_match_execution_grants():
    """The configured preopen report equals the executed run's witness."""
    engine = _engine()
    spec = _echo_spec()
    reported = engine.policy_for(spec)
    assert "/sandbox" in reported["preopens"]
    outcome = engine.execute(spec, {"message": "policy"})
    executed = outcome.report.security_baseline["preopens"]
    assert reported["preopens"] == executed


@pytest.mark.skipif(not ECHO_WASM.is_file(), reason="echo.wasm not built")
def test_policy_attests_sandbox_lifecycle():
    """get-policy states whether a call runs in a fresh sandbox or pooled."""
    assert _engine().policy_for(_echo_spec())["sandbox_lifecycle"] == "fresh-per-call"
    assert _engine(pooled=True).policy_for(_echo_spec())["sandbox_lifecycle"] == "pooled"


def test_package_version_is_single_sourced():
    """pyproject version and the runtime __version__ must never diverge."""
    root = Path(__file__).resolve().parent.parent
    pyproject = tomllib.loads((root / "pyproject.toml").read_text())
    assert pyproject["project"]["version"] == __version__
