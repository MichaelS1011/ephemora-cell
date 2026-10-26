# SPDX-License-Identifier: BUSL-1.1
# Copyright 2026 Michael Soppa

"""Real guests under real profiles (v1.2 v1.2, v1.2, v1.2).

v1.2 requires that the profile choice changes *granted capabilities*, not just
a display. These cases run actual guest modules and measure what the guest could
actually do: how far it got before the profile's fuel ceiling stopped it, and
whether a granted directory let it write a file the ungranted run could not.
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
FUEL_BOMB = REPO / "examples" / "fuel_bomb.wat"
FS_GUEST = REPO / "tests" / "fixtures" / "fs02.wasm"


def _cli(*args):
    return subprocess.run(
        [sys.executable, "-m", "ephemora_cell.cli", *args],
        capture_output=True,
        text=True,
        timeout=300,
        cwd=str(REPO),
    )


def _report(result):
    return json.loads(result.stdout)


# --- the fuel ceiling is enforced and depends on the profile --------------


def test_the_fuel_ceiling_is_enforced_and_differs_by_profile():
    """The same guest is stopped at each profile's own ceiling."""
    small = _cli("run", str(FUEL_BOMB), "--profile", "custom-restricted", "--json")
    large = _cli("run", str(FUEL_BOMB), "--profile", "build-tool", "--json")

    small_report, large_report = _report(small), _report(large)
    assert small_report["status"] == "fuel_exhausted"
    assert large_report["status"] == "fuel_exhausted"

    # Stopped exactly on the budget, and the budgets really differ.
    assert small_report["fuel_consumed"] == small_report["fuel_budget"]
    assert large_report["fuel_consumed"] == large_report["fuel_budget"]
    assert small_report["fuel_budget"] < large_report["fuel_budget"]


# --- a grant enables a capability that is otherwise absent ----------------


def test_a_granted_directory_enables_a_write_the_ungranted_run_cannot_make(tmp_path):
    """fs02 writes <argv[1]>/out.txt — only when that directory was granted."""
    refused = _cli(
        "run",
        str(FS_GUEST),
        "--profile",
        "file-converter",
        "--json",
        "--",
        str(tmp_path),
    )
    refused_report = _report(refused)
    assert refused_report["error_class"] == "execution"
    assert not (tmp_path / "out.txt").exists()
    assert refused_report["security_baseline"]["preopens"] == []

    granted = _cli(
        "run",
        str(FS_GUEST),
        "--profile",
        "file-converter",
        "--allow-dirs",
        str(tmp_path),
        "--json",
        "--",
        str(tmp_path),
    )
    granted_report = _report(granted)
    assert granted_report["error_class"] == "none"
    assert (tmp_path / "out.txt").read_text(encoding="utf-8").strip() == (
        "pwned-by-component"
    )
    assert granted_report["security_baseline"]["preopens"]


@pytest.mark.parametrize(
    "profile",
    [
        "code-interpreter",
        "data-analysis",
        "file-converter",
        "build-tool",
        "web-fetch",
        "custom-restricted",
    ],
)
def test_each_use_case_profile_can_run_a_real_guest(profile, tmp_path):
    """v1.2: allowed work stays allowed under every profile."""
    result = _cli(
        "run",
        str(FS_GUEST),
        "--profile",
        profile,
        "--allow-dirs",
        str(tmp_path),
        "--json",
        "--",
        str(tmp_path),
    )
    report = _report(result)
    assert report["error_class"] == "none", report
    assert report["fuel_consumed"] <= report["fuel_budget"]


def test_agent_readonly_still_runs_a_guest_but_grants_no_tool_call():
    """The read-only profile constrains MCP tools, not the sandbox budget."""
    from ephemora_cell.security_profiles import get_security_profile
    from ephemora_cell_mcp.authz import ACTION_CALL, Authorizer, ToolPolicy

    profile = get_security_profile("agent-readonly")
    authorizer = Authorizer(ToolPolicy.from_dict(profile.to_tool_policy("alice")))
    assert not authorizer.authorize("alice", "echo", action=ACTION_CALL).allowed
    # ... while its sandbox budget is a normal, usable one.
    assert profile.config.max_memory_mb >= 64
    assert (profile.config.max_fuel or 0) >= 500_000
