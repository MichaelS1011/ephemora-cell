# SPDX-License-Identifier: BUSL-1.1
# Copyright 2026 Michael Soppa

"""CLI surface for the security profiles (v1.2).

Runs ``python -m ephemora_cell.cli`` as a real process, so what is tested is the
exit code and stdout/stderr a user actually gets — not an in-process function.
"""

from __future__ import annotations

import json
import os
import subprocess
import sys

sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))

REPO = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))


def _run_cli(*args):
    return subprocess.run(
        [sys.executable, "-m", "ephemora_cell.cli", *args],
        capture_output=True,
        text=True,
        timeout=120,
        cwd=REPO,
    )


# --- profiles list (v1.2) ----------------------------------------------


def test_profiles_list_prints_the_security_profiles():
    result = _run_cli("profiles", "list")
    assert result.returncode == 0, result.stderr
    names = result.stdout.split()
    for expected in (
        "code-interpreter",
        "data-analysis",
        "file-converter",
        "web-fetch",
        "build-tool",
        "agent-readonly",
        "custom-restricted",
    ):
        assert expected in names, result.stdout


def test_profiles_json_lists_capabilities_per_profile():
    result = _run_cli("profiles", "list", "--json")
    assert result.returncode == 0, result.stderr
    payload = json.loads(result.stdout)
    entries = {entry["name"]: entry for entry in payload["security_profiles"]}
    assert entries["agent-readonly"]["tools"] == ["get-policy:read"]
    assert entries["custom-restricted"]["tools"] == []
    assert entries["code-interpreter"]["tools"] == []
    assert entries["web-fetch"]["network"] == "egress-mediated"


# --- profile inspect (v1.2) ------------------------------------


def test_profile_inspect_shows_budgets_and_forbidden_actions():
    result = _run_cli("profile", "inspect", "file-converter")
    assert result.returncode == 0, result.stderr
    assert "profile: file-converter" in result.stdout
    assert "preopens: none" in result.stdout


def test_profile_inspect_json_carries_the_documentation():
    result = _run_cli("profile", "inspect", "build-tool", "--json")
    assert result.returncode == 0, result.stderr
    payload = json.loads(result.stdout)
    assert payload["budgets"]["timeout_seconds"] == 180
    assert "forbidden" in payload["documentation"]


def test_profile_inspect_refuses_an_unknown_name():
    result = _run_cli("profile", "inspect", "nope")
    assert result.returncode == 2
    assert "unknown profile" in result.stderr


def test_profile_without_a_subcommand_prints_help():
    result = _run_cli("profile")
    assert result.returncode == 1
    assert "inspect" in result.stdout


# --- policy build (v1.2) -----------------------------------------------


def test_policy_build_emits_the_document_the_authorizer_reads(tmp_path):
    result = _run_cli(
        "policy", "build", "--profile", "agent-readonly", "--subject", "alice"
    )
    assert result.returncode == 0, result.stderr
    document = json.loads(result.stdout)
    assert document["subjects"][0]["subject"] == "alice"
    assert document["subjects"][0]["permissions"] == [
        {"tool": "get-policy", "action": "read"}
    ]

    # The runtime agrees: what was written denies a call and allows the read.
    from ephemora_cell_mcp.authz import ACTION_CALL, ACTION_READ, Authorizer, ToolPolicy

    authorizer = Authorizer(ToolPolicy.from_dict(document))
    assert not authorizer.authorize("alice", "echo", action=ACTION_CALL).allowed
    assert authorizer.authorize("alice", "get-policy", action=ACTION_READ).allowed


def test_policy_build_emits_no_tools_by_default():
    """v1.2: a standard execution profile grants no MCP tools by default."""
    result = _run_cli(
        "policy", "build", "--profile", "code-interpreter", "--subject", "alice"
    )
    assert result.returncode == 0, result.stderr
    document = json.loads(result.stdout)
    assert document["subjects"][0]["permissions"] == []
    assert "'*'" not in result.stderr


def test_policy_build_refuses_an_unknown_profile():
    result = _run_cli("policy", "build", "--profile", "nope", "--subject", "alice")
    assert result.returncode == 2
    assert "Unknown security profile" in result.stderr


def test_policy_build_writes_a_file_that_can_be_reloaded(tmp_path):
    out = tmp_path / "alice.json"
    result = _run_cli(
        "policy",
        "build",
        "--profile",
        "custom-restricted",
        "--subject",
        "alice",
        "--out",
        str(out),
    )
    assert result.returncode == 0, result.stderr
    assert out.is_file()
    document = json.loads(out.read_text(encoding="utf-8"))
    assert document["subjects"][0]["permissions"] == []
