# SPDX-License-Identifier: BUSL-1.1
# Copyright 2026 Michael Soppa

"""Security profiles (v1.2 v1.2, v1.2).

A profile must be more than a label: its budgets are enforced because they are a
``WASIConfig``, and its tool grants are enforced because
``to_tool_policy`` produces the document the ADR-016 authorizer reads. These
cases check both halves and that the profile choice actually changes what is
allowed.
"""

from __future__ import annotations

import os
import sys

sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))

import pytest

from ephemora_cell import profiles
from ephemora_cell.security_profiles import (
    POLICY_VERSION,
    SECURITY_PROFILES,
    get_security_profile,
    list_security_profiles,
)
from ephemora_cell_mcp import authz

REQUIRED = {
    "code-interpreter",
    "data-analysis",
    "file-converter",
    "web-fetch",
    "build-tool",
    "agent-readonly",
    "custom-restricted",
}


def _authorizer_for(profile_name: str, subject: str = "alice"):
    document = get_security_profile(profile_name).to_tool_policy(subject)
    return authz.Authorizer(authz.ToolPolicy.from_dict(document))


# --- the library (v1.2) -------------------------------------------------


def test_the_seven_directive_profiles_exist():
    assert REQUIRED <= set(SECURITY_PROFILES)
    assert list_security_profiles() == sorted(SECURITY_PROFILES)


def test_every_profile_is_selectable_through_the_profile_surface():
    for name in REQUIRED:
        assert name in profiles.list_profiles()
        assert profiles.get(name) is get_security_profile(name).config


def test_no_standard_profile_grants_host_access():
    """Kein Standardprofil erhält unbeschränkte Hostrechte (directive)."""
    for name, profile in SECURITY_PROFILES.items():
        assert profile.config.allow_dirs == (), name
        assert profile.config.allow_env == (), name


def test_an_unknown_profile_fails_closed():
    with pytest.raises(ValueError):
        get_security_profile("does-not-exist")
    with pytest.raises(ValueError):
        profiles.get("does-not-exist")


def test_the_most_restrictive_profile_has_the_lowest_budgets():
    restricted = get_security_profile("custom-restricted").config
    build = get_security_profile("build-tool").config
    assert restricted.max_memory_mb < build.max_memory_mb
    assert (restricted.max_fuel or 0) < (build.max_fuel or 0)
    assert restricted.timeout_seconds < build.timeout_seconds


def test_every_profile_documents_the_required_fields():
    """v1.2: users must not have to guess the security assumptions."""
    required_keys = {
        "allowed_applications",
        "granted",
        "forbidden",
        "limits",
        "platform",
        "residual_risks",
    }
    for name, profile in SECURITY_PROFILES.items():
        assert required_keys <= set(profile.documentation), name


# --- the bridge to the authorizer (v1.2) --------------------------


def test_the_emitted_policy_version_matches_the_authorizer():
    assert POLICY_VERSION == authz.POLICY_VERSION


def test_a_generated_policy_is_accepted_by_the_authorizer():
    authorizer = _authorizer_for("code-interpreter")
    decision = authorizer.authorize("alice", "echo", action=authz.ACTION_CALL)
    # Accepted (parseable, versioned) and default-deny: no tools were named.
    assert not decision.allowed
    assert decision.policy_version == authz.POLICY_VERSION


def test_the_profile_choice_changes_what_is_allowed():
    """v1.2: the choice must change granted capabilities, not just a label."""
    # execution profiles grant NO tool call by default (no wildcard, v1.2) ...
    exec_authorizer = _authorizer_for("code-interpreter")
    assert not exec_authorizer.authorize(
        "alice", "echo", action=authz.ACTION_CALL
    ).allowed
    # ... agent-readonly may NOT call, but MAY read the policy.
    ro_authorizer = _authorizer_for("agent-readonly")
    call = ro_authorizer.authorize("alice", "echo", action=authz.ACTION_CALL)
    assert not call.allowed and call.reason == "no matching permission"
    read = ro_authorizer.authorize("alice", "get-policy", action=authz.ACTION_READ)
    assert read.allowed
    # ... custom-restricted grants neither.
    none_authorizer = _authorizer_for("custom-restricted")
    assert not none_authorizer.authorize("alice", "echo").allowed
    assert not none_authorizer.authorize(
        "alice", "get-policy", action=authz.ACTION_READ
    ).allowed


def test_a_profile_binds_to_the_named_subject_only():
    authorizer = _authorizer_for("agent-readonly", subject="alice")
    assert authorizer.authorize("alice", "get-policy", action=authz.ACTION_READ).allowed
    assert not authorizer.authorize(
        "mallory", "get-policy", action=authz.ACTION_READ
    ).allowed


def test_no_execution_profile_grants_a_wildcard():
    """v1.2: `* → call` is gone from the standard presets."""
    for name in (
        "code-interpreter",
        "data-analysis",
        "file-converter",
        "web-fetch",
        "build-tool",
    ):
        profile = get_security_profile(name)
        assert all(tool != "*" for tool, _ in profile.tool_actions), name
        assert profile.tool_actions == (), name


def test_a_wildcard_widening_is_flagged_not_silent():
    """v1.2: a deliberately added `*` must be surfaced by the validator."""
    from ephemora_cell.security_profiles import validate_tool_policy

    document = {
        "policy_version": POLICY_VERSION,
        "subjects": [
            {"subject": "alice", "permissions": [{"tool": "*", "action": "call"}]}
        ],
    }
    problems = validate_tool_policy(document)
    assert any("grants every registered tool" in problem for problem in problems)


def test_a_profile_without_grants_emits_an_empty_permission_list():
    document = get_security_profile("custom-restricted").to_tool_policy("alice")
    assert document["subjects"][0]["permissions"] == []


def test_an_empty_subject_is_refused():
    with pytest.raises(ValueError):
        get_security_profile("code-interpreter").to_tool_policy("")
