# SPDX-License-Identifier: BUSL-1.1
# Copyright 2026 Michael Soppa

"""Security profiles — the named, default-deny presets from the v1.2 directive.

These are *use-case* profiles (``code-interpreter``, ``data-analysis`` …) on top
of the resource presets in :mod:`ephemora_cell.profiles`. Each one is a real
:class:`~ephemora_cell.wasi_runtime.WASIConfig` — so every budget below is an
enforced number, not a comment — plus two declared capabilities:

* **network** — a WASM guest has no sockets; ``web-fetch`` therefore says
  ``egress-mediated``, meaning it is only useful behind the host egress mediator
  (ADR-002/013). Every other profile is ``none``.
* **tool_actions** — which MCP tool/action pairs the profile may use. This is the
  bridge to the ADR-016 authorizer: :meth:`SecurityProfile.to_tool_policy`
  produces the exact policy document the MCP server enforces, so the profile and
  the runtime interpret the same file the same way.

No standard profile grants a tool wildcard. Tool names are deployment-specific,
so every execution profile starts with **no** tool grants and the operator names
the tools explicitly (least privilege, v1.2). ``agent-readonly`` is the one
exception: it grants the single policy *read*, never a call.

No standard profile grants a host directory or an environment variable:
``allow_dirs``/``allow_env`` stay empty, so a guest reaches only what the
operator grants explicitly with ``--allow-dirs`` (a sidecar can narrow, never
widen).
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any

from ephemora_cell.wasi_runtime import WASIConfig

__all__ = [
    "SECURITY_PROFILES",
    "SecurityProfile",
    "get_security_profile",
    "list_security_profiles",
    "validate_tool_policy",
]

#: Policy schema version this module emits. Kept as a literal so the core
#: package does not import the MCP package; ``tests/test_security_profiles.py``
#: asserts it equals ``ephemora_cell_mcp.authz.POLICY_VERSION`` so the two
#: cannot drift unnoticed.
POLICY_VERSION = "1.2.0-1"

NETWORK_NONE = "none"
NETWORK_EGRESS_MEDIATED = "egress-mediated"


@dataclass(frozen=True)
class SecurityProfile:
    """A named preset: enforced budgets plus declared, mapped capabilities."""

    name: str
    summary: str
    config: WASIConfig
    network: str = NETWORK_NONE
    #: ``(tool_pattern, action)`` pairs granted to a subject under this profile.
    #: ``"*"`` means "any registered tool"; an empty tuple grants nothing. The
    #: standard execution presets stay empty — an operator names tools directly.
    tool_actions: tuple[tuple[str, str], ...] = ()
    #: Operator-visible documentation (v1.2), all in one place.
    documentation: dict[str, Any] = field(default_factory=dict)

    def to_tool_policy(
        self, subject: str, *, policy_version: str = POLICY_VERSION
    ) -> dict:
        """The MCP policy document that grants exactly this profile.

        Fails closed: a profile that grants nothing yields a subject entry with
        no permissions, which the authorizer denies for every call.
        """
        if not subject:
            raise ValueError("a security profile needs a subject to bind to")
        permissions = [
            {"tool": tool, "action": action} for tool, action in self.tool_actions
        ]
        return {
            "policy_version": policy_version,
            "subjects": [{"subject": subject, "permissions": permissions}],
        }


def _cfg(**kwargs: Any) -> WASIConfig:
    # Every profile is default-deny on host access; only budgets differ.
    return WASIConfig(allow_dirs=(), allow_env=(), **kwargs)


SECURITY_PROFILES: dict[str, SecurityProfile] = {
    "code-interpreter": SecurityProfile(
        name="code-interpreter",
        summary="Run a short program or snippet; no host files, no network.",
        config=_cfg(
            max_memory_mb=256,
            max_fuel=5_000_000,
            timeout_seconds=45,
            disk_quota_bytes=256 * 1024 * 1024,
            io_cpu_seconds=2.0,
            io_budget_bytes=64 * 1024 * 1024,
        ),
        tool_actions=(),
        documentation={
            "allowed_applications": ["scratchpad computation", "unit-sized scripts"],
            "granted": ["128-256 MiB linear memory", "5 M fuel", "45 s wall"],
            "forbidden": [
                "host files",
                "environment variables",
                "network",
                "child processes",
            ],
            "limits": {"timeout_seconds": 45, "disk_quota_bytes": 256 * 1024 * 1024},
            "platform": ["any supported platform"],
            "residual_risks": [
                "a native worker compromise is not contained by this profile (A7)"
            ],
        },
    ),
    "data-analysis": SecurityProfile(
        name="data-analysis",
        summary="Larger in-memory analytics without host access.",
        config=_cfg(
            max_memory_mb=1024,
            max_fuel=20_000_000,
            timeout_seconds=90,
            disk_quota_bytes=512 * 1024 * 1024,
            io_cpu_seconds=5.0,
            io_budget_bytes=128 * 1024 * 1024,
        ),
        tool_actions=(),
        documentation={
            "allowed_applications": [
                "aggregation over generated data",
                "numeric workloads",
            ],
            "granted": ["up to 1 GiB linear memory", "20 M fuel", "90 s wall"],
            "forbidden": ["host files", "environment variables", "network"],
            "limits": {"timeout_seconds": 90},
            "platform": ["any supported platform"],
            "residual_risks": [
                "memory64/4.5 GiB remains opt-in via the 'analytical' profile"
            ],
        },
    ),
    "file-converter": SecurityProfile(
        name="file-converter",
        summary="Transform an operator-granted input file; no other host access.",
        config=_cfg(
            max_memory_mb=256,
            max_fuel=5_000_000,
            timeout_seconds=60,
            disk_quota_bytes=512 * 1024 * 1024,
            io_cpu_seconds=3.0,
            io_budget_bytes=128 * 1024 * 1024,
        ),
        tool_actions=(),
        documentation={
            "allowed_applications": ["format conversion of a provided file"],
            "granted": [
                "the input dir passed with --allow-dirs",
                "256 MiB memory",
                "60 s",
            ],
            "forbidden": ["any path outside the granted dir", "env", "network"],
            "limits": {"timeout_seconds": 60},
            "platform": ["any supported platform"],
            "residual_risks": [
                "granted dir is re-validated at grant time, not path-identity bound (see S2)"
            ],
        },
    ),
    "web-fetch": SecurityProfile(
        name="web-fetch",
        summary="Fetch an allowlisted endpoint through the host egress mediator.",
        config=_cfg(
            max_memory_mb=128,
            max_fuel=2_000_000,
            timeout_seconds=30,
            disk_quota_bytes=64 * 1024 * 1024,
            io_cpu_seconds=4.0,
            io_budget_bytes=32 * 1024 * 1024,
        ),
        network=NETWORK_EGRESS_MEDIATED,
        tool_actions=(),
        documentation={
            "allowed_applications": ["fetch a URL the operator put on the allowlist"],
            "granted": ["host-side egress mediation (ADR-002/013) only"],
            "forbidden": ["direct sockets", "unlisted hosts", "host files"],
            "limits": {"timeout_seconds": 30},
            "platform": ["MCP host-sidecar path"],
            "residual_risks": [
                "useless without a configured mediator; the profile does not grant egress by itself"
            ],
        },
    ),
    "build-tool": SecurityProfile(
        name="build-tool",
        summary="Compute-heavy build step; still no host access.",
        config=_cfg(
            max_memory_mb=1024,
            max_fuel=30_000_000,
            timeout_seconds=180,
            disk_quota_bytes=1024 * 1024 * 1024,
            io_cpu_seconds=10.0,
            io_budget_bytes=256 * 1024 * 1024,
        ),
        tool_actions=(),
        documentation={
            "allowed_applications": ["deterministic build-like transforms"],
            "granted": ["1 GiB memory", "30 M fuel", "180 s wall", "10 s host I/O CPU"],
            "forbidden": ["host files", "env", "network"],
            "limits": {"timeout_seconds": 180, "disk_quota_bytes": 1024 * 1024 * 1024},
            "platform": ["any supported platform"],
            "residual_risks": [
                "host-wide admission must bound concurrent build steps (v1.2)"
            ],
        },
    ),
    "agent-readonly": SecurityProfile(
        name="agent-readonly",
        summary="May read policy; may not execute tools.",
        config=_cfg(
            max_memory_mb=128,
            max_fuel=1_000_000,
            timeout_seconds=20,
        ),
        # Read-only by construction: only the policy read is granted, never a call.
        tool_actions=(("get-policy", "read"),),
        documentation={
            "allowed_applications": ["inspect what a tool would be allowed to do"],
            "granted": ["read of get-policy"],
            "forbidden": ["every tools/call", "host files", "network"],
            "limits": {"timeout_seconds": 20},
            "platform": ["MCP path"],
            "residual_risks": [],
        },
    ),
    "custom-restricted": SecurityProfile(
        name="custom-restricted",
        summary="Grants nothing; the operator extends it deliberately.",
        config=_cfg(
            max_memory_mb=64,
            max_fuel=500_000,
            timeout_seconds=10,
        ),
        tool_actions=(),
        documentation={
            "allowed_applications": ["a starting point the operator widens on purpose"],
            "granted": ["nothing by default"],
            "forbidden": ["all tools", "host files", "network"],
            "limits": {"timeout_seconds": 10},
            "platform": ["any supported platform"],
            "residual_risks": [],
        },
    ),
}


def get_security_profile(name: str) -> SecurityProfile:
    """Return a security profile by name; unknown names fail closed."""
    if name not in SECURITY_PROFILES:
        raise ValueError(
            f"Unknown security profile: {name!r} "
            f"(available: {sorted(SECURITY_PROFILES)})"
        )
    return SECURITY_PROFILES[name]


def list_security_profiles() -> list[str]:
    return sorted(SECURITY_PROFILES)


def validate_tool_policy(document: object) -> list[str]:
    """Return human-readable problems with a policy document (empty = clean).

    Structural problems are hard errors the caller must refuse; dangerous
    widenings are returned too, because v1.2 requires that a generated
    policy marks what it grants broadly. The distinction is the caller's: a
    structurally broken document must not be written, a wide one may be, with
    the warning shown.
    """
    problems: list[str] = []
    if not isinstance(document, dict):
        return ["policy document is not a JSON object"]
    version = document.get("policy_version")
    if not isinstance(version, str) or not version:
        problems.append("missing non-empty 'policy_version'")
    subjects = document.get("subjects")
    if not isinstance(subjects, list):
        return [*problems, "'subjects' must be a list"]
    for entry in subjects:
        if not isinstance(entry, dict):
            problems.append("subject entry is not an object")
            continue
        subject = entry.get("subject")
        if not isinstance(subject, str) or not subject:
            problems.append("subject entry has no name")
        permissions = entry.get("permissions", [])
        if not isinstance(permissions, list):
            problems.append(f"subject {subject!r}: 'permissions' must be a list")
            continue
        for perm in permissions:
            if not isinstance(perm, dict):
                problems.append(f"subject {subject!r}: permission is not an object")
                continue
            tool = perm.get("tool")
            if tool == "*":
                problems.append(
                    f"subject {subject!r}: 'tool' is '*', which grants every "
                    "registered tool — widen deliberately, not by default"
                )
            elif not isinstance(tool, str) or not tool:
                problems.append(f"subject {subject!r}: permission has no tool")
            if perm.get("action") == "*":
                problems.append(
                    f"subject {subject!r}: 'action' is '*', which grants every "
                    "action (call and read)"
                )
            if perm.get("not_after") is None and perm.get("not_before") is None:
                problems.append(
                    f"subject {subject!r}: permission for {tool!r} has no validity "
                    "window — it never expires"
                )
    return problems
