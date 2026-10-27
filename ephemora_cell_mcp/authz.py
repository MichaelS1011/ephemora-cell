# SPDX-License-Identifier: BUSL-1.1
# Copyright 2026 Michael Soppa

"""Per-identity, per-tool MCP authorization (ADR-016 / v1.2).

The bridge and the stdio server authenticate a *client*; this module decides
what that client may then **do**. It is deliberately a small, versioned,
auditable model — not a general IAM system:

* the **subject** (identity) is established by the host — the bearer token the
  bridge authenticated, or the process identity for stdio — and is never read
  from a request field, so a client cannot widen its own rights by naming
  itself something else;
* every grant binds a subject to a ``(tool, action, resource)`` triple with an
  optional validity window;
* the posture is **default deny**: anything not explicitly granted is refused;
* every decision yields an :class:`AuditRecord` (no tokens, no secrets).

When no policy is configured the caller keeps the pre-1.2 behaviour (a single
authenticated client may call any registered tool). That is an explicit,
operator-visible legacy mode — never a silent grant of fine-grained rights.
"""

from __future__ import annotations

import json
import time
from collections.abc import Callable
from dataclasses import dataclass
from pathlib import Path
from typing import Any

__all__ = [
    "ACTION_CALL",
    "ACTION_READ",
    "POLICY_VERSION",
    "AuditRecord",
    "Authorizer",
    "Decision",
    "Permission",
    "SubjectPolicy",
    "ToolPolicy",
    "load_tool_policy",
]

#: Bumped when the on-disk policy schema or the matching rules change.
POLICY_VERSION = "1.2.0-1"

ACTION_CALL = "call"
ACTION_READ = "read"

_WILDCARD = "*"


@dataclass(frozen=True)
class Permission:
    """One granted capability: ``subject`` may ``action`` ``tool``/``resource``."""

    tool: str
    action: str = ACTION_CALL
    resource: str = _WILDCARD
    not_before: float | None = None
    not_after: float | None = None

    def covers(self, tool: str, action: str, resource: str) -> bool:
        return (
            self.tool in (_WILDCARD, tool)
            and self.action in (_WILDCARD, action)
            and self.resource in (_WILDCARD, resource)
        )

    def window_ok(self, now: float) -> tuple[bool, str]:
        if self.not_before is not None and now < self.not_before:
            return False, "permission not yet valid"
        if self.not_after is not None and now > self.not_after:
            return False, "permission expired"
        return True, ""


@dataclass(frozen=True)
class SubjectPolicy:
    subject: str
    permissions: tuple[Permission, ...]


@dataclass(frozen=True)
class ToolPolicy:
    """A versioned set of subject policies. Default deny."""

    version: str
    subjects: dict[str, SubjectPolicy]

    def for_subject(self, subject: str | None) -> SubjectPolicy | None:
        if not subject:
            return None
        return self.subjects.get(subject)

    @classmethod
    def from_dict(cls, data: Any) -> ToolPolicy:
        """Parse and validate a policy document. **Fails closed.**

        A malformed document raises :class:`ValueError`; it is never quietly
        reduced to "allow everything".
        """
        if not isinstance(data, dict):
            raise ValueError("tool policy must be a JSON object")
        version = data.get("policy_version")
        if not isinstance(version, str) or not version:
            raise ValueError("tool policy needs a non-empty 'policy_version'")
        subjects_raw = data.get("subjects")
        if not isinstance(subjects_raw, list):
            raise ValueError("tool policy 'subjects' must be a list")
        subjects: dict[str, SubjectPolicy] = {}
        for entry in subjects_raw:
            if not isinstance(entry, dict):
                raise ValueError("each subject entry must be an object")
            subject = entry.get("subject")
            if not isinstance(subject, str) or not subject:
                raise ValueError("each subject entry needs a non-empty 'subject'")
            if subject in subjects:
                raise ValueError(f"duplicate subject {subject!r}")
            perms_raw = entry.get("permissions", [])
            if not isinstance(perms_raw, list):
                raise ValueError(f"subject {subject!r}: 'permissions' must be a list")
            perms: list[Permission] = []
            for p in perms_raw:
                perms.append(_permission_from_dict(p, subject))
            subjects[subject] = SubjectPolicy(subject, tuple(perms))
        return cls(version=version, subjects=subjects)


def _permission_from_dict(p: Any, subject: str) -> Permission:
    if not isinstance(p, dict):
        raise ValueError(f"subject {subject!r}: permission must be an object")
    tool = p.get("tool")
    if not isinstance(tool, str) or not tool:
        raise ValueError(f"subject {subject!r}: permission needs a non-empty 'tool'")
    action = p.get("action", ACTION_CALL)
    if not isinstance(action, str) or not action:
        raise ValueError(f"subject {subject!r}: 'action' must be a non-empty string")
    resource = p.get("resource", _WILDCARD)
    if not isinstance(resource, str) or not resource:
        raise ValueError(f"subject {subject!r}: 'resource' must be a non-empty string")
    return Permission(
        tool=tool,
        action=action,
        resource=resource,
        not_before=_opt_float(p.get("not_before"), subject),
        not_after=_opt_float(p.get("not_after"), subject),
    )


def _opt_float(value: Any, subject: str) -> float | None:
    if value is None:
        return None
    if isinstance(value, bool) or not isinstance(value, (int, float)):
        raise ValueError(f"subject {subject!r}: validity must be a number or null")
    return float(value)


def load_tool_policy(path: str | Path) -> ToolPolicy:
    """Load a policy file. A missing or malformed file raises — fail closed."""
    text = Path(path).read_text(encoding="utf-8")
    return ToolPolicy.from_dict(json.loads(text))


@dataclass(frozen=True)
class Decision:
    allowed: bool
    reason: str
    subject: str | None
    tool: str
    action: str
    resource: str
    policy_version: str

    def to_audit(self, **extra: Any) -> AuditRecord:
        return AuditRecord(
            subject=self.subject,
            tool=self.tool,
            action=self.action,
            resource=self.resource,
            policy_version=self.policy_version,
            decision="ALLOW" if self.allowed else "DENY",
            reason=self.reason,
            extra=extra,
        )


@dataclass(frozen=True)
class AuditRecord:
    """One authorization decision, in the clear but without secrets."""

    subject: str | None
    tool: str
    action: str
    resource: str
    policy_version: str
    decision: str
    reason: str
    extra: dict[str, Any]

    def as_dict(self) -> dict[str, Any]:
        record: dict[str, Any] = {
            "subject": self.subject,
            "tool": self.tool,
            "action": self.action,
            "resource": self.resource,
            "policy_version": self.policy_version,
            "decision": self.decision,
            "reason": self.reason,
        }
        record.update(self.extra)
        return record


class Authorizer:
    """Evaluates a :class:`ToolPolicy` for a host-established subject."""

    def __init__(
        self,
        policy: ToolPolicy,
        *,
        clock: Callable[[], float] = time.time,
    ) -> None:
        self.policy = policy
        self._clock = clock

    @property
    def version(self) -> str:
        return self.policy.version

    def authorize(
        self,
        subject: str | None,
        tool: str,
        *,
        action: str = ACTION_CALL,
        resource: str = _WILDCARD,
    ) -> Decision:
        """Return ALLOW/DENY for one ``(subject, tool, action, resource)``."""
        now = self._clock()

        def decide(allowed: bool, reason: str) -> Decision:
            return Decision(
                allowed=allowed,
                reason=reason,
                subject=subject,
                tool=tool,
                action=action,
                resource=resource,
                policy_version=self.policy.version,
            )

        if not subject:
            return decide(False, "unknown client")
        subject_policy = self.policy.for_subject(subject)
        if subject_policy is None:
            return decide(False, f"no permissions for subject {subject!r}")
        matched_but_invalid: str | None = None
        for perm in subject_policy.permissions:
            if not perm.covers(tool, action, resource):
                continue
            ok, why = perm.window_ok(now)
            if ok:
                return decide(True, "granted")
            matched_but_invalid = why
        if matched_but_invalid is not None:
            return decide(False, matched_but_invalid)
        return decide(False, "no matching permission")
