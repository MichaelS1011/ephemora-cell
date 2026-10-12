"""Tests for the public-content guard (scripts/check_public_content.py).

The guard protects the separation between the public product surface and
internal governance / private environment detail. These tests exercise the
detection logic against synthetic files — the shipped tree itself is scanned
as a CI step (`Public-content guard` in the security job).

Secret fixtures are built by concatenation so the literal leak patterns never
appear as a single token in this file: the guard stays green on the tests even
if the allowlist for this file were removed.
"""

from __future__ import annotations

import importlib.util
import json
import re
import sys
from pathlib import Path

_ROOT = Path(__file__).resolve().parents[1]
_spec = importlib.util.spec_from_file_location(
    "check_public_content", _ROOT / "scripts" / "check_public_content.py"
)
assert _spec and _spec.loader
guard = importlib.util.module_from_spec(_spec)
# Register before exec_module: the guard's @dataclass resolves its (deferred)
# annotations via sys.modules[cls.__module__], which importlib does not populate
# on its own.
sys.modules["check_public_content"] = guard
_spec.loader.exec_module(guard)

CONFIG = json.loads((_ROOT / "scripts" / "public_content_guard.json").read_text())


def _scan(tmp_path: Path, files: dict[str, str]) -> list[guard.Finding]:
    for rel, text in files.items():
        p = tmp_path / rel
        p.parent.mkdir(parents=True, exist_ok=True)
        p.write_text(text, encoding="utf-8")
    return guard.scan_tree(tmp_path, list(files), CONFIG)


def test_shipped_rules_compile() -> None:
    for rule in CONFIG["content_rules"]:
        re.compile(rule["regex"])
    for pattern in CONFIG["forbidden_tracked_paths"] + CONFIG["allow_files"]:
        re.compile(pattern)


def test_detects_personal_home_path(tmp_path: Path) -> None:
    findings = _scan(
        tmp_path, {"docs/a.md": "run it under /Users/harlan.operator/cache now\n"}
    )
    assert [f.rule for f in findings] == ["personal-home-path"]


def test_benign_system_users_are_not_flagged(tmp_path: Path) -> None:
    findings = _scan(
        tmp_path,
        {
            "evidence.json": (
                "panicked at /Users/runner/.rustup/toolchains:\n"
                "loaded from /home/operator/app/main.py\n"
            )
        },
    )
    assert findings == []


def test_detects_credential_shapes(tmp_path: Path) -> None:
    pem = "-----BEGIN " + "RSA PRIVATE KEY-----"
    token = "ghp_" + "A1" * 18
    findings = _scan(
        tmp_path,
        {"config.sh": f"export K={pem}\nexport T={token}\n"},
    )
    rules = {f.rule for f in findings}
    assert "secret-private-key" in rules
    assert "secret-github-token" in rules


def test_detects_governance_references(tmp_path: Path) -> None:
    findings = _scan(
        tmp_path,
        {
            "README.md": (
                "approved by the CTO in the plan\n"
                "package WP-L4-1 shipped\n"
                "follow the PDCA loop\n"
            )
        },
    )
    rules = {f.rule for f in findings}
    assert {"governance-role-ref", "internal-id-ref", "internal-process-ref"} <= rules


def test_detects_management_wording_families(tmp_path: Path) -> None:
    findings = _scan(
        tmp_path,
        {
            "docs/x.md": (
                "granted by decision D7 on 2026-09-12\n"
                "shipped as a separate work package\n"
                "fixed after audit F3 in a regression test\n"
                "lands with the M2 engine upgrade\n"
                "tracked as defect P1 #12 and OODA-4\n"
            )
        },
    )
    assert len(findings) == 5  # one finding per rule × line
    assert {f.rule for f in findings} == {"internal-process-ref", "internal-id-ref"}


def test_allow_marker_suppresses_line(tmp_path: Path) -> None:
    marker = CONFIG["allow_marker"]
    findings = _scan(
        tmp_path,
        {
            "tool.py": (
                f"# deliberate fixture, reviewed /Users/anita.dev/tools {marker}\n"
                "# unreviewed /Users/anita.dev/tools\n"
            )
        },
    )
    assert len(findings) == 1


def test_forbidden_internal_paths_are_flagged(tmp_path: Path) -> None:
    findings = _scan(
        tmp_path,
        {
            "social/post.md": "public-safe text\n",
            "WORKPLAN_2026.md": "public-safe text\n",
        },
    )
    assert {f.path for f in findings} == {"social/post.md", "WORKPLAN_2026.md"}
    assert all(f.rule == "tracked-internal-path" for f in findings)


def test_allowlisted_guard_files_are_exempt_from_content_scan(tmp_path: Path) -> None:
    findings = _scan(
        tmp_path,
        {
            "scripts/check_public_content.py": "the CTO pattern lives here on purpose\n",
            "docs/other.md": "the CTO pattern lives here too\n",
        },
    )
    paths = {f.path for f in findings if f.rule == "governance-role-ref"}
    assert paths == {"docs/other.md"}


def test_overlay_findings_never_carry_snippets(tmp_path: Path) -> None:
    private_word = "sensitive-partner-name"
    (tmp_path / "leak.md").write_text(
        f"talked to {private_word} today\n", encoding="utf-8"
    )
    findings = guard._scan_overlay(
        ["leak.md"],
        tmp_path,
        [{"id": "private-contact", "regex": private_word}],
    )
    assert len(findings) == 1
    assert findings[0].rule == "private-contact"
    assert private_word not in findings[0].render()
    paths = {f.path for f in findings if f.rule == "governance-role-ref"}
    assert paths == {"docs/other.md"}


def test_overlay_findings_never_carry_snippets(tmp_path: Path) -> None:
    private_word = "sensitive-partner-name"
    (tmp_path / "leak.md").write_text(
        f"talked to {private_word} today\n", encoding="utf-8"
    )
    findings = guard._scan_overlay(
        ["leak.md"],
        tmp_path,
        [{"id": "private-contact", "regex": private_word}],
    )
    assert len(findings) == 1
    assert findings[0].rule == "private-contact"
    assert private_word not in findings[0].render()
