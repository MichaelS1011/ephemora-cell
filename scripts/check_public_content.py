#!/usr/bin/env python3
"""Public-content guard.

The public repository carries the product, the engineering and the verifiable
security evidence — nothing about how the project is governed internally, and
no private environment detail (personal home paths, credentials). This guard
scans the tracked tree for leaks of the second kind so they fail CI instead of
being caught by hand after a push.

Rules are structural and generic (see ``public_content_guard.json``); the
project's private specifics — real usernames, contact names, partner names —
are never stored in the public repo. A developer who needs them runs the same
guard with a LOCAL overlay:

    EPHEMORA_PUBLIC_GUARD_RULES=~/ephemora-private-rules.json \\
        python scripts/check_public_content.py

The overlay is a JSON file with the same ``content_rules`` shape. Matches from
the overlay are reported by rule id only, never with the matched text, so the
confidential list stays out of CI logs and the repository.

This is a hygiene gate, not a sanitizer: it flags, a human classifies. It never
rewrites files and never hides a real security limitation — the public
documentation must keep stating known risks, limits and advisories.
"""

from __future__ import annotations

import argparse
import json
import os
import re
import subprocess
import sys
from collections.abc import Iterable
from dataclasses import dataclass
from pathlib import Path

CONFIG_PATH = Path(__file__).with_name("public_content_guard.json")


@dataclass(frozen=True)
class Finding:
    rule: str
    path: str
    line: int
    detail: str

    def render(self) -> str:
        return f"{self.rule}: {self.path}:{self.line}  {self.detail}".rstrip()


def _load_config(path: Path) -> dict:
    with path.open(encoding="utf-8") as handle:
        return json.load(handle)


def _compiled(patterns: Iterable[str]) -> list[re.Pattern]:
    return [re.compile(p) for p in patterns]


def _tracked_files(root: Path) -> list[str]:
    out = subprocess.run(
        ["git", "ls-files", "-z"],
        cwd=root,
        check=True,
        capture_output=True,
    ).stdout
    return sorted(p for p in out.decode("utf-8").split("\0") if p)


def _is_scannable(rel: str, suffixes: list[str]) -> bool:
    return Path(rel).suffix.lower() in suffixes


def _scan_content(
    rel: str,
    text: str,
    rules: list[dict],
    allow_marker: str,
    report_snippets: bool,
) -> list[Finding]:
    findings: list[Finding] = []
    for lineno, line in enumerate(text.splitlines(), start=1):
        if allow_marker and allow_marker in line:
            continue
        for rule in rules:
            match = re.search(rule["regex"], line)
            if not match:
                continue
            detail = ""
            if rule["id"] == "personal-home-path":
                user = match.group("user")
                if user in rule.get("benign_users", []):
                    continue
                detail = user
            elif report_snippets:
                detail = line.strip()[:80]
            findings.append(Finding(rule["id"], rel, lineno, detail))
    return findings


def scan_tree(root: Path, files: list[str], config: dict) -> list[Finding]:
    forbidden = _compiled(config.get("forbidden_tracked_paths", []))
    allowed = _compiled(config.get("allow_files", []))
    suffixes = [s.lower() for s in config.get("scan_suffixes", [])]
    rules = config.get("content_rules", [])
    marker = config.get("allow_marker", "")

    findings: list[Finding] = []
    for rel in files:
        posix = rel.replace(os.sep, "/")
        for pat in forbidden:
            if pat.search(posix):
                findings.append(
                    Finding(
                        "tracked-internal-path", posix, 0, "file must not be tracked"
                    )
                )
                break
        if any(pat.search(posix) for pat in allowed):
            continue
        if not _is_scannable(posix, suffixes):
            continue
        path = root / rel
        try:
            text = path.read_text(encoding="utf-8")
        except (UnicodeDecodeError, OSError):
            continue
        findings.extend(_scan_content(posix, text, rules, marker, report_snippets=True))
    return findings


def _overlay_rules(env_path: str) -> list[dict]:
    if not env_path:
        return []
    p = Path(env_path).expanduser()
    if not p.is_file():
        return []
    data = json.loads(p.read_text(encoding="utf-8"))
    return data.get("content_rules", [])


def _scan_overlay(rel_files: list[str], root: Path, rules: list[dict]) -> list[Finding]:
    """Overlay findings report by rule id only — never the matched confidential text."""
    findings: list[Finding] = []
    for rel in rel_files:
        if not _is_scannable(
            rel, [".py", ".md", ".yml", ".yaml", ".toml", ".json", ".txt", ".sh"]
        ):
            continue
        try:
            text = (root / rel).read_text(encoding="utf-8")
        except (UnicodeDecodeError, OSError):
            continue
        for lineno, line in enumerate(text.splitlines(), start=1):
            for rule in rules:
                if re.search(rule["regex"], line):
                    findings.append(Finding(rule["id"], rel, lineno, ""))
    return findings


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(
        description="Scan tracked files for internal/private leaks."
    )
    parser.add_argument("--root", default=".", help="repository root (default: cwd)")
    parser.add_argument(
        "--strict", action="store_true", help="fail on any finding (default)"
    )
    args = parser.parse_args(argv)

    root = Path(args.root).resolve()
    config = _load_config(CONFIG_PATH)
    files = _tracked_files(root)

    findings = scan_tree(root, files, config)

    overlay = _overlay_rules(os.environ.get("EPHEMORA_PUBLIC_GUARD_RULES", ""))
    if overlay:
        findings.extend(_scan_overlay(files, root, overlay))
        print(
            f"public-content-guard: local overlay active ({len(overlay)} private rules)"
        )

    if findings:
        by_rule: dict[str, int] = {}
        for f in findings:
            by_rule[f.rule] = by_rule.get(f.rule, 0) + 1
        print(
            f"::error::public-content-guard: {len(findings)} finding(s) across "
            f"{len(by_rule)} rule(s): {', '.join(sorted(by_rule))}"
        )
        for f in sorted(findings, key=lambda x: (x.rule, x.path, x.line)):
            print("  " + f.render())
        print(
            "Classify each finding: PUBLIC-KEEP, PUBLIC-REWRITE, or PRIVATE-MOVE. "
            "Suppress a verified false positive with an inline "
            f"'{config.get('allow_marker')}' marker on the line."
        )
        return 1

    print(f"public-content-guard: clean ({len(files)} tracked files scanned)")
    return 0


if __name__ == "__main__":
    sys.exit(main())
