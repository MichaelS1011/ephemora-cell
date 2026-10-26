#!/usr/bin/env python3
"""Security-claims consistency guard.

Guards the class of error found and fixed on 2026-10-15: the arXiv 2509.11242
eleven-strategy table lists **7 blocked / 3 bounded / 1 permitted**, but its
summary prose (and two marketing mirrors) claimed "8 blocked / 2 bounded" by
silently promoting the third bounded row (memory exhaustion) into "blocked".
A headline security number that disagrees with the table it summarises is a
correctness bug, not a rounding choice — so it is now machine-checked.

What is checked (hard, exit 1 on drift or absence):

  1. The stale overcount strings must not appear in any public document:
     "8 attack techniques fully blocked", "8 fully blocked", "8 blocked, 2
     bounded". (The faithful count is 7/3/1.)
  2. docs/security_posture.md: the arXiv table's per-technique verdict column
     must sum to exactly 7 Blocked / 3 Bounded / 1 Within-Budget, AND the
     summary line directly after the table must state the same 7 / 3 / 1.
  3. No public document asserts "18/18" blocked for the OSS Cell. The UK-AISI
     18-scenario mapping is 8 execution-denied + 10 not-expressible, and the
     public evidence bundle was scored against Ephemora Enterprise (Cell was
     explicitly NOT scored) — an "18/18 BLOCKED" line is unsupported.
  4. The consolidated matrix docs/security_attack_matrix.md exists and is
     linked from README.md, SECURITY.md and docs/security_posture.md, so every
     public security number keeps a pointer to per-scenario provenance.

Exit 0 = all checks pass. Exit 1 = any violation, or a required
source/pattern is missing (absence is an error, not a pass).
"""

from __future__ import annotations

import re
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]

# Public documents scanned for the forbidden overcount strings.
SCAN_FILES = [
    "README.md",
    "SECURITY.md",
    "CHANGELOG.md",
    "docs/security_posture.md",
    "docs/whitepaper_linkedin.md",
    "docs/threat-model.md",
    "docs/ephemora-cell-whitepaper.typ",
    "docs/comparison-mcp-servers.md",
    "docs/security_attack_matrix.md",
]

FORBIDDEN = [
    "8 attack techniques fully blocked",
    "8 fully blocked",
    "8 blocked, 2 bounded",
    "8 fully \\\nblocked, 2 bounded",  # typ hard-wrap form
    "8 von 8 attack techniques",
]

FORBIDDEN_RE = [
    # any "N ... blocked" immediately followed by "2 bounded" for the 11-strategy set
    re.compile(r"8\s+fully\s+\\\s*\n?\s*blocked", re.IGNORECASE),
]

# A line is treated as *documenting* the old mistake (not asserting it) when it
# carries one of these markers. The guard then skips it, so correction notes and
# quoted history stay allowed while an unqualified claim fails the check.
CONTEXT_MARKERS = (
    "reported",
    "stated",
    "states",
    "earlier",
    "correct",
    "unsupported",
    "not supported",
    "would be",
    "mislabel",
    "silently",
    "contradic",
    "forbidden",
    "must not",
    "not claimed",
    "overcount",
    "promoted",
    "historical",
    "reclassif",
    "old error",
)


def _read(rel: str) -> str | None:
    p = ROOT / rel
    if not p.is_file():
        return None
    return p.read_text(encoding="utf-8")


def check_forbidden() -> list[str]:
    errors: list[str] = []
    for rel in SCAN_FILES:
        text = _read(rel)
        if text is None:
            continue
        for lineno, raw in enumerate(text.splitlines(), 1):
            line = raw.lower()
            if any(mk in line for mk in CONTEXT_MARKERS):
                continue  # this line documents/renounces the claim, not asserts it
            norm = raw.replace("\\\n", " ").replace("\\", "").lower()
            for lit in FORBIDDEN:
                needle = lit.replace("\\\n", " ").replace("\\", "").lower()
                if needle and needle in norm:
                    errors.append(
                        f"{rel}:{lineno}: forbidden stale overcount string {lit!r}"
                    )
            for rx in FORBIDDEN_RE:
                if rx.search(raw):
                    errors.append(
                        f"{rel}:{lineno}: forbidden stale overcount pattern {rx.pattern!r}"
                    )
    return errors


def check_matrix_arithmetic() -> list[str]:
    errors: list[str] = []
    text = _read("docs/security_posture.md")
    if text is None:
        return ["docs/security_posture.md missing"]
    start = text.find("arXiv 2509.11242")
    if start == -1:
        return ["docs/security_posture.md: arXiv 2509.11242 section missing"]
    # the table + summary live between the heading and the next '## ' section
    end = text.find("\n## ", start + 5)
    section = text[start : end if end != -1 else len(text)]
    rows = [ln for ln in section.splitlines() if ln.strip().startswith("|")]
    blocked = bounded = budget = 0
    for ln in rows:
        cells = [c.strip() for c in ln.strip().strip("|").split("|")]
        if len(cells) < 2:
            continue
        verdict = cells[1]
        if verdict.startswith("Technique") or set(verdict) <= {"-", ":", " "}:
            continue
        low = verdict.lower()
        if "blocked" in low:
            blocked += 1
        elif "within budget" in low:
            budget += 1
        elif "bounded" in low:
            bounded += 1
    if (blocked, bounded, budget) != (7, 3, 1):
        errors.append(
            "docs/security_posture.md: arXiv table verdicts sum to "
            f"{blocked}/{bounded}/{budget}, expected 7/3/1"
        )
    # summary line must agree with the table
    m = re.search(r"(\d+)\s+attack techniques blocked", section)
    if not m or int(m.group(1)) != 7:
        errors.append(
            "docs/security_posture.md: summary does not state '7 attack techniques blocked'"
        )
    mb = re.search(r"(\d+)\s+bounded", section)
    if not mb or int(mb.group(1)) != 3:
        errors.append("docs/security_posture.md: summary does not state '3 bounded'")
    return errors


def check_no_1818() -> list[str]:
    errors: list[str] = []
    rx = re.compile(
        r"18\s*/\s*18\s+(?:attack\s+)?(?:scenarios?\s+)?blocked", re.IGNORECASE
    )
    for rel in SCAN_FILES:
        text = _read(rel)
        if text is None:
            continue
        for lineno, raw in enumerate(text.splitlines(), 1):
            if any(mk in raw.lower() for mk in CONTEXT_MARKERS):
                continue
            if rx.search(raw):
                errors.append(
                    f"{rel}:{lineno}: asserts '18/18 blocked' for OSS Cell (unsupported)"
                )
    return errors


def check_matrix_linked() -> list[str]:
    errors: list[str] = []
    if (ROOT / "docs" / "security_attack_matrix.md").is_file() is False:
        errors.append("docs/security_attack_matrix.md missing")
    for rel in ("README.md", "SECURITY.md", "docs/security_posture.md"):
        text = _read(rel)
        if text is None:
            errors.append(f"{rel} missing")
        elif "security_attack_matrix.md" not in text:
            errors.append(f"{rel}: does not link docs/security_attack_matrix.md")
    return errors


def main() -> int:
    errors = (
        check_forbidden()
        + check_matrix_arithmetic()
        + check_no_1818()
        + check_matrix_linked()
    )
    if errors:
        print("SECURITY-CLAIMS GUARD FAILED:")
        for e in errors:
            print(f"  - {e}")
        return 1
    print(
        "SECURITY-CLAIMS GUARD OK: matrix is 7/3/1, summary agrees, "
        "no 18/18 OSS claim, matrix linked from README + SECURITY + posture."
    )
    return 0


if __name__ == "__main__":
    sys.exit(main())
