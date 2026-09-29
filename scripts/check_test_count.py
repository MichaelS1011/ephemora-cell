#!/usr/bin/env python3
"""Test-count sync guard — docs claims must match the real pytest collection.

The test-count numbers used to drift across four documents (README badge,
README freshness block, README "Testing & Verification" paragraph,
docs/comparison-mcp-servers.md — audit 2026-09-29 found 532/470/424 in
various spots). This guard makes the counts machine-checked against the one
source of truth: ``pytest --collect-only``.

What is checked (hard, exit 1 on drift):

  1. README.md "Testing & Verification" paragraph:  ``N tests passing
     (M skipped)``  — must satisfy  N + M == collected.
  2. docs/comparison-mcp-servers.md ``N CI-enforced tests (M skipped)``,
     ``comprises N collected tests today`` and its ``N passing (M skipped)``
     split — same invariant, and the bare total must equal the collection.

What is reported only (WARNING, exit 0 unless strict mode):

  * README.md hero badge        ``tests-N_passing``
  * README.md freshness block   ``N tests passing, P% coverage``

These two are re-stamped by the release step with the final numbers (the
badge/freshness line is deliberately refreshed last, per release); in the
default CI mode a stale badge prints a warning instead of failing so the
guard can ship before that re-stamp. Set ``CHECK_TEST_COUNT_STRICT=1`` to
make badge/freshness drift a hard failure — intended for after the release
re-stamp, when every number must agree with the collection.

Exit 0 = all hard checks match (warnings allowed in default mode).
Exit 1 = any hard mismatch, or a source (pytest run / file / pattern)
         missing — absence is an error, not a pass.
"""

from __future__ import annotations

import os
import re
import subprocess
import sys
from pathlib import Path

REPO = Path(__file__).resolve().parent.parent
STRICT = os.environ.get("CHECK_TEST_COUNT_STRICT") == "1"


def _collected_total() -> int:
    """Run pytest --collect-only and parse the collected test total."""
    proc = subprocess.run(
        [sys.executable, "-m", "pytest", "--collect-only", "-q"],
        cwd=REPO,
        capture_output=True,
        text=True,
    )
    if proc.returncode != 0:
        print("FAIL: pytest --collect-only failed:", file=sys.stderr)
        print(proc.stdout[-2000:], file=sys.stderr)
        print(proc.stderr[-2000:], file=sys.stderr)
        raise SystemExit(1)
    matches = re.findall(r"(\d+) tests? collected", proc.stdout)
    if not matches:
        print(
            "FAIL: could not parse a 'N tests collected' total from "
            "pytest --collect-only output:",
            file=sys.stderr,
        )
        print(proc.stdout[-2000:], file=sys.stderr)
        raise SystemExit(1)
    distinct = sorted({int(m) for m in matches})
    if len(distinct) != 1:
        print(
            f"FAIL: ambiguous collection totals {distinct} — refusing to "
            "guess which is real",
            file=sys.stderr,
        )
        raise SystemExit(1)
    return distinct[0]


def _unique_int(pattern: str, text: str, where: str) -> tuple[int, ...]:
    """All distinct captures for ``pattern``; empty tuple if absent."""
    matches = {int(m) for m in re.findall(pattern, text, re.MULTILINE)}
    if len(matches) > 1:
        print(
            f"FAIL: {where}: CONFLICTING claims {sorted(matches)} — every "
            "mention must carry the same number",
            file=sys.stderr,
        )
        raise SystemExit(1)
    return tuple(matches)


def _hard_claim(
    pattern: str,
    text: str,
    where: str,
    collected: int,
    *,
    fix_hint: str,
) -> int:
    """Check one hard pattern: exactly one distinct value, == collected."""
    matches = _unique_int(pattern, text, where)
    if not matches:
        print(
            f"FAIL: {where}: no test-count claim found — the guard cannot "
            f"verify an undocumented count. {fix_hint}",
            file=sys.stderr,
        )
        raise SystemExit(1)
    value = matches[0]
    if value != collected:
        print(
            f"FAIL: test-count drift in {where}:\n"
            f"  documented:   {value}\n"
            f"  collected:    {collected}  (pytest --collect-only)\n"
            f"  delta:        {collected - value:+d}\n"
            f"  -> {fix_hint}",
            file=sys.stderr,
        )
        raise SystemExit(1)
    return value


def _passing_skipped(
    pattern: str,
    text: str,
    where: str,
    collected: int,
    *,
    fix_hint: str,
) -> None:
    """Check a ``N passing (M skipped)`` pair: N + M == collected."""
    pairs = {(int(p), int(s)) for p, s in re.findall(pattern, text, re.MULTILINE)}
    if not pairs:
        print(
            f"FAIL: {where}: no 'N passing (M skipped)' claim found. " f"{fix_hint}",
            file=sys.stderr,
        )
        raise SystemExit(1)
    if len(pairs) > 1:
        print(
            f"FAIL: {where}: CONFLICTING passing/skipped claims "
            f"{sorted(pairs)} — every mention must agree",
            file=sys.stderr,
        )
        raise SystemExit(1)
    passing, skipped = pairs.pop()
    if passing + skipped != collected:
        print(
            f"FAIL: test-count drift in {where}:\n"
            f"  documented:   {passing} passing + {skipped} skipped = "
            f"{passing + skipped}\n"
            f"  collected:    {collected}  (pytest --collect-only)\n"
            f"  delta:        {collected - passing - skipped:+d}\n"
            f"  -> {fix_hint}",
            file=sys.stderr,
        )
        raise SystemExit(1)


def _soft_claim(pattern: str, text: str, where: str, collected: int) -> None:
    """Report-only check (badge/freshness): warn on drift, never fail —
    unless CHECK_TEST_COUNT_STRICT=1 (see module docstring)."""
    matches = _unique_int(pattern, text, where)
    if not matches:
        print(f"note: {where}: no badge/freshness test count found (skipped)")
        return
    value = matches[0]
    if value != collected:
        message = (
            f"WARNING: {where}: badge/freshness says {value} but "
            f"{collected} tests are collected — re-stamp at release "
            "(CHECK_TEST_COUNT_STRICT=1 makes this a hard failure)"
        )
        if STRICT:
            print(f"FAIL: {message}", file=sys.stderr)
            raise SystemExit(1)
        print(message)
    else:
        print(f"ok: {where}: {value} matches the collection")


def main() -> int:
    collected = _collected_total()
    print(f"pytest --collect-only: {collected} tests collected")

    readme_path = REPO / "README.md"
    if not readme_path.exists():
        print("FAIL: README.md not found", file=sys.stderr)
        return 1
    readme = readme_path.read_text(encoding="utf-8")

    comparison_path = REPO / "docs" / "comparison-mcp-servers.md"
    if not comparison_path.exists():
        print(
            "FAIL: docs/comparison-mcp-servers.md not found",
            file=sys.stderr,
        )
        return 1
    comparison = comparison_path.read_text(encoding="utf-8")

    # --- hard checks (drift = exit 1) -----------------------------------
    # Patterns are whitespace-tolerant (\s+): prose reflows across lines,
    # the claim must still be found.
    _passing_skipped(
        r"(\d+)\s+tests\s+passing\s+\((\d+)\s+skipped\)",
        readme,
        'README.md "Testing & Verification"',
        collected,
        fix_hint=(
            "update the test-count sentence in the README "
            '"Testing & Verification" section (passing = collected - skipped)'
        ),
    )
    _passing_skipped(
        r"(\d+)\s+CI-enforced\s+tests\s+\((\d+)\s+skipped\)",
        comparison,
        "docs/comparison-mcp-servers.md",
        collected,
        fix_hint=(
            "update the CI-enforced test count in " "docs/comparison-mcp-servers.md"
        ),
    )
    _hard_claim(
        r"comprises\s+(\d+)\s+collected\s+tests\s+today",
        comparison,
        "docs/comparison-mcp-servers.md",
        collected,
        fix_hint=(
            "update the 'comprises N collected tests today' sentence in "
            "docs/comparison-mcp-servers.md"
        ),
    )
    _passing_skipped(
        r"—\s*(\d+)\s+passing\s+\((\d+)\s+skipped\)",
        comparison,
        "docs/comparison-mcp-servers.md (suite total)",
        collected,
        fix_hint=(
            "update the passing/skipped split after 'collected tests today' "
            "in docs/comparison-mcp-servers.md"
        ),
    )

    # --- soft checks (badge/freshness — release re-stamps) ---------------
    _soft_claim(r"tests-(\d+)_passing", readme, "README.md hero badge", collected)
    _soft_claim(
        r"(\d+)\s+tests\s+passing,\s*\d+%\s*coverage",
        readme,
        "README.md freshness block",
        collected,
    )

    print(
        f"OK: documented test counts match the collection ({collected} "
        "collected)"
        + (" [strict mode]" if STRICT else " (badge/freshness: warning only)")
    )
    return 0


if __name__ == "__main__":
    sys.exit(main())
