#!/usr/bin/env python3
"""Run the WebAssembly/wasi-testsuite against Ephemora Cell.

Orchestrates, as a thin layer (no runner internals forked):

1. Ensure the suite checkout exists at the pinned commit
   (``.conformance_cache/wasi-testsuite``, gitignored — never vendored
   into this repo).
2. Invoke the suite's own ``run-tests`` with the Cell adapter and the
   by-design expectations file.
3. Copy the JSON result into ``conformance/results/`` and print a
   per-suite summary.

Usage:
    .venv/bin/python conformance/run_wasi_testsuite.py [--json-only]

Exit code mirrors the suite runner: 0 when no unexpected failure,
1 otherwise (expected failures do not count as failures).
"""

from __future__ import annotations

import argparse
import json
import os
import subprocess
import sys
import time
from datetime import date, datetime, timedelta, timezone
from pathlib import Path

REPO = Path(__file__).resolve().parents[1]
CACHE = REPO / ".conformance_cache" / "wasi-testsuite"
RESULTS = Path(__file__).resolve().parent / "results"

# Pinned: prod/testsuite-base carries precompiled test binaries.
PINNED_COMMIT = "609c446139956ff30239f87cb18af1dc6128bed2"
SUITE_URL = "https://github.com/WebAssembly/wasi-testsuite.git"

ADAPTER = Path(__file__).resolve().parent / "adapters" / "ephemora_cell.py"
EXPECTATIONS = Path(__file__).resolve().parent / "expectations.toml"


def ensure_suite() -> None:
    if (CACHE / ".git").exists():
        head = subprocess.run(
            ["git", "-C", str(CACHE), "rev-parse", "HEAD"],
            capture_output=True,
            text=True,
            check=True,
        ).stdout.strip()
        if head == PINNED_COMMIT:
            return
        subprocess.run(
            ["git", "-C", str(CACHE), "fetch", "--quiet", "origin"], check=True
        )
        subprocess.run(
            ["git", "-C", str(CACHE), "checkout", "--quiet", PINNED_COMMIT], check=True
        )
        return
    CACHE.parent.mkdir(parents=True, exist_ok=True)
    subprocess.run(
        [
            "git",
            "clone",
            "--quiet",
            "--branch",
            "prod/testsuite-base",
            SUITE_URL,
            str(CACHE),
        ],
        check=True,
    )
    head = subprocess.run(
        ["git", "-C", str(CACHE), "rev-parse", "HEAD"],
        capture_output=True,
        text=True,
        check=True,
    ).stdout.strip()
    if head != PINNED_COMMIT:
        subprocess.run(
            ["git", "-C", str(CACHE), "checkout", "--quiet", PINNED_COMMIT], check=True
        )


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument(
        "--expectations",
        default=str(EXPECTATIONS),
        help="TOML expectations file (default: by-design list)",
    )
    args = parser.parse_args()

    ensure_suite()

    RESULTS.mkdir(parents=True, exist_ok=True)
    stamp = f"{PINNED_COMMIT[:12]}-{date.today()}"
    raw_json = RESULTS / f"wasi-testsuite-{stamp}.json"

    cmd = [
        sys.executable,  # run-tests' shebang would pick system python3
        str(CACHE / "run-tests"),
        "-r",
        str(ADAPTER),
        "--expectations",
        args.expectations,
        "--json-output-location",
        str(raw_json),
        "--disable-colors",
    ]
    print(f"[conformance] pinned {PINNED_COMMIT[:12]}, adapter {ADAPTER.name}")
    print(f"[conformance] {' '.join(cmd)}")
    start = time.monotonic()
    started = datetime.now(timezone.utc) - timedelta(seconds=5)
    proc = subprocess.run(cmd, cwd=str(CACHE))
    elapsed = time.monotonic() - start
    print(f"[conformance] runner exit {proc.returncode} in {elapsed:.0f}s")

    if raw_json.exists():
        summarize(raw_json, stamp, started)
    else:
        print("[conformance] WARNING: no JSON output produced")
        return 1
    return proc.returncode


def engine_abort_retries(started: datetime) -> list[dict]:
    """Retry entries logged by adapters/cell_retry_wrapper.py this run."""
    path = Path(os.getenv("CELL_RETRY_LOG") or RESULTS / "engine_abort_retries.jsonl")
    if not path.exists():
        return []
    out = []
    for line in path.read_text().splitlines():
        try:
            entry = json.loads(line)
        except json.JSONDecodeError:
            continue
        if entry.get("timestamp", "") >= started.isoformat(timespec="seconds"):
            out.append(entry)
    return out


def summarize(raw_json: Path, stamp: str, started: datetime) -> None:
    data = json.loads(raw_json.read_text())
    per_suite: dict[str, dict[str, int]] = {}
    for suite in data.get("results", []):
        key = f"{suite.get('name', '?')} [{suite.get('runtime', {}).get('name', '?')}]"
        counts = {
            "pass": suite.get("passed", 0),
            "expected_fail": suite.get("xfailed", 0),
            "unexpected_pass": suite.get("xpassed", 0),
            "fail": suite.get("failed", 0),
            "skip": suite.get("skipped", 0),
        }
        per_suite[key] = counts
    print("\n[conformance] summary")
    for key, counts in per_suite.items():
        print(f"  {key}: {counts}")

    keys = ("pass", "expected_fail", "unexpected_pass", "fail", "skip")
    total = {k: sum(c.get(k, 0) for c in per_suite.values()) for k in keys}
    retries = engine_abort_retries(started)
    meta = {
        "pinned_commit": PINNED_COMMIT,
        "date": str(date.today()),
        "totals": total,
        "per_suite": per_suite,
        "raw": raw_json.name,
        "engine_abort_retries": retries,
    }
    if retries:
        print(
            f"[conformance] NOTE: {len(retries)} engine-abort retry(ies) "
            "recorded this run (see conformance/README.md)"
        )
    digest = RESULTS / f"summary-{stamp}.json"
    digest.write_text(json.dumps(meta, indent=2))
    print(f"[conformance] totals: {total}")
    print(f"[conformance] summary: {digest}")


if __name__ == "__main__":
    sys.exit(main())
