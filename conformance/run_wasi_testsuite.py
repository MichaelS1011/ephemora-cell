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
    """Put the suite at PINNED_COMMIT and PROVE it is there before measuring.

    The summary this harness writes used to carry `pinned_commit` as a constant:
    the claim was about the file, not about the checkout. A cache left on another
    revision therefore produced evidence labelled with a revision it never ran —
    the same defect class that was found and closed in `run_core_spec.py` on
    2026-10-20. The assertion below makes the claim self-evidencing: no run at a
    different commit can reach the results directory.
    """
    if (CACHE / ".git").exists():
        if not _is_at_pin():
            if not _pin_available():
                subprocess.run(
                    ["git", "-C", str(CACHE), "fetch", "--quiet", "origin"], check=True
                )
            subprocess.run(
                ["git", "-C", str(CACHE), "checkout", "--quiet", PINNED_COMMIT],
                check=True,
            )
    else:
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
        if not _is_at_pin():
            subprocess.run(
                ["git", "-C", str(CACHE), "checkout", "--quiet", PINNED_COMMIT],
                check=True,
            )

    # Verified on BOTH paths. An early return after a checkout would leave the
    # warm-cache branch — the one CI and every repeat run actually take — without
    # the assertion at all.
    if not _is_at_pin():
        sys.exit(
            f"FAIL: wasi-testsuite is at {observed_commit()}, not the pinned "
            f"{PINNED_COMMIT} — a conformance result measured on another "
            "revision is not this claim"
        )


def _is_at_pin() -> bool:
    """Is the cache's HEAD the pinned commit?"""
    return observed_commit() == PINNED_COMMIT


def _pin_available() -> bool:
    """Is the pinned commit already an object in this cache?"""
    return (
        subprocess.run(
            ["git", "-C", str(CACHE), "cat-file", "-t", PINNED_COMMIT],
            capture_output=True,
            text=True,
        ).returncode
        == 0
    )


def observed_commit() -> str:
    """The commit the suite checkout is ACTUALLY on, read from the cache.

    Written into the summary next to the declared pin, so a reader can see whether
    the evidence is about the revision the file claims.
    """
    if not (CACHE / ".git").exists():
        return "missing"
    proc = subprocess.run(
        ["git", "-C", str(CACHE), "rev-parse", "HEAD"],
        capture_output=True,
        text=True,
        check=False,
    )
    return proc.stdout.strip() if proc.returncode == 0 else "error"


def runtime_identity() -> dict:
    """What this run executed against, as observed rather than declared."""
    from importlib.metadata import PackageNotFoundError
    from importlib.metadata import version as _pkg_version

    def _v(name: str) -> str:
        try:
            return _pkg_version(name)
        except PackageNotFoundError:
            return "absent"

    return {
        "python": sys.version.split()[0],
        "wasmtime": _v("wasmtime"),
        "ephemora-cell": _v("ephemora-cell"),
        # Basename only: this string is committed as evidence, and an absolute
        # venv path would put an operator's home directory into the repository.
        "adapter_cli": os.path.basename(os.getenv("EPHEMORA_CELL_REAL", ""))
        or "ephemora-cell (PATH)",
    }


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


#: How the suite runner spells a per-test outcome, mapped onto the five columns
#: this summary reports. Anything unmapped is counted as a FAILURE, not dropped:
#: an outcome the harness does not know is not evidence that nothing went wrong.
_OUTCOME_MAP = {
    "pass": "pass",
    "passed": "pass",
    "xfail": "expected_fail",
    "expected_fail": "expected_fail",
    "xpass": "unexpected_pass",
    "unexpected_pass": "unexpected_pass",
    "fail": "fail",
    "failed": "fail",
    "unexpected_fail": "fail",
    "skip": "skip",
    "skipped": "skip",
}


def count_outcomes(suite: dict) -> tuple[dict, list[str]]:
    """Count one suite by what each test actually reported.

    The runner's per-suite header used to be the only source here, and that header
    counts an expected failure in its `passed` column as well: measured on the
    2026-10-20 run, the C suite reports `passed: 14, xfailed: 1` while its 14
    entries are 13 `pass` + 1 `xfail`. The published "72 pass / 1 xfail" therefore
    described 73 results from 72 executed tests. The header is still kept in the
    summary when it disagrees, so the difference is visible instead of corrected
    away.
    """
    counts = {
        "pass": 0,
        "expected_fail": 0,
        "unexpected_pass": 0,
        "fail": 0,
        "skip": 0,
    }
    unknown: list[str] = []
    for test in suite.get("tests", []):
        outcome = str(test.get("outcome", "")).lower()
        column = _OUTCOME_MAP.get(outcome)
        if column is None:
            unknown.append(f"{test.get('name', '?')}:{outcome or 'empty'}")
            counts["fail"] += 1
            continue
        counts[column] += 1
    return counts, unknown


def summarize(raw_json: Path, stamp: str, started: datetime) -> None:
    data = json.loads(raw_json.read_text())
    per_suite: dict[str, dict[str, int]] = {}
    runner_headers: dict[str, dict[str, int]] = {}
    unknown_outcomes: dict[str, list[str]] = {}
    for suite in data.get("results", []):
        key = f"{suite.get('name', '?')} [{suite.get('runtime', {}).get('name', '?')}]"
        counts, unknown = count_outcomes(suite)
        per_suite[key] = counts
        if unknown:
            unknown_outcomes[key] = unknown
        header = {
            "pass": suite.get("passed", 0),
            "expected_fail": suite.get("xfailed", 0),
            "unexpected_pass": suite.get("xpassed", 0),
            "fail": suite.get("failed", 0),
            "skip": suite.get("skipped", 0),
        }
        if header != counts:
            runner_headers[key] = header
    print("\n[conformance] summary")
    for key, counts in per_suite.items():
        print(f"  {key}: {counts}")
    for key, header in runner_headers.items():
        print(
            f"  [runner-header differs for {key}]: {header} — counted from "
            "per-test outcomes instead"
        )

    keys = ("pass", "expected_fail", "unexpected_pass", "fail", "skip")
    total = {k: sum(c.get(k, 0) for c in per_suite.values()) for k in keys}
    retries = engine_abort_retries(started)
    meta = {
        "pinned_commit": PINNED_COMMIT,
        # Declared pin and OBSERVED revision, side by side. If these ever differ,
        # the document says so instead of quietly claiming the pin.
        "observed_commit": observed_commit(),
        "runtime_identity": runtime_identity(),
        "date": str(date.today()),
        "totals": total,
        "per_suite": per_suite,
        "raw": raw_json.name,
        "engine_abort_retries": retries,
    }
    if runner_headers:
        meta["runner_headers"] = runner_headers
        meta["counting_note"] = (
            "totals come from the per-test `outcome` values; the runner's own "
            "per-suite header counts an expected failure inside `passed`, and is "
            "reported alongside whenever the two differ"
        )
    if unknown_outcomes:
        meta["unknown_outcomes"] = unknown_outcomes
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
