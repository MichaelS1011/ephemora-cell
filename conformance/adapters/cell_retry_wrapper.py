#!/usr/bin/env python3
"""Retry-on-abort wrapper for the Cell CLI in conformance runs.

Shared CI runners show a rare, documented wasmtime engine abort
(exit code -6 / SIGABRT, "panic in a function that cannot unwind") on
VARYING filesystem tests — engine-internal, not reproducible locally
(see conformance/README.md). The suite runner counts the abort as a
test failure, so a healthy run can land at 71/72.

This wrapper is optional and transparent: it runs the real Cell CLI
and, ONLY on exit -6, reruns that one test once. Any other exit code —
including genuine conformance failures — passes through untouched, and
a second abort is returned as-is. Every retry is appended as one JSON
line to CELL_RETRY_LOG (default: conformance/results/
engine_abort_retries.jsonl) so the committed evidence shows exactly
which runs needed a retry and for which test. It never decides an
outcome: pass or fail comes from the same CLI execution logic either
way.

Standard library only; the underlying command is resolved from
EPHEMORA_CELL_REAL (fallback: the ``ephemora-cell`` console script next
to this interpreter). POSIX-only abort semantics (returncode -6).
"""

from __future__ import annotations

import json
import os
import subprocess
import sys
import time
from datetime import datetime, timezone
from pathlib import Path

_DEFAULT_LOG = (
    Path(__file__).resolve().parents[1] / "results" / "engine_abort_retries.jsonl"
)


def _real_command() -> list[str]:
    env = os.getenv("EPHEMORA_CELL_REAL", "").strip()
    if env:
        return env.split()
    sibling = Path(sys.executable).parent / "ephemora-cell"
    return [str(sibling) if sibling.exists() else sibling.name]


def _log_retry(argv: list[str], first_rc: int) -> None:
    entry = {
        "timestamp": datetime.now(timezone.utc).isoformat(timespec="seconds"),
        "test": next(
            (a for a in argv if a.endswith(".wasm")),
            "unknown",
        ),
        "first_exit_code": first_rc,
        "attempts": 2,
    }
    path = Path(os.getenv("CELL_RETRY_LOG") or _DEFAULT_LOG)
    path.parent.mkdir(parents=True, exist_ok=True)
    with path.open("a", encoding="utf-8") as fh:
        fh.write(json.dumps(entry) + "\n")
    print(
        f"[cell-retry-wrapper] engine abort (exit {first_rc}) on attempt 1 — "
        f"rerunning once: {entry['test']}",
        file=sys.stderr,
        flush=True,
    )


def main() -> int:
    argv = sys.argv[1:]
    if not argv:
        print("usage: cell_retry_wrapper.py <cell-cli-args...>", file=sys.stderr)
        return 2
    cmd = [*_real_command(), *argv]
    # stdio inherited: the suite runner captures test output itself.
    start = time.monotonic()
    proc = subprocess.run(cmd)
    if proc.returncode != -6:
        return proc.returncode
    _log_retry(argv, proc.returncode)
    retried = subprocess.run(cmd)
    print(
        f"[cell-retry-wrapper] attempt 2 exit {retried.returncode} "
        f"after {time.monotonic() - start:.1f}s total",
        file=sys.stderr,
        flush=True,
    )
    return retried.returncode


if __name__ == "__main__":
    sys.exit(main())
