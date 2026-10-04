#!/usr/bin/env python3
# SPDX-License-Identifier: BUSL-1.1
# Copyright 2026 Michael Soppa
"""Statelessness / ephemerality probe — the product promise, measured.

Answers one sentence with numbers: **no execution state survives into the next
execution.** Run A writes everything a guest can reach (a marker file in its
scratch, the marker on stdout, a generated identifier); run B tries to see it.
Repeated N times, on all three execution paths, and with the crash question
asked separately: what does the audit book look like when a writer is SIGKILLed
mid-append?

Why it is a script and not only a test: a unit test answers "did this one
transition leak?" (see `tests/test_execution_invariants.py`). This one produces a
dated, sized measurement — iteration count, per-path cost, leak count, surviving
handles — so the claim in README/SECURITY can point at data instead of at
confidence.

Usage:
    python benchmarks/statelessness_probe.py --iterations 1000 \
        --out benchmarks/results/2026-10-05/statelessness.json

Requires the repo's test guests (`tests/test_persistence_worm.py` WAT sources),
which are the same writer/reader pair the worm probe uses, so this file cannot
pass by testing a harness that detects nothing.
"""

from __future__ import annotations

import argparse
import json
import os
import resource
import subprocess
import sys
import time
from pathlib import Path

REPO = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(REPO))

import wasmtime  # noqa: E402

from ephemora_cell import ExecutionStatus, WASIConfig, WASISandbox  # noqa: E402

TOKEN = "PERSIST-MARKER-42"

# The book-kill child: appends until it is killed, so the parent can inspect a
# book whose writer died at an arbitrary point.
_CHILD = r"""
import sys
sys.path.insert(0, %(repo)r)
from ephemora_cell.egress_sidecar import EgressGrant
from ephemora_cell.grant_ledger import GrantLedger

grant = EgressGrant(
    grant_id="g-crash",
    tool="weather",
    allowed_endpoints=("https://api.example.com/v1",),
    max_calls=None,
)
book = GrantLedger(sys.argv[1])
while True:
    book.record_call(grant)
"""


def _guests(work: Path) -> tuple[str, str]:
    # The worm probe's own guests: a marker READER that never detects anything
    # would report zero leaks, so the detector comes from the file that already
    # proves it detects a real marker (see positive_control below).
    sys.path.insert(0, str(REPO / "tests"))
    from test_persistence_worm import MARKER_READER_WAT, MARKER_WRITER_WAT

    writer = work / "writer.wasm"
    reader = work / "reader.wasm"
    writer.write_bytes(wasmtime.wat2wasm(MARKER_WRITER_WAT))
    reader.write_bytes(wasmtime.wat2wasm(MARKER_READER_WAT))
    return str(writer), str(reader)


def _config(*, pooled: bool) -> WASIConfig:
    # `io_budget_bytes` forces a per-run engine, so the pooled path is only
    # reached when the byte wall is lifted deliberately.
    return WASIConfig(
        max_fuel=1_000_000,
        timeout_seconds=10,
        io_budget_bytes=None if pooled else 64 * 1024 * 1024,
        allow_dirs=(),
    )


def sweep(
    writer: str, reader: str, *, pooled: bool, isolated: bool, iterations: int
) -> dict:
    sandbox = WASISandbox(config=_config(pooled=pooled and not isolated))
    leaks: list[str] = []
    dirs: set[str] = set()
    started = time.monotonic()
    residue = 0
    for i in range(iterations):
        first = sandbox.run(writer, use_subprocess=isolated)
        if first.status is not ExecutionStatus.SUCCESS:
            raise SystemExit(f"writer failed at iteration {i}: {first.stderr[:200]}")
        dirs.add(str(first.sandbox_dir))
        second = sandbox.run(reader, use_subprocess=isolated)
        if not isolated:
            residue += len(sandbox.cleanup())
        if second.exit_code == 0:
            leaks.append(f"iteration {i}: reader found the marker (exit 0)")
        if TOKEN in (second.stdout or "") + (second.stderr or ""):
            leaks.append(f"iteration {i}: token visible in run B output")
        if str(second.sandbox_dir) in dirs:
            leaks.append(f"iteration {i}: run B reused run A's sandbox directory")
        dirs.add(str(second.sandbox_dir))
    elapsed = time.monotonic() - started
    return {
        "path": (
            "isolated-subprocess"
            if isolated
            else ("engine-pool" if pooled else "in-process-per-run-engine")
        ),
        "iterations": iterations,
        "pairs": iterations,
        "leaks": len(leaks),
        "leak_details": leaks[:5],
        "unique_sandbox_dirs": len(dirs),
        "cleanup_residues": residue,
        "seconds_total": round(elapsed, 3),
        "ms_per_pair": round(elapsed * 1000 / iterations, 3),
        # macOS reports ru_maxrss in bytes, Linux in kilobytes: label the unit
        # the way the platform defines it instead of pretending it is KB.
        "host_rusage_maxrss": resource.getrusage(resource.RUSAGE_SELF).ru_maxrss,
        "host_rusage_unit": "bytes" if sys.platform == "darwin" else "kilobytes",
    }


def crash_during_append(work: Path, rounds: int) -> dict:
    """Kill a book writer mid-append, then ask the book what it thinks it holds.

    A torn tail must be LOUD (GrantTamperError / a verify() finding), and a
    complete book must agree with itself: the replayed call count equals the
    number of call lines.
    """
    from ephemora_cell.grant_ledger import GrantLedger

    book_dir = work / "crash"
    book_dir.mkdir(parents=True, exist_ok=True)
    consistent = 0
    loud = 0
    silent_wrong = 0
    for i in range(rounds):
        path = book_dir / f"book-{i}.jsonl"
        path.write_text("")
        proc = subprocess.Popen(
            [sys.executable, "-c", _CHILD % {"repo": str(REPO)}, str(path)],
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL,
        )
        time.sleep(0.02 + 0.01 * (i % 5))
        proc.kill()
        proc.wait()
        if not path.exists():
            raise SystemExit(f"child never created {path}")
        book = GrantLedger(path)
        try:
            state = book.usage("g-crash")
        except Exception:  # noqa: BLE001 - torn tail must raise, that is the point
            loud += 1
            continue
        lines = [ln for ln in path.read_text().splitlines() if ln.strip()]
        calls = [ln for ln in lines if '"call"' in ln]
        if state.calls == len(calls):
            consistent += 1
        else:
            silent_wrong += 1
    return {
        "rounds": rounds,
        "self_consistent": consistent,
        "torn_tail_detected_loudly": loud,
        "silently_wrong": silent_wrong,
        "note": (
            "silently_wrong must be 0: a book whose replay disagrees with its own "
            "lines is an enforcement that has stopped meaning anything"
        ),
    }


def positive_control(reader: str, work: Path) -> dict:
    """The detector works: a marker that IS present must be seen.

    Without this, "0 leaks" could mean the reader never notices anything.
    """
    base = work / "legitimate"
    base.mkdir(exist_ok=True)
    (base / "marker.txt").write_text(TOKEN)
    sandbox = WASISandbox(
        config=WASIConfig(
            max_fuel=1_000_000,
            timeout_seconds=10,
            io_budget_bytes=None,
            allow_dirs=(str(base),),
        )
    )
    result = sandbox.run(reader)
    sandbox.cleanup()
    return {
        "reader_exit_code": result.exit_code,
        "detects_a_real_marker": result.exit_code == 0,
        "path_count": len(result.effective_preopens),
    }


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--iterations", type=int, default=1000)
    parser.add_argument("--crash-rounds", type=int, default=40)
    parser.add_argument("--out", default="")
    args = parser.parse_args()

    work = Path(os.environ.get("TMPDIR", "/tmp")) / "cell-statelessness"
    work.mkdir(parents=True, exist_ok=True)
    writer, reader = _guests(work)

    results = {
        "measured": True,
        "date": time.strftime("%Y-%m-%dT%H:%M:%S%z"),
        "python": sys.version.split()[0],
        "promise": "no execution state survives into the next execution",
        "control": positive_control(reader, work),
        "sweeps": [
            sweep(writer, reader, pooled=True, isolated=False, iterations=args.iterations),
            sweep(
                writer, reader, pooled=False, isolated=False, iterations=min(300, args.iterations)
            ),
            sweep(
                writer, reader, pooled=False, isolated=True, iterations=min(40, args.iterations)
            ),
        ],
        "crash_during_append": crash_during_append(work, args.crash_rounds),
    }
    leaks = sum(s["leaks"] for s in results["sweeps"])
    results["total_leaks"] = leaks
    results["silently_wrong_books"] = results["crash_during_append"]["silently_wrong"]
    results["verdict"] = (
        "PASS"
        if leaks == 0
        and results["control"]["detects_a_real_marker"]
        and results["silently_wrong_books"] == 0
        else "FAIL"
    )

    text = json.dumps(results, indent=2, sort_keys=True)
    print(text)
    if args.out:
        out = Path(args.out)
        out.parent.mkdir(parents=True, exist_ok=True)
        out.write_text(text + "\n", encoding="utf-8")
        print(f"wrote {out}", file=sys.stderr)
    return 0 if results["verdict"] == "PASS" else 1


if __name__ == "__main__":
    raise SystemExit(main())
