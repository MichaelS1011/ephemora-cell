#!/usr/bin/env python3
"""Watch PyPI for the wasmtime wheels this project is waiting on.

The 2026 advisory wave (GHSA-j366-h8gg-77pm, GHSA-gqmc-89g8-p25r,
GHSA-96f6-r43r-8c24, RUSTSEC-2026-0324, on top of GHSA-m63x-6p34-q65x and
GHSA-vqjp-4c8c-hfgg) is closed by the 49.0.3 fix line. 1.2.0 is therefore
qualified against `wasmtime>=49.0.3,<50`, and the audited build it actually runs
on is `49.0.3.post2+git.1d21c90f` — a local build of the patched source, supplied
from the release wheelhouse, because the binding publishes one wheel per major
(47.0.1, 48.0.0, 49.0.0) and PyPI carries no 49.0.3 wheel.

What is still being waited for is the ordinary-install path: an OFFICIAL PyPI
wheel inside the qualified line, so a plain `pip install` reaches a patched engine
instead of requiring the wheelhouse. Until then the version gate refuses anything
outside the line (docs/cli-errors.md), and `EPHEMORA_ALLOW_UNQUALIFIED_RUNTIME`
stays the documented escape hatch rather than a supported configuration.

Run this (manually or from CI) to learn when that opens:

    python scripts/check_wasmtime_patch.py

Exit codes: 0 = a wheel inside the qualified line is available on PyPI,
1 = still waiting. Stdlib only — no dependencies.
"""

from __future__ import annotations

import json
import sys
import urllib.request

# Candidate targets, most preferred first: any of these inside the 49.0.3 line
# would let a plain install reach a patched engine.
TARGETS = ("49.0.3", "49.0.4", "49.1.0")
FULLY_PATCHED = TARGETS
REQUIRED_WHEEL_MARKERS = ("macosx", "manylinux")  # Cell ships macOS + Linux


def fetch_release(version: str) -> dict | None:
    url = f"https://pypi.org/pypi/wasmtime/{version}/json"
    try:
        with urllib.request.urlopen(url, timeout=15) as resp:
            return json.load(resp)
    except urllib.error.HTTPError as e:
        if e.code == 404:
            return None
        raise


def summarize(version: str) -> str:
    data = fetch_release(version)
    if data is None:
        return f"  {version}: (not on PyPI yet)"
    files = data.get("urls", [])
    wheels = [f["filename"] for f in files if f["filename"].endswith(".whl")]
    markers = [m for m in REQUIRED_WHEEL_MARKERS if any(m in w for w in wheels)]
    requires = data.get("info", {}).get("requires_python", "?")
    missing = [m for m in REQUIRED_WHEEL_MARKERS if m not in markers]
    note = "OK" if not missing else f"platform wheels missing: {missing}"
    return f"  {version}: {len(wheels)} wheels ({note}), " f"requires_python {requires}"


def main() -> int:
    print(
        "wasmtime wheels for the 2026 security advisories (qualified line: >=49.0.3,<50):"
    )
    for version in TARGETS:
        print(summarize(version))
    for version in FULLY_PATCHED:
        data = fetch_release(version)
        if data is None:
            continue
        wheels = [
            f["filename"]
            for f in data.get("urls", [])
            if f["filename"].endswith(".whl")
        ]
        if all(m in " ".join(wheels) for m in REQUIRED_WHEEL_MARKERS):
            print(
                f"\nUPGRADE PATH OPEN: wasmtime {version} is on PyPI — a plain "
                "install can reach the qualified line without the wheelhouse."
            )
            return 0
    print(
        "\nStill waiting: the qualified engine remains the audited wheelhouse build "
        "(49.0.3.post2+git.1d21c90f); anything outside the line is refused by the "
        "runtime gate unless the documented hatch is set."
    )
    return 1


if __name__ == "__main__":
    sys.exit(main())
