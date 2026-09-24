#!/usr/bin/env python3
"""Watch PyPI for the wasmtime patch releases this project is waiting on.

GHSA-m63x-6p34-q65x (fuel amplification via call_ref/try_table) is patched
in wasmtime 48.0.3 / 49.0.1; GHSA-vqjp-4c8c-hfgg (CVE-2026-47261,
filesystem escape) in 47.0.4. As of 2026-09-24 none of these exist as
Python wheels on PyPI (latest was 49.0.0, itself affected), so Ephemora
Cell runs its interim posture on wasmtime 47.0.1 with the affected
proposals enforced-off (see SECURITY_ADVISORY_PLAN_2026-09-24.md).

Run this (manually or from CI) to learn when the upgrade path M2 opens:

    python scripts/check_wasmtime_patch.py

Exit codes: 0 = a fully-patched target is available, 1 = still waiting.
Stdlib only — no dependencies.
"""

from __future__ import annotations

import json
import sys
import urllib.request

# Candidate targets, most preferred first.
TARGETS = ("48.0.3", "49.0.1", "47.0.4")
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
        return f"  {version}: (noch nicht auf PyPI)"
    files = data.get("urls", [])
    wheels = [f["filename"] for f in files if f["filename"].endswith(".whl")]
    markers = [m for m in REQUIRED_WHEEL_MARKERS if any(m in w for w in wheels)]
    requires = data.get("info", {}).get("requires_python", "?")
    missing = [m for m in REQUIRED_WHEEL_MARKERS if m not in markers]
    note = "OK" if not missing else f"Plattformen fehlen: {missing}"
    return f"  {version}: {len(wheels)} Wheels ({note}), " f"requires_python {requires}"


def main() -> int:
    print("wasmtime-Patch-Wheels für die 2026er Security-Advisories:")
    for version in TARGETS:
        print(summarize(version))
    for version in TARGETS[:2]:  # fully patched targets: 48.0.3, 49.0.1
        data = fetch_release(version)
        if data is None:
            continue
        wheels = [
            f["filename"]
            for f in data.get("urls", [])
            if f["filename"].endswith(".whl")
        ]
        if all(m in " ".join(wheels) for m in REQUIRED_WHEEL_MARKERS):
            print(f"\nUPGRADE-PFAD OFFEN: wasmtime {version} ist verfügbar.")
            return 0
    print(
        "\nNoch wartend: gehärtete Interim-Posture (47.0.1 + enforced-off Proposals) bleibt aktiv."
    )
    return 1


if __name__ == "__main__":
    sys.exit(main())
