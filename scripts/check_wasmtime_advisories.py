#!/usr/bin/env python3
# SPDX-License-Identifier: BUSL-1.1
# Copyright 2026 Michael Soppa
"""Check the qualified Wasmtime version against upstream security advisories.

The old watcher only asked PyPI for a newer wheel. That misses advisories that
are published before (or without) a PyPI wheel — the 2026-10 aarch64
``br_table`` escape was published on 2026-10-19 with a GitHub release and no
PyPI artifact. This script reads the repository's published security
advisories and evaluates their vulnerable version ranges against the version
this project pins.

Exit codes:
  0 = no published advisory matches the qualified version
  1 = at least one published advisory matches; treat the runtime as affected
  2 = the advisory feed could not be read (fail closed, never a silent pass)

No token is required. ``GITHUB_TOKEN`` is used if present (rate limit only) and
is never printed. This script only reports; it never changes a pin, a release
or an asset.
"""

from __future__ import annotations

import json
import os
import re
import sys
import urllib.error
import urllib.request

QUALIFIED_VERSION = "49.0.4.post1+git.2c2970205f"
ADVISORIES_URL = (
    "https://api.github.com/repos/bytecodealliance/wasmtime/"
    "security-advisories?state=published&per_page=100"
)
RELEASE_RE = re.compile(r"^(\d+)\.(\d+)\.(\d+)")


def release_tuple(version: str) -> tuple[int, int, int]:
    match = RELEASE_RE.match(version.strip())
    if not match:
        raise ValueError(f"cannot parse a release version from {version!r}")
    return tuple(int(part) for part in match.groups())


def _compare(left: tuple[int, ...], right: tuple[int, ...]) -> int:
    return (left > right) - (left < right)


def parse_range(
    spec: str,
) -> list[
    tuple[
        tuple[str, tuple[int, int, int]] | None, tuple[str, tuple[int, int, int]] | None
    ]
]:
    """Parse a GitHub advisory range into a union of (lower, upper) intervals.

    GitHub writes unions, not conjunctions: ``<36.0.19, >=37.0.0, <48.0.7``
    means "below 36.0.19 OR in [37.0.0, 48.0.7)". A lower-bound token opens a
    new interval; an upper-bound token closes the current one.
    """
    groups: list[tuple] = []
    lower: tuple[str, tuple[int, int, int]] | None = None
    upper: tuple[str, tuple[int, int, int]] | None = None

    def flush() -> None:
        nonlocal lower, upper
        if lower is not None or upper is not None:
            groups.append((lower, upper))
        lower = None
        upper = None

    for token in spec.split(","):
        token = token.strip()
        if not token:
            continue
        match = re.fullmatch(r"(<=|>=|<|>|==|=)?\s*(\d+)\.(\d+)\.(\d+)", token)
        if not match:
            raise ValueError(f"unsupported version constraint {token!r}")
        operator = match.group(1) or "=="
        version = tuple(int(part) for part in match.groups()[1:])
        if operator in (">", ">=", "==", "="):
            if lower is not None or upper is not None:
                flush()
            lower = (operator, version)
        else:
            if upper is not None:
                flush()
            upper = (operator, version)
    flush()
    if not groups:
        raise ValueError(f"empty version range {spec!r}")
    return groups


def _above(current: tuple[int, int, int], bound) -> bool:
    if bound is None:
        return True
    operator, target = bound
    comparison = _compare(current, target)
    if operator == ">":
        return comparison > 0
    if operator == ">=":
        return comparison >= 0
    return comparison == 0


def _below(current: tuple[int, int, int], bound) -> bool:
    if bound is None:
        return True
    operator, target = bound
    comparison = _compare(current, target)
    return comparison < 0 if operator == "<" else comparison <= 0


def is_affected(version: str, ranges: list[str]) -> bool:
    current = release_tuple(version)
    for spec in ranges:
        for lower, upper in parse_range(spec):
            if _above(current, lower) and _below(current, upper):
                return True
    return False


def concerns_line(ranges: list[str], floor: tuple[int, int, int] = (49, 0, 0)) -> bool:
    """True when a range can touch the qualified major line at all.

    Legacy advisories carry ranges like ``<= 0.38.1, >=0.37.0``; evaluating
    those against a 49.x version is meaningless and, for an upper-bound-only
    first interval, produces a false positive. An advisory is evaluated only
    when its highest named version reaches the qualified floor.
    """
    versions = [
        release_tuple(version)
        for spec in ranges
        for version in re.findall(r"\d+\.\d+\.\d+", spec)
    ]
    return bool(versions) and max(versions) >= floor


def fetch_advisories() -> list[dict]:
    request = urllib.request.Request(
        ADVISORIES_URL,
        headers={
            "Accept": "application/vnd.github+json",
            "User-Agent": "ephemora-cell-advisory-watch/1.2",
            **(
                {"Authorization": f"Bearer {os.environ['GITHUB_TOKEN']}"}
                if os.environ.get("GITHUB_TOKEN")
                else {}
            ),
        },
    )
    with urllib.request.urlopen(request, timeout=30) as response:
        return json.load(response)


def main() -> int:
    try:
        advisories = fetch_advisories()
    except (urllib.error.URLError, TimeoutError, json.JSONDecodeError) as exc:
        print(f"advisory feed unreadable: {exc}", file=sys.stderr)
        return 2

    print(f"qualified wasmtime: {QUALIFIED_VERSION}")
    affected: list[str] = []
    for advisory in advisories:
        ranges = [
            item.get("vulnerable_version_range", "")
            for item in advisory.get("vulnerabilities", [])
            if item.get("package", {}).get("name") == "wasmtime"
        ]
        if not ranges:
            continue
        if not concerns_line(ranges):
            continue
        try:
            hit = is_affected(QUALIFIED_VERSION, ranges)
        except ValueError as exc:
            print(
                f"{advisory.get('ghsa_id')}: unparsed range ({exc}) — review manually"
            )
            return 2
        status = "AFFECTED" if hit else "not affected"
        patched = ",".join(
            item.get("patched_versions", "")
            for item in advisory.get("vulnerabilities", [])
            if item.get("package", {}).get("name") == "wasmtime"
        )
        print(
            f"{status:12} {advisory.get('ghsa_id')} "
            f"[{advisory.get('severity')}] ranges={';'.join(ranges)} "
            f"patched={patched or '-'} :: {advisory.get('summary', '')[:100]}"
        )
        if hit:
            affected.append(advisory.get("ghsa_id", "?"))

    if affected:
        print(
            f"\nACTION REQUIRED: {len(affected)} advisory(ies) match: {', '.join(affected)}"
        )
        return 1
    print("\nno published wasmtime advisory matches the qualified version")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
