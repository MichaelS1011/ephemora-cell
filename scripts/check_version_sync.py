#!/usr/bin/env python3
"""Version-sync guard — proves the four version sources agree.

The 1.0.4.1 release introduced single-source versioning across four
files after the 1.0.3 wheel drifted (serverInfo said 1.0.1, ``--version``
said 1.0.3). This guard makes that invariant machine-checked, not
remembered: every source must carry the SAME version, and that version
must equal the newest ``v*`` git tag — so ``main`` can never sit on an
older version string than the release next to it (the exact divergence
an external review flagged as the repo's worst hygiene risk).

Sources checked:
  1. pyproject.toml                 -> [project] version
  2. ephemora_cell/__init__.py      -> __version__ (feeds ``--version``)
  3. ephemora_cell_mcp/_version.py  -> __version__ (feeds serverInfo)
  4. server.json                    -> top-level version AND
                                       packages[].version (MCP Registry)

Exit 0 = all five strings identical and equal to the latest v*-tag.
Exit 1 = any drift (message names every disagreeing source).
"""

from __future__ import annotations

import json
import re
import subprocess
import sys
from pathlib import Path

REPO = Path(__file__).resolve().parent.parent


def _pyproject_version() -> str:
    text = (REPO / "pyproject.toml").read_text(encoding="utf-8")
    match = re.search(r'^version\s*=\s*"([^"]+)"', text, re.MULTILINE)
    if not match:
        raise ValueError("pyproject.toml: no [project] version field found")
    return match.group(1)


def _module_version(rel_path: str) -> str:
    text = (REPO / rel_path).read_text(encoding="utf-8")
    match = re.search(r'^__version__\s*=\s*"([^"]+)"', text, re.MULTILINE)
    if not match:
        raise ValueError(f"{rel_path}: no __version__ assignment found")
    return match.group(1)


def _server_json_versions() -> list[str]:
    data = json.loads((REPO / "server.json").read_text(encoding="utf-8"))
    versions: list[str] = []
    top = data.get("version")
    if not isinstance(top, str):
        raise ValueError("server.json: no top-level version field")
    versions.append(top)
    packages = data.get("packages")
    if not isinstance(packages, list) or not packages:
        raise ValueError("server.json: no packages[] entry")
    for pkg in packages:
        pkg_version = pkg.get("version")
        if not isinstance(pkg_version, str):
            raise ValueError("server.json: packages[] entry without version")
        versions.append(pkg_version)
    return versions


def _latest_tag() -> str:
    try:
        result = subprocess.run(
            ["git", "describe", "--tags", "--abbrev=0", "--match", "v*"],
            cwd=REPO,
            capture_output=True,
            text=True,
            check=True,
        )
    except subprocess.CalledProcessError as e:
        raise ValueError(
            "no v* tag reachable from HEAD — tag the release first "
            f"({e.stderr.strip()})"
        ) from e
    tag = result.stdout.strip()
    return tag[1:] if tag.startswith("v") else tag


def main() -> int:
    sources: dict[str, str] = {"pyproject.toml": _pyproject_version()}
    sources["ephemora_cell/__init__.py"] = _module_version(
        "ephemora_cell/__init__.py"
    )
    sources["ephemora_cell_mcp/_version.py"] = _module_version(
        "ephemora_cell_mcp/_version.py"
    )
    server_versions = _server_json_versions()
    sources["server.json (top)"] = server_versions[0]
    if len(server_versions) > 1:
        sources["server.json (packages[0])"] = server_versions[1]

    latest_tag = _latest_tag()
    sources["latest git tag"] = latest_tag

    values = set(sources.values())
    print(f"Version-sync check ({len(sources)} sources):")
    for name, value in sources.items():
        print(f"  {value:<10} {name}")
    if len(values) != 1:
        print(
            "FAIL: version drift — every source must carry the SAME "
            "version (bump all four files together, then re-tag)"
        )
        return 1
    print(f"OK: all sources in sync at {values.pop()}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
