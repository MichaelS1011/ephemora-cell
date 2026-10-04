#!/usr/bin/env python3
"""Version-sync guard — proves the four version sources agree.

The 1.0.4.1 release introduced single-source versioning across four
files after the 1.0.3 wheel drifted (serverInfo said 1.0.1, ``--version``
said 1.0.3). This guard makes that invariant machine-checked, not
remembered: every source must carry the SAME version, and that version must be
the newest ``v*`` git tag or the release about to be tagged — so ``main`` can
never sit on an older version string than the release next to it (the exact
divergence an external review flagged as the repo's worst hygiene risk).

Sources checked:
  1. pyproject.toml                 -> [project] version
  2. ephemora_cell/__init__.py      -> __version__ (feeds ``--version``)
  3. ephemora_cell_mcp/_version.py  -> __version__ (feeds serverInfo)
  4. server.json                    -> top-level version AND
                                       packages[].version (MCP Registry)

Exit 0 = every source carries the SAME version, and that version is either the
newest ``v*`` tag or a HIGHER one (the bump commit exists before its tag — the
documented release order is bump -> gate -> CI -> tag, so this is the state of a
release in progress and prints a WARNING).
Exit 1 = sources disagree with each other, or they are LOWER than the newest
reachable tag (``main`` sitting behind its own release — the drift this guard was
built for).
"""

from __future__ import annotations

import json
import re
import subprocess
import sys
from pathlib import Path

REPO = Path(__file__).resolve().parent.parent


def _single_match(pattern: str, text: str, where: str) -> str:
    matches = re.findall(pattern, text, re.MULTILINE)
    if not matches:
        raise ValueError(f"{where}: no version assignment found")
    if len(set(matches)) > 1:
        raise ValueError(f"{where}: CONFLICTING version assignments {matches}")
    return matches[0]


def _pyproject_version() -> str:
    text = (REPO / "pyproject.toml").read_text(encoding="utf-8")
    return _single_match(r'^version\s*=\s*"([^"]+)"', text, "pyproject.toml")


def _module_version(rel_path: str) -> str:
    text = (REPO / rel_path).read_text(encoding="utf-8")
    return _single_match(r'^__version__\s*=\s*"([^"]+)"', text, rel_path)


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
    """The HIGHEST v* tag across ALL refs, then proven reachable from HEAD.

    `git describe` semantics (nearest reachable tag) would let a newer
    release tag on an unreachable branch slip through unnoticed — so we
    sort every v* tag by version instead, and then explicitly verify the
    winner is an ancestor of HEAD (fail-closed either way: a stray newer
    tag anywhere is an alarm, a tag on the wrong commit is an alarm).
    """
    try:
        listed = subprocess.run(
            ["git", "tag", "-l", "v*", "--sort=-v:refname"],
            cwd=REPO,
            capture_output=True,
            text=True,
            check=True,
        ).stdout.split()
    except subprocess.CalledProcessError as e:
        raise ValueError(f"git tag failed: {e.stderr.strip()}") from e
    if not listed:
        raise ValueError("no v* tag exists — tag the release first")
    tag = listed[0]
    try:
        subprocess.run(
            ["git", "merge-base", "--is-ancestor", tag, "HEAD"],
            cwd=REPO,
            check=True,
            capture_output=True,
            text=True,
        )
    except subprocess.CalledProcessError as e:
        raise ValueError(
            f"latest tag {tag!r} is NOT reachable from HEAD — it points "
            "at a divergent commit; fix the tag before trusting the sync"
        ) from e
    return tag[1:] if tag.startswith("v") else tag


def _as_tuple(version: str) -> tuple[int, ...] | None:
    """Numeric dotted version for ordering, or None if it is not one."""
    parts = version.split(".")
    if not parts or not all(part.isdigit() for part in parts):
        return None
    return tuple(int(part) for part in parts)


def main() -> int:
    sources: dict[str, str] = {"pyproject.toml": _pyproject_version()}
    sources["ephemora_cell/__init__.py"] = _module_version("ephemora_cell/__init__.py")
    sources["ephemora_cell_mcp/_version.py"] = _module_version(
        "ephemora_cell_mcp/_version.py"
    )
    server_versions = _server_json_versions()
    sources["server.json (top)"] = server_versions[0]
    for i, v in enumerate(server_versions[1:]):
        sources[f"server.json (packages[{i}])"] = v

    latest_tag = _latest_tag()

    print(f"Version-sync check ({len(sources)} sources + latest tag):")
    for name, value in sources.items():
        print(f"  {value:<10} {name}")
    print(f"  {latest_tag:<10} latest git tag")

    values = set(sources.values())
    if len(values) != 1:
        print(
            "FAIL: version drift — every source must carry the SAME "
            "version (bump all four files together, then re-tag)"
        )
        return 1
    version = values.pop()

    if version == latest_tag:
        print(f"OK: all sources in sync at {version}, equal to the newest tag")
        return 0

    repo_parts, tag_parts = _as_tuple(version), _as_tuple(latest_tag)
    if repo_parts is not None and tag_parts is not None and repo_parts > tag_parts:
        # The documented release order is bump -> gate -> CI -> tag, so the
        # commit that carries the new version is by definition ahead of the
        # tag that names it. Intra-repo agreement stays hard; only the
        # tag-equality check is relaxed here, and it closes itself the moment
        # the tag exists.
        print(
            f"WARNING: release in progress — sources at {version}, newest tag is "
            f"v{latest_tag}. The sources themselves agree, which is what this "
            "commit can be checked for; re-run after tagging v{version} and this "
            "becomes a hard equality check.".format(version=version)
        )
        return 0

    print(
        f"FAIL: sources carry {version} but the newest reachable tag is "
        f"v{latest_tag} — main sits on an older version than its own release"
    )
    return 1


if __name__ == "__main__":
    sys.exit(main())
