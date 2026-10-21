#!/usr/bin/env python3
"""Bind one release artifact set to one commit, and verify it before installing.

A file name is not an identity. `ephemora_cell-1.2.0-py3-none-any.whl` exists in
many builds, and a rebuilt wheel differs byte-for-byte from the one that was
measured (zip timestamps), while its members are identical. So the release set
publishes four files next to the artifacts, and this script is what writes and
re-checks three of them:

  ``SHA256SUMS``              every artifact, one line each, sorted by name
  ``release_manifest.json``   commit + tree + artifact digests + the runtime
                              identity read from INSIDE the runtime wheel
  ``requirements-release.txt`` pip requirements with ``--hash`` pins for all
                              four distributions, so an install resolves only
                              these bytes (``--require-hashes``)

Usage:

    python scripts/release_manifest.py write  --set <dir> [--commit SHA]
    python scripts/release_manifest.py verify --set <dir>

`write` refuses a set that does not carry exactly the four expected roles (core
wheel, sdist, qualified runtime wheel, both guest wheels), so a manifest cannot
silently describe half a release. `verify` returns 0 only when every listed file
matches its digest AND no unexpected artifact appeared in the directory; an
extra wheel is a failure, not a warning — the canonical install path is
``--find-links <dir> --require-hashes``, and a directory with something else in
it is not the set that was measured.

The runtime identity is deliberately read out of the wheel instead of the
running environment: the question the manifest answers is "which native engine
is inside these bytes", and the answer must not depend on what the maintainer
happened to have installed.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import re
import subprocess
import sys
import zipfile
from pathlib import Path

REPO = Path(__file__).resolve().parents[1]
MANIFEST_NAME = "release_manifest.json"
SUMS_NAME = "SHA256SUMS"
REQUIREMENTS_NAME = "requirements-release.txt"
CORE_REQUIREMENTS_NAME = "requirements-release-core.txt"
GENERATED = {MANIFEST_NAME, SUMS_NAME, REQUIREMENTS_NAME, CORE_REQUIREMENTS_NAME}

#: A release set is these five artifacts and nothing else. Both verbs check it:
#: `write` refuses to describe half a release, `verify` refuses to bless one.
EXPECTED_ROLES = {"core-wheel", "sdist", "runtime", "guest-python", "guest-javascript"}


def sha256(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        for chunk in iter(lambda: handle.read(1 << 20), b""):
            digest.update(chunk)
    return digest.hexdigest()


def _metadata(wheel: Path) -> dict[str, str]:
    """The wheel's own METADATA header block, as a dict."""
    with zipfile.ZipFile(wheel) as archive:
        name = next(n for n in archive.namelist() if n.endswith(".dist-info/METADATA"))
        text = archive.read(name).decode("utf-8", "replace")
    fields: dict[str, str] = {}
    for line in text.splitlines():
        if not line:
            break  # end of the header block
        key, _, value = line.partition(": ")
        if key and value:
            fields.setdefault(key, value)
    return fields


def classify(path: Path) -> str | None:
    name = path.name
    if name.startswith("wasmtime-") and name.endswith(".whl"):
        return "runtime"
    if name.startswith("ephemora_cell_python_guest-") and name.endswith(".whl"):
        return "guest-python"
    if name.startswith("ephemora_cell_javascript_guest-") and name.endswith(".whl"):
        return "guest-javascript"
    if re.fullmatch(r"ephemora_cell-\d[^-]*-py3-none-any\.whl", name):
        return "core-wheel"
    if re.fullmatch(r"ephemora_cell-\d.*\.tar\.gz", name):
        return "sdist"
    return None


def runtime_identity(wheel: Path) -> dict[str, str]:
    """Version, license expression and the embedded native library digest.

    The digest is the point: the runtime is the engine the advisories were
    measured against, and a wheel that merely says ``49.0.3`` is not that
    artifact. Reading it from the archive makes the statement artifact-derived.
    """
    fields = _metadata(wheel)
    with zipfile.ZipFile(wheel) as archive:
        libs = [
            n
            for n in archive.namelist()
            if n.endswith("/_libwasmtime.dylib") or n.endswith("/_libwasmtime.so")
        ]
        if len(libs) != 1:
            raise SystemExit(
                f"{wheel.name}: expected exactly one _libwasmtime library, found {libs}"
            )
        member = libs[0]
        digest = hashlib.sha256(archive.read(member)).hexdigest()
    return {
        "distribution": fields.get("Name", "wasmtime"),
        "version": fields.get("Version", ""),
        "license": fields.get("License-Expression") or fields.get("License", ""),
        "native_library": member.rsplit("/", 1)[-1],
        "native_sha256": digest,
    }


def git(*args: str) -> str:
    return subprocess.run(
        ["git", *args], cwd=REPO, capture_output=True, text=True, check=True
    ).stdout.strip()


def render_sums(manifest: dict) -> str:
    return "".join(
        f"{entry['sha256']}  {entry['name']}\n" for entry in manifest["artifacts"]
    )


def render_requirements(manifest: dict, *, guests: bool) -> str:
    by_role = {entry["role"]: entry for entry in manifest["artifacts"]}
    version = manifest["version"]
    lines = [
        "# Generated by scripts/release_manifest.py — do not edit by hand.",
        "#",
        "# Canonical install (offline, only these bytes):",
        "#   python -m pip install --no-index --require-hashes \\",
        f"#       --find-links <this directory> -r {REQUIREMENTS_NAME}",
        "#",
        "# --require-hashes makes pip refuse every wheel whose digest differs from",
        "# the pins below, which is what turns a tampered download into a failed",
        "# install instead of a silent substitution. --no-index keeps an unpinned",
        "# engine (e.g. the unpatched 49.0.0 line) out of the resolution entirely.",
        f"ephemora-cell=={version} --hash=sha256:{by_role['core-wheel']['sha256']}",
        f"wasmtime=={manifest['runtime']['version']} "
        f"--hash=sha256:{by_role['runtime']['sha256']}",
    ]
    if guests:
        lines += [
            f"ephemora-cell-python-guest=={version} "
            f"--hash=sha256:{by_role['guest-python']['sha256']}",
            f"ephemora-cell-javascript-guest=={version} "
            f"--hash=sha256:{by_role['guest-javascript']['sha256']}",
        ]
    return "\n".join(lines) + "\n"


def render_core_requirements(manifest: dict) -> str:
    header = (
        "# Core + qualified runtime only (no language guests).\n"
        "# The guests are separate distributions; installing them is a decision\n"
        "# (see docs/product_contract.md), not a dependency of this package.\n"
    )
    body = render_requirements(manifest, guests=False)
    body = "\n".join(line for line in body.splitlines() if not line.startswith("#"))
    return header + body + "\n"


def write_manifest(set_dir: Path, commit: str | None) -> int:
    artifacts = sorted(
        p for p in set_dir.iterdir() if p.is_file() and p.name not in GENERATED
    )
    roles: dict[str, Path] = {}
    for path in artifacts:
        role = classify(path)
        if role is None:
            raise SystemExit(
                f"unexpected file in the release set: {path.name} — the set carries "
                "the four distributions and nothing else"
            )
        if role in roles:
            raise SystemExit(
                f"two artifacts claim the role {role!r}: {roles[role].name}, {path.name}"
            )
        roles[role] = path

    expected = EXPECTED_ROLES
    missing = expected - set(roles)
    if missing:
        raise SystemExit(f"release set is incomplete: missing {sorted(missing)}")

    runtime = runtime_identity(roles["runtime"])
    core = _metadata(roles["core-wheel"])
    version = core.get("Version", "")
    for role in ("guest-python", "guest-javascript"):
        guest_version = _metadata(roles[role]).get("Version", "")
        if guest_version != version:
            raise SystemExit(
                f"{roles[role].name} carries version {guest_version!r}, the core wheel "
                f"carries {version!r} — a release set is one version"
            )

    head = commit or git("rev-parse", "HEAD")
    tree = git("rev-parse", f"{head}^{{tree}}")
    dirty = bool(git("status", "--porcelain"))

    manifest = {
        "schema": 1,
        "version": version,
        "source": {
            "commit": head,
            "tree": tree,
            "worktree_dirty_at_write": dirty,
        },
        "runtime": runtime,
        "artifacts": [
            {
                "role": classify(path),
                "name": path.name,
                "size": path.stat().st_size,
                "sha256": sha256(path),
            }
            for path in sorted(roles.values(), key=lambda p: p.name)
        ],
    }

    (set_dir / REQUIREMENTS_NAME).write_text(
        render_requirements(manifest, guests=True), encoding="utf-8"
    )
    (set_dir / CORE_REQUIREMENTS_NAME).write_text(
        render_core_requirements(manifest), encoding="utf-8"
    )
    (set_dir / SUMS_NAME).write_text(render_sums(manifest), encoding="utf-8")
    (set_dir / MANIFEST_NAME).write_text(
        json.dumps(manifest, indent=2, sort_keys=True) + "\n", encoding="utf-8"
    )

    print(f"version           {version}")
    print(f"source commit     {head}")
    print(f"source tree       {tree}")
    print(f"worktree dirty    {dirty}")
    print(f"runtime           {runtime['version']} ({runtime['license']})")
    print(
        f"native library    {runtime['native_library']} sha256 {runtime['native_sha256']}"
    )
    for entry in manifest["artifacts"]:
        print(f"  {entry['role']:<18} {entry['sha256']}  {entry['name']}")
    print(
        f"wrote {SUMS_NAME}, {MANIFEST_NAME}, {REQUIREMENTS_NAME}, {CORE_REQUIREMENTS_NAME}"
    )
    return 0


def verify_set(set_dir: Path) -> int:
    manifest_path = set_dir / MANIFEST_NAME
    if not manifest_path.exists():
        print(f"FAIL: {manifest_path} is missing — cannot verify an unbound set")
        return 1
    manifest = json.loads(manifest_path.read_text(encoding="utf-8"))
    failures: list[str] = []
    if manifest.get("schema") != 1:
        failures.append(f"manifest schema {manifest.get('schema')!r} is not 1")
    roles = {entry["role"] for entry in manifest["artifacts"]}
    missing_roles = EXPECTED_ROLES - roles
    if missing_roles:
        failures.append(
            f"manifest describes an incomplete set: {sorted(missing_roles)}"
        )
    listed = {entry["name"] for entry in manifest["artifacts"]}
    for entry in manifest["artifacts"]:
        path = set_dir / entry["name"]
        if not path.exists():
            failures.append(f"{entry['name']}: missing")
            continue
        actual = sha256(path)
        if actual != entry["sha256"]:
            failures.append(f"{entry['name']}: sha256 {actual} != {entry['sha256']}")
        if path.stat().st_size != entry["size"]:
            failures.append(f"{entry['name']}: size differs from the manifest")
    extras = [
        p.name
        for p in set_dir.iterdir()
        if p.is_file() and p.name not in GENERATED and p.name not in listed
    ]
    for extra in sorted(extras):
        failures.append(f"{extra}: not part of the manifest (unexpected artifact)")

    runtime_entries = [
        entry for entry in manifest["artifacts"] if entry["role"] == "runtime"
    ]
    if len(runtime_entries) != 1:
        failures.append("the manifest does not name exactly one runtime artifact")
    else:
        runtime_path = set_dir / runtime_entries[0]["name"]
        if runtime_path.exists():
            actual_runtime = runtime_identity(runtime_path)
            if actual_runtime["native_sha256"] != manifest["runtime"]["native_sha256"]:
                failures.append(
                    "runtime wheel names a different native library digest than the "
                    "manifest"
                )
        else:
            failures.append(
                f"{runtime_entries[0]['name']}: missing — cannot verify the native runtime"
            )

    if failures:
        for line in failures:
            print(f"FAIL: {line}")
        return 1

    # The three generated files are part of what a user is told to trust, and
    # requirements-release.txt is what pip consumes with --require-hashes. An
    # earlier version of this function skipped them entirely, so a file whose
    # pins had been rewritten still verified OK (independent review, 2026-10-20).
    # They are deterministic, so they are re-rendered and compared byte for byte.
    expected = {
        SUMS_NAME: render_sums(manifest),
        REQUIREMENTS_NAME: render_requirements(manifest, guests=True),
        CORE_REQUIREMENTS_NAME: render_core_requirements(manifest),
    }
    for name, text in expected.items():
        path = set_dir / name
        if not path.exists():
            failures.append(f"{name}: missing")
        elif path.read_text(encoding="utf-8") != text:
            failures.append(f"{name}: does not match the manifest (edited or stale)")

    if failures:
        for line in failures:
            print(f"FAIL: {line}")
        return 1
    print(
        f"OK: {len(manifest['artifacts'])} artifacts match the manifest "
        f"({manifest['version']}, commit {manifest['source']['commit'][:12]}, "
        f"native {manifest['runtime']['native_sha256'][:12]})"
    )
    return 0


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    parser.add_argument("command", choices=["write", "verify"])
    parser.add_argument("--set", required=True, type=Path, help="artifact directory")
    parser.add_argument(
        "--commit",
        default=None,
        help="commit to bind (default: HEAD of this repository)",
    )
    args = parser.parse_args(argv)
    set_dir: Path = args.set
    if not set_dir.is_dir():
        raise SystemExit(f"not a directory: {set_dir}")
    if args.command == "write":
        return write_manifest(set_dir, args.commit)
    return verify_set(set_dir)


if __name__ == "__main__":
    sys.exit(main())
