#!/usr/bin/env python3
"""Release identity — bind one set of artifacts to one source commit.

A version STRING cannot identify a build. `1.1.0` on PyPI and a `1.1.0` wheel
built locally from a verification branch carry the same name while containing
different code, and that confusion is exactly what a security gate must make
impossible: an external reviewer who runs against "the tested artifact" has to
be able to prove WHICH artifact was tested.

This script emits a machine-checkable identity manifest that ties together

  * the source: full commit SHA, tree SHA, newest tag, working-tree cleanliness,
    and the four single-source version strings,
  * the distribution artifacts found in `--dist` (name, size, sha256),
  * the native runtime actually importable here (wasmtime version + the digest
    of the `_libwasmtime` binary the bindings load — the engine the advisories
    were measured against, not the version range declared in metadata),
  * the reference container, when one is given: image ID digest and the
    base-image digest pinned in the Dockerfile,
  * publication scope: whether this identity is publishable at all.

Publishable is FALSE whenever the tree is dirty or the version carries a PEP 440
label (rc/dev/local) — a labelled, source-built verification artifact can then
never be mistaken for the released one, because the manifest says so out loud
instead of relying on the version string.

No timestamps, no paths outside the repo: the same commit + same artifacts
produce the same manifest, so a later auditor can diff it rather than trust it.
Machine-local absolute paths are reported as repo-relative or as the installed
distribution name only.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import os
import re
import subprocess
import sys
from pathlib import Path

REPO = Path(__file__).resolve().parents[1]


def _git(*args: str) -> str:
    out = subprocess.run(
        ["git", *args], cwd=REPO, capture_output=True, text=True, check=True
    )
    # Only trailing newlines: a porcelain status line STARTS with its XY marker
    # (" M path"), and a blanket strip() would shift every path one column left.
    return out.stdout.rstrip("\n")


def _sha256(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        for chunk in iter(lambda: handle.read(1 << 20), b""):
            digest.update(chunk)
    return digest.hexdigest()


def source_identity() -> dict:
    status = _git("status", "--porcelain", "--untracked-files=no")
    dirty = [line for line in status.splitlines() if line.strip()]
    return {
        "commit": _git("rev-parse", "HEAD"),
        "tree": _git("rev-parse", "HEAD^{tree}"),
        "branch": _git("rev-parse", "--abbrev-ref", "HEAD"),
        "newest_tag": (
            _git("tag", "-l", "v*", "--sort=-v:refname").splitlines() or [""]
        )[0],
        "worktree_dirty": bool(dirty),
        "worktree_dirty_files": [line[3:].strip() for line in dirty],
    }


def version_identity() -> dict:
    """The four version sources, via the same parser the CI guard uses."""
    sys.path.insert(0, str(REPO / "scripts"))
    import check_version_sync as cvs

    sources = {
        "pyproject.toml": cvs._pyproject_version(),
        "ephemora_cell/__init__.py": cvs._module_version("ephemora_cell/__init__.py"),
        "ephemora_cell_mcp/_version.py": cvs._module_version(
            "ephemora_cell_mcp/_version.py"
        ),
    }
    server = cvs._server_json_versions()
    for i, v in enumerate(server[1:], start=1):
        sources[f"server.json(packages[{i - 1}])"] = v
    sources["server.json(top)"] = server[0]
    parsed = cvs._split_version(sources["pyproject.toml"])
    label = parsed[1] if parsed else None
    return {
        "sources": sources,
        "in_sync": len(set(sources.values())) == 1,
        "version": sources["pyproject.toml"],
        "pep440_label": label,
        "labelled_build": bool(label),
    }


def artifact_identity(dist: Path) -> list[dict]:
    out: list[dict] = []
    for path in sorted(dist.glob("*")):
        if not path.is_file() or path.suffix not in {".whl", ".gz", ".tar.bz2", ".zip"}:
            continue
        out.append(
            {
                "name": path.name,
                "bytes": path.stat().st_size,
                "sha256": _sha256(path),
            }
        )
    return out


def engine_identity() -> dict:
    """The native engine this interpreter would actually load."""
    try:
        import wasmtime
    except Exception as exc:  # pragma: no cover - depends on the local venv
        return {"importable": False, "error": f"{type(exc).__name__}: {exc}"}
    import importlib.metadata as md
    import platform
    import sysconfig

    package_dir = Path(wasmtime.__file__).resolve().parent
    candidates = sorted(p for p in package_dir.rglob("_libwasmtime.*"))
    libs = []
    for lib in candidates:
        if lib.suffix in {".py", ".pyc"}:
            continue
        libs.append(
            {
                "artifact": f"{lib.parent.name}/{lib.name}",
                "bytes": lib.stat().st_size,
                "sha256": _sha256(lib),
            }
        )
    return {
        "importable": True,
        "wasmtime_version": md.version("wasmtime"),
        "python_version": platform.python_version(),
        "wheel_platform": sysconfig.get_platform(),
        "native_libraries": libs,
    }


def container_identity(image: str, dockerfile: Path) -> dict:
    out: dict = {"image_ref": image or None}
    if not image:
        out["note"] = "no image given (IMAGE env or --image)"
        return out
    if dockerfile.is_file():
        text = dockerfile.read_text(encoding="utf-8")
        pins = re.findall(r"^FROM\s+\S+@(sha256:[0-9a-f]{64})", text, re.MULTILINE)
        out["base_image_digests"] = pins
        out["base_digest_pinned"] = bool(pins)
    try:
        inspection = subprocess.run(
            ["docker", "image", "inspect", image],
            capture_output=True,
            text=True,
            check=True,
        ).stdout
        data = json.loads(inspection)[0]
        out["reachable"] = True
        out["image_id"] = data.get("Id")
        out["architecture"] = data.get("Architecture")
        out["os"] = data.get("Os")
        config = data.get("Config", {})
        out["config_user"] = config.get("User")
        out["config_entrypoint"] = config.get("Entrypoint")
        out["created"] = data.get("Created")
    except Exception as exc:
        out["reachable"] = False
        out["error"] = f"{type(exc).__name__}: {exc}"
    return out


def pypi_state(version: str, timeout: float = 15.0) -> dict:
    """Is this exact version string already published? (opt-in, needs network)."""
    import urllib.error
    import urllib.request

    url = f"https://pypi.org/pypi/ephemora-cell/{version}/json"
    try:
        with urllib.request.urlopen(url, timeout=timeout) as response:
            payload = json.loads(response.read().decode("utf-8"))
        published = sorted(
            {
                f"{file['filename']}:{file['digests']['sha256']}"
                for file in payload.get("urls", [])
                if file.get("packagetype") in {"bdist_wheel", "sdist"}
                and file.get("digests", {}).get("sha256")
            }
        )
        return {"queried": True, "published": True, "published_digests": published}
    except urllib.error.HTTPError as exc:
        if exc.code == 404:
            return {"queried": True, "published": False, "published_digests": []}
        return {"queried": True, "error": f"HTTP {exc.code}"}
    except Exception as exc:  # pragma: no cover - offline runs
        return {"queried": False, "error": f"{type(exc).__name__}: {exc}"}


def build(dist: Path, image: str, dockerfile: Path, check_pypi: bool) -> dict:
    source = source_identity()
    version = version_identity()
    artifacts = artifact_identity(dist)
    manifest = {
        "schema": "ephemora-cell/release-identity/1",
        "source": source,
        "version": version,
        "artifacts": artifacts,
        "native_runtime": engine_identity(),
        "reference_container": container_identity(image, dockerfile),
    }
    if check_pypi:
        publication = pypi_state(version["version"])
        # The confusion this whole script exists to rule out, stated as data: the
        # published bytes and the bytes on disk are different objects even when
        # both are named 1.1.0.
        published_shas = {
            entry.split(":", 1)[1] for entry in publication.get("published_digests", [])
        }
        local_shas = {a["sha256"] for a in artifacts}
        publication["identical_to_local_build"] = sorted(local_shas & published_shas)
        manifest["publication"] = publication
    blockers = []
    if source["worktree_dirty"]:
        blockers.append("working tree carries uncommitted changes")
    if not version["in_sync"]:
        blockers.append("version sources disagree")
    if not manifest["artifacts"]:
        blockers.append(f"no distribution artifacts found in {dist.name}/")
    manifest["identity"] = "commit {} / artifacts {}".format(
        source["commit"][:12],
        "+".join(a["sha256"][:12] for a in manifest["artifacts"]) or "none",
    )
    # A labelled build is by design NOT publishable: the label is what keeps it
    # apart from the released artifact of the same line.
    manifest["publishable"] = not blockers and not version["labelled_build"]
    manifest["publish_blockers"] = blockers
    return manifest


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    parser.add_argument("--dist", default=str(REPO / "dist"), type=Path)
    parser.add_argument("--image", default=os.environ.get("IMAGE", ""))
    parser.add_argument(
        "--dockerfile", default=str(REPO / "deploy" / "linux-reference" / "Dockerfile")
    )
    parser.add_argument(
        "--check-pypi",
        action="store_true",
        help="query PyPI for this exact version string (needs network)",
    )
    parser.add_argument("--out", type=Path, default=None)
    args = parser.parse_args(argv)

    manifest = build(args.dist, args.image, Path(args.dockerfile), args.check_pypi)

    text = json.dumps(manifest, indent=2, sort_keys=True) + "\n"
    if args.out:
        args.out.parent.mkdir(parents=True, exist_ok=True)
        args.out.write_text(text, encoding="utf-8")
    print(text, end="")
    return 0


if __name__ == "__main__":
    sys.exit(main())
