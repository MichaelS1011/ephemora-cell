#!/usr/bin/env python3
"""Attack-surface audit — measured install footprints, not quotes.

Formalizes comparison-mcp-servers.md §4 point 2: for every candidate with a
local install path, this script counts what actually lands on the machine
when a user installs it (distributions, package directories, bytes) and
records version + date + repro command per row. Rows without a local
install path are literature rows in the docs table, labeled there — never
presented as measured here.

Measured candidates:
  - ephemora-cell       fresh venv, `pip install ephemora-cell` (PyPI)
  - official MCP filesystem server   temp dir, `npm install` (pinned)
  - docker images       python:3.12-slim, node:24-alpine (local image sizes)

Evidence: benchmarks/results/<date>/06_attack_surface_audit.json
"""

from __future__ import annotations

import json
import subprocess
import sys
import tempfile
from datetime import date
from pathlib import Path

REPO = Path(__file__).resolve().parents[1]


def _du_kb(path: str) -> int:
    p = subprocess.run(["du", "-sk", path], capture_output=True, text=True)
    return int(p.stdout.split()[0]) if p.returncode == 0 else -1


def _docker_image(image: str) -> dict:
    size = subprocess.run(
        ["docker", "image", "inspect", image, "--format", "{{.Size}}"],
        capture_output=True,
        text=True,
    )
    digest = subprocess.run(
        ["docker", "image", "inspect", image, "--format", "{{index .RepoDigests 0}}"],
        capture_output=True,
        text=True,
    )
    return {
        "image": image,
        "uncompressed_mb": (
            round(int(size.stdout.strip()) / 1e6, 1) if size.returncode == 0 else None
        ),
        "digest": digest.stdout.strip() or None,
    }


def main() -> int:
    rows: list[dict] = []

    # 1. ephemora-cell from PyPI into a fresh venv
    venv = tempfile.mkdtemp(prefix="surface_pip_")
    subprocess.run(
        [sys.executable, "-m", "venv", venv], check=True, capture_output=True
    )
    pip = Path(venv) / "bin" / "pip"
    inst = subprocess.run(
        [str(pip), "install", "-q", "ephemora-cell"],
        capture_output=True,
        text=True,
        timeout=300,
    )
    if inst.returncode == 0:
        listing = json.loads(
            subprocess.run(
                [str(Path(venv) / "bin" / "pip"), "list", "--format", "json"],
                capture_output=True,
                text=True,
            ).stdout
        )
        names = sorted(d["name"].lower() for d in listing)
        deps = [n for n in names if n not in ("pip", "setuptools", "wheel")]
        sp = Path(venv) / "lib"
        site = next(sp.glob("python*/site-packages"), None)
        rows.append(
            {
                "candidate": "ephemora-cell (pip, PyPI)",
                "repro": "python3 -m venv v && v/bin/pip install ephemora-cell",
                "measured_date": str(date.today()),
                "installed_distributions": len(deps),
                "distributions": deps,
                "site_packages_mb": (
                    round(_du_kb(str(site)) / 1024, 1) if site else None
                ),
                "notes": "1 runtime dependency (wasmtime); counts exclude pip/setuptools",
            }
        )
    else:
        rows.append(
            {
                "candidate": "ephemora-cell (pip, PyPI)",
                "error": inst.stderr[-200:],
                "measured_date": str(date.today()),
            }
        )
    shutil.rmtree(venv, ignore_errors=True)

    # 2. official MCP filesystem server via npm (pinned)
    ndir = tempfile.mkdtemp(prefix="surface_npm_")
    npm = subprocess.run(
        [
            "npm",
            "install",
            "--no-audit",
            "--no-fund",
            "@modelcontextprotocol/server-filesystem@2025.3.28",
        ],
        cwd=ndir,
        capture_output=True,
        text=True,
        timeout=300,
    )
    nm = Path(ndir) / "node_modules"
    if npm.returncode == 0 and nm.exists():
        pkgs = [
            d.name for d in nm.iterdir() if d.is_dir() and not d.name.startswith(".")
        ]
        scoped = sum(1 for d in nm.glob("@*/*") if d.is_dir())
        rows.append(
            {
                "candidate": "@modelcontextprotocol/server-filesystem@2025.3.28 (npm)",
                "repro": "mkdir d && cd d && npm install @modelcontextprotocol/server-filesystem@2025.3.28",
                "measured_date": str(date.today()),
                "package_dirs": len(pkgs) + scoped,
                "node_modules_mb": round(_du_kb(str(nm)) / 1024, 1),
                "notes": "transitive npm tree installed before the first tool call",
            }
        )
    else:
        rows.append(
            {
                "candidate": "@modelcontextprotocol/server-filesystem (npm)",
                "error": npm.stderr[-200:],
                "measured_date": str(date.today()),
            }
        )
    shutil.rmtree(ndir, ignore_errors=True)

    # 3. container images (cached locally, digests pinned in evidence)
    for image in ("python:3.12-slim", "node:24-alpine"):
        info = _docker_image(image)
        info.update(
            {
                "repro": f"docker pull {image} && docker image inspect {image}",
                "measured_date": str(date.today()),
                "notes": "uncompressed local image size — pulled before any tool call",
            }
        )
        rows.append(info)

    doc = {
        "measured": True,
        "source": "measurement",
        "date": str(date.today()),
        "rows": rows,
    }
    out_dir = REPO / "benchmarks" / "results" / str(date.today())
    out_dir.mkdir(parents=True, exist_ok=True)
    dest = out_dir / "06_attack_surface_audit.json"
    dest.write_text(json.dumps(doc, indent=2))
    for r in rows:
        print(
            f"{r.get('candidate', '?')[:52]:54} "
            f"dist/pkgs={r.get('installed_distributions', r.get('package_dirs', '-'))} "
            f"mb={r.get('site_packages_mb', r.get('node_modules_mb', r.get('uncompressed_mb', '-')))}"
        )
    print(f"Saved: {dest}")
    return 0


if __name__ == "__main__":
    import shutil  # local import keeps the audit imports grouped above

    raise SystemExit(main())
