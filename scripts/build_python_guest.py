#!/usr/bin/env python3
# SPDX-License-Identifier: BUSL-1.1
# Copyright 2026 Michael Soppa
"""Reproducible build recipe for a modern Python WASI-0.2 component guest.

ADR-009 makes Python a mandatory language and requires the
guest to be *built reproducibly and digested* rather than hunted for at runtime.
This script is the single documented recipe that turns that contract into a
measured artifact on a properly provisioned build host:

    python scripts/build_python_guest.py --out guest.wasm

It pins the exact toolchain version, lays down a minimal ``wasi:cli/run``-style
command world (the only component entry point Cell executes — reactor worlds
with no ``run`` export are refused by the component runner), componentizes a tiny
app, and prints the sha256 + size of the produced bytes.

Honest caveats this tool exists to record, not hide:
  * **Byte-nondeterminism.** componentize-py (0.25.1) is not bit-reproducible
    even back-to-back with ``SOURCE_DATE_EPOCH=0`` — it embeds build-id/temp-path
    metadata. So *behaviour* is reproducible from this recipe, but a shipped
    package pins the digest of one build-once artifact rather than a rebuild
    hash. Re-pack the artifact once, digest it, distribute those exact bytes.
  * **Not a publish.** This only produces a local guest. Publishing a versioned
    ``ephemora-cell[python]`` distribution (entry-point registration, license /
    SBOM review of the embedded CPython tree, PyPI upload) is a separate,
    governance-gated supply-chain step and is not performed here.
  * **Toolchain must already be installed.** Nothing is downloaded at build time
    beyond the explicit ``pip install`` the operator runs; the module never
    fetches or runs an interpreter at Cell execution time (see lang_guest.py).
"""

from __future__ import annotations

import argparse
import hashlib
import os
import shutil
import subprocess
import sys
import tempfile
from pathlib import Path

#: Exact toolchain version this recipe was qualified against (2026-10-14).
PINNED_COMPONENTIZE_PY = "componentize-py==0.25.1"

#: Expected stdout of the built guest when run through the Cell sandbox.
GUEST_EXPECTED_OUTPUT = "hello from ephemora-cell python command guest\n"

_COMMAND_WIT = """package demo:runnable@0.1.0;

world runnable {
  export run: func();
}
"""

_APP_PY = """class WitWorld:
    def run(self):
        print("hello from ephemora-cell python command guest")
"""


def _sha256(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        for chunk in iter(lambda: handle.read(1 << 20), b""):
            digest.update(chunk)
    return digest.hexdigest()


def _require_componentize_py() -> str:
    exe = shutil.which("componentize-py")
    if exe is None:
        raise SystemExit(
            f"componentize-py not on PATH. This recipe was qualified against "
            f"{PINNED_COMPONENTIZE_PY}; install it in an isolated build venv "
            f"(e.g. `python -m venv .gvenv && .gvenv/bin/pip install "
            f"{PINNED_COMPONENTIZE_PY}`) and re-run on PATH. Nothing is "
            f"downloaded by Cell itself."
        )
    out = subprocess.run(
        [exe, "--version"], capture_output=True, text=True, check=False
    )
    return (out.stdout or out.stderr).strip() or "unknown version"


def build(out_path: Path) -> tuple[str, int]:
    """Build the guest into ``out_path``; return (sha256, size_bytes)."""
    tool = _require_componentize_py()
    print(f"toolchain: {tool}", file=sys.stderr)
    with tempfile.TemporaryDirectory() as work:
        root = Path(work)
        (root / "wit").mkdir()
        (root / "wit" / "command.wit").write_text(_COMMAND_WIT)
        (root / "app.py").write_text(_APP_PY)
        # componentize-py resolves the app module from --python-path (cwd default).
        result = subprocess.run(
            [
                "componentize-py",
                "-d",
                str(root / "wit"),
                "-w",
                "runnable",
                "componentize",
                "app",
                "-o",
                str(out_path),
            ],
            cwd=str(root),
            capture_output=True,
            text=True,
            check=False,
        )
        if result.returncode != 0 or not out_path.exists():
            sys.stderr.write(result.stdout + result.stderr)
            raise SystemExit(f"componentize-py build failed (rc={result.returncode})")
    return _sha256(out_path), out_path.stat().st_size


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(
        description="Build a reproducible Python component guest."
    )
    parser.add_argument("--out", default="guest.wasm", help="output .wasm path")
    parser.add_argument(
        "--smoke",
        action="store_true",
        help="after building, run the guest through the isolated Cell sandbox and assert success",
    )
    args = parser.parse_args(argv)
    out_path = Path(args.out).resolve()

    digest, size = build(out_path)
    print(f"digest sha256={digest} size={size}")

    if args.smoke:
        sys.path.insert(0, str(Path(__file__).resolve().parent.parent))
        from ephemora_cell import WASISandbox, get_profile

        sandbox = WASISandbox(config=get_profile("interpreter"))
        try:
            result = sandbox.run(
                str(out_path),
                abi="component",
                use_subprocess=True,
                expected_sha256=digest,
            )
            status = getattr(result.status, "name", str(result.status))
            ok = status == "SUCCESS" and (result.stdout or "") == GUEST_EXPECTED_OUTPUT
            print(f"smoke status={status} stdout={result.stdout!r} qualified={ok}")
            return 0 if ok else 1
        finally:
            sandbox.cleanup()
    return 0


if __name__ == "__main__" or os.environ.get("_BUILD_PYTHON_GUEST") == "1":
    raise SystemExit(main())
