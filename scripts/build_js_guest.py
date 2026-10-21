#!/usr/bin/env python3
# SPDX-License-Identifier: BUSL-1.1
# Copyright 2026 Michael Soppa
"""Reproducible build recipe for a modern JavaScript WASI Preview1 guest.

ADR-009 makes JavaScript a supported guest language and
requires the guest to be *built reproducibly and digested* rather than hunted
for at runtime. This script is the single documented recipe that turns that
contract into a measured artifact on a properly provisioned build host:

    python scripts/build_js_guest.py --out guest.wasm

It pins the exact Javy toolchain version (bytecodealliance/javy 9.1.0), lays
down a tiny, self-contained ES program (stdin JSON in, stdout JSON out — the
same fixture contract the ``lang_js`` adapter round-trip test asserts), builds
it to a standalone core module with the operator-provided ``javy`` CLI, and
prints the sha256 + size of the produced bytes.

Honest caveats this tool exists to record, not hide:
  * **Module path only — not the shipped user-JS guest.** This builds a
    pre-compiled Javy static ES *module* (the ``run_javascript_module`` /
    ``entrypoint=`` path). The guest actually shipped in
    ``ephemora-cell[javascript]`` for running a *user's own JS source* is the
    QuickJS interpreter built by ``scripts/build_js_interpreter_guest.py``.
    Do not confuse the two recipes.
  * **Byte-nondeterminism.** javy 9.1.0 is not bit-reproducible back-to-back —
    the emitted module embeds build metadata, so two runs of this recipe over
    the same source yield the same size but a different digest. *Behaviour* is
    reproducible from this recipe; a shipped package pins the digest of one
    build-once artifact rather than a rebuild hash. Re-pack once, digest it,
    distribute those exact bytes.
  * **Not Node/npm.** The guest is a plain Javy static module: only the ES
    features QuickJS-in-WASM provides, no Node.js or npm compatibility.
  * **Not a publish.** This only produces a local guest. Publishing a versioned
    ``ephemora-cell[javascript]`` distribution (entry-point registration,
    license / SBOM review of the embedded QuickJS tree, PyPI upload) is a
    separate, governance-gated supply-chain step and is not done here.
  * **Toolchain must already be installed.** javy is a native CLI, not a
    pip/npm package; the operator installs it (or points ``EPHEMORA_JAVY_BIN``
    at a vetted binary) before running this. Nothing is downloaded at Cell
    execution time — see ``ephemora_cell/lang_js.py``.
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

#: Exact toolchain version this recipe was qualified against (2026-10-15).
PINNED_JAVY = "javy 9.1.0"

#: Fixture contract asserted by the lang_js adapter round-trip: n + 30, msg + "!".
GUEST_INPUT = {"n": 10, "msg": "baz"}
GUEST_EXPECTED_OUTPUT = {"answer": 40, "echo": "baz!"}

#: Env var that may point at an operator-installed javy binary when it is not
#: on PATH (mirrors the ``EPHEMORA_PY_GUEST_QUALIFY`` opt-in toolchain pattern).
JAVY_BIN_ENV = "EPHEMORA_JAVY_BIN"

_GUEST_JS = r"""// Reproducible ephemora-cell JS guest fixture: stdin JSON -> stdout JSON.
// Deliberately small and self-contained (no Node compatibility claim).
function run() {
  const chunkSize = 1024;
  const inputChunks = [];
  let totalBytes = 0;
  while (1) {
    const buffer = new Uint8Array(chunkSize);
    const bytesRead = Javy.IO.readSync(0, buffer);
    totalBytes += bytesRead;
    if (bytesRead === 0) break;
    inputChunks.push(buffer.subarray(0, bytesRead));
  }
  const finalBuffer = new Uint8Array(totalBytes);
  let offset = 0;
  for (const chunk of inputChunks) {
    finalBuffer.set(chunk, offset);
    offset += chunk.length;
  }
  const input = JSON.parse(new TextDecoder().decode(finalBuffer));
  const output = { answer: input.n + 30, echo: input.msg + "!" };
  const encoded = new TextEncoder().encode(JSON.stringify(output) + "\n");
  Javy.IO.writeSync(1, encoded);
}
run();
"""


def _sha256(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        for chunk in iter(lambda: handle.read(1 << 20), b""):
            digest.update(chunk)
    return digest.hexdigest()


def _resolve_javy() -> str:
    """Locate the operator-installed javy CLI; never download it here."""
    override = os.environ.get(JAVY_BIN_ENV)
    exe = override or shutil.which("javy")
    if exe is None or not Path(exe).exists():
        raise SystemExit(
            f"javy CLI not found. This recipe was qualified against "
            f"{PINNED_JAVY}; install the bytecodealliance/javy CLI and put it "
            f"on PATH, or point {JAVY_BIN_ENV} at a vetted binary. Nothing is "
            f"downloaded by Cell itself."
        )
    out = subprocess.run(
        [exe, "--version"], capture_output=True, text=True, check=False
    )
    return (out.stdout or out.stderr).strip() or "unknown version"


def build(out_path: Path) -> tuple[str, int]:
    """Build the JS guest into ``out_path``; return (sha256, size_bytes)."""
    tool = _resolve_javy()
    print(f"toolchain: {tool}", file=sys.stderr)
    exe = os.environ.get(JAVY_BIN_ENV) or shutil.which("javy")
    assert exe is not None
    with tempfile.TemporaryDirectory() as work:
        src = Path(work) / "guest.js"
        src.write_text(_GUEST_JS)
        result = subprocess.run(
            [exe, "build", str(src), "-o", str(out_path)],
            capture_output=True,
            text=True,
            check=False,
        )
        if result.returncode != 0 or not out_path.exists():
            sys.stderr.write(result.stdout + result.stderr)
            raise SystemExit(f"javy build failed (rc={result.returncode})")
    return _sha256(out_path), out_path.stat().st_size


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(
        description="Build a reproducible JavaScript Preview1 guest."
    )
    parser.add_argument("--out", default="guest.wasm", help="output .wasm path")
    parser.add_argument(
        "--smoke",
        action="store_true",
        help="after building, run the guest through the isolated lang_js adapter "
        "and assert the JSON round-trip matches",
    )
    args = parser.parse_args(argv)
    out_path = Path(args.out).resolve()

    digest, size = build(out_path)
    print(f"digest sha256={digest} size={size}")

    if args.smoke:
        sys.path.insert(0, str(Path(__file__).resolve().parent.parent))
        from ephemora_cell.lang_js import run_javascript_module

        res = run_javascript_module(
            str(out_path), input_json=GUEST_INPUT, expected_sha256=digest
        )
        ok = (
            res["status"].endswith("SUCCESS") and res["output"] == GUEST_EXPECTED_OUTPUT
        )
        print(f"smoke status={res['status']} output={res['output']!r} qualified={ok}")
        return 0 if ok else 1
    return 0


if __name__ == "__main__" or os.environ.get("_BUILD_JS_GUEST") == "1":
    raise SystemExit(main())
