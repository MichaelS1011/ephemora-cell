#!/usr/bin/env python3
# SPDX-License-Identifier: BUSL-1.1
# Copyright 2026 Michael Soppa
"""Reproducible build recipe for the shipped JavaScript *interpreter* guest.

ADR-009 makes JavaScript a supported guest language and requires the guest to be
*built reproducibly and digested* rather than hunted for at runtime. This script
is the single documented recipe that turns the shipped ``ephemora-cell[javascript]``
guest into a measured artifact on a properly provisioned build host:

    python scripts/build_js_interpreter_guest.py --out js_guest.wasm [--smoke]

It pins the exact toolchain, lays down a tiny ``wasm32-wasip1`` crate that embeds
QuickJS (the ``quickjs-ng`` fork) through ``rquickjs``, builds it with a committed
``Cargo.lock`` (``cargo build --locked``) so the whole dependency graph — not just
the direct pin — is version-fixed, and prints the sha256 + size of the produced
bytes. The guest reads the user's own source from ``/work/main.js`` and delivers
``input_json`` via ``/work/input.json``; user faults are reported on stderr with
the ``EPHEMORA_USER_ERROR`` marker (see ``ephemora_cell/lang_js.py``).

This is DISTINCT from ``scripts/build_js_guest.py``, which builds the pre-compiled
**module** path with Javy 9.1.0 (a static ES module, stdin-JSON contract). The
interpreter here is what actually runs *arbitrary user JS*.

Honest caveats this tool exists to record, not hide:
  * **Graph-pinned, not bit-deterministic.** ``--locked`` freezes the resolved
    dependency versions (rquickjs 0.14.0, quickjs-ng via rquickjs-sys, hashbrown
    0.17.1, serde 1.0.229, …), so a rebuild selects the *same crates*. But cargo
    embeds build paths/metadata, so the emitted bytes are not guaranteed
    identical run-to-run. The supply-chain guarantee is therefore the
    digest-pinned shipped artifact (one audited build) plus bring-your-own
    recompute-and-verify — **not** a claim of byte-for-byte rebuild parity.
  * **The shipped ``js_guest.wasm`` predates this lock.** The current packaged
    digest (``88a39697…``) was produced before this ``Cargo.lock`` was captured,
    so this recipe is the pinned source-of-truth for *future* builds; it is not
    asserted to reproduce ``88a39697`` exactly. Re-pack once, digest it, ship those
    bytes.
  * **Not a publish.** This only produces a local guest. Publishing a versioned
    ``ephemora-cell[javascript]`` distribution (entry-point registration, license /
    SBOM review, PyPI upload) is a separate, governance-gated supply-chain step.
  * **Toolchain must already be installed.** cargo/rustc with the ``wasm32-wasip1``
    target and a working C toolchain (for the vendored QuickJS ``cc`` build). No
    download happens at Cell execution time.
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

#: Exact toolchain pins this recipe is qualified against (2026-10-15).
PINNED_RQUICKJS = "rquickjs==0.14.0 (quickjs-ng)"
RUST_TARGET = "wasm32-wasip1"

#: Committed, graph-complete lock so ``cargo build --locked`` fixes every crate.
_LOCK = Path(__file__).resolve().parent / "data" / "js_interpreter_guest" / "Cargo.lock"

_CARGO_TOML = """[package]
name = "qjsrun"
version = "0.1.0"
edition = "2024"

[dependencies]
rquickjs = "=0.14.0"

[profile.release]
opt-level = "z"
lto = true
strip = true
"""

_MAIN_RS = r"""use rquickjs::{Context, Ctx, Function, Runtime, Value};
use std::fs;

const SRC: &str = "/work/main.js";
const INPUT: &str = "/work/input.json";

fn real_main(ctx: Ctx) {
    let src = match fs::read_to_string(SRC) {
        Ok(s) => s,
        Err(e) => {
            eprintln!("EPHEMORA_CANNOT_READ_SCRIPT: {}", e);
            return;
        }
    };
    let input = fs::read_to_string(INPUT).unwrap_or_else(|_| "null".to_string());
    let g = ctx.globals();
    let logfn = Function::new(ctx.clone(), |s: String| println!("{}", s)).unwrap();
    let _ = g.set("__log", logfn);
    let _ = g.set("__inputJson", input.as_str());
    let shim = "var input=(function(){try{return JSON.parse(__inputJson)}catch(e){return null}})();\
                var console={log:function(){var a=Array.prototype.slice.call(arguments);\
                __log(a.map(function(x){try{return (x&&typeof x==='object')?JSON.stringify(x):String(x)}\
                catch(e){return String(x)}}).join(' '))},error:function(){},warn:function(){}};";
    let combined = format!("{}\n{}", shim, src);
    match ctx.eval::<Value, _>(combined.as_str()) {
        Ok(_) => {}
        Err(e) => eprintln!("EPHEMORA_USER_ERROR: {}", e),
    }
}

fn main() {
    let rt = match Runtime::new() {
        Ok(rt) => rt,
        Err(e) => {
            eprintln!("EPHEMORA_RUNTIME_ERROR: {}", e);
            return;
        }
    };
    let ctx = match Context::full(&rt) {
        Ok(ctx) => ctx,
        Err(e) => {
            eprintln!("EPHEMORA_RUNTIME_ERROR: {}", e);
            return;
        }
    };
    ctx.with(|ctx| real_main(ctx));
    // normal return -> wasi exit 0; user faults are surfaced via the stderr
    // marker, so the adapter can distinguish them without an abort backtrace.
}
"""


def _sha256(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        for chunk in iter(lambda: handle.read(1 << 20), b""):
            digest.update(chunk)
    return digest.hexdigest()


def _require_cargo() -> str:
    if shutil.which("cargo") is None:
        raise SystemExit(
            "cargo not on PATH. This recipe pins "
            f"{PINNED_RQUICKJS} and targets {RUST_TARGET}; install a Rust "
            "toolchain with `rustup target add wasm32-wasip1` and a working C "
            "compiler (the vendored QuickJS is built via `cc`). Nothing is "
            "downloaded by Cell itself."
        )
    out = subprocess.run(
        ["rustc", "--version"], capture_output=True, text=True, check=False
    )
    return (out.stdout or out.stderr).strip() or "unknown rustc"


def build(out_path: Path) -> tuple[str, int]:
    """Build the interpreter guest into ``out_path``; return (sha256, size)."""
    print(f"toolchain: {_require_cargo()}", file=sys.stderr)
    with tempfile.TemporaryDirectory() as work:
        root = Path(work)
        (root / "src").mkdir()
        (root / "Cargo.toml").write_text(_CARGO_TOML)
        (root / "src" / "main.rs").write_text(_MAIN_RS)
        cmd = ["cargo", "build", "--release", "--target", RUST_TARGET]
        if _LOCK.exists():
            shutil.copyfile(_LOCK, root / "Cargo.lock")
            cmd.append("--locked")
            print(
                f"pinned graph: {os.path.relpath(_LOCK, Path.cwd())} (cargo --locked)",
                file=sys.stderr,
            )
        else:  # pragma: no cover - data file ships with the repo
            print(
                "WARNING: Cargo.lock missing; building unlocked (graph not pinned)",
                file=sys.stderr,
            )
        result = subprocess.run(
            cmd, cwd=str(root), capture_output=True, text=True, check=False
        )
        built = root / "target" / RUST_TARGET / "release" / "qjsrun.wasm"
        if result.returncode != 0 or not built.exists():
            sys.stderr.write(result.stdout + result.stderr)
            raise SystemExit(f"cargo build failed (rc={result.returncode})")
        shutil.copyfile(built, out_path)
    return _sha256(out_path), out_path.stat().st_size


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(
        description="Build a reproducible QuickJS JavaScript interpreter guest."
    )
    parser.add_argument("--out", default="js_guest.wasm", help="output .wasm path")
    parser.add_argument(
        "--smoke",
        action="store_true",
        help="after building, run the user's own JS through the isolated sandbox",
    )
    args = parser.parse_args(argv)
    out_path = Path(args.out).resolve()

    digest, size = build(out_path)
    print(f"digest sha256={digest} size={size}")

    if args.smoke:
        sys.path.insert(0, str(Path(__file__).resolve().parent.parent))
        from ephemora_cell.lang import run_javascript

        res = run_javascript(
            entrypoint=str(out_path),
            source="console.log([1,2,3].reduce((a,b)=>a+b,0))",
            expected_sha256=digest,
        )
        status = str(res["status"])
        ok = status.endswith("SUCCESS") and (res.get("stdout") or "").strip() == "6"
        print(f"smoke status={status} stdout={res.get('stdout')!r} qualified={ok}")
        return 0 if ok else 1
    return 0


if __name__ == "__main__" or os.environ.get("_BUILD_JS_INTERPRETER_GUEST") == "1":
    raise SystemExit(main())
