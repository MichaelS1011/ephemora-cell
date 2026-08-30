#!/usr/bin/env python3
"""Ephemora Cell — Componentize PoC: module builder.

Generates preview1 core modules + lifts them with
`wasm-tools component new --adapt wasi_snapshot_preview1.command.wasm`.

Run from the repo root:

    .venv/bin/python benchmarks/pocs/componentize_poc/build_modules.py

Produces (preview1 core modules and their lifted components):
  p1_print.wat/.wasm -> p1_print_lifted.wasm    fd_write + proc_exit(0)
  p1_loop.wat/.wasm  -> p1_loop_lifted.wasm     infinite loop (_start)
  p1_grow.wat/.wasm  -> p1_grow_lifted.wasm     memory.grow loop
  rust_fs.wasm       (prebuilt Rust wasm32-wasip1, sources in rust_fs/src)
                     -> rust_fs_lifted.wasm     args/env/fs/preopen exercise
"""
from __future__ import annotations

import os
import shutil
import subprocess
import sys
import time

import wasmtime

HERE = os.path.dirname(os.path.abspath(__file__))
ADAPTER = os.path.join(HERE, "adapters", "wasi_snapshot_preview1.command.wasm")

MODULES = {
    "p1_print.wat": '''\
(module
  (import "wasi_snapshot_preview1" "fd_write" (func $fd_write (param i32 i32 i32 i32) (result i32)))
  (import "wasi_snapshot_preview1" "proc_exit" (func $exit (param i32)))
  (memory (export "memory") 1)
  (data (i32.const 0) "\\08\\00\\00\\00\\17\\00\\00\\00")
  (data (i32.const 8) "lifted-preview1: hello\\n")
  (func (export "_start")
    (i32.const 1) (i32.const 0) (i32.const 1) (i32.const 32)
    call $fd_write drop
    i32.const 0 call $exit))
''',
    "p1_loop.wat": '''\
(module
  (import "wasi_snapshot_preview1" "proc_exit" (func $exit (param i32)))
  (memory (export "memory") 1)
  (func (export "_start")
    (local $n i32)
    loop $l
      local.get $n i32.const 1 i32.add local.set $n br $l
    end
    i32.const 0 call $exit)
)
''',
    "p1_grow.wat": '''\
(module
  (import "wasi_snapshot_preview1" "proc_exit" (func $exit (param i32)))
  (memory (export "memory") 1)
  (func (export "_start")
    (local $i i32)
    loop $l
      i32.const 1 memory.grow
      i32.const -1 i32.eq if unreachable end
      local.get $i i32.const 1 i32.add local.set $i
      local.get $i i32.const 1400 i32.lt_u if br $l end
    end
    i32.const 0 call $exit)
)
''',
}


def build(name: str, wat: str) -> None:
    wat_path = os.path.join(HERE, name)
    wasm_path = os.path.join(HERE, name.replace(".wat", ".wasm"))
    with open(wat_path, "w") as f:
        f.write(wat)
    with open(wasm_path, "wb") as f:
        f.write(wasmtime.wat2wasm(wat))
    print(f"  built {name} -> {os.path.basename(wasm_path)}", end=" ")
    lift(wasm_path, wasm_path.replace(".wasm", "_lifted.wasm"))


def lift(module_path: str, out_path: str) -> None:
    if not os.path.exists(ADAPTER):
        raise SystemExit("missing adapter: " + ADAPTER)
    t0 = time.perf_counter()
    subprocess.run(
        ["wasm-tools", "component", "new", module_path, "--adapt", ADAPTER,
         "-o", out_path],
        check=True,
    )
    dt = (time.perf_counter() - t0) * 1000
    print(f"-> {os.path.basename(out_path)} ({os.path.getsize(out_path)} B, lift {dt:.1f} ms)")


def main() -> None:
    print("Building componentize PoC modules under", HERE)
    for name, wat in MODULES.items():
        build(name, wat)

    rust_wasm = os.path.join(HERE, "rust_fs", "target", "wasm32-wasip1",
                             "release", "rust_fs.wasm")
    prebuilt = os.path.join(HERE, "rust_fs.wasm")
    if os.path.exists(rust_wasm):
        shutil.copyfile(rust_wasm, prebuilt)
    elif not os.path.exists(prebuilt):
        raise SystemExit(
            "rust_fs.wasm missing — build it in scratch first:\n"
            "  cargo build --target wasm32-wasip1 --release "
            "(manifest: benchmarks/pocs/componentize_poc/rust_fs/Cargo.toml) "
            "then copy target/wasm32-wasip1/release/rust_fs.wasm here"
        )
    lift(prebuilt, os.path.join(HERE, "rust_fs_lifted.wasm"))
    print("done.")


if __name__ == "__main__":
    sys.exit(main())