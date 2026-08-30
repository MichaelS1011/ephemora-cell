#!/usr/bin/env python3
"""Ephemora Cell — GC PoC: module builder.

Generates all .wat/.wasm artifacts for the WASM-GC proof-of-concept under
benchmarks/pocs/gc_poc/. Run from the repo root:

    .venv/bin/python benchmarks/pocs/gc_poc/build_modules.py

Produces:
  gc_workload.wat/.wasm   GC-heavy preview1 core module (_start, fd_write)
  arith_workload.wat/.wasm  non-GC arithmetic twin (same loop count)
  gc_infinite.wat/.wasm   unbounded GC churn (fuel / epoch tests)
  gc_grow.wat/.wasm       GC alloc + linear memory.grow (memory-limit test)
  gc_core.wat/.wasm       self-contained GC module with direct `run` export
  gc_wrapper.wat/.wasm    hand-written component wrapping gc_core (no WASI)
  lifted.wasm             gc_workload lifted to a component via wasm-tools
                          (preview1 -> WASI 0.2, command adapter embedded)
"""
from __future__ import annotations

import os
import subprocess
import sys
import time

import wasmtime

HERE = os.path.dirname(os.path.abspath(__file__))
REPO = os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
ADAPTER = os.path.join(HERE, "..", "componentize_poc", "adapters",
                       "wasi_snapshot_preview1.command.wasm")

LOOP_N = 100_000  # default iteration count for the GC vs arith comparison

GC_TYPES = """\
  (type $pt (sub (struct (field i32) (field i32))))
  (type $at (sub (array (mut i32))))
"""

# A single GC-work chunk: allocate a struct + array, mutate them, fold a
# checksum. Used by every GC workload so all scenarios churn the same way.
GC_CHUNK = """\
    (local.set $s (struct.new $pt (local.get $acc) (local.get $i)))
    (local.set $a (array.new $at (i32.const 1) (i32.const 4)))
    (array.set $at (local.get $a) (i32.const 0) (local.get $i))
    (local.set $acc
      (i32.add
        (i32.mul (struct.get $pt 0 (local.get $s)) (i32.const 3))
        (array.get $at (local.get $a) (i32.const 0))))
"""


def gc_loop(n: int, count_var: str = "i32.const {n}") -> str:
    """Emit a `$gc_loop` func (param $n i32) (result i32)."""
    return f"""\
  (func $gc_loop (param $n i32) (result i32)
    (local $i i32) (local $acc i32)
    (local $s (ref null $pt)) (local $a (ref null $at))
    (loop $l
{GC_CHUNK}
      (local.set $i (i32.add (local.get $i) (i32.const 1)))
      (local.get $i) (local.get $n) (i32.lt_s) (if (then (br $l)))
    )
    (local.get $acc)
  )
"""


def arith_loop(n: int) -> str:
    """Non-GC arithmetic twin — same trip count, no heap allocation."""
    return f"""\
  (func $arith_loop (param $n i32) (result i32)
    (local $i i32) (local $acc i32)
    (loop $l
      (local.set $acc (i32.add (i32.mul (local.get $acc) (i32.const 3))
                               (local.get $i)))
      (local.set $i (i32.add (local.get $i) (i32.const 1)))
      (local.get $i) (local.get $n) (i32.lt_s) (if (then (br $l)))
    )
    (local.get $acc)
  )
"""

WASI_PRELUDE = """\
  (import "wasi_snapshot_preview1" "fd_write" (func $fd_write
    (param i32 i32 i32 i32) (result i32)))
  (import "wasi_snapshot_preview1" "proc_exit" (func $exit (param i32)))
"""


def wasi_print(msg: str, body: str = "i32.const 0 call $exit") -> str:
    """fd_write + proc_exit(0) epilogue printing `msg`.

    `body` is emitted first inside `_start` (e.g. the workload call).
    """
    msg_bytes = msg.encode("utf-8")
    escaped = msg_bytes.decode("utf-8").replace("\\", "\\\\").replace('"', '\\"')
    escaped = escaped.replace("\n", "\\n")
    iovec_len = len(msg_bytes)
    out = f"""\
  (memory (export "memory") 1)
  (data (i32.const 0) "\\08\\00\\00\\00\\{iovec_len:02x}\\00\\00\\00")
  (data (i32.const 8) "{escaped}")
  (func (export "_start")
    {body}
    (i32.const 1) (i32.const 0) (i32.const 1) (i32.const 32)
    call $fd_write drop
    i32.const 0 call $exit)
"""
    return out


def build(name: str, wat: str) -> str:
    """Compile wat text to benchmarks/pocs/gc_poc/<name>.wasm; return path."""
    wat_path = os.path.join(HERE, name + ".wat")
    wasm_path = os.path.join(HERE, name + ".wasm")
    with open(wat_path, "w") as f:
        f.write(wat)
    t0 = time.perf_counter()
    wasm = bytes(wasmtime.wat2wasm(wat))
    dt = (time.perf_counter() - t0) * 1000
    with open(wasm_path, "wb") as f:
        f.write(wasm)
    print(f"  built {name}.wasm  ({len(wasm)} bytes, wat2wasm {dt:.2f} ms)")
    return wasm_path


def main() -> None:
    print("Building GC PoC modules under", HERE)

    # 1. GC-heavy preview1 command module.
    build("gc_workload", (
        "(module\n"
        + WASI_PRELUDE
        + GC_TYPES
        + gc_loop(LOOP_N)
        + wasi_print(
            f"gc-workload done ({LOOP_N} iterations)\n",
            body=f"i32.const {LOOP_N} call $gc_loop drop",
        )
        + ")\n"
    ))

    # 2. Non-GC arithmetic twin, same loop count.
    build("arith_workload", (
        "(module\n"
        + WASI_PRELUDE
        + arith_loop(LOOP_N)
        + wasi_print(
            f"arith-workload done ({LOOP_N} iterations)\n",
            body=f"i32.const {LOOP_N} call $arith_loop drop",
        )
        + ")\n"
    ))

    # 3. Unbounded GC churn (fuel / epoch timeout scenarios).
    build("gc_infinite", (
        "(module\n"
        + WASI_PRELUDE
        + GC_TYPES
        + gc_loop(2 ** 31 - 1)
        + wasi_print(
            "unreachable\n",
            body=f"i32.const {2 ** 31 - 1} call $gc_loop drop",
        )
        + ")\n"
    ))

    # 4. GC + linear memory growth (Store.set_limits applies to linear
    #    memory even when GC is enabled — the GC heap itself is separate).
    build("gc_grow", (
        "(module\n"
        + WASI_PRELUDE
        + GC_TYPES
        + """\
  (memory (export "memory") 1)
  (func (export "_start")
    (local $i i32) (local $s (ref null $pt)) (local $acc i32)
    (loop $l
      (local.set $s (struct.new $pt (local.get $i) (i32.const 0)))
      (local.set $acc (struct.get $pt 0 (local.get $s)))
      (i32.const 1) (memory.grow)
      (i32.const -1) (i32.eq) if unreachable end
      (local.set $i (i32.add (local.get $i) (i32.const 1)))
      (local.get $i) (i32.const 1400) (i32.lt_u) (if (then (br $l)))
    )
    (drop (local.get $acc))
    i32.const 0 call $exit)
"""
        + ")\n"
    ))

    # 5. Self-contained GC core module with a direct `run` export — the
    #    payload of the hand-written wrapper component (no WASI imports).
    build("gc_core", (
        "(module\n"
        + GC_TYPES
        + gc_loop(LOOP_N).replace("$gc_loop (param $n i32)", "$run (export \"run\") (result i32)").replace("local.get $n", "i32.const " + str(LOOP_N))
        + ")\n"
    ))

    # 6. Hand-written component wrapping the GC core module with a direct
    #    `run` export (canon lift). No preview1 adapter involved.
    build("gc_wrapper", """\
(component
    (core module $m
        (type $pt (sub (struct (field i32) (field i32))))
        (type $at (sub (array (mut i32))))
        (func $run (export "run") (result i32)
            (local $i i32) (local $acc i32)
            (local $s (ref null $pt)) (local $a (ref null $at))
            (loop $l
                (local.set $s (struct.new $pt (local.get $acc) (local.get $i)))
                (local.set $a (array.new $at (i32.const 1) (i32.const 4)))
                (array.set $at (local.get $a) (i32.const 0) (local.get $i))
                (local.set $acc
                  (i32.add
                    (i32.mul (struct.get $pt 0 (local.get $s)) (i32.const 3))
                    (array.get $at (local.get $a) (i32.const 0))))
                (local.set $i (i32.add (local.get $i) (i32.const 1)))
                (local.get $i) (i32.const %d) (i32.lt_s) (if (then (br $l)))
            )
            (drop (local.get $acc))
            i32.const 0
        )
    )
    (core instance $i (instantiate $m))
    (func (export "run") (result u32) (canon lift (core func $i "run")))
)
""" % LOOP_N)

    # 6b. Infinite-GC twin of the wrapper for fuel/epoch component tests.
    build("gc_wrapper_inf", """\
(component
    (core module $m
        (type $pt (sub (struct (field i32) (field i32))))
        (type $at (sub (array (mut i32))))
        (func $run (export "run") (result i32)
            (local $i i32) (local $acc i32)
            (local $s (ref null $pt)) (local $a (ref null $at))
            (loop $l
                (local.set $s (struct.new $pt (local.get $acc) (local.get $i)))
                (local.set $a (array.new $at (i32.const 1) (i32.const 4)))
                (array.set $at (local.get $a) (i32.const 0) (local.get $i))
                (local.set $i (i32.add (local.get $i) (i32.const 1)))
                (br $l)
            )
            i32.const 0
        )
    )
    (core instance $i (instantiate $m))
    (func (export "run") (result u32) (canon lift (core func $i "run")))
)
""")

    # 7. Lift the WASI GC module into a component (wasm-tools command
    #    adapter, same path as the componentize PoC).
    if os.path.exists(ADAPTER):
        lifted = os.path.join(HERE, "lifted.wasm")
        subprocess.run([
            "wasm-tools", "component", "new",
            os.path.join(HERE, "gc_workload.wasm"),
            "--adapt", ADAPTER, "-o", lifted,
        ], check=True)
        print(f"  built lifted.wasm  ({os.path.getsize(lifted)} bytes, wasm-tools)")
    else:
        print("  SKIP lifted.wasm — adapter missing; run componentize PoC build first")

    print("done.")


if __name__ == "__main__":
    sys.exit(main())
