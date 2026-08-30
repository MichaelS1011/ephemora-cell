"""Compile benchmark workload WASM modules."""
import wasmtime
from pathlib import Path

WORKLOADS_DIR = Path(__file__).parent / "workloads"
WORKLOADS_DIR.mkdir(exist_ok=True)

# CPU-bound
CODE_REVIEW_WAT = r"""(module
  (import "wasi_snapshot_preview1" "proc_exit" (func $exit (param i32)))
  (import "wasi_snapshot_preview1" "fd_write" (func $write (param i32 i32 i32 i32) (result i32)))
  (memory (export "memory") 1)
  (data (i32.const 0) "OK")
  (func (export "_start")
    (local $i i32) (local $sum i32)
    (loop $loop
      (local.set $i (i32.add (local.get $i) (i32.const 1)))
      (local.set $sum (i32.add (local.get $sum) (local.get $i)))
      (i32.lt_s (local.get $i) (i32.const 1000))
      br $loop
    )
    i32.const 1 i32.const 0 i32.const 1 i32.const 2
    call $write drop
    i32.const 0 call $exit
  )
)"""

# Mixed CPU+I/O
DATA_TRANSFORM_WAT = r"""(module
  (import "wasi_snapshot_preview1" "proc_exit" (func $exit (param i32)))
  (import "wasi_snapshot_preview1" "fd_write" (func $write (param i32 i32 i32 i32) (result i32)))
  (memory (export "memory") 1)
  (data (i32.const 0) "1,alice,100\r\n2,bob,200\r\n3,charlie,300\r\n")
  (func (export "_start")
    i32.const 1 i32.const 0 i32.const 1 i32.const 36
    call $write drop
    i32.const 0 call $exit
  )
)"""

# Variable workload
PLUGIN_CHAIN_WAT = r"""(module
  (import "wasi_snapshot_preview1" "proc_exit" (func $exit (param i32)))
  (import "wasi_snapshot_preview1" "fd_write" (func $write (param i32 i32 i32 i32) (result i32)))
  (memory (export "memory") 1)
  (data (i32.const 0) "plugin_ok")
  (func (export "_start")
    (local $i i32)
    (loop $loop
      (local.set $i (i32.add (local.get $i) (i32.const 1)))
      (i32.lt_s (local.get $i) (i32.const 500))
      br $loop
    )
    i32.const 1 i32.const 0 i32.const 1 i32.const 9
    call $write drop
    i32.const 0 call $exit
  )
)"""

# Exploit — fd_psync blocked
EXPLOIT_WAT = r"""(module
  (import "wasi_snapshot_preview1" "proc_exit" (func $exit (param i32)))
  (import "wasi_snapshot_preview1" "fd_psync" (func $psync (param i32 i32) (result i32)))
  (memory (export "memory") 1)
  (data (i32.const 0) "exploit")
  (func (export "_start")
    i32.const 0 i32.const 0 call $psync drop
    i32.const 0 call $exit
  )
)"""

workloads = {
    "code_review.wasm": CODE_REVIEW_WAT,
    "data_transform.wasm": DATA_TRANSFORM_WAT,
    "plugin_chain.wasm": PLUGIN_CHAIN_WAT,
    "exploit.wasm": EXPLOIT_WAT,
}

if __name__ == "__main__":
    for name, wat in workloads.items():
        wasm = wasmtime.wat2wasm(wat)
        (WORKLOADS_DIR / name).write_bytes(wasm)
        print(f"  {name}: {len(wasm):,} bytes")
    print(f"Total: {len(workloads)} modules in {WORKLOADS_DIR}/")