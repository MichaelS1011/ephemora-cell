"""Defect-B discriminator #1: the failing guest shape through wasmtime ALONE.

No Cell code is imported here. If this raises the same
``list indices must be integers or slices, not function``, the fault is in
wasmtime 47.0.1 on this interpreter build, not in ephemora-cell.

Every step is reported separately so the log names the FIRST failing call.
"""

import platform
import sys
import tempfile
import traceback
from pathlib import Path

import wasmtime

WAT = """
(module
  (import "wasi_snapshot_preview1" "proc_exit" (func $exit (param i32)))
  (memory (export "memory") 1)
  (func (export "_start")
    i32.const 0
    call $exit
  )
)
"""


def step(label, fn):
    try:
        value = fn()
        print(f"  OK   {label}" + (f" -> {value}" if value is not None else ""))
        return True
    except BaseException:  # noqa: BLE001 - the point of this script is the error
        print(f"  FAIL {label}")
        traceback.print_exc()
        return False


def main() -> int:
    from importlib.metadata import version as dist_version

    print("== interpreter ==")
    print("  python -VV      :", platform.python_version())
    print("  sys.version     :", sys.version.replace("\n", " "))
    print("  sys.executable  :", sys.executable)
    print("  prefix          :", sys.prefix)
    print("  base_exec_prefix:", getattr(sys, "base_exec_prefix", ""))
    print("  architecture    :", platform.architecture())
    print("  machine         :", platform.machine())
    print("  platform        :", platform.platform())
    print("  mac_ver         :", platform.mac_ver())
    print("== wasmtime ==")
    print("  module file     :", wasmtime.__file__)
    try:
        print("  dist version    :", dist_version("wasmtime"))
    except BaseException as exc:  # noqa: BLE001
        print("  dist version    : unavailable:", exc)
    site = Path(wasmtime.__file__).parent
    print("  native libs     :", [p.name for p in site.rglob("*") if p.suffix in (".so", ".dylib")][:6])

    ok = True
    wasm = {}

    def compile_wat():
        wasm["bytes"] = wasmtime.wat2wasm(WAT)
        return f"{len(wasm['bytes'])} bytes"

    ok &= step("wasmtime.wat2wasm", compile_wat)

    holder = {}

    def make_engine():
        cfg = wasmtime.Config()
        cfg.consume_fuel = True
        holder["engine"] = wasmtime.Engine(cfg)
        return None

    ok &= step("Engine(consume_fuel=True)", make_engine)

    def make_module():
        holder["module"] = wasmtime.Module(holder["engine"], wasm["bytes"])
        return None

    ok &= step("Module(engine, bytes)", make_module)

    def run_zero_fuel():
        store = wasmtime.Store(holder["engine"])
        store.set_fuel(0)
        linker = wasmtime.Linker(holder["engine"])
        linker.define_wasi()
        store.set_wasi(wasmtime.WasiConfig())
        instance = linker.instantiate(store, holder["module"])
        start = instance.exports(store).get("_start")
        if start is None:
            raise RuntimeError("no _start export")
        start(store)
        return "returned without trap"

    # On a fuel-limited store this is EXPECTED to raise a wasmtime Trap
    # ("all fuel consumed"); a TypeError with the defect-B message is not.
    print("== guest run with zero fuel (Trap expected, TypeError is the bug) ==")
    try:
        print("  result:", run_zero_fuel())
    except BaseException as exc:  # noqa: BLE001
        kind = type(exc).__name__
        print(f"  raised: {kind}: {exc}")
        if "list indices" in str(exc):
            print("  >>> DEFECT B REPRODUCED IN RAW WASMTIME <<<")
            traceback.print_exc()
            ok = False

    print("== verdict ==")
    print("  raw wasmtime path clean:", bool(ok))
    return 0 if ok else 1


if __name__ == "__main__":
    sys.exit(main())
