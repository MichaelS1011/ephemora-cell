"""Defect-B discriminator #2: one minimal REAL guest run through Cell's sandbox.

The run swallows exceptions into ``ExecutionResult(status=ERROR)``, so the
traceback is produced by the debug-branch guard (CELL_DEBUG_TRACEBACK) at the
catch site in ``wasi_runtime`` / ``wasi_02``. Prints both paths: preview1
in-process and preview1 isolated subprocess.

No secrets: only versions, paths, statuses and tracebacks.
"""

import os
import platform
import tempfile
import traceback
from pathlib import Path

os.environ["CELL_DEBUG_TRACEBACK"] = "1"

import wasmtime  # noqa: E402
from ephemora_cell import ExecutionStatus, WASIConfig, WASISandbox  # noqa: E402

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


def guest(name: str) -> str:
    path = Path(tempfile.mkdtemp(prefix="cell_debug_b_")) / name
    path.write_bytes(wasmtime.wat2wasm(WAT))
    return str(path)


def report(label: str, wasm_path: str, config: WASIConfig, **run_kwargs) -> None:
    print(f"-- {label}")
    try:
        result = WASISandbox(config=config).run(wasm_path, **run_kwargs)
    except BaseException:  # noqa: BLE001
        print("   raised out of run():")
        traceback.print_exc()
        return
    print("   status      :", result.status)
    print("   exit_code   :", result.exit_code)
    print("   stderr      :", repr(result.stderr)[:300])
    print("   host_tb     :", repr(result.host_traceback)[:300])
    print("   expected    :", ExecutionStatus.FUEL_EXHAUSTED)


def main() -> int:
    print("== interpreter ==")
    print("  python        :", platform.python_version(), sys_machine())
    print("  executable    :", __import__("sys").executable)
    import ephemora_cell

    print("  ephemora_cell :", ephemora_cell.__version__, Path(ephemora_cell.__file__).parent)
    print("  wasmtime      :", wasmtime.__file__)

    zero = guest("zero_fuel.wasm")
    ok = guest("plain_start.wasm")
    report("preview1 in-process, max_fuel=0", zero, WASIConfig(max_fuel=0))
    report("preview1 in-process, default config", ok, WASIConfig())
    report("preview1 isolated subprocess, default", ok, WASIConfig(), use_subprocess=True)
    return 0


def sys_machine() -> str:
    return f"{platform.machine()} / {platform.mac_ver()[0] or platform.system()}"


if __name__ == "__main__":
    main()
