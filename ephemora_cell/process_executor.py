# Ephemora Cell — Subprocess-level execution isolation
# SPDX-License-Identifier: Apache-2.0
"""
Process-level isolation for WASM execution.

``run_isolated`` executes a WASI module in a fresh worker subprocess
(``python -m ephemora_cell.process_worker``) so that compile bombs,
FD-draining guests, and wasmtime panic/escape classes are contained in a
disposable process instead of the caller's process. JSON is exchanged over
the process's own stdin/stdout pipes; guest output is collected by the
worker via the sandbox API and never written to guest-visible locations.

The worker applies per-process limits before the sandbox runs:
  - RLIMIT_NOFILE=256 (fd-drain containment)
  - RLIMIT_AS = max(guest memory limit + 64 MiB, 8 GiB) — wasmtime
    reserves 4 GiB of virtual address space per 32-bit linear memory, so a
    tighter AS cap breaks instantiation on Linux; the AS limit is a
    runaway-allocation backstop, not a physical cap
  - RLIMIT_RSS = guest memory limit + 64 MiB (physical-memory intent, best
    effort; historically unenforced on Linux)
The parent enforces a wall-clock process timeout of config.timeout_seconds
+ 5 s and kills the worker afterwards.
"""

from __future__ import annotations

import json
import subprocess
import sys
import time
from pathlib import Path

from .process_worker import DEFAULT_MAX_WASM_BYTES
from .wasi_runtime import ExecutionStatus, WASIConfig

__all__ = ["DEFAULT_MAX_WASM_BYTES", "measure_overhead", "run_isolated"]

# Extra seconds the parent grants a worker beyond the guest timeout.
_PROCESS_TIMEOUT_MARGIN = 5
# Absolute floor for the parent-side process timeout.
_MIN_PROCESS_TIMEOUT = 5

_STATUS_BY_VALUE = {status.value: status for status in ExecutionStatus}


def _payload_bytes(
    config: WASIConfig, args: list[str], stdin_data: str | None
) -> bytes:
    """Serialize the run payload (config, guest argv, stdin) for the pipe.

    Security: everything sensitive — the full WASIConfig including
    ``allow_env`` values, guest argv, and stdin data — travels over the
    worker's stdin pipe, never on the command line, so local users cannot
    read it via ``ps``/``/proc`` while the worker runs.
    """
    return json.dumps(
        {
            "config": {
                "max_memory_mb": config.max_memory_mb,
                "max_fuel": config.max_fuel,
                "timeout_seconds": config.timeout_seconds,
                "allow_dirs": list(config.allow_dirs),
                "allow_env": [list(pair) for pair in config.allow_env],
                "sandbox_base_dir": config.sandbox_base_dir,
                "max_threads": config.max_threads,
                "memory64": config.memory64,
                "max_gc_heap_mb": config.max_gc_heap_mb,
                "disk_quota_bytes": config.disk_quota_bytes,
                "io_cpu_seconds": config.io_cpu_seconds,
                "io_budget_bytes": config.io_budget_bytes,
            },
            "args": args,
            "stdin": stdin_data,
        }
    ).encode("utf-8")


def _worker_cmd(wasm_path: str, max_wasm_bytes: int, abi: str = "auto") -> list[str]:
    """Worker argv carrying only non-sensitive parameters.

    The wasm path, size cap, and ABI selector stay on argv; config,
    guest argv, and stdin data are delivered via the stdin pipe
    (``--payload-stdin``). The worker is started via ``-c`` import
    instead of ``-m``: ``-m`` runs runpy's module resolution before any
    payload handling and has proven unreliable for editable installs
    on some hosts, while direct imports resolve identically everywhere.
    """
    return [
        sys.executable,
        "-c",
        "import sys; from ephemora_cell.process_worker import main; sys.exit(main())",
        "--wasm",
        wasm_path,
        "--max-wasm-bytes",
        str(max_wasm_bytes),
        "--abi",
        abi,
        "--payload-stdin",
    ]


def _spawn_worker(
    cmd: list[str], payload: bytes, process_timeout: float
) -> tuple[int, bytes, bytes]:
    """Run the worker, return (returncode, stdout, stderr).

    The payload is written to the worker's stdin pipe. Raises
    subprocess.TimeoutExpired after killing the worker when
    process_timeout is exceeded.
    """
    proc = subprocess.Popen(
        cmd, stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=subprocess.PIPE
    )
    try:
        raw_out, raw_err = proc.communicate(input=payload, timeout=process_timeout)
    except subprocess.TimeoutExpired:
        proc.kill()
        raw_out, raw_err = proc.communicate()
        raise
    return proc.returncode, raw_out, raw_err


def _failure_result(status: ExecutionStatus, message: str, elapsed_ms: float) -> dict:
    return {
        "status": status,
        "exit_code": 1,
        "stdout": "",
        "stderr": message,
        "elapsed_ms": elapsed_ms,
        "fuel_consumed": None,
        "sandbox_dir": None,
        "baseline_ms": 0.0,
    }


def run_isolated(
    wasm_path: str,
    config: WASIConfig,
    args: list[str] | None = None,
    stdin_data: str | None = None,
    max_wasm_bytes: int = DEFAULT_MAX_WASM_BYTES,
    abi: str = "auto",
) -> dict:
    """Execute a WASI module in an isolated worker subprocess.

    Returns a dict with the same fields as ``ExecutionResult`` plus
    ``baseline_ms`` (worker bootstrap overhead measured inside the worker):
    status (ExecutionStatus), exit_code, stdout, stderr, elapsed_ms,
    fuel_consumed, sandbox_dir.

    Failure mapping: worker death without a JSON report -> ERROR with
    "worker crashed"; parent-side process timeout -> TIMEOUT; unparseable
    output -> ERROR.
    """
    start = time.monotonic()

    resolved = Path(wasm_path).resolve()
    if not resolved.is_file():
        return _failure_result(
            ExecutionStatus.ERROR,
            f"WASM module not found: {wasm_path}",
            (time.monotonic() - start) * 1000,
        )
    if resolved.stat().st_size > max_wasm_bytes:
        return _failure_result(
            ExecutionStatus.ERROR,
            (
                f"WASM module exceeds size limit of {max_wasm_bytes} bytes: "
                f"{resolved.stat().st_size}"
            ),
            (time.monotonic() - start) * 1000,
        )

    process_timeout = max(
        config.timeout_seconds + _PROCESS_TIMEOUT_MARGIN, _MIN_PROCESS_TIMEOUT
    )
    cmd = _worker_cmd(str(resolved), max_wasm_bytes, abi)
    payload = _payload_bytes(config, args or [], stdin_data)
    try:
        returncode, raw_out, raw_err = _spawn_worker(cmd, payload, process_timeout)
    except subprocess.TimeoutExpired:
        return _failure_result(
            ExecutionStatus.TIMEOUT,
            (
                f"Worker process timed out after {process_timeout:.0f}s "
                f"(config timeout {config.timeout_seconds}s + margin)"
            ),
            (time.monotonic() - start) * 1000,
        )

    elapsed_ms = (time.monotonic() - start) * 1000
    stderr_text = raw_err.decode("utf-8", errors="replace").strip()

    if returncode != 0:
        return _failure_result(
            ExecutionStatus.ERROR,
            "worker crashed" + (f": {stderr_text}" if stderr_text else ""),
            elapsed_ms,
        )

    try:
        payload = json.loads(raw_out.decode("utf-8", errors="replace"))
    except (json.JSONDecodeError, ValueError):
        return _failure_result(
            ExecutionStatus.ERROR,
            "worker produced invalid output"
            + (f": {stderr_text}" if stderr_text else ""),
            elapsed_ms,
        )

    if not isinstance(payload, dict):
        return _failure_result(
            ExecutionStatus.ERROR, "worker produced invalid JSON report", elapsed_ms
        )

    status = _STATUS_BY_VALUE.get(str(payload.get("status", "")))
    if status is None:
        return _failure_result(
            ExecutionStatus.ERROR,
            f"worker reported unknown status: {payload.get('status')!r}",
            elapsed_ms,
        )

    report = {
        "status": status,
        "exit_code": int(payload.get("exit_code", 1)),
        "stdout": str(payload.get("stdout", "")),
        "stderr": str(payload.get("stderr", "")),
        "elapsed_ms": float(payload.get("elapsed_ms", 0.0)),
        "fuel_consumed": payload.get("fuel_consumed"),
        "sandbox_dir": payload.get("sandbox_dir"),
        "effective_preopens": tuple(payload.get("effective_preopens", ())),
        "io_cpu_used_seconds": payload.get("io_cpu_used_seconds"),
        "io_bytes_written": payload.get("io_bytes_written"),
        "io_budget_exceeded": bool(payload.get("io_budget_exceeded", False)),
        "baseline_ms": float(payload.get("baseline_ms", 0.0)),
    }
    if "security_baseline" in payload:
        report["security_baseline"] = payload["security_baseline"]
    return report


def measure_overhead(num_runs: int = 16, wasm_path: str | None = None) -> dict:
    """Measure worker process startup overhead (wall-clock per run).

    Runs a trivial module ``num_runs`` times and returns min/median/mean
    of total wall-clock time per call. Requires a compiled trivial .wasm;
    if none is given, one is compiled on the fly via wasmtime.wat2wasm.
    """
    import tempfile

    import wasmtime

    if wasm_path is None:
        wat = (
            b'(module (import "wasi_snapshot_preview1" "proc_exit" '
            b'(func $exit (param i32))) (memory (export "memory") 1) '
            b'(func (export "_start") i32.const 0 call $exit))'
        )
        tmp = Path(tempfile.mkdtemp(prefix="ephemora_overhead_")) / "trivial.wasm"
        tmp.write_bytes(wasmtime.wat2wasm(wat))
        wasm_path = str(tmp)

    config = WASIConfig(max_fuel=1_000_000)
    samples = []
    for _ in range(num_runs):
        t0 = time.monotonic()
        run_isolated(wasm_path, config)
        samples.append((time.monotonic() - t0) * 1000)
    samples.sort()
    return {
        "num_runs": num_runs,
        "min_ms": samples[0],
        "median_ms": samples[num_runs // 2],
        "mean_ms": sum(samples) / len(samples),
    }
