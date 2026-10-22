# Ephemora Cell — Subprocess-level execution isolation
# SPDX-License-Identifier: BUSL-1.1
# Copyright 2026 Michael Soppa
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
import os
import shutil
import signal
import subprocess
import sys
import tempfile
import threading
import time
from collections.abc import Iterator
from contextlib import contextmanager
from dataclasses import replace
from pathlib import Path

from .runtime_qualification import (
    runtime_qualification,
    unqualified_runtime_allowed,
)
from .wasi_runtime import (
    DEFAULT_MAX_WASM_BYTES,
    ExecutionStatus,
    WASIConfig,
    module_size_cap_error,
)

__all__ = ["DEFAULT_MAX_WASM_BYTES", "measure_overhead", "run_isolated"]

# Extra seconds the parent grants a worker beyond the guest timeout.
_PROCESS_TIMEOUT_MARGIN = 5
# Absolute floor for the parent-side process timeout.
_MIN_PROCESS_TIMEOUT = 5

_STATUS_BY_VALUE = {status.value: status for status in ExecutionStatus}

# Seconds to let a SIGKILLed worker group drain before force-reaping its pipes.
_REAP_GRACE_SECONDS = 5


def _default_max_concurrent_workers() -> int:
    """Bound on concurrently-spawned worker subprocesses.

    The 1.2.0 default posture routes every ``untrusted``/``unknown`` run through
    a worker; an unbounded fan-out (parallel test suite, MCP request fan-out)
    spawns hundreds of OS processes and any that outlive the caller become
    uncontrolled orphans — the observed 759-worker incident. The semaphore below
    turns that fan-out into backpressure: excess calls queue for a slot instead
    of spawning. Constrained CI/pilot hosts can lower it via
    ``EPHEMORA_MAX_CONCURRENT_WORKERS``.
    """
    raw = os.environ.get("EPHEMORA_MAX_CONCURRENT_WORKERS", "0")
    try:
        requested = int(raw)
    except ValueError:
        requested = 0
    if requested > 0:
        return requested
    return max(1, min(8, os.cpu_count() or 4))


MAX_CONCURRENT_WORKERS = _default_max_concurrent_workers()
_worker_slots = threading.BoundedSemaphore(MAX_CONCURRENT_WORKERS)

# The worker is Python, not a generic shell: it needs its interpreter search
# path, locale and temp directory, but not the caller's ambient credentials.
# A native compromise (A7) already owns the worker process; this whitelist
# keeps unrelated secrets out of its initial environment, not out of the host.
_WORKER_ENV_ALLOW = frozenset(
    {
        "PATH",
        "PYTHONPATH",
        "PYTHONHOME",
        "PYTHONUTF8",
        "PYTHONIOENCODING",
        "PYTHONHASHSEED",
        "PYTHONDONTWRITEBYTECODE",
        "VIRTUAL_ENV",
        "CONDA_PREFIX",
        "TMPDIR",
        "TEMP",
        "TMP",
        "LANG",
        "LC_ALL",
        "LC_CTYPE",
        "TZ",
        "SYSTEMROOT",
        "WINDIR",
        "COMSPEC",
        "PATHEXT",
        "EPHEMORA_ALLOW_UNQUALIFIED_RUNTIME",
        "EPHEMORA_WORKER_PAYLOAD_DEADLINE_SECONDS",
    }
)


def _worker_env(worker_root: Path) -> dict[str, str]:
    env = {key: value for key, value in os.environ.items() if key in _WORKER_ENV_ALLOW}
    env.update(
        {"TMPDIR": str(worker_root), "TEMP": str(worker_root), "TMP": str(worker_root)}
    )
    return env


@contextmanager
def _worker_slot() -> Iterator[None]:
    """Admission control: at most MAX_CONCURRENT_WORKERS workers spawn at once."""
    _worker_slots.acquire()
    try:
        yield
    finally:
        _worker_slots.release()


def _payload_bytes(
    config: WASIConfig,
    args: list[str],
    stdin_data: str | None,
    expected_sha256: str | None = None,
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
                "max_wasm_bytes": config.max_wasm_bytes,
                "allow_fsync": config.allow_fsync,
            },
            "args": args,
            "stdin": stdin_data,
            "expected_sha256": expected_sha256,
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


def _kill_worker_group(proc: subprocess.Popen) -> None:
    """SIGKILL the worker and every process it spawned.

    The worker is started with ``start_new_session=True``, so its pid is also
    the process-group id; killing the group reaps any grandchild a runaway
    guest forked, which a bare ``proc.kill()`` would leave as an orphan. Best
    effort — the group may already be gone (a clean exit) or the platform may
    not support ``killpg``; fall back to killing the direct child.
    """
    try:
        os.killpg(os.getpgid(proc.pid), signal.SIGKILL)
    except (ProcessLookupError, PermissionError, OSError):
        try:
            proc.kill()
        except OSError:
            pass


def _reap(proc: subprocess.Popen) -> tuple[bytes, bytes]:
    """Collect a killed worker's output and guarantee it is reaped (no zombie)."""
    try:
        return proc.communicate(timeout=_REAP_GRACE_SECONDS)
    except subprocess.TimeoutExpired:
        # A stream still open after SIGKILLing the whole group means a
        # descendant holds the fd: close the pipes and force-reap rather than
        # hang the caller forever.
        _kill_worker_group(proc)
        for stream in (proc.stdout, proc.stderr):
            try:
                if stream is not None:
                    stream.close()
            except OSError:
                pass
        proc.wait()
        return b"", b""
    except (OSError, ValueError):
        _kill_worker_group(proc)
        proc.wait()
        return b"", b""


def _spawn_worker(
    cmd: list[str],
    payload: bytes,
    process_timeout: float,
    env: dict[str, str] | None = None,
) -> tuple[int, bytes, bytes]:
    """Run the worker, return (returncode, stdout, stderr).

    The payload is written to the worker's stdin pipe and the pipe is closed on
    EOF, so a worker blocked on ``sys.stdin.read()`` always sees the end of the
    payload. Raises ``subprocess.TimeoutExpired`` after killing the whole worker
    process group when ``process_timeout`` is exceeded. Any other interruption
    (``KeyboardInterrupt``, a broken pipe on a huge payload, ``OSError``) also
    kills and reaps the group before propagating, so no worker outlives this
    call as an orphan.
    """
    proc = subprocess.Popen(
        cmd,
        stdin=subprocess.PIPE,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        start_new_session=True,
        env=env,
    )
    try:
        raw_out, raw_err = proc.communicate(input=payload, timeout=process_timeout)
    except subprocess.TimeoutExpired:
        _kill_worker_group(proc)
        _reap(proc)
        raise
    except BaseException:
        _kill_worker_group(proc)
        _reap(proc)
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
    max_wasm_bytes: int | None = None,
    abi: str = "auto",
    expected_sha256: str | None = None,
) -> dict:
    """Execute a WASI module in an isolated worker subprocess.

    Returns a dict with the same fields as ``ExecutionResult`` plus
    ``baseline_ms`` (worker bootstrap overhead measured inside the worker):
    status (ExecutionStatus), exit_code, stdout, stderr, elapsed_ms,
    fuel_consumed, sandbox_dir.

    ``max_wasm_bytes`` overrides the module size cap; unset takes
    ``config.max_wasm_bytes`` (0 = no cap). The resolved cap is enforced
    here AND in the worker, and travels to the worker on argv — the payload
    config carries it too, so parent and worker cannot end up with two
    different caps for one run.

    Failure mapping: worker death without a JSON report -> ERROR with
    "worker crashed"; parent-side process timeout -> TIMEOUT; unparseable
    output -> ERROR.
    """
    start = time.monotonic()

    # The spawn point carries the runtime precondition itself, not only the
    # facade: ``ephemora_cell.run_isolated`` is public API and reaches this
    # function without passing :meth:`WASISandbox.run`, so a caller could
    # otherwise get a worker running a guest on an engine the release was never
    # audited against. Nothing is spawned, resolved or sized before this.
    qualified, why = runtime_qualification()
    if not qualified and not unqualified_runtime_allowed():
        return _failure_result(
            ExecutionStatus.ERROR,
            f"refused: unqualified runtime — {why}",
            (time.monotonic() - start) * 1000,
        )

    cap = config.max_wasm_bytes if max_wasm_bytes is None else max_wasm_bytes
    if cap < 0:
        return _failure_result(
            ExecutionStatus.ERROR,
            "max_wasm_bytes must be a non-negative int (0 disables the cap)",
            (time.monotonic() - start) * 1000,
        )

    resolved = Path(wasm_path).resolve()
    if not resolved.is_file():
        return _failure_result(
            ExecutionStatus.ERROR,
            f"WASM module not found: {wasm_path}",
            (time.monotonic() - start) * 1000,
        )
    cap_error = module_size_cap_error(resolved, cap)
    if cap_error is not None:
        return _failure_result(
            ExecutionStatus.ERROR, cap_error, (time.monotonic() - start) * 1000
        )

    # The parent owns the worker's scratch root. A hard parent kill cannot be
    # cleaned by the worker's own finally block; pointing TMPDIR and
    # sandbox_base_dir at one root lets the parent remove every capture
    # directory even when the child never reaches its cleanup.
    if config.sandbox_base_dir is None:
        worker_root = Path(tempfile.mkdtemp(prefix="ephemora_worker_"))
    else:
        worker_root = Path(
            tempfile.mkdtemp(prefix="ephemora_worker_", dir=config.sandbox_base_dir)
        )
    worker_config = replace(config, sandbox_base_dir=str(worker_root))
    worker_env = _worker_env(worker_root)

    process_timeout = max(
        worker_config.timeout_seconds + _PROCESS_TIMEOUT_MARGIN, _MIN_PROCESS_TIMEOUT
    )
    cmd = _worker_cmd(str(resolved), cap, abi)
    payload = _payload_bytes(worker_config, args or [], stdin_data, expected_sha256)
    try:
        try:
            with _worker_slot():
                returncode, raw_out, raw_err = _spawn_worker(
                    cmd, payload, process_timeout, worker_env
                )
        except subprocess.TimeoutExpired:
            return _failure_result(
                ExecutionStatus.TIMEOUT,
                (
                    f"Worker process timed out after {process_timeout:.0f}s "
                    f"(config timeout {worker_config.timeout_seconds}s + margin)"
                ),
                (time.monotonic() - start) * 1000,
            )
        except OSError as exc:
            # Spawn/pipe failure (fork pressure, broken pipe on a huge payload):
            # fail closed with no in-process fallback, exactly like a crash.
            return _failure_result(
                ExecutionStatus.ERROR,
                f"worker could not be started: {exc!r}",
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
        # ADR-014: the ABI the worker ACTUALLY ran under is a top-level
        # runtime fact (not only a baseline field) so _result_from_report can carry
        # it back to the parent as ExecutionResult.abi. It stays in
        # security_baseline too — the worker stamps both from one source decision.
        if "abi" in payload:
            report["abi"] = payload["abi"]
        # The same source-decision argument applies to the exit channel: only the
        # worker watched whether a guest exit status actually reached it. The parent
        # must not infer that from the routed ABI, or a run whose module never loaded
        # would attest an exit status no guest produced.
        if "guest_exit_observed" in payload:
            report["guest_exit_observed"] = bool(payload["guest_exit_observed"])
        if "security_baseline" in payload:
            report["security_baseline"] = payload["security_baseline"]
        return report
    finally:
        shutil.rmtree(worker_root, ignore_errors=True)


def measure_overhead(num_runs: int = 16, wasm_path: str | None = None) -> dict:
    """Measure worker process startup overhead (wall-clock per run).

    Runs a trivial module ``num_runs`` times and returns min/median/mean
    of total wall-clock time per call. Requires a compiled trivial .wasm;
    if none is given, one is compiled on the fly via wasmtime.wat2wasm.
    """
    import tempfile

    import wasmtime

    created_dir: str | None = None
    if wasm_path is None:
        wat = (
            b'(module (import "wasi_snapshot_preview1" "proc_exit" '
            b'(func $exit (param i32))) (memory (export "memory") 1) '
            b'(func (export "_start") i32.const 0 call $exit))'
        )
        created_dir = tempfile.mkdtemp(prefix="ephemora_overhead_")
        tmp = Path(created_dir) / "trivial.wasm"
        tmp.write_bytes(wasmtime.wat2wasm(wat))
        wasm_path = str(tmp)

    config = WASIConfig(max_fuel=1_000_000)
    samples = []
    try:
        for _ in range(num_runs):
            t0 = time.monotonic()
            run_isolated(wasm_path, config)
            samples.append((time.monotonic() - t0) * 1000)
    finally:
        # measure_overhead owns the scratch dir only when it created it; drop
        # it so the overhead probe leaves no ephemora_overhead_ residue.
        if created_dir is not None:
            import shutil

            shutil.rmtree(created_dir, ignore_errors=True)
    samples.sort()
    return {
        "num_runs": num_runs,
        "min_ms": samples[0],
        "median_ms": samples[num_runs // 2],
        "mean_ms": sum(samples) / len(samples),
    }
