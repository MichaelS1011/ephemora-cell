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
import stat
import subprocess
import sys
import tempfile
import threading
import time
from collections.abc import Iterator
from contextlib import contextmanager
from dataclasses import replace
from pathlib import Path

from ._sandbox_common import OUTPUT_FILE_HARD_LIMIT, limit_output_text
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


class WorkerSpawnError(OSError):
    """A worker pipe failed after Popen may already have started the child.

    ``started`` is the fact the accounting needs: a failed Popen consumed no
    guest fuel, while a broken pipe after Popen may have. The parent must not
    turn the second case into a proven zero.
    """

    def __init__(self, message: str, *, started: bool) -> None:
        super().__init__(message)
        self.started = started


def _capture_cap_hit(root: Path) -> bool:
    """Whether a worker capture file reached the host's write-side cap.

    A worker killed mid-flood cannot report its flag. The capture files are
    host-owned and still on disk at that moment, so the parent can attest the
    cap without trusting a report that never arrived.
    """
    for path in root.rglob("*"):
        if path.name not in ("stdout.txt", "stderr.txt"):
            continue
        try:
            if path.stat().st_size >= OUTPUT_FILE_HARD_LIMIT:
                return True
        except OSError:
            continue
    return False


def _measure_attempt_bytes(root: Path) -> int | None:
    """Host-side byte count of an attempt's scratch tree, before cleanup.

    The worker report carries ``io_bytes_written`` for its own run, but a
    worker killed during a flood cannot send one. The scratch root is
    host-owned and still present here, so the parent measures it directly
    instead of turning an unknown output into zero. Only regular files count;
    FIFOs, sockets and symlinks are not followed (a guest-created symlink must
    not make a host file part of the bill).
    """
    total = 0
    try:
        for path in root.rglob("*"):
            try:
                info = path.lstat()
            except OSError:
                continue
            if stat.S_ISREG(info.st_mode):
                total += info.st_size
    except OSError:
        return None
    return total


def _parse_worker_report(raw: bytes) -> dict | None:
    """The worker's JSON report, if the pipe holds one; otherwise None.

    A worker can write its complete report and still exit non-zero when
    teardown fails. Parsing the report regardless of the exit code is what
    lets the parent measure the first attempt instead of calling it zero.
    """
    try:
        candidate = json.loads(raw.decode("utf-8", errors="replace"))
    except (json.JSONDecodeError, ValueError):
        return None
    return candidate if isinstance(candidate, dict) else None


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
        # Diagnostic only: lets a native panic print its Rust backtrace.
        "RUST_BACKTRACE",
        "RUST_LIB_BACKTRACE",
        "EPHEMORA_DIAG_MAPS",
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


#: `-c` puts the caller's cwd at sys.path[0]. A source tree or an attacker
#: controlled directory named ``ephemora_cell`` would then replace the worker's
#: own code — including the runtime-identity gate. Drop the cwd entries before
#: importing; installed/editable site-packages and an explicit PYTHONPATH stay.
_WORKER_BOOTSTRAP = (
    "import os, sys; "
    "sys.path[:] = [p for p in sys.path if p not in ('', '.', os.getcwd())]; "
    "from ephemora_cell.process_worker import main; sys.exit(main())"
)


def _worker_cmd(wasm_path: str, max_wasm_bytes: int, abi: str = "auto") -> list[str]:
    """Worker argv carrying only non-sensitive parameters.

    The wasm path, size cap, and ABI selector stay on argv; config,
    guest argv, and stdin data are delivered via the stdin pipe
    (``--payload-stdin``). The worker is started via ``-c`` import
    instead of ``-m``: ``-m`` runs runpy's module resolution before any
    payload handling and has proven unreliable for editable installs
    on some hosts, while direct imports resolve identically everywhere.
    The bootstrap removes cwd from ``sys.path`` first (see above).
    """
    return [
        sys.executable,
        "-c",
        _WORKER_BOOTSTRAP,
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
    try:
        proc = subprocess.Popen(
            cmd,
            stdin=subprocess.PIPE,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            start_new_session=True,
            env=env,
        )
    except OSError as exc:
        raise WorkerSpawnError(str(exc), started=False) from exc
    try:
        raw_out, raw_err = proc.communicate(input=payload, timeout=process_timeout)
    except subprocess.TimeoutExpired:
        _kill_worker_group(proc)
        _reap(proc)
        raise
    except BaseException as exc:
        _kill_worker_group(proc)
        _reap(proc)
        if isinstance(exc, OSError):
            raise WorkerSpawnError(str(exc), started=True) from exc
        raise
    return proc.returncode, raw_out, raw_err


def _failure_result(
    status: ExecutionStatus,
    message: str,
    elapsed_ms: float,
    *,
    worker_crashed: bool = False,
    worker_started: bool = False,
    execution_started: bool | None = False,
    worker_attempts: int = 1,
    first_attempt_crashed: bool = False,
    first_attempt_error: str = "",
    first_attempt_fuel_consumed: int | None = None,
    first_attempt_stdout_bytes: int | None = None,
    first_attempt_stderr_bytes: int | None = None,
    first_attempt_output_bytes_observed: int | None = None,
    first_attempt_output_unknown: bool = False,
    first_attempt_execution_started: bool | None = None,
    first_attempt_report_bytes: int = 0,
    first_attempt_worker_stderr_bytes: int = 0,
    first_attempt_wall_ms: int = 0,
    retry_suppressed_reason: str = "",
    output_files_exceeded: bool = False,
    output_bytes_observed: int | None = None,
    output_bytes_unknown: bool = True,
) -> dict:
    return {
        "status": status,
        "exit_code": 1,
        "stdout": "",
        "stderr": message,
        "elapsed_ms": elapsed_ms,
        "fuel_consumed": None,
        "sandbox_dir": None,
        "output_files_exceeded": output_files_exceeded,
        "output_bytes_observed": output_bytes_observed,
        "output_bytes_unknown": output_bytes_unknown,
        "baseline_ms": 0.0,
        "worker_crashed": worker_crashed,
        "worker_started": worker_started,
        "execution_started": execution_started,
        "worker_attempts": worker_attempts,
        "first_attempt_crashed": first_attempt_crashed,
        "first_attempt_error": first_attempt_error,
        "first_attempt_fuel_consumed": first_attempt_fuel_consumed,
        "first_attempt_stdout_bytes": first_attempt_stdout_bytes,
        "first_attempt_stderr_bytes": first_attempt_stderr_bytes,
        "first_attempt_output_bytes_observed": first_attempt_output_bytes_observed,
        "first_attempt_output_unknown": first_attempt_output_unknown,
        "first_attempt_execution_started": first_attempt_execution_started,
        "first_attempt_report_bytes": first_attempt_report_bytes,
        "first_attempt_worker_stderr_bytes": first_attempt_worker_stderr_bytes,
        "first_attempt_wall_ms": first_attempt_wall_ms,
        "retry_suppressed_reason": retry_suppressed_reason,
    }


def _recovered_failure_result(
    report: dict,
    message: str,
    elapsed_ms: float,
    *,
    worker_crashed: bool,
    any_capture_cap_hit: bool,
    worker_attempts: int,
    first_attempt_crashed: bool,
    first_attempt_error: str,
    first_attempt_fuel_consumed: int | None,
    first_attempt_stdout_bytes: int | None,
    first_attempt_stderr_bytes: int | None,
    first_attempt_output_bytes_observed: int | None,
    first_attempt_output_unknown: bool,
    first_attempt_execution_started: bool | None,
    first_attempt_report_bytes: int,
    first_attempt_worker_stderr_bytes: int,
    first_attempt_wall_ms: int,
    retry_suppressed_reason: str,
    output_bytes_observed: int | None,
) -> dict:
    """A crash that left a complete report still carries measured resources.

    The worker's non-zero exit is a host fact and keeps the result an ERROR;
    the report it wrote before exiting is the only measurement of what the
    guest actually consumed. Discarding it would bill the attempt as unknown
    and, on a single attempt, count the same attempt twice.
    """
    guest_stdout = report.get("stdout")
    guest_stderr = report.get("stderr")
    if not isinstance(guest_stdout, str):
        guest_stdout = ""
    if not isinstance(guest_stderr, str):
        guest_stderr = ""
    detail = "\n".join(part for part in (guest_stderr, message) if part)

    fuel = report.get("fuel_consumed")
    if isinstance(fuel, bool) or not isinstance(fuel, int):
        fuel = None
    execution_started = report.get("execution_started")
    if not isinstance(execution_started, bool) and execution_started is not None:
        execution_started = None
    preopens = report.get("effective_preopens", ())
    if not isinstance(preopens, (list, tuple)) or not all(
        isinstance(item, str) for item in preopens
    ):
        preopens = ()
    io_bytes = report.get("io_bytes_written")
    if isinstance(io_bytes, bool) or not isinstance(io_bytes, int):
        io_bytes = None
    # A report with no raw byte count, or no report at all, cannot prove zero
    # output. The host scan may still be attached as evidence.
    output_unknown = io_bytes is None and execution_started is not False
    abi = report.get("abi")
    if not isinstance(abi, str):
        abi = None

    result = _failure_result(
        ExecutionStatus.ERROR,
        message,
        elapsed_ms,
        worker_crashed=worker_crashed,
        worker_started=True,
        execution_started=execution_started,
        output_files_exceeded=any_capture_cap_hit
        or bool(report.get("output_files_exceeded", False)),
        worker_attempts=worker_attempts,
        first_attempt_crashed=first_attempt_crashed,
        first_attempt_error=first_attempt_error,
        first_attempt_fuel_consumed=first_attempt_fuel_consumed,
        first_attempt_stdout_bytes=first_attempt_stdout_bytes,
        first_attempt_stderr_bytes=first_attempt_stderr_bytes,
        first_attempt_output_bytes_observed=first_attempt_output_bytes_observed,
        first_attempt_output_unknown=first_attempt_output_unknown,
        first_attempt_execution_started=first_attempt_execution_started,
        first_attempt_report_bytes=first_attempt_report_bytes,
        first_attempt_worker_stderr_bytes=first_attempt_worker_stderr_bytes,
        first_attempt_wall_ms=first_attempt_wall_ms,
        retry_suppressed_reason=retry_suppressed_reason,
        output_bytes_observed=output_bytes_observed,
        output_bytes_unknown=output_unknown,
    )
    result["stdout"] = limit_output_text(guest_stdout)
    result["stderr"] = limit_output_text(detail)
    result["fuel_consumed"] = fuel
    result["effective_preopens"] = tuple(preopens)
    result["io_bytes_written"] = io_bytes
    result["output_bytes_observed"] = output_bytes_observed
    result["output_bytes_unknown"] = output_unknown
    result["io_budget_exceeded"] = bool(report.get("io_budget_exceeded", False))
    result["guest_exit_observed"] = bool(report.get("guest_exit_observed", False))
    if abi is not None:
        result["abi"] = abi
    return result


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
    # directory even when the child never reaches its cleanup. Each attempt
    # gets its OWN root: a retry must not inherit the first attempt's files,
    # or a crash caused by damaged scratch state would survive the retry.
    process_timeout = max(
        config.timeout_seconds + _PROCESS_TIMEOUT_MARGIN, _MIN_PROCESS_TIMEOUT
    )
    cmd = _worker_cmd(str(resolved), cap, abi)
    attempts = 0
    first_crashed = False
    last_crashed = False
    first_failure = ""
    report_payload = None
    final_recovered_report: dict | None = None
    final_recovered_message = ""
    last_failure = ""
    elapsed_ms = 0.0
    first_attempt_fuel_consumed: int | None = None
    first_attempt_stdout_bytes: int | None = None
    first_attempt_stderr_bytes: int | None = None
    first_attempt_output_bytes_observed: int | None = None
    first_attempt_output_unknown = False
    first_attempt_execution_started: bool | None = None
    first_attempt_report_bytes = 0
    first_attempt_worker_stderr_bytes = 0
    first_attempt_wall_ms = 0
    final_output_observed: int | None = None
    # A retry may repeat guest side effects. Without a host commit contract we
    # only retry runs that cannot write through a host grant.
    max_attempts = 1 if config.allow_dirs else 2
    any_capture_cap_hit = False
    for attempt in range(max_attempts):
        attempts = attempt + 1
        attempt_start = time.monotonic()
        if config.sandbox_base_dir is None:
            attempt_root = Path(tempfile.mkdtemp(prefix="ephemora_worker_"))
        else:
            attempt_root = Path(
                tempfile.mkdtemp(prefix="ephemora_worker_", dir=config.sandbox_base_dir)
            )
        capture_cap_hit = False
        try:
            attempt_config = replace(config, sandbox_base_dir=str(attempt_root))
            worker_payload = _payload_bytes(
                attempt_config, args or [], stdin_data, expected_sha256
            )
            attempt_env = _worker_env(attempt_root)
            try:
                with _worker_slot():
                    returncode, raw_out, raw_err = _spawn_worker(
                        cmd, worker_payload, process_timeout, attempt_env
                    )
            except subprocess.TimeoutExpired:
                # The worker was started and then killed at the wall. Its fuel
                # is not a proven zero; the accounting must treat this attempt
                # as started-but-unknown. The host-owned capture, not the
                # absent report, still decides whether the cap was hit.
                capture_cap_hit = _capture_cap_hit(attempt_root)
                any_capture_cap_hit = any_capture_cap_hit or capture_cap_hit
                observed_output = _measure_attempt_bytes(attempt_root)
                # A worker killed mid-run leaves a footprint, but the worker
                # also cleans its scratch before reporting. An observed zero
                # therefore does not prove zero guest output; only a complete
                # report does. Keep the scan as evidence, not as a zero bill.
                output_unknown = True
                if attempts == 1:
                    first_attempt_wall_ms = int(
                        (time.monotonic() - attempt_start) * 1000
                    )
                    first_attempt_execution_started = True
                    first_attempt_output_bytes_observed = observed_output
                    first_attempt_output_unknown = True
                return _failure_result(
                    ExecutionStatus.TIMEOUT,
                    (
                        f"Worker process timed out after {process_timeout:.0f}s "
                        f"(config timeout {config.timeout_seconds}s + margin)"
                    ),
                    (time.monotonic() - start) * 1000,
                    worker_started=True,
                    execution_started=True,
                    output_files_exceeded=any_capture_cap_hit,
                    output_bytes_observed=observed_output,
                    output_bytes_unknown=output_unknown,
                    worker_attempts=attempts,
                    first_attempt_crashed=first_crashed,
                    first_attempt_error=first_failure,
                    first_attempt_fuel_consumed=first_attempt_fuel_consumed,
                    first_attempt_stdout_bytes=first_attempt_stdout_bytes,
                    first_attempt_stderr_bytes=first_attempt_stderr_bytes,
                    first_attempt_output_bytes_observed=(
                        first_attempt_output_bytes_observed
                    ),
                    first_attempt_output_unknown=first_attempt_output_unknown,
                    first_attempt_execution_started=first_attempt_execution_started,
                    first_attempt_report_bytes=first_attempt_report_bytes,
                    first_attempt_worker_stderr_bytes=(
                        first_attempt_worker_stderr_bytes
                    ),
                    first_attempt_wall_ms=first_attempt_wall_ms,
                    retry_suppressed_reason=(
                        "host_grants"
                        if max_attempts == 1 and attempts == 1 and first_crashed
                        else ""
                    ),
                )
            except OSError as exc:
                # Spawn/pipe failure (fork pressure, broken pipe on a huge
                # payload): fail closed with no in-process fallback. A failure
                # after Popen may have consumed guest fuel; a failed Popen
                # cannot have.
                capture_cap_hit = _capture_cap_hit(attempt_root)
                any_capture_cap_hit = any_capture_cap_hit or capture_cap_hit
                started = bool(getattr(exc, "started", False))
                observed_output = _measure_attempt_bytes(attempt_root) if started else 0
                # A started worker may have produced output and cleaned its
                # scratch before the pipe broke; a zero scan is not proof of
                # zero output.
                output_unknown = bool(started)
                if attempts == 1:
                    first_attempt_wall_ms = int(
                        (time.monotonic() - attempt_start) * 1000
                    )
                    first_attempt_execution_started = started
                    first_attempt_output_bytes_observed = observed_output
                    if started:
                        first_attempt_output_unknown = True
                    else:
                        # No worker, hence no guest: this zero is measured.
                        first_attempt_stdout_bytes = 0
                        first_attempt_stderr_bytes = 0
                return _failure_result(
                    ExecutionStatus.ERROR,
                    f"worker could not be started: {exc!r}",
                    (time.monotonic() - start) * 1000,
                    worker_started=started,
                    execution_started=started,
                    output_files_exceeded=any_capture_cap_hit,
                    output_bytes_observed=observed_output,
                    output_bytes_unknown=output_unknown,
                    worker_attempts=attempts,
                    first_attempt_crashed=first_crashed,
                    first_attempt_error=first_failure,
                    first_attempt_fuel_consumed=first_attempt_fuel_consumed,
                    first_attempt_stdout_bytes=first_attempt_stdout_bytes,
                    first_attempt_stderr_bytes=first_attempt_stderr_bytes,
                    first_attempt_output_bytes_observed=(
                        first_attempt_output_bytes_observed
                    ),
                    first_attempt_output_unknown=first_attempt_output_unknown,
                    first_attempt_execution_started=first_attempt_execution_started,
                    first_attempt_report_bytes=first_attempt_report_bytes,
                    first_attempt_worker_stderr_bytes=(
                        first_attempt_worker_stderr_bytes
                    ),
                    first_attempt_wall_ms=first_attempt_wall_ms,
                    retry_suppressed_reason=(
                        "host_grants"
                        if max_attempts == 1 and attempts == 1 and first_crashed
                        else ""
                    ),
                )
        finally:
            observed_output = _measure_attempt_bytes(attempt_root)
            final_output_observed = observed_output
            capture_cap_hit = _capture_cap_hit(attempt_root)
            any_capture_cap_hit = any_capture_cap_hit or capture_cap_hit
            shutil.rmtree(attempt_root, ignore_errors=True)

        elapsed_ms = (time.monotonic() - start) * 1000
        fallback_report = _parse_worker_report(raw_out)
        if attempts == 1:
            first_attempt_wall_ms = int((time.monotonic() - attempt_start) * 1000)
            first_attempt_report_bytes = len(raw_out)
            first_attempt_worker_stderr_bytes = len(raw_err)
            first_attempt_output_bytes_observed = observed_output
            if fallback_report is not None:
                first_attempt_fuel_consumed = fallback_report.get("fuel_consumed")
                if "stdout" in fallback_report and "stderr" in fallback_report:
                    first_attempt_stdout_bytes = len(
                        str(fallback_report["stdout"]).encode("utf-8")
                    )
                    first_attempt_stderr_bytes = len(
                        str(fallback_report["stderr"]).encode("utf-8")
                    )
                else:
                    # A partial report is not a measured zero.
                    first_attempt_output_unknown = True
                first_attempt_execution_started = fallback_report.get(
                    "execution_started"
                )
                if first_attempt_execution_started is False:
                    first_attempt_output_bytes_observed = 0
                    first_attempt_output_unknown = False
                else:
                    reported_output = fallback_report.get("io_bytes_written")
                    if isinstance(reported_output, int) and not isinstance(
                        reported_output, bool
                    ):
                        first_attempt_output_bytes_observed = reported_output
                        first_attempt_output_unknown = False
                    else:
                        # A report without a raw byte count is not a proven
                        # zero; the host scan is only a lower-bound witness.
                        first_attempt_output_unknown = True
            else:
                # Popen succeeded: the guest may have produced output and
                # burned fuel before the pipe broke. The host scan of the
                # scratch root is evidence; a zero scan is not a zero bill.
                first_attempt_execution_started = True
                first_attempt_output_unknown = True
        stderr_text = raw_err.decode("utf-8", errors="replace").strip()
        last_crashed = False

        if returncode == 0:
            final_recovered_report = None
            if fallback_report is not None:
                report_payload = fallback_report
                break
            try:
                candidate = json.loads(raw_out.decode("utf-8", errors="replace"))
            except (json.JSONDecodeError, ValueError):
                candidate = None
            if candidate is not None:
                last_failure = "worker produced invalid JSON report"
            else:
                last_failure = "worker produced invalid output" + (
                    f": {stderr_text}" if stderr_text else ""
                )
        else:
            last_crashed = True
            if attempts == 1:
                first_crashed = True
            last_failure = "worker crashed" + (
                f": {stderr_text}" if stderr_text else ""
            )
            # The LAST attempt decides. A complete report written before the
            # non-zero exit is the measurement of this attempt, not a licence
            # to bill a second, conservative attempt on top of it.
            final_recovered_report = fallback_report
            final_recovered_message = last_failure
        if not first_failure:
            first_failure = last_failure

    first_kwargs = {
        "first_attempt_crashed": first_crashed,
        "first_attempt_error": first_failure,
        "first_attempt_fuel_consumed": first_attempt_fuel_consumed,
        "first_attempt_stdout_bytes": first_attempt_stdout_bytes,
        "first_attempt_stderr_bytes": first_attempt_stderr_bytes,
        "first_attempt_output_bytes_observed": first_attempt_output_bytes_observed,
        "first_attempt_output_unknown": first_attempt_output_unknown,
        "first_attempt_execution_started": first_attempt_execution_started,
        "first_attempt_report_bytes": first_attempt_report_bytes,
        "first_attempt_worker_stderr_bytes": first_attempt_worker_stderr_bytes,
        "first_attempt_wall_ms": first_attempt_wall_ms,
        "retry_suppressed_reason": (
            "host_grants" if max_attempts == 1 and first_crashed else ""
        ),
    }
    if report_payload is None:
        if final_recovered_report is not None:
            return _recovered_failure_result(
                final_recovered_report,
                final_recovered_message,
                elapsed_ms,
                worker_crashed=last_crashed,
                any_capture_cap_hit=any_capture_cap_hit,
                worker_attempts=attempts,
                output_bytes_observed=final_output_observed,
                **first_kwargs,
            )
        return _failure_result(
            ExecutionStatus.ERROR,
            last_failure,
            elapsed_ms,
            worker_crashed=last_crashed,
            worker_started=True,
            execution_started=True,
            output_files_exceeded=any_capture_cap_hit,
            output_bytes_observed=final_output_observed,
            output_bytes_unknown=True,
            worker_attempts=attempts,
            **first_kwargs,
        )

    status = _STATUS_BY_VALUE.get(str(report_payload.get("status", "")))
    if status is None:
        return _recovered_failure_result(
            report_payload,
            f"worker reported unknown status: {report_payload.get('status')!r}",
            elapsed_ms,
            worker_crashed=last_crashed,
            any_capture_cap_hit=any_capture_cap_hit,
            worker_attempts=attempts,
            output_bytes_observed=final_output_observed,
            **first_kwargs,
        )

    final_execution_started = report_payload.get("execution_started", True)
    reported_output = report_payload.get("io_bytes_written")
    if final_execution_started is False:
        final_output_observed = 0
        final_output_unknown = False
    elif isinstance(reported_output, int) and not isinstance(reported_output, bool):
        final_output_unknown = False
    else:
        # A report without raw bytes, or no report at all, is not a measured
        # zero. The scan stays evidence; the settlement books the ceiling.
        final_output_unknown = True
    report = {
        "status": status,
        "exit_code": int(report_payload.get("exit_code", 1)),
        "stdout": str(report_payload.get("stdout", "")),
        "stderr": str(report_payload.get("stderr", "")),
        "elapsed_ms": float(report_payload.get("elapsed_ms", 0.0)),
        "fuel_consumed": report_payload.get("fuel_consumed"),
        "sandbox_dir": report_payload.get("sandbox_dir"),
        "effective_preopens": tuple(report_payload.get("effective_preopens", ())),
        "io_cpu_used_seconds": report_payload.get("io_cpu_used_seconds"),
        "io_bytes_written": reported_output,
        "output_bytes_observed": final_output_observed,
        "output_bytes_unknown": final_output_unknown,
        "io_budget_exceeded": bool(report_payload.get("io_budget_exceeded", False)),
        # The worker's flag covers its own run; the parent scan covers an
        # attempt that died before it could report. Either proves the cap.
        "output_files_exceeded": bool(
            report_payload.get("output_files_exceeded", False)
        )
        or any_capture_cap_hit,
        "baseline_ms": float(report_payload.get("baseline_ms", 0.0)),
    }
    # ADR-014: the ABI the worker ACTUALLY ran under is a top-level
    # runtime fact (not only a baseline field) so _result_from_report can carry
    # it back to the parent as ExecutionResult.abi. It stays in
    # security_baseline too — the worker stamps both from one source decision.
    if "abi" in report_payload:
        report["abi"] = report_payload["abi"]
    # The same source-decision argument applies to the exit channel: only the
    # worker watched whether a guest exit status actually reached it. The parent
    # must not infer that from the routed ABI, or a run whose module never loaded
    # would attest an exit status no guest produced.
    if "guest_exit_observed" in report_payload:
        report["guest_exit_observed"] = bool(report_payload["guest_exit_observed"])
    if "security_baseline" in report_payload:
        report["security_baseline"] = report_payload["security_baseline"]
    report["worker_started"] = True
    report["execution_started"] = report_payload.get("execution_started", True)
    report["worker_attempts"] = attempts
    report["first_attempt_crashed"] = first_crashed
    report["first_attempt_error"] = first_failure
    if attempts > 1 or first_crashed:
        report["first_attempt_fuel_consumed"] = first_attempt_fuel_consumed
        report["first_attempt_stdout_bytes"] = first_attempt_stdout_bytes
        report["first_attempt_stderr_bytes"] = first_attempt_stderr_bytes
        report["first_attempt_output_bytes_observed"] = (
            first_attempt_output_bytes_observed
        )
        report["first_attempt_output_unknown"] = first_attempt_output_unknown
        report["first_attempt_execution_started"] = first_attempt_execution_started
        report["first_attempt_report_bytes"] = first_attempt_report_bytes
        report["first_attempt_worker_stderr_bytes"] = first_attempt_worker_stderr_bytes
        report["first_attempt_wall_ms"] = first_attempt_wall_ms
    return report


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
