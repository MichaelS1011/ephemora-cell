# Ephemora Cell — Isolated worker subprocess for subprocess-level sandboxing
# SPDX-License-Identifier: Apache-2.0
"""
Worker subprocess for process-level isolation (run_isolated).

The parent (process_executor) launches it with --wasm <path>
--payload-stdin; the run payload {config, args, stdin} arrives as JSON
on stdin (S1: never on the command line).

The worker applies OS-level resource limits (RLIMIT_NOFILE, RLIMIT_AS/RSS),
runs the WASI sandbox via ``WASISandbox.run``, and prints a single JSON
report on stdout. The parent (process_executor.run_isolated) is the only
consumer; any non-JSON stdout means the worker died unexpectedly.

RLIMIT note: RLIMIT_AS is a virtual-address-space backstop with a
wasmtime-compatible floor (wasmtime reserves 4 GiB of address space per
32-bit linear memory); the physical memory cap is ``Store.set_limits``
inside the sandbox, with RLIMIT_RSS as best-effort reinforcement.
"""

from __future__ import annotations

import argparse
import json
import sys
import threading
import time
from pathlib import Path

try:
    import resource
except ImportError:  # pragma: no cover — non-POSIX platforms
    resource = None  # type: ignore[assignment]

from .execution_report import ExecutionReport
from .wasi_runtime import ExecutionStatus, WASIConfig, WASISandbox

# Hard cap for guest .wasm files (checked in worker and parent).
DEFAULT_MAX_WASM_BYTES = 32 * 1024 * 1024
# Worker FD cap — bounds guest fd-draining per process.
_RLIMIT_NOFILE = 256
# Address-space headroom above the guest memory limit (best effort).
_RLIMIT_MARGIN_BYTES = 64 * 1024 * 1024
# RLIMIT_AS floor. wasmtime reserves a large virtual address space per
# 32-bit linear memory (default memory_reservation is 4 GiB) plus JIT code
# space; a tighter AS cap breaks instantiation on Linux with "mmap failed /
# Cannot allocate memory" (macOS does not enforce RLIMIT_AS, which is why
# this only surfaced on Linux CI). The AS limit is therefore a
# runaway-allocation backstop, not a physical-memory cap — the physical cap
# is Store.set_limits (enforced inside the sandbox) and RLIMIT_RSS (best
# effort; historically unenforced on Linux).
_RLIMIT_AS_FLOOR_BYTES = 8 * 1024 * 1024 * 1024


def _apply_rlimits(config: WASIConfig) -> None:
    """Apply OS-level process limits (best effort, platform dependent).

    Disk quota: RLIMIT_FSIZE caps each file the worker writes —
    including guest writes into preopened dirs and the sandbox dir — at
    ``disk_quota_bytes``. SIGXFSZ is ignored so an over-quota write fails
    with EFBIG (a controlled error the guest sees) instead of killing the
    worker with a signal.
    """
    if resource is None:
        return
    try:
        resource.setrlimit(resource.RLIMIT_NOFILE, (_RLIMIT_NOFILE, _RLIMIT_NOFILE))
    except (OSError, ValueError):
        pass
    if config.disk_quota_bytes is not None and config.disk_quota_bytes > 0:
        quota = config.disk_quota_bytes
        try:
            resource.setrlimit(resource.RLIMIT_FSIZE, (quota, quota))
        except (OSError, ValueError):
            pass
        try:
            import signal

            sigxfsz = getattr(signal, "SIGXFSZ", None)
            if sigxfsz is not None:
                signal.signal(sigxfsz, signal.SIG_IGN)
        except (OSError, ValueError):
            pass
    if config.memory_capacity_bytes > 0:
        budget = config.memory_capacity_bytes + _RLIMIT_MARGIN_BYTES
        # RLIMIT_AS: virtual-address backstop at a wasmtime-compatible floor
        # (see _RLIMIT_AS_FLOOR_BYTES). RLIMIT_RSS: physical-memory intent.
        as_budget = max(budget, _RLIMIT_AS_FLOOR_BYTES)
        for limit, cap in (
            (resource.RLIMIT_AS, as_budget),
            (resource.RLIMIT_RSS, budget),
        ):
            try:
                resource.setrlimit(limit, (cap, cap))
            except (OSError, ValueError, AttributeError):
                pass


def _cpu_usage() -> float:
    """Worker CPU time (user+sys, seconds) since process start (ADR-002)."""
    if resource is None:
        return 0.0
    ru = resource.getrusage(resource.RUSAGE_SELF)
    return float(ru.ru_utime) + float(ru.ru_stime)


def _start_io_cpu_watchdog(
    limit: float, interrupt_event, done_event
) -> threading.Thread:
    """Watch worker CPU time; interrupt the guest when ``limit`` is hit.

    Every unmetered host syscall the guest induces (file writes, stat/
    open churn) shows up as CPU time of the worker process — fuel meters
    guest compute, not host work. Runs until the budget is
    breached (sets interrupt_event) or the run completes (done_event).
    """

    def _watch() -> None:
        used = 0.0
        while not done_event.wait(0.1):
            used = _cpu_usage()
            if used >= limit:
                interrupt_event.set()
                return

    t = threading.Thread(target=_watch, daemon=True, name="ephemora-io-cpu-watch")
    t.start()
    return t


def _build_report(
    result,
    baseline_ms: float,
    config: WASIConfig,
    *,
    io_cpu_used: float = 0.0,
    io_budget_exceeded: bool | None = None,
) -> dict:
    """Convert a sandbox ExecutionResult into the JSON report payload.

    The security baseline is derived from the effective config so that
    subprocess runs carry the same authoritative limits as direct runs.
    I/O-budget observability (ADR-002): io_cpu_used_seconds and
    io_bytes_written make induced host work auditable per run.
    """
    report = {
        "status": result.status.value,
        "exit_code": result.exit_code,
        "stdout": result.stdout,
        "stderr": result.stderr,
        "elapsed_ms": result.elapsed_ms,
        "fuel_consumed": result.fuel_consumed,
        "sandbox_dir": result.sandbox_dir,
        "effective_preopens": list(result.effective_preopens),
        "io_cpu_used_seconds": round(io_cpu_used, 4),
        "io_bytes_written": result.io_bytes_written,
        "io_budget_exceeded": (
            result.io_budget_exceeded
            if io_budget_exceeded is None
            else io_budget_exceeded
        ),
        "baseline_ms": baseline_ms,
    }
    report["security_baseline"] = (
        ExecutionReport(
            status=result.status.value,
            exit_code=result.exit_code,
            elapsed_ms=result.elapsed_ms,
        )
        .apply_config(config, effective_preopens=result.effective_preopens)
        .security_baseline
    )
    return report


def run_worker(
    wasm_path: str,
    config: WASIConfig,
    args: list[str] | None = None,
    stdin_data: str | None = None,
    max_wasm_bytes: int = DEFAULT_MAX_WASM_BYTES,
    abi: str = "auto",
) -> dict:
    """Execute one sandboxed run and return the report dict (no process exit)."""
    start = time.monotonic()

    resolved = Path(wasm_path).resolve()
    if not resolved.is_file():
        return {
            "status": "error",
            "exit_code": 1,
            "stdout": "",
            "stderr": f"WASM module not found: {wasm_path}",
            "elapsed_ms": (time.monotonic() - start) * 1000,
            "fuel_consumed": None,
            "sandbox_dir": None,
            "baseline_ms": (time.monotonic() - start) * 1000,
        }
    if resolved.stat().st_size > max_wasm_bytes:
        return {
            "status": "error",
            "exit_code": 1,
            "stdout": "",
            "stderr": (
                f"WASM module exceeds size limit of {max_wasm_bytes} bytes: "
                f"{resolved.stat().st_size}"
            ),
            "elapsed_ms": (time.monotonic() - start) * 1000,
            "fuel_consumed": None,
            "sandbox_dir": None,
            "baseline_ms": (time.monotonic() - start) * 1000,
        }

    _apply_rlimits(config)
    baseline_ms = (time.monotonic() - start) * 1000

    try:
        if abi == "preview1":
            sandbox = WASISandbox(config=config)
        elif abi == "component":
            from .wasi_02 import ComponentSandbox

            sandbox = ComponentSandbox(config=config)
        else:  # auto
            from .wasi_02 import is_component_binary

            if is_component_binary(str(resolved)):
                from .wasi_02 import ComponentSandbox

                sandbox = ComponentSandbox(config=config)
            else:
                sandbox = WASISandbox(config=config)
    except ValueError as exc:
        return {
            "status": "error",
            "exit_code": 1,
            "stdout": "",
            "stderr": str(exc),
            "elapsed_ms": (time.monotonic() - start) * 1000,
            "fuel_consumed": None,
            "sandbox_dir": None,
            "baseline_ms": baseline_ms,
        }
    # ADR-002 io_cpu_seconds: the worker's own CPU time is the meter for
    # all guest-induced host work. The watchdog signals the sandbox via
    # interrupt_event (epoch) and we translate the breach into a clean
    # ERROR report below.
    io_cpu_used = 0.0
    interrupt_event = threading.Event()
    done_event = threading.Event()
    cpu_at_start = 0.0
    if config.io_cpu_seconds is not None and resource is not None:
        cpu_at_start = _cpu_usage()
        _start_io_cpu_watchdog(config.io_cpu_seconds, interrupt_event, done_event)
    try:
        result = sandbox.run(
            str(resolved),
            args=args or [],
            stdin_data=stdin_data,
            interrupt_event=interrupt_event,
        )
    finally:
        done_event.set()
        io_cpu_used = max(0.0, _cpu_usage() - cpu_at_start)
        sandbox.cleanup()
    cpu_budget_breached = (
        interrupt_event.is_set()
        and config.io_cpu_seconds is not None
        and result.status is ExecutionStatus.TIMEOUT
    )
    if cpu_budget_breached:
        # Epoch fired by the CPU watchdog, not the wall-clock timer.
        result.status = ExecutionStatus.ERROR
        result.stderr = (
            f"I/O budget exceeded: worker used {io_cpu_used:.2f}s CPU "
            f"(io_cpu_seconds={config.io_cpu_seconds}): {result.stderr}"
        )
    return _build_report(
        result,
        baseline_ms,
        config,
        io_cpu_used=io_cpu_used,
        io_budget_exceeded=cpu_budget_breached or result.io_budget_exceeded,
    )


def main(argv: list[str] | None = None) -> int:
    """CLI entry point: run one sandboxed execution, print JSON report.

    Security: the run payload (WASIConfig including ``allow_env``
    values, guest argv, stdin data) is read from stdin when
    ``--payload-stdin`` is given, so it never appears in ``ps``/``/proc``
    output.
    """
    parser = argparse.ArgumentParser(prog="ephemora_cell.process_worker")
    parser.add_argument("--wasm", required=True, help="path to the .wasm module")
    parser.add_argument(
        "--payload-stdin",
        action="store_true",
        help="read the run payload {config, args, stdin} as JSON from stdin",
    )
    parser.add_argument(
        "--max-wasm-bytes",
        type=int,
        default=DEFAULT_MAX_WASM_BYTES,
        help="maximum .wasm file size in bytes",
    )
    parser.add_argument(
        "--abi",
        choices=["auto", "preview1", "component"],
        default="auto",
        help="execution ABI (auto detects components by magic bytes)",
    )
    opts = parser.parse_args(argv)

    try:
        if opts.payload_stdin:
            payload = json.loads(sys.stdin.read())
            if not isinstance(payload, dict):
                raise ValueError("payload must be a JSON object")
            config = WASIConfig(**payload.get("config", {}))
            guest_args = payload.get("args") or []
            stdin_data = payload.get("stdin")
        else:
            config = WASIConfig()
            guest_args = []
            stdin_data = None
        if not isinstance(guest_args, list) or not all(
            isinstance(a, str) for a in guest_args
        ):
            raise ValueError("payload.args must be a list of strings")
        if stdin_data is not None and not isinstance(stdin_data, str):
            raise ValueError("payload.stdin must be a string or null")
        report = run_worker(
            opts.wasm,
            config,
            args=guest_args,
            stdin_data=stdin_data,
            max_wasm_bytes=opts.max_wasm_bytes,
            abi=opts.abi,
        )
    except Exception:
        sys.stderr.write(f"worker crashed: {sys.exc_info()[1]!r}\n")
        return 1

    sys.stdout.write(json.dumps(report))
    sys.stdout.flush()
    return 0


if __name__ == "__main__":
    sys.exit(main())
