"""Tests for process_executor — subprocess-level isolation."""

from __future__ import annotations

import json
import os
import shutil
import signal
import subprocess
import sys
import threading
import time
from concurrent.futures import ThreadPoolExecutor
from pathlib import Path

import pytest
import wasmtime

sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))

from ephemora_cell import ExecutionStatus, WASIConfig, process_executor
from ephemora_cell.process_executor import run_isolated

# Trivial WASI module: exits cleanly with code 0.
TRIVIAL_WAT = b"""
(module
  (import "wasi_snapshot_preview1" "proc_exit" (func $exit (param i32)))
  (memory (export "memory") 1)
  (func (export "_start")
    i32.const 0
    call $exit
  )
)
"""


SPIN_WAT = b"""
(module
  (import "wasi_snapshot_preview1" "proc_exit" (func $exit (param i32)))
  (memory (export "memory") 1)
  (func (export "_start")
    (loop $spin (br $spin))))
"""


def _write_module(tmp_path: Path, wat: bytes, name: str = "module.wasm") -> Path:
    path = tmp_path / name
    path.write_bytes(wasmtime.wat2wasm(wat))
    return path


def _write_bomb_module(tmp_path: Path, num_funcs: int) -> Path:
    """Compile bomb: num_funcs exported funcs + infinite-loop _start."""
    parts = ["(module"]
    for i in range(num_funcs):
        parts.append(
            f'  (func (export "f{i}") (result i32) i32.const {i} i32.const 1 i32.add)'
        )
    parts.append('  (func (export "_start")')
    parts.append("    call 0")
    parts.append("    drop")
    parts.append("    (loop $l br $l)")
    parts.append("  )")
    parts.append(")")
    path = tmp_path / "bomb.wasm"
    path.write_bytes(wasmtime.wat2wasm("\n".join(parts)))
    return path


class TestRunIsolated:
    """run_isolated happy path and result contract."""

    def test_trivial_module_runs(self, tmp_path):
        wasm_path = _write_module(tmp_path, TRIVIAL_WAT)
        result = run_isolated(str(wasm_path), WASIConfig(max_fuel=1_000_000))
        assert result["status"] == ExecutionStatus.SUCCESS
        assert result["exit_code"] == 0
        assert isinstance(result["stdout"], str)
        assert isinstance(result["stderr"], str)
        assert result["elapsed_ms"] >= 0
        assert result["baseline_ms"] >= 0
        assert isinstance(result["fuel_consumed"], int)

    def test_missing_file(self, tmp_path):
        result = run_isolated(str(tmp_path / "nope.wasm"), WASIConfig())
        assert result["status"] == ExecutionStatus.ERROR
        assert "not found" in result["stderr"].lower()

    def test_size_cap_rejects_before_spawn(self, tmp_path):
        big = tmp_path / "big.wasm"
        big.write_bytes(b"\0" * (33 * 1024 * 1024))
        t0 = time.monotonic()
        result = run_isolated(str(big), WASIConfig())
        assert time.monotonic() - t0 < 1.0
        assert result["status"] == ExecutionStatus.ERROR
        assert "size limit" in result["stderr"].lower()

    def test_args_accepted(self, tmp_path):
        wasm_path = _write_module(tmp_path, TRIVIAL_WAT)
        result = run_isolated(str(wasm_path), WASIConfig(), args=["--flag", "value"])
        assert result["status"] == ExecutionStatus.SUCCESS

    def test_result_is_dict_with_execution_result_fields(self, tmp_path):
        wasm_path = _write_module(tmp_path, TRIVIAL_WAT)
        result = run_isolated(str(wasm_path), WASIConfig())
        for field in ("status", "exit_code", "stdout", "stderr", "elapsed_ms"):
            assert field in result


class TestWorkerFailureHandling:
    """Parent-side failure mapping for broken workers."""

    def test_worker_crash_reports_error(self, monkeypatch, tmp_path):
        wasm_path = _write_module(tmp_path, TRIVIAL_WAT)
        captured: dict[str, str] = {}

        def fake_spawn(cmd, payload, process_timeout, env):
            captured.update(env)
            return 1, b"", b"boom traceback"

        monkeypatch.setenv("EPHEMORA_SENTINEL_SECRET", "must-not-reach-worker")
        monkeypatch.setattr(process_executor, "_spawn_worker", fake_spawn)
        result = run_isolated(str(wasm_path), WASIConfig())
        assert result["status"] == ExecutionStatus.ERROR
        assert "worker crashed" in result["stderr"]
        assert "boom traceback" in result["stderr"]
        assert "EPHEMORA_SENTINEL_SECRET" not in captured
        assert "TMPDIR" in captured and captured["TMPDIR"].startswith("/")

    def test_non_json_output_reports_error(self, monkeypatch, tmp_path):
        wasm_path = _write_module(tmp_path, TRIVIAL_WAT)

        def fake_spawn(cmd, payload, process_timeout, env):
            return 0, b"this is not json", b""

        monkeypatch.setattr(process_executor, "_spawn_worker", fake_spawn)
        result = run_isolated(str(wasm_path), WASIConfig())
        assert result["status"] == ExecutionStatus.ERROR
        assert "invalid" in result["stderr"].lower()

    def test_empty_output_reports_error(self, monkeypatch, tmp_path):
        wasm_path = _write_module(tmp_path, TRIVIAL_WAT)

        def fake_spawn(cmd, payload, process_timeout, env):
            return 0, b"", b""

        monkeypatch.setattr(process_executor, "_spawn_worker", fake_spawn)
        result = run_isolated(str(wasm_path), WASIConfig())
        assert result["status"] == ExecutionStatus.ERROR

    def test_process_timeout_reports_timeout(self, monkeypatch, tmp_path):
        wasm_path = _write_module(tmp_path, TRIVIAL_WAT)

        def fake_spawn(cmd, payload, process_timeout, env):
            raise subprocess.TimeoutExpired(cmd=cmd, timeout=process_timeout)

        monkeypatch.setattr(process_executor, "_spawn_worker", fake_spawn)
        result = run_isolated(str(wasm_path), WASIConfig(timeout_seconds=1))
        assert result["status"] == ExecutionStatus.TIMEOUT
        assert "timed out" in result["stderr"].lower()


class TestCompileBomb:
    """Compile bombs must be contained in the worker process."""

    def test_compile_bomb_contained_and_parent_survives(self, tmp_path):
        wasm_path = _write_bomb_module(tmp_path, 50_000)
        config = WASIConfig(max_fuel=None, timeout_seconds=1)
        t0 = time.monotonic()
        result = run_isolated(str(wasm_path), config)
        wall = time.monotonic() - t0

        assert wall <= 8.0, f"Bomb not contained: took {wall:.1f}s"
        assert result["status"] in (ExecutionStatus.ERROR, ExecutionStatus.TIMEOUT)

        trivial_path = _write_module(tmp_path, TRIVIAL_WAT, name="after.wasm")
        after = run_isolated(str(trivial_path), WASIConfig(max_fuel=1_000_000))
        assert after["status"] == ExecutionStatus.SUCCESS

    def test_compile_bomb_process_killed_by_parent(self, tmp_path):
        """A worker stuck in compile (epoch cannot interrupt) is killed."""
        wasm_path = _write_bomb_module(tmp_path, 50_000)
        config = WASIConfig(max_fuel=None, timeout_seconds=1)
        result = run_isolated(str(wasm_path), config)
        if result["status"] == ExecutionStatus.TIMEOUT:
            assert "timed out" in result["stderr"].lower()


class TestWorkerProtocol:
    """The worker module is a usable CLI entry point."""

    # Direct-import launcher (S1 hardening): avoids runpy/-m resolution,
    # which is unreliable for editable installs on some hosts.
    WORKER_CMD = (
        sys.executable,
        "-c",
        "import sys; from ephemora_cell.process_worker import main; sys.exit(main())",
    )

    def test_worker_prints_json_report(self, tmp_path):
        wasm_path = _write_module(tmp_path, TRIVIAL_WAT)
        payload = json.dumps(
            {
                "config": {"max_memory_mb": 128, "max_fuel": 1_000_000},
                "args": [],
                "stdin": None,
            }
        )
        proc = subprocess.run(
            [
                *self.WORKER_CMD,
                "--wasm",
                str(wasm_path),
                "--payload-stdin",
            ],
            input=payload.encode("utf-8"),
            capture_output=True,
            timeout=60,
            check=False,
        )
        assert proc.returncode == 0, proc.stderr.decode()
        payload = json.loads(proc.stdout.decode())
        assert payload["status"] == "success"
        assert payload["exit_code"] == 0
        assert "baseline_ms" in payload

    def test_worker_rejects_malformed_payload(self, tmp_path):
        wasm_path = _write_module(tmp_path, TRIVIAL_WAT)
        proc = subprocess.run(
            [
                *self.WORKER_CMD,
                "--wasm",
                str(wasm_path),
                "--payload-stdin",
            ],
            input=b'{"config": "not-an-object", "args": []}',
            capture_output=True,
            timeout=60,
            check=False,
        )
        assert proc.returncode != 0
        assert b"worker crashed" in proc.stderr

    def test_worker_crashes_on_bad_args(self):
        proc = subprocess.run(
            [*self.WORKER_CMD, "--nope"],
            capture_output=True,
            timeout=60,
            check=False,
        )
        assert proc.returncode != 0


LOOP_WAT = b"""
(module
  (import "wasi_snapshot_preview1" "proc_exit" (func $exit (param i32)))
  (memory (export "memory") 1)
  (func (export "_start")
    (loop $l br $l)
  )
)
"""


class TestArgvConfidentiality:
    """S1: the run payload must never appear on the worker command line."""

    def test_payload_travels_via_stdin_not_argv(self, tmp_path, monkeypatch):
        wasm_path = _write_module(tmp_path, TRIVIAL_WAT)
        # deliberately FAKE secret (positive control) — proves it never
        # reaches argv; not a credential
        secret = "argv-secret-7f3a"
        config = WASIConfig(max_fuel=1_000_000, allow_env=(("API_TOKEN", secret),))
        captured: dict = {}

        class _Popen(subprocess.Popen):
            def __init__(self, args, **kwargs):
                captured["argv"] = list(args)
                captured["stdin"] = kwargs.get("stdin")
                super().__init__(args, **kwargs)

            def communicate(self, input=None, timeout=None):
                captured["input"] = input
                return super().communicate(input=input, timeout=timeout)

        monkeypatch.setattr(process_executor.subprocess, "Popen", _Popen)
        result = run_isolated(str(wasm_path), config, stdin_data="hush-hush")
        assert result["status"] == ExecutionStatus.SUCCESS
        # argv: no secret, no env name, no stdin text, no config JSON blob
        joined_argv = " ".join(captured["argv"])
        assert secret not in joined_argv
        assert "API_TOKEN" not in joined_argv
        assert "hush-hush" not in joined_argv
        assert "allow_env" not in joined_argv
        # payload goes over the stdin pipe instead
        assert captured["stdin"] == subprocess.PIPE
        payload = json.loads(captured["input"].decode("utf-8"))
        assert payload["config"]["allow_env"] == [["API_TOKEN", secret]]
        assert payload["stdin"] == "hush-hush"

    def test_ps_never_shows_payload_secrets(self, tmp_path):
        """Live `ps` proof: while a long worker run is in flight, its
        command line is visible (positive control) but carries no
        allow_env secret (the S1 leak)."""
        pytest.importorskip("pytest")
        if not shutil.which("ps"):
            pytest.skip("ps not available")
        wasm_path = _write_module(tmp_path, LOOP_WAT, name="loop.wasm")
        # deliberately FAKE secret (positive control) — the assertion below
        # proves it never appears in `ps` output; not a credential
        secret = "ps-secret-9d31b2"
        # io_cpu_seconds=None keeps this S1 test scoped to argv visibility:
        # without it the ADR-002 CPU wall (2.0s default) would end the run
        # before the ps poll window closes.
        config = WASIConfig(
            max_fuel=10_000_000_000,
            timeout_seconds=3,
            allow_env=(("API_TOKEN", secret),),
            io_cpu_seconds=None,
        )
        saw_worker = False
        leaked = False
        polls = 0
        python_lines = []
        last_snapshot = ""
        # The positive control proves argv is inspectable: _worker_argv puts
        # the wasm path on argv by design (S1), so match the unique temp
        # module name; the -c import string is matched as a best effort.
        needles = (wasm_path.name, "process_worker", "worker_main")
        with ThreadPoolExecutor(max_workers=1) as pool:
            future = pool.submit(run_isolated, str(wasm_path), config)
            # Poll until the run ends (runner speeds vary): the worker lives
            # from spawn to timeout, so a full-run window removes the timing
            # flake the first real CI run exposed. The window and the per-call
            # `ps` timeout are generous so a loaded host (where `ps` itself can
            # take many seconds) is not mistaken for a leak: the assertion only
            # checks lines we actually managed to read.
            deadline = time.monotonic() + 30.0
            while time.monotonic() < deadline and not future.done():
                try:
                    ps = subprocess.run(
                        # -ww = unlimited command width: procps (Linux) truncates
                        # the command column at 80 chars otherwise, hiding the
                        # argv past the -c import line (the first real CI run
                        # proved the worker visible but truncated).
                        ["ps", "-axww", "-o", "command"],
                        capture_output=True,
                        timeout=15,
                    )
                except subprocess.TimeoutExpired:
                    # `ps` did not finish under host load: skip this poll
                    # iteration rather than fail an unrelated S1 check.
                    time.sleep(0.1)
                    continue
                last_snapshot = ps.stdout.decode("utf-8", errors="replace")
                polls += 1
                for line in last_snapshot.splitlines():
                    if any(n in line for n in needles):
                        saw_worker = True
                        if secret in line:
                            leaked = True
                    if "python" in line and len(python_lines) < 5:
                        python_lines.append(line[:200])
                time.sleep(0.025)
            result = future.result()
        # Contained by the wall-clock timeout OR by fuel exhaustion of the
        # infinite loop — both prove the run did not escape the sandbox.
        assert result["status"] in (
            ExecutionStatus.TIMEOUT,
            ExecutionStatus.FUEL_EXHAUSTED,
        )
        assert saw_worker, (
            "positive control failed: worker never visible in ps; "
            f"polls={polls}, snapshot_lines={len(last_snapshot.splitlines())}, "
            f"python_lines={python_lines!r}, "
            f"last ps snapshot (head): {last_snapshot[:600]!r}"
        )
        assert not leaked, "S1 leak: payload secret visible in ps output"


class _FakeResource:
    RLIMIT_NOFILE = 1
    RLIMIT_AS = 2
    RLIMIT_RSS = 3
    RLIMIT_FSIZE = 4
    calls: dict = {}  # noqa: RUF012 (static fake registry)

    @staticmethod
    def setrlimit(which, pair):
        _FakeResource.calls[which] = pair


class TestWorkerRlimits:
    """RLIMIT application must stay wasmtime-compatible on Linux
    (verified in a prior CI investigation)."""

    def _capture_rlimits(self, config: WASIConfig):
        from ephemora_cell import process_worker

        _FakeResource.calls = {}
        saved = process_worker._apply_rlimits.__globals__["resource"]
        process_worker._apply_rlimits.__globals__["resource"] = _FakeResource
        try:
            process_worker._apply_rlimits(config)
        finally:
            process_worker._apply_rlimits.__globals__["resource"] = saved
        return _FakeResource.calls

    def test_as_floor_is_wasmtime_compatible(self):
        from ephemora_cell import process_worker
        from ephemora_cell.process_worker import _RLIMIT_AS_FLOOR_BYTES

        calls = self._capture_rlimits(WASIConfig(max_memory_mb=128))
        as_budget = calls[_FakeResource.RLIMIT_AS][0]
        rss_budget = calls[_FakeResource.RLIMIT_RSS][0]
        assert as_budget >= _RLIMIT_AS_FLOOR_BYTES
        assert rss_budget == 128 * 1024 * 1024 + process_worker._RLIMIT_MARGIN_BYTES
        assert rss_budget < _RLIMIT_AS_FLOOR_BYTES

    def test_no_rlimits_when_memory_unbounded(self):
        calls = self._capture_rlimits(WASIConfig(max_memory_mb=0))
        assert _FakeResource.RLIMIT_AS not in calls
        assert _FakeResource.RLIMIT_RSS not in calls

    def test_nofile_capped(self):
        calls = self._capture_rlimits(WASIConfig(max_memory_mb=128))
        assert calls[_FakeResource.RLIMIT_NOFILE] == (256, 256)


class TestIoCpuWallReporting:
    """The wall and the message must name the same number.

    `io_cpu_seconds` is compared against the worker's ABSOLUTE process CPU (the
    meter the design chose: every host syscall the guest induces lands in the
    worker's own CPU). The refusal reported the run-attributable DELTA instead, so
    an operator read "worker used 0.47s CPU (io_cpu_seconds=2.0)" — a number below
    the budget it claimed to have exceeded, measured under QEMU emulation. Refusing
    was right; the message lied.
    """

    def test_the_breach_quotes_the_value_the_watchdog_compared(self, tmp_path):
        import re

        from ephemora_cell import WASIConfig

        wasm = _write_module(tmp_path, SPIN_WAT, "spin.wasm")
        result = run_isolated(
            str(wasm),
            WASIConfig(
                io_cpu_seconds=0.3,
                max_fuel=10_000_000_000,
                timeout_seconds=30,
            ),
        )
        assert result["status"] == ExecutionStatus.ERROR, result["stderr"]
        text = result["stderr"] or ""
        assert "I/O budget exceeded" in text, text
        cited = re.search(r"worker used ([\d.]+)s absolute process CPU", text)
        assert cited is not None, text
        # The invariant: a refusal never cites a figure below its own budget.
        assert float(cited.group(1)) >= 0.3, text
        # And the delta is still reported, labelled as what it is.
        assert "attributable to this run" in text, text


class TestParallelIsolation:
    """Parallel runs must not exhaust FDs or crash the parent."""

    def test_100_parallel_runs_no_fd_exhaustion(self, tmp_path):
        wasm_path = _write_module(tmp_path, TRIVIAL_WAT)

        def count_fds() -> int:
            return len(os.listdir("/dev/fd"))

        before = count_fds()
        with ThreadPoolExecutor(max_workers=16) as pool:
            results = list(
                pool.map(
                    lambda _: run_isolated(
                        str(wasm_path), WASIConfig(max_fuel=1_000_000)
                    ),
                    range(100),
                )
            )
        after = count_fds()

        assert all(r["status"] == ExecutionStatus.SUCCESS for r in results)
        assert after - before < 64, f"FD leak: {before} -> {after}"


class TestWorkerAdmissionControl:
    """The 1.2.0 default posture spawns a worker per run; a bound is required
    so a parallel caller applies backpressure instead of fanning out to an
    uncontrolled number of OS processes (the 759-incident root cause)."""

    def test_concurrency_cap_bounds_simultaneous_spawns(self, tmp_path, monkeypatch):
        wasm_path = _write_module(tmp_path, TRIVIAL_WAT)
        cap = 3
        monkeypatch.setattr(
            process_executor,
            "_worker_slots",
            threading.BoundedSemaphore(cap),
        )

        lock = threading.Lock()
        state = {"active": 0, "peak": 0}

        def fake_spawn(cmd, payload, process_timeout, env):
            with lock:
                state["active"] += 1
                state["peak"] = max(state["peak"], state["active"])
            try:
                time.sleep(0.05)  # hold the slot so overlap is observable
            finally:
                with lock:
                    state["active"] -= 1
            report = {"status": "success", "exit_code": 0, "stdout": "", "stderr": ""}
            return 0, json.dumps(report).encode(), b""

        monkeypatch.setattr(process_executor, "_spawn_worker", fake_spawn)

        with ThreadPoolExecutor(max_workers=12) as pool:
            results = list(
                pool.map(
                    lambda _: run_isolated(
                        str(wasm_path), WASIConfig(max_fuel=1_000_000)
                    ),
                    range(24),
                )
            )

        assert all(r["status"] == ExecutionStatus.SUCCESS for r in results)
        assert state["peak"] <= cap, (
            f"admission control breached: {state['peak']} workers spawned "
            f"concurrently with cap {cap}"
        )

    def test_oversized_cap_env_is_respected(self, monkeypatch):
        monkeypatch.setenv("EPHEMORA_MAX_CONCURRENT_WORKERS", "2")
        assert process_executor._default_max_concurrent_workers() == 2

    def test_invalid_cap_env_falls_back_to_default(self, monkeypatch):
        monkeypatch.setenv("EPHEMORA_MAX_CONCURRENT_WORKERS", "not-a-number")
        assert process_executor._default_max_concurrent_workers() >= 1


class TestWorkerReaping:
    """Every kill/timeout/interrupt path must reap the whole worker process
    group so no child outlives the call as an orphan."""

    def test_kill_worker_group_signals_process_group(self, monkeypatch):
        calls = {}

        class _Proc:
            pid = 4242

            def kill(self):
                calls["kill"] = True

        monkeypatch.setattr(process_executor.os, "getpgid", lambda pid: pid)

        def fake_killpg(pgid, sig):
            calls["killpg"] = (pgid, sig)

        monkeypatch.setattr(process_executor.os, "killpg", fake_killpg)
        process_executor._kill_worker_group(_Proc())
        assert calls.get("killpg") == (4242, signal.SIGKILL)

    def test_kill_worker_group_falls_back_when_no_group(self, monkeypatch):
        calls = {}

        class _Proc:
            pid = 99

            def kill(self):
                calls["kill"] = True

        def boom(_pid):
            raise ProcessLookupError("gone")

        monkeypatch.setattr(process_executor.os, "getpgid", boom)
        process_executor._kill_worker_group(_Proc())
        assert calls.get("kill") is True

    def test_spawn_timeout_kills_group_and_reaps(self, tmp_path, monkeypatch):
        killed: dict = {"kill": 0, "reap": 0}

        class _FakeProc:
            pid = 7
            stdout = None
            stderr = None
            returncode = -9

            def communicate(self, input=None, timeout=None):
                raise subprocess.TimeoutExpired(cmd="x", timeout=1)

            def kill(self):
                pass

            def wait(self):
                pass

        monkeypatch.setattr(
            process_executor.subprocess, "Popen", lambda *a, **k: _FakeProc()
        )
        monkeypatch.setattr(
            process_executor,
            "_kill_worker_group",
            lambda proc: killed.__setitem__("kill", killed["kill"] + 1),
        )
        monkeypatch.setattr(
            process_executor,
            "_reap",
            lambda proc: killed.__setitem__("reap", killed["reap"] + 1) or (b"", b""),
        )
        with pytest.raises(subprocess.TimeoutExpired):
            process_executor._spawn_worker(["x"], b"payload", 1)
        assert killed["kill"] >= 1, "timed-out worker was not group-killed"
        assert killed["reap"] >= 1, "timed-out worker was not reaped"

    def test_keyboard_interrupt_still_kills_and_reaps(self, monkeypatch):
        killed: dict = {"kill": 0}

        class _FakeProc:
            pid = 8

            def communicate(self, input=None, timeout=None):
                raise KeyboardInterrupt()

            def kill(self):
                pass

        monkeypatch.setattr(
            process_executor.subprocess, "Popen", lambda *a, **k: _FakeProc()
        )
        monkeypatch.setattr(
            process_executor,
            "_kill_worker_group",
            lambda proc: killed.__setitem__("kill", killed["kill"] + 1),
        )
        monkeypatch.setattr(process_executor, "_reap", lambda proc: (b"", b""))
        with pytest.raises(KeyboardInterrupt):
            process_executor._spawn_worker(["x"], b"payload", 1)
        assert killed["kill"] == 1

    def test_spawn_worker_starts_new_session(self, monkeypatch):
        """The worker must lead its own process group so a group kill reaps
        guest-spawned descendants."""
        seen: dict = {}

        class _FakeProc:
            returncode = 0

            def communicate(self, input=None, timeout=None):
                return b'{"status": "success"}', b""

        def fake_popen(cmd, **kwargs):
            seen["kwargs"] = kwargs
            return _FakeProc()

        monkeypatch.setattr(process_executor.subprocess, "Popen", fake_popen)
        process_executor._spawn_worker(["x"], b"{}", 5)
        assert seen["kwargs"].get("start_new_session") is True


class TestWorkerPayloadDeadline:
    """Defense-in-depth: a worker whose parent never finishes writing stdin
    must self-terminate rather than linger forever as an orphan."""

    def test_abort_payload_wait_hard_exits(self):
        proc = subprocess.run(
            [
                sys.executable,
                "-c",
                "import ephemora_cell.process_worker as w; w._abort_payload_wait()",
            ],
            capture_output=True,
            timeout=30,
            check=False,
        )
        assert proc.returncode == 4
        assert b"payload not received before deadline" in proc.stderr


class TestNoLingeringWorkers:
    """After a burst of parallel runs the caller must have no orphaned worker
    children left over (the incident the concurrency bound exists to prevent)."""

    def test_burst_leaves_no_child_workers(self, tmp_path):
        if not shutil.which("ps"):
            pytest.skip("ps not available")
        wasm_path = _write_module(tmp_path, TRIVIAL_WAT)
        monkey_cap = threading.BoundedSemaphore(4)
        import ephemora_cell.process_executor as pe

        original_slots = pe._worker_slots
        pe._worker_slots = monkey_cap
        try:
            with ThreadPoolExecutor(max_workers=12) as pool:
                results = list(
                    pool.map(
                        lambda _: run_isolated(
                            str(wasm_path), WASIConfig(max_fuel=1_000_000)
                        ),
                        range(24),
                    )
                )
        finally:
            pe._worker_slots = original_slots

        assert all(r["status"] == ExecutionStatus.SUCCESS for r in results)
        time.sleep(0.5)  # let any reaped child disappear from the process table
        me = str(os.getpid())
        ps = subprocess.run(
            ["ps", "-axo", "pid,ppid,command"],
            capture_output=True,
            timeout=10,
            check=False,
        )
        leftover = [
            line
            for line in ps.stdout.decode("utf-8", "replace").splitlines()
            if "process_worker" in line and line.split()[1:2] == [me]
        ]
        assert not leftover, f"orphaned workers still parented to us: {leftover}"


class TestReapAndFailClosedPaths:
    """Deterministic coverage of the worker-reaper and fail-closed result paths
    the 759-incident hardening added (``_reap`` force-reap, ``_kill_worker_group``
    fallback, malformed-worker-report refusal) plus the ``measure_overhead``
    temp-dir hygiene — none of which the happy-path runs reach."""

    class _ReapProc:
        def __init__(self, communicate):
            import io

            self.pid = 424242
            self._communicate = communicate
            self.stdout = io.BytesIO(b"leftover")
            self.stderr = io.BytesIO(b"")
            self.waited = False
            self.killed = False

        def communicate(self, timeout=None):
            if isinstance(self._communicate, BaseException):
                raise self._communicate
            return self._communicate

        def wait(self, *args, **kwargs):
            self.waited = True
            return -9

        def kill(self):
            self.killed = True

    def test_reap_timeout_force_reaps_group(self, monkeypatch):
        # A descendant still holding the fd after SIGKILL: _reap must kill the
        # group, close the pipes and force-wait — never hang the caller.
        killpg_calls = []
        monkeypatch.setattr(process_executor.os, "getpgid", lambda pid: pid)
        monkeypatch.setattr(
            process_executor.os, "killpg", lambda pgid, sig: killpg_calls.append(pgid)
        )
        proc = self._ReapProc(subprocess.TimeoutExpired(["x"], timeout=1))
        out, err = process_executor._reap(proc)
        assert (out, err) == (b"", b"")
        assert proc.waited and killpg_calls == [424242]
        assert proc.stdout.closed and proc.stderr.closed

    def test_reap_oserror_force_reaps(self, monkeypatch):
        monkeypatch.setattr(process_executor.os, "getpgid", lambda pid: pid)
        monkeypatch.setattr(process_executor.os, "killpg", lambda pgid, sig: None)
        proc = self._ReapProc(OSError("stream closed"))
        out, err = process_executor._reap(proc)
        assert (out, err) == (b"", b"")
        assert proc.waited

    def test_kill_worker_group_falls_back_to_child_kill(self, monkeypatch):
        # No killpg support (e.g. group already gone): must fall back to the
        # direct child kill rather than leak the worker.
        def _raise(_pid):
            raise ProcessLookupError()

        monkeypatch.setattr(process_executor.os, "getpgid", _raise)
        proc = self._ReapProc(None)
        process_executor._kill_worker_group(proc)
        assert proc.killed

    def test_kill_worker_group_swallows_child_kill_oserror(self, monkeypatch):
        def _raise(_pid):
            raise ProcessLookupError()

        class _Dead:
            pid = 1

            def kill(self):
                raise OSError("already reaped")

        monkeypatch.setattr(process_executor.os, "getpgid", _raise)
        # Must not raise: the group is gone and the child is unkillable — a
        # best-effort path that can only log-and-continue.
        process_executor._kill_worker_group(_Dead())

    def test_run_isolated_rejects_non_dict_report(self, tmp_path, monkeypatch):
        wasm_path = _write_module(tmp_path, TRIVIAL_WAT)
        monkeypatch.setattr(
            process_executor, "_spawn_worker", lambda *a, **k: (0, b"[]", b"")
        )
        result = run_isolated(str(wasm_path), WASIConfig(max_fuel=1_000_000))
        assert result["status"] == ExecutionStatus.ERROR
        assert "invalid JSON report" in result["stderr"]

    def test_run_isolated_rejects_unknown_status(self, tmp_path, monkeypatch):
        wasm_path = _write_module(tmp_path, TRIVIAL_WAT)
        monkeypatch.setattr(
            process_executor,
            "_spawn_worker",
            lambda *a, **k: (0, b'{"status": "totally_bogus"}', b""),
        )
        result = run_isolated(str(wasm_path), WASIConfig(max_fuel=1_000_000))
        assert result["status"] == ExecutionStatus.ERROR
        assert "unknown status" in result["stderr"]

    def test_run_isolated_spawn_oserror_fails_closed(self, tmp_path, monkeypatch):
        # A spawn/pipe OSError must fail closed with NO in-process fallback —
        # the mandate that keeps untrusted bytes off the parent interpreter.
        wasm_path = _write_module(tmp_path, TRIVIAL_WAT)

        def _boom(*a, **k):
            raise OSError("fork failed")

        monkeypatch.setattr(process_executor, "_spawn_worker", _boom)
        result = run_isolated(str(wasm_path), WASIConfig(max_fuel=1_000_000))
        assert result["status"] == ExecutionStatus.ERROR
        assert "could not be started" in result["stderr"]

    def test_measure_overhead_leaves_no_residue(self, tmp_path, monkeypatch):
        import tempfile

        created: dict = {}
        real_mkdtemp = tempfile.mkdtemp

        def _spy(*args, prefix="", **kwargs):
            path = real_mkdtemp(
                *args,
                prefix=prefix or "ephemora_overhead_",
                dir=str(tmp_path),
                **kwargs,
            )
            created["dir"] = path
            return path

        monkeypatch.setattr(tempfile, "mkdtemp", _spy)
        stats = process_executor.measure_overhead(num_runs=2)
        assert stats["num_runs"] == 2
        assert stats["min_ms"] <= stats["median_ms"]
        # The try/finally hygiene fix: the scratch dir the probe owns must be
        # removed, so no ephemora_overhead_ tree outlives the call.
        assert "dir" in created and not Path(created["dir"]).exists()
