"""Tests for process_executor — subprocess-level isolation."""

from __future__ import annotations

import json
import os
import shutil
import subprocess
import sys
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

        def fake_spawn(cmd, payload, process_timeout):
            return 1, b"", b"boom traceback"

        monkeypatch.setattr(process_executor, "_spawn_worker", fake_spawn)
        result = run_isolated(str(wasm_path), WASIConfig())
        assert result["status"] == ExecutionStatus.ERROR
        assert "worker crashed" in result["stderr"]
        assert "boom traceback" in result["stderr"]

    def test_non_json_output_reports_error(self, monkeypatch, tmp_path):
        wasm_path = _write_module(tmp_path, TRIVIAL_WAT)

        def fake_spawn(cmd, payload, process_timeout):
            return 0, b"this is not json", b""

        monkeypatch.setattr(process_executor, "_spawn_worker", fake_spawn)
        result = run_isolated(str(wasm_path), WASIConfig())
        assert result["status"] == ExecutionStatus.ERROR
        assert "invalid" in result["stderr"].lower()

    def test_empty_output_reports_error(self, monkeypatch, tmp_path):
        wasm_path = _write_module(tmp_path, TRIVIAL_WAT)

        def fake_spawn(cmd, payload, process_timeout):
            return 0, b"", b""

        monkeypatch.setattr(process_executor, "_spawn_worker", fake_spawn)
        result = run_isolated(str(wasm_path), WASIConfig())
        assert result["status"] == ExecutionStatus.ERROR

    def test_process_timeout_reports_timeout(self, monkeypatch, tmp_path):
        wasm_path = _write_module(tmp_path, TRIVIAL_WAT)

        def fake_spawn(cmd, payload, process_timeout):
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
            # flake the first real CI run exposed.
            deadline = time.monotonic() + 10.0
            while time.monotonic() < deadline and not future.done():
                ps = subprocess.run(
                    # -ww = unlimited command width: procps (Linux) truncates
                    # the command column at 80 chars otherwise, hiding the
                    # argv past the -c import line (the first real CI run
                    # proved the worker visible but truncated).
                    ["ps", "-axww", "-o", "command"],
                    capture_output=True,
                    timeout=5,
                )
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
    """RLIMIT application must stay wasmtime-compatible on Linux (CI #7)."""

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
