# SPDX-License-Identifier: BUSL-1.1
# Copyright 2026 Michael Soppa

"""The first attempt is measured, or explicitly unknown.

The worker's stdout is its JSON report; its stderr is worker diagnostics. Neither
is guest output. A complete report written before a non-zero teardown is
recoverable; without one, the guest byte counts are None (unknown), never 0.
"""

from __future__ import annotations

import json
import os
import sys

import pytest

sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))

from ephemora_cell import WASIConfig, WASISandbox
from ephemora_cell._lang_common import shape_result
from ephemora_cell.execution_report import ExecutionReport
from ephemora_cell.process_executor import WorkerSpawnError, run_isolated
from ephemora_cell.wasi_runtime import ExecutionResult, ExecutionStatus
from ephemora_cell_mcp.engine import build_report as build_mcp_report

WAT = (
    '(module (import "wasi_snapshot_preview1" "proc_exit" '
    '(func $exit (param i32))) (memory (export "memory") 1) '
    '(func (export "_start") i32.const 0 call $exit))'
)


def _module(tmp_path) -> str:
    import wasmtime

    path = tmp_path / "trivial.wasm"
    path.write_bytes(wasmtime.wat2wasm(WAT))
    return str(path)


def _report(**overrides) -> bytes:
    payload = {
        "status": "success",
        "exit_code": 0,
        "stdout": "ok",
        "stderr": "",
        "elapsed_ms": 1.0,
        "fuel_consumed": 1,
        "sandbox_dir": None,
        "baseline_ms": 0.0,
        "execution_started": True,
    }
    payload.update(overrides)
    payload.setdefault(
        "io_bytes_written",
        len(str(payload.get("stdout", "")).encode("utf-8"))
        + len(str(payload.get("stderr", "")).encode("utf-8")),
    )
    return json.dumps(payload).encode()


def _run_with_spawn(monkeypatch, tmp_path, first, later=None, config=None):
    calls = {"n": 0}

    def fake_spawn(cmd, payload, process_timeout, env):
        calls["n"] += 1
        return first if calls["n"] == 1 else (later or _success())

    monkeypatch.setattr("ephemora_cell.process_executor._spawn_worker", fake_spawn)
    return run_isolated(
        _module(tmp_path),
        config if config is not None else WASIConfig(max_fuel=1_000_000),
    )


def _write_capture(env, name, data):
    root = os.environ.get("TMPDIR") if env is None else env.get("TMPDIR")
    assert root
    with open(os.path.join(root, name), "wb") as handle:
        handle.write(data)


def _run_with_capture(monkeypatch, tmp_path, raw, captured, **kwargs):
    calls = {"n": 0}

    def fake_spawn(cmd, payload, process_timeout, env):
        calls["n"] += 1
        if calls["n"] == 1:
            _write_capture(env, "stdout.txt", captured)
            return raw
        return _success()

    monkeypatch.setattr("ephemora_cell.process_executor._spawn_worker", fake_spawn)
    return run_isolated(
        _module(tmp_path),
        kwargs.get("config") or WASIConfig(max_fuel=1_000_000),
    )


def _success():
    return 0, _report(), b""


def test_an_oserror_before_popen_is_proven_not_started(monkeypatch, tmp_path):
    def boom(*args, **kwargs):
        raise WorkerSpawnError("fork failed", started=False)

    monkeypatch.setattr("ephemora_cell.process_executor._spawn_worker", boom)
    result = run_isolated(_module(tmp_path), WASIConfig(max_fuel=1000))
    assert result["status"] == ExecutionStatus.ERROR
    assert result["worker_started"] is False
    assert result["execution_started"] is False


def test_an_oserror_after_popen_is_unknown_not_zero(monkeypatch, tmp_path):
    def boom(*args, **kwargs):
        raise WorkerSpawnError("pipe broke", started=True)

    monkeypatch.setattr("ephemora_cell.process_executor._spawn_worker", boom)
    result = run_isolated(_module(tmp_path), WASIConfig(max_fuel=1000))
    assert result["status"] == ExecutionStatus.ERROR
    assert result["worker_started"] is True
    assert result["execution_started"] is True


def test_a_crash_without_a_report_uses_the_host_scan(monkeypatch, tmp_path):
    result = _run_with_capture(
        monkeypatch,
        tmp_path,
        (1, b"", b"tokio-rt-worker panicked"),
        b"guest-bytes",
    )
    assert result["status"] == ExecutionStatus.SUCCESS
    assert result["first_attempt_fuel_consumed"] is None
    assert result["first_attempt_stdout_bytes"] is None
    assert result["first_attempt_stderr_bytes"] is None
    assert result["first_attempt_output_bytes_observed"] == len(b"guest-bytes")
    assert result["first_attempt_output_unknown"] is True
    assert result["first_attempt_report_bytes"] == 0
    assert result["first_attempt_worker_stderr_bytes"] == len(
        b"tokio-rt-worker panicked"
    )
    assert result["first_attempt_execution_started"] is True


def test_a_crash_with_writable_preopens_stays_unknown(monkeypatch, tmp_path):
    # The host scan sees only the scratch root; an allow_dirs preopen is a
    # second writable scope, so an empty scratch root is not proof of zero.
    result = _run_with_spawn(
        monkeypatch,
        tmp_path,
        (1, b"", b"panic"),
        config=WASIConfig(max_fuel=1_000_000, allow_dirs=(str(tmp_path),)),
    )
    assert result["status"] == ExecutionStatus.ERROR
    assert result["first_attempt_output_unknown"] is True
    assert result["first_attempt_output_bytes_observed"] == 0


def test_a_complete_report_before_a_nonzero_exit_is_recovered(monkeypatch, tmp_path):
    recovered = _report(
        status="error",
        exit_code=1,
        stdout="guest-out",
        stderr="guest-err",
        fuel_consumed=321,
        execution_started=True,
    )
    result = _run_with_spawn(monkeypatch, tmp_path, (1, recovered, b"panic"))
    assert result["first_attempt_fuel_consumed"] == 321
    assert result["first_attempt_stdout_bytes"] == len(b"guest-out")
    assert result["first_attempt_stderr_bytes"] == len(b"guest-err")
    assert result["first_attempt_output_unknown"] is False
    assert result["first_attempt_report_bytes"] == len(recovered)
    assert result["first_attempt_worker_stderr_bytes"] == len(b"panic")


def test_the_report_pipe_length_is_not_guest_output(monkeypatch, tmp_path):
    pipe = b"not-a-json-report"
    result = _run_with_capture(monkeypatch, tmp_path, (1, pipe, b"panic"), b"abc")
    assert result["first_attempt_stdout_bytes"] is None
    assert result["first_attempt_stderr_bytes"] is None
    assert result["first_attempt_output_bytes_observed"] == 3
    assert result["first_attempt_output_unknown"] is True
    assert result["first_attempt_report_bytes"] == len(pipe)
    assert result["first_attempt_worker_stderr_bytes"] == len(b"panic")


def test_a_partial_report_still_uses_the_host_scan(monkeypatch, tmp_path):
    result = _run_with_capture(
        monkeypatch,
        tmp_path,
        (1, b'{"status":"error"}', b"panic"),
        b"data",
    )
    assert result["first_attempt_stdout_bytes"] is None
    assert result["first_attempt_stderr_bytes"] is None
    assert result["first_attempt_output_bytes_observed"] == len(b"data")
    assert result["first_attempt_output_unknown"] is True
    assert result["first_attempt_report_bytes"] == len(b'{"status":"error"}')


def test_a_measured_zero_output_report_stays_zero(monkeypatch, tmp_path):
    recovered = _report(
        status="error",
        exit_code=1,
        stdout="",
        stderr="",
        fuel_consumed=0,
    )
    result = _run_with_spawn(monkeypatch, tmp_path, (1, recovered, b""))
    assert result["first_attempt_fuel_consumed"] == 0
    assert result["first_attempt_stdout_bytes"] == 0
    assert result["first_attempt_stderr_bytes"] == 0
    assert result["first_attempt_output_unknown"] is False
    assert result["first_attempt_report_bytes"] == len(recovered)


def _unknown_result() -> ExecutionResult:
    return ExecutionResult(
        status=ExecutionStatus.SUCCESS,
        exit_code=0,
        stdout="ok",
        stderr="",
        elapsed_ms=1.0,
        fuel_consumed=1,
        abi="preview1",
        guest_exit_observed=True,
        worker_attempts=2,
        first_attempt_crashed=True,
        first_attempt_error="worker crashed: panic",
        first_attempt_fuel_consumed=None,
        first_attempt_stdout_bytes=None,
        first_attempt_stderr_bytes=None,
        first_attempt_output_unknown=True,
        first_attempt_execution_started=True,
        first_attempt_report_bytes=12,
        first_attempt_worker_stderr_bytes=5,
        first_attempt_wall_ms=42,
    )


def test_mcp_meta_does_not_invent_zero_for_unknown_output():
    payload = build_mcp_report(_unknown_result(), WASIConfig()).to_dict()
    assert payload["first_attempt_output_bytes"] is None
    assert payload["first_attempt_output_unknown"] is True
    assert payload["first_attempt_report_bytes"] == 12
    assert payload["first_attempt_worker_stderr_bytes"] == 5
    assert payload["first_attempt_fuel_consumed"] is None


def test_language_report_does_not_invent_zero_for_unknown_output():
    payload = shape_result(_unknown_result(), config=WASIConfig())
    assert payload["first_attempt_output_bytes"] is None
    assert payload["first_attempt_output_unknown"] is True
    assert payload["first_attempt_fuel_consumed"] is None


def test_a_single_invalid_report_keeps_the_marker_in_mcp(monkeypatch, tmp_path):
    """Verifier: worker_attempts=1 + invalid report hid the unknown marker."""
    monkeypatch.setattr(
        "ephemora_cell.process_executor._spawn_worker",
        lambda *a, **k: (0, b"[]", b""),
    )
    report = run_isolated(
        _module(tmp_path),
        WASIConfig(max_fuel=1000, allow_dirs=(str(tmp_path),)),
    )
    assert report["worker_attempts"] == 1
    assert report["first_attempt_crashed"] is False
    assert report["first_attempt_output_unknown"] is True
    assert report["first_attempt_report_bytes"] == 2

    result = WASISandbox._result_from_report(report)
    payload = build_mcp_report(result, WASIConfig()).to_dict()
    assert payload["first_attempt_output_bytes"] is None
    assert payload["first_attempt_output_unknown"] is True
    assert payload["first_attempt_report_bytes"] == 2


def test_signed_record_carries_and_binds_the_unknown_marker():
    pytest.importorskip("cryptography")
    from cryptography.exceptions import InvalidSignature
    from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

    key = Ed25519PrivateKey.generate()
    public = key.public_key()

    def verifier(canonical, signature):
        try:
            public.verify(signature, canonical)
            return True
        except InvalidSignature:
            return False

    report = ExecutionReport(
        status="success",
        exit_code=0,
        elapsed_ms=1.0,
        fuel_consumed=1,
        worker_attempts=2,
        first_attempt_crashed=True,
        first_attempt_error="worker crashed: panic",
        first_attempt_fuel_consumed=None,
        first_attempt_output_bytes=None,
        first_attempt_output_unknown=True,
        first_attempt_execution_started=True,
        first_attempt_report_bytes=12,
        first_attempt_worker_stderr_bytes=5,
        first_attempt_wall_ms=42,
    )
    payload = report.to_dict()
    assert payload["first_attempt_output_bytes"] is None
    assert payload["first_attempt_output_unknown"] is True
    assert payload["first_attempt_report_bytes"] == 12

    signed = report.sign(key.sign, alg="EdDSA")
    assert ExecutionReport.verify(signed, verifier)
    tampered = dict(signed)
    tampered["first_attempt_output_unknown"] = False
    assert not ExecutionReport.verify(tampered, verifier)
