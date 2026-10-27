# SPDX-License-Identifier: BUSL-1.1
# Copyright 2026 Michael Soppa

"""MCP `_meta` carries the worker retry history (containment)."""

from __future__ import annotations

from ephemora_cell import WASIConfig
from ephemora_cell.wasi_runtime import ExecutionResult, ExecutionStatus
from ephemora_cell_mcp.engine import build_report


def test_build_report_carries_a_successful_retry():
    result = ExecutionResult(
        status=ExecutionStatus.SUCCESS,
        exit_code=0,
        stdout="ok",
        abi="preview1",
        guest_exit_observed=True,
        worker_attempts=2,
        first_attempt_crashed=True,
        first_attempt_error="worker crashed: tokio-rt-worker panicked",
        first_attempt_stdout_bytes=5,
        first_attempt_stderr_bytes=7,
        first_attempt_wall_ms=42,
    )
    payload = build_report(result, WASIConfig()).to_dict()
    assert payload["worker_attempts"] == 2
    assert payload["first_attempt_crashed"] is True
    assert "tokio-rt-worker panicked" in payload["first_attempt_error"]
    assert payload["first_attempt_output_bytes"] == 12
    assert payload["first_attempt_wall_ms"] == 42
    assert payload["first_attempt_fuel_consumed"] is None
    assert "worker_crashed" not in payload


def test_build_report_carries_a_final_worker_crash():
    result = ExecutionResult(
        status=ExecutionStatus.ERROR,
        exit_code=1,
        abi="preview1",
        worker_crashed=True,
        worker_attempts=2,
        first_attempt_crashed=True,
        first_attempt_error="worker crashed: panic",
    )
    payload = build_report(result, WASIConfig()).to_dict()
    assert payload["worker_crashed"] is True
    assert payload["worker_attempts"] == 2
    assert payload["first_attempt_crashed"] is True


def test_build_report_carries_first_attempt_resources_without_a_retry():
    result = ExecutionResult(
        status=ExecutionStatus.ERROR,
        exit_code=1,
        abi="preview1",
        worker_crashed=True,
        worker_attempts=1,
        first_attempt_crashed=True,
        first_attempt_error="worker crashed: panic",
        first_attempt_fuel_consumed=None,
        first_attempt_stdout_bytes=3,
        first_attempt_stderr_bytes=4,
        first_attempt_wall_ms=55,
        retry_suppressed_reason="host_grants",
    )
    payload = build_report(result, WASIConfig()).to_dict()
    assert payload["first_attempt_output_bytes"] == 7
    assert payload["first_attempt_wall_ms"] == 55
    assert payload["first_attempt_fuel_consumed"] is None
    assert payload["retry_suppressed_reason"] == "host_grants"
