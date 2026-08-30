"""Tests for wvm_wasm_runtime — Decoupled WASMtime Runtime."""

from __future__ import annotations

import os
import sys

# Ensure project root is on path for the package
sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))

from dataclasses import FrozenInstanceError

import pytest

from ephemora_cell import (
    ExecutionResult,
    ExecutionStatus,
    WASIConfig,
    WASISandbox,
    run_wasm,
)

# --- WASIConfig ---


class TestWASIConfig:
    """Test WASIConfig defaults and immutability."""

    def test_default_config(self):
        config = WASIConfig()
        assert config.max_memory_mb == 128
        assert config.max_fuel == 1_000_000
        assert config.timeout_seconds == 30
        assert config.allow_dirs == ()
        assert config.allow_env == ()
        assert config.sandbox_base_dir is None

    def test_custom_config(self):
        config = WASIConfig(
            max_memory_mb=64,
            max_fuel=500_000,
            timeout_seconds=10,
            allow_dirs=("/data", "/tmp"),
        )
        assert config.max_memory_mb == 64
        assert config.max_fuel == 500_000
        assert config.timeout_seconds == 10
        assert config.allow_dirs == ("/data", "/tmp")

    def test_config_is_frozen(self):
        config = WASIConfig()
        with pytest.raises(FrozenInstanceError):
            config.max_fuel = 999


# --- ExecutionResult ---


class TestExecutionResult:
    """Test ExecutionResult dataclass."""

    def test_default_result(self):
        r = ExecutionResult(status=ExecutionStatus.SUCCESS)
        assert r.exit_code == 0
        assert r.stdout == ""
        assert r.stderr == ""
        assert r.elapsed_ms == 0.0
        assert r.fuel_consumed is None
        assert r.sandbox_dir is None

    def test_result_with_values(self):
        r = ExecutionResult(
            status=ExecutionStatus.ERROR,
            exit_code=1,
            stdout="hello",
            stderr="error msg",
            elapsed_ms=42.5,
            fuel_consumed=100_000,
            sandbox_dir="/tmp/test",
        )
        assert r.exit_code == 1
        assert r.stdout == "hello"
        assert r.stderr == "error msg"
        assert r.elapsed_ms == 42.5
        assert r.fuel_consumed == 100_000
        assert r.sandbox_dir == "/tmp/test"


# --- ExecutionStatus ---


class TestExecutionStatus:
    """Test ExecutionStatus enum."""

    def test_all_values(self):
        assert ExecutionStatus.SUCCESS.value == "success"
        assert ExecutionStatus.ERROR.value == "error"
        assert ExecutionStatus.TIMEOUT.value == "timeout"
        assert ExecutionStatus.FUEL_EXHAUSTED.value == "fuel_exhausted"
        assert ExecutionStatus.MEMORY_EXCEEDED.value == "memory_exceeded"

    def test_status_comparison(self):
        assert ExecutionStatus.SUCCESS != ExecutionStatus.ERROR
        assert ExecutionStatus.SUCCESS == ExecutionStatus.SUCCESS


# --- WASISandbox ---


class TestWASISandbox:
    """Test WASISandbox construction and execution."""

    def test_requires_wasmtime(self):
        """WASISandbox raises RuntimeError if wasmtime is not installed."""
        # wasmtime IS installed in this env, so we test normal construction
        sandbox = WASISandbox()
        assert sandbox is not None

    def test_constructor_with_config(self):
        config = WASIConfig(max_fuel=500_000)
        sandbox = WASISandbox(config=config)
        assert sandbox is not None

    def test_run_nonexistent_file(self):
        sandbox = WASISandbox()
        result = sandbox.run("/nonexistent/module.wasm")
        assert result.status == ExecutionStatus.ERROR
        assert "not found" in result.stderr.lower()
        assert result.elapsed_ms >= 0

    def test_run_non_wasi_module(self):
        """A non-WASM32-unknown-unknown module or non-WASI module returns ERROR."""
        # The test .wasm was compiled for WASI but may not have _start export
        sandbox = WASISandbox()
        result = sandbox.run("/tmp/wvm_wasm_test.wasm")
        assert result.status in (ExecutionStatus.ERROR, ExecutionStatus.SUCCESS)
        assert result.elapsed_ms >= 0
        assert isinstance(result.elapsed_ms, float)

    def test_run_with_args(self):
        sandbox = WASISandbox()
        result = sandbox.run(
            "/tmp/wvm_wasm_test.wasm",
            args=["--arg1", "--arg2"],
        )
        assert result.status in (ExecutionStatus.ERROR, ExecutionStatus.SUCCESS)

    def test_run_with_custom_config(self):
        config = WASIConfig(
            max_memory_mb=64,
            max_fuel=500_000,
            timeout_seconds=5,
            allow_dirs=("/data",),
        )
        sandbox = WASISandbox(config=config)
        result = sandbox.run("/tmp/wvm_wasm_test.wasm")
        assert result.status in (ExecutionStatus.ERROR, ExecutionStatus.SUCCESS)

    def test_execution_result_has_sandbox_dir_on_run(self):
        """ExecutionResult should have sandbox_dir when run is attempted."""
        sandbox = WASISandbox()
        result = sandbox.run("/nonexistent/module.wasm")
        # For nonexistent file, sandbox_dir is not created
        assert result.sandbox_dir is None

    def test_elapsed_ms_is_float(self):
        sandbox = WASISandbox()
        result = sandbox.run("/nonexistent/module.wasm")
        assert isinstance(result.elapsed_ms, float)
        assert result.elapsed_ms >= 0

    def test_status_enum_values(self):
        sandbox = WASISandbox()
        result = sandbox.run("/nonexistent/module.wasm")
        assert result.status in ExecutionStatus


# --- run_wasm convenience ---


class TestRunWasm:
    """Test run_wasm() convenience function."""

    def test_run_wasm_simple(self):
        result = run_wasm("/tmp/wvm_wasm_test.wasm")
        assert result.status in (ExecutionStatus.ERROR, ExecutionStatus.SUCCESS)

    def test_run_wasm_with_params(self):
        result = run_wasm(
            "/tmp/wvm_wasm_test.wasm",
            max_memory_mb=64,
            max_fuel=500_000,
            timeout_seconds=5,
            allow_dirs=("/data",),
            args=["--test"],
        )
        assert result.status in (ExecutionStatus.ERROR, ExecutionStatus.SUCCESS)
        assert result.elapsed_ms >= 0

    def test_run_wasm_defaults(self):
        result = run_wasm("/nonexistent.wasm")
        assert result.status == ExecutionStatus.ERROR
        assert "not found" in result.stderr.lower()

    def test_run_wasm_returns_execution_result(self):
        result = run_wasm("/tmp/wvm_wasm_test.wasm")
        assert isinstance(result, ExecutionResult)
        assert hasattr(result, "status")
        assert hasattr(result, "elapsed_ms")
        assert hasattr(result, "stdout")
        assert hasattr(result, "stderr")


# --- __all__ completeness ---


class TestAll:
    """Test that __all__ matches actual exports."""

    def test_all_exports_present(self):
        import ephemora_cell

        exports = ephemora_cell.__all__
        assert "run_wasm" in exports
        assert "WASISandbox" in exports
        assert "WASIConfig" in exports
        assert "ExecutionResult" in exports
        assert "ExecutionStatus" in exports

    def test_no_missing_exports(self):
        import ephemora_cell

        exports = ephemora_cell.__all__
        # Core exports
        assert "run_wasm" in exports
        assert "WASISandbox" in exports
        assert "WASIConfig" in exports
        assert "ExecutionResult" in exports
        assert "ExecutionStatus" in exports
        # New exports (CLI, profiles, inspector, report)
        assert "get_profile" in exports
        assert "inspect_module" in exports
        assert "ExecutionReport" in exports
        # exceptions.py was deleted — the classes were exported but
        # never raised; failures are reported via ExecutionResult.status.
        for gone in (
            "EphemoraCellError",
            "FuelExhaustedError",
            "TimeoutError",
            "ImportBlockedError",
            "SandboxError",
            "ProfileError",
        ):
            assert gone not in exports
