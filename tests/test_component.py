"""WASI 0.2 component runtime tests (dual-ABI opt-in)."""

import os
import shutil
import tempfile
from pathlib import Path

import pytest

from ephemora_cell import (
    ComponentSandbox,
    ExecutionStatus,
    WASIConfig,
    WASISandbox,
    is_component_binary,
    run_wasm,
)

FIXTURES = os.path.join(os.path.dirname(__file__), "fixtures")
HELLO02 = os.path.join(FIXTURES, "hello02.wasm")
FS02 = os.path.join(FIXTURES, "fs02.wasm")
WAT_RUN = os.path.join(FIXTURES, "wat_run.wasm")
WAT_LOOP = os.path.join(FIXTURES, "wat_loop.wasm")
WAT_NO_RUN = os.path.join(FIXTURES, "wat_no_run.wasm")


@pytest.fixture
def tmp_dir():
    d = tempfile.mkdtemp(prefix="ephemora_component_test_")
    yield d
    shutil.rmtree(d, ignore_errors=True)


class TestComponentDetection:
    def test_hello_fixture_is_component(self):
        assert is_component_binary(HELLO02) is True
        assert is_component_binary(FS02) is True

    def test_core_module_is_not_component(self):
        import tempfile as tf

        import wasmtime

        wat = (
            b'(module (import "wasi_snapshot_preview1" "proc_exit" '
            b'(func $exit (param i32))) (memory (export "memory") 1) '
            b'(func (export "_start") i32.const 0 call $exit))'
        )
        p = os.path.join(tf.gettempdir(), "core.wasm")
        with open(p, "wb") as f:
            f.write(wasmtime.wat2wasm(wat))
        assert is_component_binary(p) is False

    def test_missing_file_is_not_component(self):
        assert is_component_binary("/nonexistent/nope.wasm") is False


class TestHelloComponent:
    def test_run_success(self):
        sandbox = ComponentSandbox(WASIConfig(max_fuel=5_000_000))
        result = sandbox.run(HELLO02)
        try:
            assert result.status == ExecutionStatus.SUCCESS
            assert result.exit_code == 0
            assert "hello from wasip2 component" in result.stdout
        finally:
            sandbox.cleanup()

    def test_fuel_consumed_reported(self):
        """ComponentSandbox reports fuel_consumed."""
        sandbox = ComponentSandbox(WASIConfig(max_fuel=5_000_000))
        result = sandbox.run(HELLO02)
        try:
            assert result.status == ExecutionStatus.SUCCESS
            assert result.fuel_consumed is not None
            assert 0 < result.fuel_consumed < 5_000_000
        finally:
            sandbox.cleanup()

    def test_fuel_consumed_none_without_metering(self):
        sandbox = ComponentSandbox(WASIConfig(max_fuel=None))
        result = sandbox.run(HELLO02)
        try:
            assert result.status == ExecutionStatus.SUCCESS
            assert result.fuel_consumed is None
        finally:
            sandbox.cleanup()

    def test_fuel_exhausted_reports_consumption(self):
        """FUEL_EXHAUSTED reports fuel_consumed (all budget spent)."""
        sandbox = ComponentSandbox(WASIConfig(max_fuel=10))
        result = sandbox.run(HELLO02)
        try:
            assert result.status == ExecutionStatus.FUEL_EXHAUSTED
            assert result.fuel_consumed == 10
        finally:
            sandbox.cleanup()

    def test_args_and_env_passthrough(self):
        sandbox = ComponentSandbox(
            WASIConfig(
                max_fuel=5_000_000,
                allow_env=(("EPHEMORA_TEST", "42"),),
            )
        )
        result = sandbox.run(HELLO02, args=["world"])
        try:
            assert result.status == ExecutionStatus.SUCCESS
            assert "arg1=world" in result.stdout
            assert "env_ephemora_test=42" in result.stdout
        finally:
            sandbox.cleanup()

    def test_no_env_leak(self):
        os.environ["EPHEMORA_TEST"] = "leaked"
        sandbox = ComponentSandbox(WASIConfig(max_fuel=5_000_000))
        result = sandbox.run(HELLO02)
        try:
            assert result.status == ExecutionStatus.SUCCESS
            assert "env_ephemora_test=leaked" not in result.stdout
            assert "env_ephemora_test=" in result.stdout
        finally:
            sandbox.cleanup()
            os.environ.pop("EPHEMORA_TEST", None)

    def test_auto_abi_dispatch(self):
        result = run_wasm(HELLO02, max_fuel=5_000_000)
        assert result.status == ExecutionStatus.SUCCESS
        assert "hello from wasip2 component" in result.stdout

    def test_missing_module(self):
        sandbox = ComponentSandbox()
        result = sandbox.run("/nonexistent/nope.wasm")
        try:
            assert result.status == ExecutionStatus.ERROR
        finally:
            sandbox.cleanup()

    def test_core_module_rejected(self):
        import wasmtime

        wat = (
            b'(module (import "wasi_snapshot_preview1" "proc_exit" '
            b'(func $exit (param i32))) (memory (export "memory") 1) '
            b'(func (export "_start") i32.const 0 call $exit))'
        )
        with tempfile.NamedTemporaryFile(suffix=".wasm", delete=False) as f:
            f.write(wasmtime.wat2wasm(wat))
            p = f.name
        sandbox = ComponentSandbox()
        result = sandbox.run(p)
        try:
            assert result.status == ExecutionStatus.ERROR
            assert "Not a component binary" in result.stderr
        finally:
            sandbox.cleanup()
            os.unlink(p)

    def test_abi_preview1_forces_core_path(self):
        sandbox = WASISandbox(WASIConfig(max_fuel=5_000_000))
        result = sandbox.run(HELLO02, abi="preview1")
        try:
            # Component bytes fed to the preview1 runtime must error cleanly.
            assert result.status == ExecutionStatus.ERROR
        finally:
            sandbox.cleanup()

    def test_abi_component_forces_component_path(self):
        import wasmtime

        wat = (
            b'(module (import "wasi_snapshot_preview1" "proc_exit" '
            b'(func $exit (param i32))) (memory (export "memory") 1) '
            b'(func (export "_start") i32.const 0 call $exit))'
        )
        with tempfile.NamedTemporaryFile(suffix=".wasm", delete=False) as f:
            f.write(wasmtime.wat2wasm(wat))
            p = f.name
        sandbox = WASISandbox(WASIConfig(max_fuel=5_000_000))
        result = sandbox.run(p, abi="component")
        try:
            assert result.status == ExecutionStatus.ERROR
            assert "Not a component binary" in result.stderr
        finally:
            sandbox.cleanup()
            os.unlink(p)


class TestFilesystemComponent:
    def test_write_to_preopen_dir(self):
        # macOS realpaths /var & /tmp into /private, which the canonical
        # allowlist rejects by design — use the home dir like test_io_budget.
        target = Path.home() / f".ephemora_component_preopen_{os.getpid()}"
        target.mkdir(parents=True, exist_ok=True)
        sandbox = ComponentSandbox(
            WASIConfig(max_fuel=5_000_000, allow_dirs=(str(target),))
        )
        try:
            result = sandbox.run(FS02, args=[str(target)])
            assert result.status == ExecutionStatus.SUCCESS
            with open(os.path.join(target, "out.txt")) as f:
                assert f.read() == "pwned-by-component\n"
        finally:
            sandbox.cleanup()
            shutil.rmtree(target, ignore_errors=True)

    def test_write_blocked_without_preopen(self, tmp_dir):
        target = os.path.join(tmp_dir, "preopen")
        os.mkdir(target)
        sandbox = ComponentSandbox(WASIConfig(max_fuel=5_000_000))
        result = sandbox.run(FS02, args=[target])
        try:
            assert result.status == ExecutionStatus.ERROR
            assert not os.path.exists(os.path.join(target, "out.txt"))
        finally:
            sandbox.cleanup()

    def test_forbidden_allow_dir_rejected(self):
        with pytest.raises(ValueError, match="forbidden"):
            ComponentSandbox(WASIConfig(allow_dirs=("/etc",)))
        with pytest.raises(ValueError, match="forbidden"):
            ComponentSandbox(WASIConfig(allow_dirs=("/",)))


class TestWATComponents:
    def test_direct_run_export(self):
        sandbox = ComponentSandbox(WASIConfig(max_fuel=1_000_000))
        result = sandbox.run(WAT_RUN)
        try:
            assert result.status == ExecutionStatus.SUCCESS
            assert result.exit_code == 0
        finally:
            sandbox.cleanup()

    def test_fuel_exhaustion(self):
        sandbox = ComponentSandbox(WASIConfig(max_fuel=1_000))
        result = sandbox.run(WAT_LOOP)
        try:
            assert result.status == ExecutionStatus.FUEL_EXHAUSTED
        finally:
            sandbox.cleanup()

    def test_timeout_via_epoch(self):
        sandbox = ComponentSandbox(WASIConfig(max_fuel=None, timeout_seconds=1))
        result = sandbox.run(WAT_LOOP)
        try:
            assert result.status == ExecutionStatus.TIMEOUT
            assert "Timeout after 1s" in result.stderr
        finally:
            sandbox.cleanup()

    def test_no_run_export_rejected(self):
        sandbox = ComponentSandbox(WASIConfig(max_fuel=1_000_000))
        result = sandbox.run(WAT_NO_RUN)
        try:
            assert result.status == ExecutionStatus.ERROR
            assert "no wasi:cli/run export" in result.stderr
        finally:
            sandbox.cleanup()


class TestSubprocess:
    def test_run_isolated_component(self):
        from ephemora_cell import run_isolated

        report = run_isolated(HELLO02, WASIConfig(max_fuel=5_000_000), abi="auto")
        assert report["status"] == ExecutionStatus.SUCCESS
        assert "hello from wasip2 component" in report["stdout"]
        assert "baseline_ms" in report

    def test_run_isolated_auto_core_module(self):
        import wasmtime

        from ephemora_cell import run_isolated

        wat = (
            b'(module (import "wasi_snapshot_preview1" "proc_exit" '
            b'(func $exit (param i32))) (memory (export "memory") 1) '
            b'(func (export "_start") i32.const 0 call $exit))'
        )
        with tempfile.NamedTemporaryFile(suffix=".wasm", delete=False) as f:
            f.write(wasmtime.wat2wasm(wat))
            p = f.name
        try:
            report = run_isolated(p, WASIConfig(max_fuel=1_000_000))
            assert report["status"] == ExecutionStatus.SUCCESS
        finally:
            os.unlink(p)
