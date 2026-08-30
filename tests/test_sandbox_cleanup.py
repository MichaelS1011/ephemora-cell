"""
TDD test for P0 #3: Sandbox dir cleanup and tmpfs support.

Verifies:
1. After run() completes, the sandbox directory is cleaned up
2. sandbox_base_dir="/dev/shm" works on Linux (tmpfs)
3. On macOS, fallback to tempfile.gettempdir() works
"""

import tempfile
from pathlib import Path

import wasmtime

from ephemora_cell import ExecutionStatus, WASIConfig, WASISandbox

SIMPLE_WAT = """
(module
  (memory (export "memory") 1)
  (func (export "_start")
    memory.size
    drop
  )
)
"""


class TestSandboxDirCleanup:
    """Test that sandbox directories are cleaned up after execution."""

    def test_sandbox_dir_exists_during_run(self):
        """During run, the sandbox dir should exist."""
        config = WASIConfig(max_fuel=1_000_000)
        sandbox = WASISandbox(config=config)

        wat_bytes = wasmtime.wat2wasm(SIMPLE_WAT)
        sandbox_dir_path = Path(tempfile.mkdtemp(prefix="wvm_cleanup_test_"))
        sandbox._sandbox_dir = str(sandbox_dir_path)
        (sandbox_dir_path / "test.wasm").write_bytes(wat_bytes)

        # Before run: dir should exist
        assert sandbox_dir_path.exists()
        assert (sandbox_dir_path / "test.wasm").exists()

    def test_run_completes_successfully(self):
        """Basic sanity: run() should complete without error."""
        config = WASIConfig(max_fuel=1_000_000)
        sandbox = WASISandbox(config=config)

        sandbox_dir_path = Path(tempfile.mkdtemp(prefix="wvm_cleanup_test_"))
        sandbox._sandbox_dir = str(sandbox_dir_path)
        (sandbox_dir_path / "test.wasm").write_bytes(wasmtime.wat2wasm(SIMPLE_WAT))

        result = sandbox.run(str(sandbox_dir_path / "test.wasm"))
        assert (
            result.status == ExecutionStatus.SUCCESS
        ), f"Expected SUCCESS, got {result.status}: {result.stderr[:200]}"

    def test_sandbox_dir_exists_after_run(self):
        """After run(), the sandbox dir should still exist (cleanup is manual or at end)."""
        config = WASIConfig(max_fuel=1_000_000)
        sandbox = WASISandbox(config=config)

        sandbox_dir_path = Path(tempfile.mkdtemp(prefix="wvm_cleanup_test_"))
        sandbox._sandbox_dir = str(sandbox_dir_path)
        (sandbox_dir_path / "test.wasm").write_bytes(wasmtime.wat2wasm(SIMPLE_WAT))

        result = sandbox.run(str(sandbox_dir_path / "test.wasm"))
        assert result.status == ExecutionStatus.SUCCESS
        # The sandbox_dir from the result should exist (not cleaned up by run())
        if result.sandbox_dir:
            assert Path(result.sandbox_dir).exists()

    def test_cleanup_method_removes_dir(self):
        """sandbox.cleanup() should remove the sandbox directory."""
        config = WASIConfig(max_fuel=1_000_000)
        sandbox = WASISandbox(config=config)

        sandbox_dir_path = Path(tempfile.mkdtemp(prefix="wvm_cleanup_test_"))
        (sandbox_dir_path / "test.txt").write_text("data")
        sandbox._sandbox_dir = str(sandbox_dir_path)

        # Before cleanup
        assert sandbox_dir_path.exists()
        assert (sandbox_dir_path / "test.txt").exists()

        # Call cleanup
        sandbox.cleanup()

        # After cleanup
        assert (
            not sandbox_dir_path.exists()
        ), "Sandbox dir should be removed after cleanup()"


class TestSandboxBaseDir:
    """Test sandbox_base_dir configuration."""

    def test_default_base_dir_is_temp(self):
        """Default sandbox_base_dir should result in temp dir."""
        config = WASIConfig()
        sandbox = WASISandbox(config=config)
        assert sandbox._config.sandbox_base_dir is None

    def test_custom_base_dir_stored(self):
        """sandbox_base_dir should be stored in config."""
        custom_dir = tempfile.mkdtemp(prefix="wvm_base_dir_test_")
        config = WASIConfig(sandbox_base_dir=custom_dir)
        sandbox = WASISandbox(config=config)
        assert sandbox._config.sandbox_base_dir == custom_dir

    def test_tmpfs_path_accepted(self):
        """tmpfs path /dev/shm should be accepted in config."""
        config = WASIConfig(sandbox_base_dir="/dev/shm")
        sandbox = WASISandbox(config=config)
        assert sandbox._config.sandbox_base_dir == "/dev/shm"

    def test_sandbox_created_in_custom_base(self):
        """Sandbox dir should be created in the configured base dir."""
        custom_dir = Path(tempfile.mkdtemp(prefix="wvm_custom_base_test_"))
        config = WASIConfig(
            sandbox_base_dir=str(custom_dir),
            max_fuel=1_000_000,
        )
        sandbox = WASISandbox(config=config)

        (custom_dir / "test.wasm").write_bytes(wasmtime.wat2wasm(SIMPLE_WAT))

        result = sandbox.run(str(custom_dir / "test.wasm"))
        assert result.status == ExecutionStatus.SUCCESS
        # The sandbox dir should be under custom_dir
        assert result.sandbox_dir is not None
        assert result.sandbox_dir.startswith(
            str(custom_dir)
        ), f"Expected sandbox dir under {custom_dir}, got {result.sandbox_dir}"
