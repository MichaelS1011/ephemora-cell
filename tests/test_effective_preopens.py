"""The security baseline attests the EFFECTIVE preopens.

``apply_config`` must report the directories actually granted to the guest
(per ABI: preview1 additionally mounts /sandbox, component grants none of
that), not the configured ``allow_dirs``, which may contain entries that
were filtered out or never existed. Grant-time revalidation (TOCTOU)
must skip entries whose canonical path changed into a forbidden location
between config validation and the preopen grant.

Note: preopen targets live under $HOME (like tests/test_component.py) —
pytest's tmp_path sits in /private/var on macOS, which the canonical
allowlist forbids.
"""

from __future__ import annotations

import os
import shutil
import sys
import time
from pathlib import Path

import pytest
import wasmtime

sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))

from ephemora_cell import (
    ComponentSandbox,
    ExecutionReport,
    ExecutionStatus,
    WASIConfig,
    WASISandbox,
    run_isolated,
)

# WASI 0.2 component fixture (same file as tests/test_component.py uses).
HELLO02 = os.path.join(os.path.dirname(__file__), "fixtures", "hello02.wasm")

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


def _write_module(base: Path, name: str = "module.wasm") -> Path:
    path = base / name
    path.write_bytes(wasmtime.wat2wasm(TRIVIAL_WAT))
    return path


@pytest.fixture
def home_dir():
    """Grant-safe scratch dir under $HOME (never /private on macOS)."""
    d = Path.home() / f".ephemora_s2_{os.getpid()}_{time.monotonic_ns()}"
    d.mkdir()
    yield d
    shutil.rmtree(d, ignore_errors=True)


class TestPreview1Attestation:
    def test_granted_dir_and_sandbox_attested(self, home_dir):
        data = home_dir / "data"
        data.mkdir()
        config = WASIConfig(max_fuel=1_000_000, allow_dirs=(str(data),))
        sandbox = WASISandbox(config=config)
        try:
            result = sandbox.run(str(_write_module(home_dir)))
        finally:
            sandbox.cleanup()
        assert result.status == ExecutionStatus.SUCCESS
        canon = str(data.resolve())
        assert canon in result.effective_preopens
        assert "/sandbox" in result.effective_preopens

        report = ExecutionReport(
            status="success", exit_code=0, elapsed_ms=0.0
        ).apply_config(config, effective_preopens=result.effective_preopens)
        assert report.security_baseline["preopens"] == [canon, "/sandbox"]

    def test_nonexistent_dir_is_not_attested(self, home_dir):
        # Passes validation (not forbidden), but isdir() fails at grant time.
        ghost = str(home_dir / "ghost")
        config = WASIConfig(max_fuel=1_000_000, allow_dirs=(ghost,))
        sandbox = WASISandbox(config=config)
        try:
            result = sandbox.run(str(_write_module(home_dir)))
        finally:
            sandbox.cleanup()
        assert result.status == ExecutionStatus.SUCCESS
        assert result.effective_preopens == ("/sandbox",)

    def test_configured_only_when_no_run_result(self):
        # Without a live run result no grant is claimed: /sandbox must NOT
        # appear in a config-only baseline.
        config = WASIConfig(allow_dirs=("/data",))
        report = ExecutionReport(
            status="success", exit_code=0, elapsed_ms=0.0
        ).apply_config(config)
        assert report.security_baseline["preopens"] == ["/data"]


class TestComponentAttestation:
    def test_component_grants_dirs_but_no_sandbox_mount(self, home_dir):
        data = home_dir / "data"
        data.mkdir()
        config = WASIConfig(max_fuel=5_000_000, allow_dirs=(str(data),))
        sandbox = ComponentSandbox(config=config)
        try:
            result = sandbox.run(HELLO02)
        finally:
            sandbox.cleanup()
        assert result.status == ExecutionStatus.SUCCESS
        canon = str(data.resolve())
        assert canon in result.effective_preopens
        assert "/sandbox" not in result.effective_preopens

    def test_component_baseline_attests_without_sandbox(self, home_dir):
        data = home_dir / "data"
        data.mkdir()
        config = WASIConfig(max_fuel=5_000_000, allow_dirs=(str(data),))
        sandbox = ComponentSandbox(config=config)
        try:
            result = sandbox.run(HELLO02)
        finally:
            sandbox.cleanup()
        report = ExecutionReport(
            status="success", exit_code=0, elapsed_ms=0.0
        ).apply_config(config, effective_preopens=result.effective_preopens)
        assert report.security_baseline["preopens"] == [str(data.resolve())]


class TestSubprocessAttestation:
    def test_isolated_run_attests_effective_preopens(self, home_dir):
        data = home_dir / "data"
        data.mkdir()
        config = WASIConfig(max_fuel=1_000_000, allow_dirs=(str(data),))
        result = run_isolated(str(_write_module(home_dir)), config)
        assert result["status"] == ExecutionStatus.SUCCESS
        canon = str(data.resolve())
        assert canon in result["effective_preopens"]
        assert "/sandbox" in result["effective_preopens"]
        assert result["security_baseline"]["preopens"] == [canon, "/sandbox"]


class TestGrantTimeRevalidation:
    """TOCTOU: an entry valid at config time must be re-checked at grant
    time; if it now resolves into a forbidden location it is skipped (with
    a warning) instead of preopened."""

    @staticmethod
    def _stateful_swap(sandbox: WASISandbox, entry: str, monkeypatch) -> None:
        """Model the race: the config-time filter passes, the grant-time
        revalidation resolves the entry into /etc.

        The patch is applied after WASISandbox.__init__ (validation ran
        with the real canonicalize), so the remaining calls are:
        config-time filter (1st) → grant-time revalidation (2nd).
        """
        calls = {"n": 0}

        def _swapped(self_, dir_path: str) -> str:
            calls["n"] += 1
            if calls["n"] == 1:
                return os.path.realpath(dir_path)
            return "/etc" if dir_path == entry else os.path.realpath(dir_path)

        monkeypatch.setattr(WASISandbox, "_canonicalize", _swapped, raising=False)

    def test_swapped_entry_not_granted(self, home_dir, monkeypatch):
        data = home_dir / "data"
        data.mkdir()
        config = WASIConfig(max_fuel=1_000_000, allow_dirs=(str(data),))
        sandbox = WASISandbox(config=config)
        self._stateful_swap(sandbox, str(data), monkeypatch)
        try:
            result = sandbox.run(
                str(_write_module(home_dir)),
                use_engine_pool=False,
            )
        finally:
            sandbox.cleanup()
        assert result.status == ExecutionStatus.SUCCESS
        # The swapped dir was NOT granted; only /sandbox survived.
        assert result.effective_preopens == ("/sandbox",)

    def test_swapped_entry_warns(self, home_dir, monkeypatch):
        data = home_dir / "data"
        data.mkdir()
        config = WASIConfig(max_fuel=1_000_000, allow_dirs=(str(data),))
        sandbox = WASISandbox(config=config)
        self._stateful_swap(sandbox, str(data), monkeypatch)
        try:
            with pytest.warns(RuntimeWarning, match="TOCTOU"):
                sandbox.run(str(_write_module(home_dir)), use_engine_pool=False)
        finally:
            sandbox.cleanup()
