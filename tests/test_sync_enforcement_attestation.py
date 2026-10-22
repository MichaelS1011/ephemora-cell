"""ADR-014 — effective sync-blockade attestation, end-to-end.

The signed baseline must describe what a run ACTUALLY enforces, not merely
what was configured. ``allow_fsync`` is a PREVIEW1 setting: the sandbox traps
``fd_sync``/``fd_datasync``/``fd_psync`` at the call layer only on the
preview1 path. The WASI 0.2 component path links ``wasi:filesystem`` through
``Linker.add_wasip2()``, where no such trap exists — so a component run that
signed ``allow_fsync: false`` was attesting a blockade its execution path
never performed.

These tests pin the enforcement truth table against REAL guest behaviour
(the sync call genuinely blocked on preview1 / genuinely reaching the host,
the component write genuinely landing) plus the receipt each run produces,
the auto-dispatch resolution, the subprocess source-stamp, and the
``require_sync_blockade`` gate that refuses a downgrade instead of silently
passing it.

Framework: the preview1 sync guest is the same shape used by
tests/test_module_size_cap.py (created + synced file, traps on a non-zero
errno); the component guests reuse the committed ``tests/fixtures`` binaries.
"""

from __future__ import annotations

import os
import sys
import tempfile
from pathlib import Path

import wasmtime

sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))

from ephemora_cell import (
    ExecutionReport,
    ExecutionStatus,
    WASIConfig,
    WASISandbox,
    run_isolated,
)
from ephemora_cell.execution_report import (
    effective_sync_blockade,
    exit_status_fidelity,
    sync_blockade_attested,
)

FIXTURES = os.path.join(os.path.dirname(__file__), "fixtures")
HELLO02 = os.path.join(FIXTURES, "hello02.wasm")
FS02 = os.path.join(FIXTURES, "fs02.wasm")

_SMALL = dict(max_fuel=5_000_000, timeout_seconds=30)

# Preview1 guest: create a file in the first preopen (fd 3) then sync it. The
# sync import is legal; only the CALL is refused by the blockade, so under the
# default config the guest dies at the sync (the file survives), and with
# allow_fsync=True the real wasmtime sync runs and returns success.
SYNC_WAT = """
(module
  (import "wasi_snapshot_preview1" "path_open"
    (func $path_open (param i32 i32 i32 i32 i32 i64 i64 i32 i32) (result i32)))
  (import "wasi_snapshot_preview1" "%(name)s"
    (func $sync (param i32) (result i32)))
  (memory (export "memory") 1)
  (data (i32.const 8) "sync.tmp")
  (func (export "_start")
    (drop
      (call $path_open
        (i32.const 3) (i32.const 0) (i32.const 8) (i32.const 8)
        (i32.const 1) (i64.const 0x1FFFFF) (i64.const 0x1FFFFF)
        (i32.const 0) (i32.const 64)))
    (if (call $sync (i32.load (i32.const 64)))
        (then (unreachable)))))
"""

HELLO_PREVIEW1_WAT = '(module (func (export "_start")))'


def _write(tmp_path: Path, wat: str, name: str = "guest.wasm") -> str:
    path = tmp_path / name
    path.write_bytes(wasmtime.wat2wasm(wat))
    return str(path)


def _attest(result, config) -> dict:
    """Fold a run result + config into the signed baseline EXACTLY the way the
    CLI/MCP wiring does (execution_mode + abi read off the result, never
    inferred) — so these tests exercise the same path a verifier reads."""
    return (
        ExecutionReport(status="success", exit_code=0, elapsed_ms=0.0)
        .apply_config(
            config,
            effective_preopens=result.effective_preopens,
            execution_mode=result.execution_mode,
            abi=result.abi,
        )
        .security_baseline
    )


class TestPreview1Enforcement:
    """Cases 1 & 2: the preview1 blockade is real, and the record says so."""

    def test_sync_blocked_and_enforcement_attested(self, tmp_path):
        wasm = _write(tmp_path, SYNC_WAT % {"name": "fd_sync"})
        config = WASIConfig(allow_dirs=(str(tmp_path),), **_SMALL)
        assert config.allow_fsync is False
        sandbox = WASISandbox(config=config)
        try:
            result = sandbox.run(wasm, abi="preview1")
        finally:
            sandbox.cleanup()
        # Behaviour: the guest died AT the sync call — the wall actually held.
        assert result.status is ExecutionStatus.ERROR
        assert "blocked by sandbox" in result.stderr
        # The refusal is a host decision. It is not a status the guest left,
        # and the receipt must not upgrade its placeholder exit code to an
        # "exact" guest exit.
        assert result.guest_exit_observed is False
        assert (
            exit_status_fidelity(
                abi=result.abi, guest_exit_observed=result.guest_exit_observed
            )
            == "none"
        )
        # Attestation: the signed record confirms the effective blockade.
        baseline = _attest(result, config)
        assert baseline["abi"] == "preview1"
        assert baseline["allow_fsync"] is False
        assert baseline["sync_blockade_enforced"] is True
        assert effective_sync_blockade(baseline) is True

    def test_sync_allowed_and_no_blockade_claimed(self, tmp_path):
        wasm = _write(tmp_path, SYNC_WAT % {"name": "fd_sync"})
        config = WASIConfig(allow_fsync=True, allow_dirs=(str(tmp_path),), **_SMALL)
        sandbox = WASISandbox(config=config)
        try:
            result = sandbox.run(wasm, abi="preview1")
        finally:
            sandbox.cleanup()
        # Behaviour: the real wasmtime sync ran and returned success.
        assert result.status is ExecutionStatus.SUCCESS, result.stderr
        # Attestation: an open sync must never claim a blockade.
        baseline = _attest(result, config)
        assert baseline["abi"] == "preview1"
        assert baseline["allow_fsync"] is True
        assert baseline["sync_blockade_enforced"] is False
        assert effective_sync_blockade(baseline) is False


class TestComponentNoBlockade:
    """Cases 3 & 4: the component path cannot enforce the blockade, and the
    record must say so instead of inheriting the preview1 promise."""

    def test_component_write_reaches_host_and_no_blockade_attested(self, tmp_path):
        # A granted component write lands on the host: the wasi:filesystem path
        # is live and NOT trapped — the same reason a sync would reach the host.
        target = tempfile.mkdtemp(prefix="ephemora_r07_grant_")
        config = WASIConfig(allow_dirs=(target,), **_SMALL)
        sandbox = WASISandbox(config=config)
        try:
            result = sandbox.run(FS02, args=[target], abi="component")
        finally:
            sandbox.cleanup()
        assert result.status is ExecutionStatus.SUCCESS, result.stderr
        assert Path(target, "out.txt").read_text() == "pwned-by-component\n"
        # The crux: allow_fsync defaults False, yet a component run
        # must attest the blockade as NOT enforced (the path never had it).
        baseline = _attest(result, config)
        assert baseline["abi"] == "component"
        assert baseline["allow_fsync"] is False
        assert baseline["sync_blockade_enforced"] is False
        assert effective_sync_blockade(baseline) is False
        assert sync_blockade_attested(baseline) is True

    def test_component_without_grant_attests_nothing_false(self):
        config = WASIConfig(**_SMALL)
        sandbox = WASISandbox(config=config)
        try:
            result = sandbox.run(HELLO02, abi="component")
        finally:
            sandbox.cleanup()
        assert result.status is ExecutionStatus.SUCCESS, result.stderr
        baseline = _attest(result, config)
        assert baseline["abi"] == "component"
        # No filesystem grant expanded (component runs grant no /sandbox), and
        # no false enforcement claimed despite the closed allow_fsync default.
        assert list(baseline["preopens"]) == []
        assert baseline["sync_blockade_enforced"] is False


class TestAutoDispatch:
    """Case 5: auto attestes the ABI ACTUALLY resolved, not the request."""

    def test_auto_resolves_preview1(self, tmp_path):
        wasm = _write(tmp_path, HELLO_PREVIEW1_WAT)
        config = WASIConfig(**_SMALL)
        sandbox = WASISandbox(config=config)
        try:
            result = sandbox.run(wasm, abi="auto")
        finally:
            sandbox.cleanup()
        assert result.abi == "preview1"
        assert _attest(result, config)["abi"] == "preview1"

    def test_auto_resolves_component(self):
        config = WASIConfig(**_SMALL)
        sandbox = WASISandbox(config=config)
        try:
            result = sandbox.run(HELLO02, abi="auto")
        finally:
            sandbox.cleanup()
        assert result.abi == "component"
        baseline = _attest(result, config)
        assert baseline["abi"] == "component"
        assert baseline["sync_blockade_enforced"] is False


class TestSubprocessSourceStamp:
    """Case 6: the worker stamps its own executed ABI + enforcement at the
    source, so direct/subprocess/auto stay consistent."""

    def test_subprocess_preview1_attests_enforcement(self, tmp_path):
        wasm = _write(tmp_path, HELLO_PREVIEW1_WAT)
        config = WASIConfig(**_SMALL)
        result = run_isolated(wasm, config, abi="preview1")
        assert result.execution_mode == "subprocess"
        assert result.abi == "preview1"
        baseline = result["security_baseline"]
        assert baseline["abi"] == "preview1"
        assert baseline["sync_blockade_enforced"] is True

    def test_subprocess_component_attests_no_blockade(self):
        config = WASIConfig(**_SMALL)
        result = run_isolated(HELLO02, config, abi="component")
        assert result.execution_mode == "subprocess"
        assert result.abi == "component"
        baseline = result["security_baseline"]
        assert baseline["abi"] == "component"
        # allow_fsync default False, but a component worker cannot claim a
        # blockade it does not have.
        assert baseline["allow_fsync"] is False
        assert baseline["sync_blockade_enforced"] is False


class TestStrictEnforcementGate:
    """Case 9: a caller who REQUIRES the blockade gets a controlled refusal on
    a path that cannot honour it — never a silent pass, and never a guest run."""

    def test_component_refused_before_execution(self):
        config = WASIConfig(**_SMALL)
        sandbox = WASISandbox(config=config)
        try:
            result = sandbox.run(HELLO02, abi="component", require_sync_blockade=True)
        finally:
            sandbox.cleanup()
        assert result.status is ExecutionStatus.ERROR
        assert "refused" in result.stderr
        # Nothing ran: an unattested guest produced no output.
        assert result.stdout == ""

    def test_component_with_grant_refused_no_file_written(self):
        target = tempfile.mkdtemp(prefix="ephemora_r07_gate_")
        config = WASIConfig(allow_dirs=(target,), **_SMALL)
        sandbox = WASISandbox(config=config)
        try:
            result = sandbox.run(
                FS02, args=[target], abi="component", require_sync_blockade=True
            )
        finally:
            sandbox.cleanup()
        assert result.status is ExecutionStatus.ERROR
        assert "refused" in result.stderr
        # The gate fires BEFORE execution: the guest never wrote its file.
        assert not Path(target, "out.txt").exists()

    def test_preview1_closed_fsync_passes_gate(self, tmp_path):
        wasm = _write(tmp_path, HELLO_PREVIEW1_WAT)
        config = WASIConfig(**_SMALL)  # allow_fsync default False
        sandbox = WASISandbox(config=config)
        try:
            result = sandbox.run(wasm, abi="preview1", require_sync_blockade=True)
        finally:
            sandbox.cleanup()
        # preview1 with the wall closed is exactly what the caller needs.
        assert result.status is ExecutionStatus.SUCCESS, result.stderr

    def test_preview1_open_fsync_refused_by_gate(self, tmp_path):
        wasm = _write(tmp_path, HELLO_PREVIEW1_WAT)
        config = WASIConfig(allow_fsync=True, **_SMALL)
        sandbox = WASISandbox(config=config)
        try:
            result = sandbox.run(wasm, abi="preview1", require_sync_blockade=True)
        finally:
            sandbox.cleanup()
        # A preview1 run with sync allowed enforces nothing -> refused.
        assert result.status is ExecutionStatus.ERROR
        assert "refused" in result.stderr
