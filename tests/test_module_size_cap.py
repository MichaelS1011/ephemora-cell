"""Interpreter blockers: the module size cap and the fsync blockade.

Both used to be hard refusals with no opt-in, and each one alone stopped a
bring-your-own interpreter guest (docs/languages.md): the cap rejected
interpreter-scale modules with no way to raise it through profile, API or
CLI, and the P1 #12 sync blockade rejected CPython-WASI because it imports
``fd_datasync`` during startup. The cap is configurable and attested now. The
blockade did not need an opt-in at all — it was refusing an IMPORT that no
mainstream guest ever calls, and the measurement (probe_datasync.py) shows
CPython boots behind the trap, so the interpreter profile ships with the sync
wall closed.

Testing the blockade surfaced a gap in it: the matcher keyed on
``fsync``/``psync``/``datasync`` substrings and so never saw ``fd_sync``,
Preview1's own sync call — which ran against the host under the default
config, contradicting SECURITY.md. All three sync entry points are now
refused at the CALL layer, which is where the harm is; importing them stays
legal because wasm32-wasi toolchains (Zig) and interpreters (CPython) emit
the symbols without calling them.
"""

from __future__ import annotations

import json
import os
import subprocess
import sys
from pathlib import Path

import pytest
import wasmtime

sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))

from ephemora_cell import (
    ExecutionReport,
    ExecutionStatus,
    WASIConfig,
    WASISandbox,
    get_profile,
    run_wasm,
)
from ephemora_cell.engine_pool import config_fingerprint
from ephemora_cell.process_executor import run_isolated
from ephemora_cell.profiles import list_profiles
from ephemora_cell.wasi_runtime import DEFAULT_MAX_WASM_BYTES

HELLO_WAT = '(module (func (export "_start")))'
# Fuel/timeout the guests in this file need: an empty _start.
_SMALL = dict(max_fuel=2_000_000, timeout_seconds=30)

#: Creates a file in the first preopen (fd 3) and syncs it — the startup
#: behaviour CPython-WASI has, and the call class the P1 #12 blockade
#: rejects. Traps on a nonzero errno, so SUCCESS here means the sync reached
#: the host and returned success.
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
        (i32.const 3)
        (i32.const 0)
        (i32.const 8)
        (i32.const 8)
        (i32.const 1)
        (i64.const 0x1FFFFF)
        (i64.const 0x1FFFFF)
        (i32.const 0)
        (i32.const 64)))
    (if (call $sync (i32.load (i32.const 64)))
        (then (unreachable)))))
"""


def _uleb(value: int) -> bytes:
    out = bytearray()
    while True:
        byte = value & 0x7F
        value >>= 7
        if value:
            out.append(byte | 0x80)
        else:
            out.append(byte)
            return bytes(out)


def _section(sid: int, body: bytes) -> bytes:
    return bytes([sid]) + _uleb(len(body)) + body


def oversized_module_bytes(payload_bytes: int) -> bytes:
    """A valid preview1 module whose FILE carries payload_bytes of padding.

    Custom sections are legal and ignored by the compiler, so the module
    compiles in milliseconds while its file size is interpreter-scale —
    the shape the cap has to survive for a real BYO guest.
    """
    name = b"bench-padding"
    custom = _uleb(len(name)) + name + b"\x00" * payload_bytes
    return (
        b"\x00asm"
        + (1).to_bytes(4, "little")
        + _section(0, custom)
        + _section(1, _uleb(1) + b"\x60" + _uleb(0) + _uleb(0))
        + _section(3, _uleb(1) + _uleb(0))
        + _section(7, _uleb(1) + _uleb(6) + b"_start" + b"\x00" + _uleb(0))
        + _section(10, _uleb(1) + _uleb(2) + b"\x00\x0b")
    )


@pytest.fixture
def small_wasm(tmp_path):
    path = tmp_path / "hello.wasm"
    path.write_bytes(wasmtime.wat2wasm(HELLO_WAT))
    return path


@pytest.fixture
def oversized_wasm(tmp_path):
    path = tmp_path / "interpreter-sized.wasm"
    path.write_bytes(oversized_module_bytes(DEFAULT_MAX_WASM_BYTES + 1024))
    assert path.stat().st_size > DEFAULT_MAX_WASM_BYTES
    return path


@pytest.fixture
def sync_wasm(tmp_path):
    """Writer that drops a sync-calling module into tmp_path (which the tests
    also preopen), returning its path."""

    def _write(name: str = "fd_datasync") -> Path:
        wasm = tmp_path / f"{name}.wasm"
        wasm.write_bytes(wasmtime.wat2wasm(SYNC_WAT % {"name": name}))
        return wasm

    return _write


class TestCapIsConfigurable:
    def test_default_is_the_previous_hard_cap(self):
        assert WASIConfig().max_wasm_bytes == DEFAULT_MAX_WASM_BYTES
        assert DEFAULT_MAX_WASM_BYTES == 32 * 1024 * 1024

    def test_negative_cap_is_refused(self):
        with pytest.raises(ValueError, match="max_wasm_bytes"):
            WASISandbox(config=WASIConfig(max_wasm_bytes=-1))

    def test_cap_is_not_an_engine_knob(self):
        """Two configs differing only in their cap share one pooled engine:
        the cap gates which module may be compiled, not how the engine is
        built — so raising it cannot shard the engine pool."""
        assert config_fingerprint(WASIConfig(max_wasm_bytes=1024)) == (
            config_fingerprint(WASIConfig())
        )


class TestInProcessEnforcement:
    def test_over_cap_rejected_before_compiling(self, small_wasm):
        result = WASISandbox(config=WASIConfig(max_wasm_bytes=4)).run(str(small_wasm))
        assert result.status is ExecutionStatus.ERROR
        assert "size limit" in result.stderr.lower()

    def test_within_cap_executes(self, small_wasm):
        config = WASIConfig(max_wasm_bytes=small_wasm.stat().st_size, **_SMALL)
        result = WASISandbox(config=config).run(str(small_wasm))
        assert result.status is ExecutionStatus.SUCCESS, result.stderr

    def test_zero_disables_the_cap(self, small_wasm):
        config = WASIConfig(max_wasm_bytes=0, **_SMALL)
        result = WASISandbox(config=config).run(str(small_wasm))
        assert result.status is ExecutionStatus.SUCCESS, result.stderr

    def test_oversized_module_runs_with_raised_cap(self, oversized_wasm):
        config = WASIConfig(
            max_wasm_bytes=oversized_wasm.stat().st_size,
            max_memory_mb=256,
            **_SMALL,
        )
        sandbox = WASISandbox(config=config)
        try:
            result = sandbox.run(str(oversized_wasm))
        finally:
            sandbox.cleanup()
        assert result.status is ExecutionStatus.SUCCESS, result.stderr

    def test_component_path_enforces_the_same_cap(self, tmp_path):
        from ephemora_cell.wasi_02 import ComponentSandbox

        component = tmp_path / "guest.wasm"
        # Component magic in a file larger than the cap — the size check runs
        # before any component parsing.
        component.write_bytes(b"\x00asm\x0d\x00\x00\x00" + b"\x00" * 64)
        result = ComponentSandbox(config=WASIConfig(max_wasm_bytes=4)).run(
            str(component)
        )
        assert result.status is ExecutionStatus.ERROR
        assert "size limit" in result.stderr.lower()


class TestIsolationPathEnforcement:
    def test_default_cap_still_blocks_an_oversized_module(self, oversized_wasm):
        report = run_isolated(str(oversized_wasm), WASIConfig(**_SMALL))
        assert report["status"] is ExecutionStatus.ERROR
        assert "size limit" in report["stderr"].lower()

    def test_config_cap_reaches_the_worker(self, oversized_wasm):
        """The cap travels in the stdin payload, so parent and worker enforce
        ONE value — a raised cap that only the parent saw would let the
        worker reject the run the caller configured."""
        config = WASIConfig(
            max_wasm_bytes=64 * 1024 * 1024,
            max_memory_mb=256,
            **_SMALL,
        )
        report = run_isolated(str(oversized_wasm), config)
        assert report["status"] is ExecutionStatus.SUCCESS, report["stderr"]

    def test_explicit_override_wins_over_config(self, small_wasm):
        report = run_isolated(str(small_wasm), WASIConfig(**_SMALL), max_wasm_bytes=4)
        assert report["status"] is ExecutionStatus.ERROR
        assert "size limit" in report["stderr"].lower()

    def test_negative_override_is_refused(self, small_wasm):
        report = run_isolated(str(small_wasm), WASIConfig(**_SMALL), max_wasm_bytes=-1)
        assert report["status"] is ExecutionStatus.ERROR
        assert "non-negative" in report["stderr"].lower()

    def test_sandbox_run_forwards_the_cap(self, oversized_wasm):
        """The original blocker: WASISandbox.run(use_subprocess=True) had no
        way to carry a raised cap at all."""
        config = WASIConfig(
            max_wasm_bytes=0,
            max_memory_mb=256,
            **_SMALL,
        )
        sandbox = WASISandbox(config=config)
        try:
            result = sandbox.run(str(oversized_wasm), use_subprocess=True)
        finally:
            sandbox.cleanup()
        assert result.status is ExecutionStatus.SUCCESS, result.stderr


class TestPublicApiAndCli:
    def test_run_wasm_override(self, oversized_wasm):
        result = run_wasm(
            str(oversized_wasm),
            max_wasm_bytes=0,
            max_memory_mb=256,
            max_fuel=2_000_000,
            timeout_seconds=30,
        )
        assert result.status is ExecutionStatus.SUCCESS, result.stderr

    def test_run_wasm_default_cap_rejects(self, oversized_wasm):
        result = run_wasm(str(oversized_wasm), **_SMALL)
        assert result.status is ExecutionStatus.ERROR
        assert "size limit" in result.stderr.lower()

    def test_cli_flag_overrides_the_profile(self, small_wasm):
        proc = subprocess.run(
            [
                sys.executable,
                "-m",
                "ephemora_cell.cli",
                "run",
                str(small_wasm),
                "--profile",
                "plugin",
                "--max-wasm-bytes",
                "4",
                "--json",
            ],
            capture_output=True,
            text=True,
        )
        assert "size limit" in proc.stderr.lower(), proc.stderr

    def test_cli_zero_disables_the_cap(self, oversized_wasm):
        proc = subprocess.run(
            [
                sys.executable,
                "-m",
                "ephemora_cell.cli",
                "run",
                str(oversized_wasm),
                "--max-wasm-bytes",
                "0",
                "--memory-mb",
                "256",
                "--fuel",
                "2000000",
            ],
            capture_output=True,
            text=True,
        )
        assert "size limit" not in proc.stderr.lower(), proc.stderr
        assert proc.returncode == 0, proc.stderr


class TestInterpreterProfile:
    def test_profile_is_listed_and_reachable(self):
        assert "interpreter" in list_profiles()
        assert get_profile("interpreter") is not None

    def test_budgets_clear_an_interpreter_guest(self):
        config = get_profile("interpreter")
        assert config.max_wasm_bytes > DEFAULT_MAX_WASM_BYTES
        assert config.max_memory_mb >= 1024
        assert config.max_fuel and config.max_fuel >= 100_000_000

    def test_profile_keeps_the_sync_blockade_closed(self):
        """CPython IMPORTS fd_datasync at startup but never CALLS it (measured,
        probe_datasync.py), so the interpreter profile needs no sync exception
        — the wall it shares with every other guest stays up."""
        assert get_profile("interpreter").allow_fsync is False

    def test_profile_raises_the_host_cpu_wall_for_the_worker(self):
        """Not a guest budget: compiling a 22 MB interpreter inside the worker
        costs 5.40 s of host CPU (measured), which the default 2.0 s
        io_cpu_seconds wall kills. The profile raises it and nothing else in
        the security posture moves."""
        config = get_profile("interpreter")
        assert config.io_cpu_seconds > WASIConfig().io_cpu_seconds

    def test_profile_grants_no_new_capability(self):
        """The profile raises budgets only. Filesystem/env access stays an
        explicit per-run grant (ADR-009 Tier 2 brings a binary, not a
        capability)."""
        config = get_profile("interpreter")
        assert config.allow_dirs == ()
        assert config.allow_env == ()

    def test_oversized_module_fails_on_fuel_not_on_size(self, oversized_wasm):
        """With the profile's cap the size gate is open; the run then
        terminates on a budget instead — proving the cap, not the default
        limits, was what blocked interpreter-scale modules."""
        config = get_profile("interpreter")
        sandbox = WASISandbox(config=config)
        try:
            result = sandbox.run(str(oversized_wasm))
        finally:
            sandbox.cleanup()
        assert "size limit" not in (result.stderr or "").lower()
        assert result.status in (
            ExecutionStatus.SUCCESS,
            ExecutionStatus.FUEL_EXHAUSTED,
            ExecutionStatus.MEMORY_EXCEEDED,
        ), result.stderr

    def test_component_run_with_the_profile(self, tmp_path):
        """CPython-WASI ships a 21 MB core module — the profile carries it
        without the caller touching a single knob."""
        config = get_profile("interpreter")
        wasm = tmp_path / "guest.wasm"
        wasm.write_bytes(oversized_module_bytes(20 * 1024 * 1024))
        assert 20 * 1024 * 1024 < wasm.stat().st_size < DEFAULT_MAX_WASM_BYTES
        sandbox = WASISandbox(config=config)
        try:
            result = sandbox.run(str(wasm))
        finally:
            sandbox.cleanup()
        assert result.status is ExecutionStatus.SUCCESS, result.stderr


class TestFsyncBlockadeOptIn:
    """The second interpreter blocker: P1 #12 rejected every module that
    IMPORTED a sync call, and CPython imports one at startup. That layer is
    gone — all three sync entry points (``fd_sync``, ``fd_datasync``,
    ``fd_psync``) are now refused at the CALL layer, where the harm is, and
    ``allow_fsync`` is the escape for a caller that genuinely needs
    durability. The default stays blocked.

    Why the import layer had to go: every wasm32-wasi binary Zig emits imports
    ``fd_sync`` and every CPython-WASI guest imports ``fd_datasync``, in both
    cases without calling it (measured — the guest boots behind the full trap
    set, cold and warm stdlib tree). Refusing the import refused the toolchain
    and the interpreter while letting the actual attack through: ``fd_sync``
    was in neither layer before this change, so a guest that called it got a
    real host fsync under the default config while SECURITY.md and
    docs/threat-model.md claimed it was rejected.
    """

    @pytest.mark.parametrize("name", ["fd_sync", "fd_datasync", "fd_psync"])
    def test_sync_calls_are_refused_by_default(self, tmp_path, sync_wasm, name):
        """The refusal is the Cell's own trap, so wasmtime's real sync was
        never reached — which also proves the shadow over define_wasi took
        effect. Importing the symbol is legal; calling it is not."""
        config = WASIConfig(allow_dirs=(str(tmp_path),), **_SMALL)
        assert config.allow_fsync is False
        sandbox = WASISandbox(config=config)
        try:
            result = sandbox.run(str(sync_wasm(name)))
        finally:
            sandbox.cleanup()
        assert result.status is ExecutionStatus.ERROR
        assert "Blocked WASI import" not in result.stderr
        assert "blocked by sandbox" in result.stderr
        # Refusing at the call means the calls BEFORE it stood: the guest
        # created and wrote the file, then died at the sync. Fail-closed
        # protects the host disk, not the guest's own partial work — and
        # saying so is the honest version of "nothing reached the host",
        # which the import-layer design could claim but this one cannot.
        assert (tmp_path / "sync.tmp").exists()

    @pytest.mark.parametrize("name", ["fd_sync", "fd_datasync", "fd_psync"])
    def test_sync_symbols_can_be_imported_without_being_called(self, tmp_path, name):
        """The toolchain and interpreter regression guard: wasm32-wasi
        binaries import fd_sync, CPython imports fd_datasync, and neither may
        be rejected for it."""
        wasm = tmp_path / "imports_only.wasm"
        wasm.write_bytes(wasmtime.wat2wasm(f"""
(module
  (import "wasi_snapshot_preview1" "{name}"
    (func $sync (param i32) (result i32)))
  (func (export "_start")))
"""))
        config = WASIConfig(allow_dirs=(str(tmp_path),), **_SMALL)
        sandbox = WASISandbox(config=config)
        try:
            result = sandbox.run(str(wasm))
        finally:
            sandbox.cleanup()
        assert result.status is ExecutionStatus.SUCCESS, result.stderr

    @pytest.mark.parametrize("name", ["fd_sync", "fd_datasync"])
    def test_sync_runs_when_allowed(self, tmp_path, sync_wasm, name):
        config = WASIConfig(allow_fsync=True, allow_dirs=(str(tmp_path),), **_SMALL)
        sandbox = WASISandbox(config=config)
        try:
            result = sandbox.run(str(sync_wasm(name)))
        finally:
            sandbox.cleanup()
        assert result.status is ExecutionStatus.SUCCESS, result.stderr
        assert (tmp_path / "sync.tmp").exists()

    def test_fd_psync_stays_trapped_even_when_allowed(self, tmp_path, sync_wasm):
        """``allow_fsync`` restores the two sync calls WASI actually defines;
        fd_psync is not one of them. Preview1 has no such call, so the Cell's
        own trapping shim is the only implementation it can offer and opting in
        does not open it."""
        config = WASIConfig(allow_fsync=True, allow_dirs=(str(tmp_path),), **_SMALL)
        sandbox = WASISandbox(config=config)
        try:
            result = sandbox.run(str(sync_wasm("fd_psync")))
        finally:
            sandbox.cleanup()
        assert "Blocked WASI import" not in (result.stderr or "")
        assert result.status is ExecutionStatus.ERROR
        assert "blocked by sandbox" in result.stderr

    def test_isolation_path_carries_the_flag(self, tmp_path, sync_wasm):
        """allow_fsync travels in the stdin payload like the cap does: a flag
        only the parent honoured would leave the worker refusing the run."""
        config = WASIConfig(allow_fsync=True, allow_dirs=(str(tmp_path),), **_SMALL)
        report = run_isolated(str(sync_wasm()), config)
        assert report["status"] is ExecutionStatus.SUCCESS, report["stderr"]

    def test_cli_allow_fsync(self, tmp_path, sync_wasm):
        wasm = sync_wasm()
        proc = subprocess.run(
            [
                sys.executable,
                "-m",
                "ephemora_cell.cli",
                "run",
                str(wasm),
                "--allow-dirs",
                str(tmp_path),
                "--allow-fsync",
                "--fuel",
                "2000000",
                "--json",
            ],
            capture_output=True,
            text=True,
        )
        assert proc.returncode == 0, proc.stderr
        payload = json.loads(proc.stdout)
        assert payload["status"] == "success", payload
        assert payload["security_baseline"]["allow_fsync"] is True
        assert (tmp_path / "sync.tmp").exists()

    def test_cli_without_the_flag_still_blocks(self, tmp_path, sync_wasm):
        proc = subprocess.run(
            [
                sys.executable,
                "-m",
                "ephemora_cell.cli",
                "run",
                str(sync_wasm()),
                "--allow-dirs",
                str(tmp_path),
                "--fuel",
                "2000000",
            ],
            capture_output=True,
            text=True,
        )
        assert "blocked by sandbox" in proc.stderr, proc.stderr
        assert "Blocked WASI import" not in proc.stderr


class TestBaselineAttestation:
    """Both knobs are security posture, so the signed baseline has to say
    which one a run carried — a run with a raised cap or an opened sync wall
    must not read like a default run."""

    def test_default_config_attests_the_closed_posture(self):
        report = ExecutionReport(
            status="success", exit_code=0, elapsed_ms=0.0
        ).apply_config(WASIConfig())
        assert report.security_baseline["max_wasm_bytes"] == DEFAULT_MAX_WASM_BYTES
        assert report.security_baseline["allow_fsync"] is False

    def test_report_defaults_match_the_config_defaults(self):
        """The untouchable default (no apply_config) and the config default
        agree, so a report from a path that never overlaid cannot claim a
        posture different from the library's."""
        baseline = ExecutionReport(
            status="success", exit_code=0, elapsed_ms=0.0
        ).security_baseline
        config = WASIConfig()
        assert baseline["max_wasm_bytes"] == config.max_wasm_bytes
        assert baseline["allow_fsync"] == config.allow_fsync

    def test_interpreter_profile_attests_the_closed_posture(self):
        """The profile raises budgets, so the baseline shows a raised cap —
        but the sync wall stays closed, which is what distinguishes it from
        the allow_fsync opt-in."""
        report = ExecutionReport(
            status="success", exit_code=0, elapsed_ms=0.0
        ).apply_config(get_profile("interpreter"))
        baseline = report.security_baseline
        assert baseline["allow_fsync"] is False
        assert baseline["max_wasm_bytes"] == 512 * 1024 * 1024

    def test_cli_json_attests_a_raised_cap(self, small_wasm):
        proc = subprocess.run(
            [
                sys.executable,
                "-m",
                "ephemora_cell.cli",
                "run",
                str(small_wasm),
                "--max-wasm-bytes",
                "0",
                "--fuel",
                "2000000",
                "--json",
            ],
            capture_output=True,
            text=True,
        )
        assert proc.returncode == 0, proc.stderr
        baseline = json.loads(proc.stdout)["security_baseline"]
        assert baseline["max_wasm_bytes"] == 0
        assert baseline["allow_fsync"] is False
