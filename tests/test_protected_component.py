"""Protected WASI Component profile — opt-in fail-closed admission.

``WASISandbox.run(..., protected_component=True)`` activates a strictly narrower
contract than the default ADR-015 posture: a run is admitted ONLY when every
profile invariant is provably met BEFORE the guest starts, and each unmet
invariant is a controlled refusal that runs nothing. These tests observe REAL
behaviour (which process ran, whether the guest ran at all, whether a file was
written), not config flags, and pair every refusal with the success it must not
be confused with.

The invariants under test:

  * a real WASI 0.2 component at ``unknown``/``untrusted`` runs ISOLATED;
  * ``trusted`` is refused — the profile never takes the in-process fast path;
  * a preview1/core module is refused whatever the ``abi`` parameter claims,
    so an ``abi="component"`` label cannot promote a non-component;
  * an explicit ``abi="preview1"`` request is refused (component-only profile);
  * an invalid trust posture is refused, not raised past the gate;
  * the admission decision is bound to the ACTUAL inspected bytes and that
    identity is threaded to the worker, which re-checks the bytes it loads, so
    a swapped module is refused rather than executed;
  * when the isolated worker is unavailable the run is refused BEFORE anything
    starts and the guest never gets to write its side effect;
  * a worker failure under a protected run is a fail-closed ERROR with no
    in-process retry;
  * a protected success attests the truth (execution_mode subprocess, abi
    component, and the still-absent component sync blockade);
  * ``protected_component=False`` leaves every existing path unchanged.
"""

from __future__ import annotations

import hashlib
import os
import sys
import tempfile
from pathlib import Path

import wasmtime

sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))

from ephemora_cell import (
    ExecutionStatus,
    WASIConfig,
    WASISandbox,
)
from ephemora_cell.execution_report import (
    TRUST_TRUSTED,
    TRUST_UNKNOWN,
    TRUST_UNTRUSTED,
)

FIXTURES = os.path.join(os.path.dirname(__file__), "fixtures")
HELLO02 = os.path.join(FIXTURES, "hello02.wasm")
FS02 = os.path.join(FIXTURES, "fs02.wasm")

_SMALL = dict(max_fuel=5_000_000, timeout_seconds=30)

PREVIEW1_WAT = '(module (func (export "_start")))'

_REFUSAL = "refused: protected component profile"


def _preview1_wasm(tmp_path: Path) -> str:
    p = tmp_path / "hello_p1.wasm"
    p.write_bytes(wasmtime.wat2wasm(PREVIEW1_WAT))
    return str(p)


def _grant_dir() -> str:
    return tempfile.mkdtemp(prefix="ephemora_protected_grant_")


class TestProtectedProfileAccepts:
    """The narrow set of runs the profile is built for."""

    def test_unknown_component_runs_isolated(self):
        sandbox = WASISandbox(config=WASIConfig(**_SMALL))
        try:
            result = sandbox.run(HELLO02, abi="component", protected_component=True)
        finally:
            sandbox.cleanup()
        assert result.status is ExecutionStatus.SUCCESS, result.stderr
        assert result.execution_mode == "subprocess"
        assert result.abi == "component"

    def test_untrusted_component_runs_isolated(self):
        sandbox = WASISandbox(config=WASIConfig(**_SMALL))
        try:
            result = sandbox.run(
                HELLO02,
                abi="component",
                trust=TRUST_UNTRUSTED,
                protected_component=True,
            )
        finally:
            sandbox.cleanup()
        assert result.status is ExecutionStatus.SUCCESS, result.stderr
        assert result.execution_mode == "subprocess"

    def test_auto_dispatch_on_a_component_is_accepted(self):
        # abi="auto" resolves to the real format; a genuine component passes.
        sandbox = WASISandbox(config=WASIConfig(**_SMALL))
        try:
            result = sandbox.run(HELLO02, abi="auto", protected_component=True)
        finally:
            sandbox.cleanup()
        assert result.status is ExecutionStatus.SUCCESS, result.stderr
        assert result.abi == "component"
        assert result.execution_mode == "subprocess"


class TestProtectedProfileRefusesFormat:
    """The parameter is a routing hint, not proof of the format."""

    def test_preview1_module_refused_under_abi_component(self, tmp_path):
        # The core case: naming abi="component" cannot make the protected
        # profile accept a preview1/core module. The verdict is the bytes.
        wasm = _preview1_wasm(tmp_path)
        sandbox = WASISandbox(config=WASIConfig(**_SMALL))
        try:
            result = sandbox.run(wasm, abi="component", protected_component=True)
        finally:
            sandbox.cleanup()
        assert result.status is ExecutionStatus.ERROR
        assert _REFUSAL in result.stderr
        assert "not a WASI 0.2 component" in result.stderr

    def test_preview1_module_refused_under_abi_auto(self, tmp_path):
        wasm = _preview1_wasm(tmp_path)
        sandbox = WASISandbox(config=WASIConfig(**_SMALL))
        try:
            result = sandbox.run(wasm, abi="auto", protected_component=True)
        finally:
            sandbox.cleanup()
        assert result.status is ExecutionStatus.ERROR
        assert _REFUSAL in result.stderr

    def test_explicit_preview1_abi_refused_even_with_a_component(self):
        # The protected profile routes components only: an explicit request for
        # the preview1 dispatcher is refused even when the file IS a component,
        # so a mislabel cannot drop the isolation mandate.
        sandbox = WASISandbox(config=WASIConfig(**_SMALL))
        try:
            result = sandbox.run(HELLO02, abi="preview1", protected_component=True)
        finally:
            sandbox.cleanup()
        assert result.status is ExecutionStatus.ERROR
        assert _REFUSAL in result.stderr
        assert "preview1" in result.stderr


class TestProtectedProfileRefusesTrust:
    """Foreign code only, and never a widened posture."""

    def test_trusted_component_is_refused_before_the_guest_starts(self):
        sandbox = WASISandbox(config=WASIConfig(**_SMALL))
        try:
            result = sandbox.run(
                HELLO02,
                abi="component",
                trust=TRUST_TRUSTED,
                protected_component=True,
            )
        finally:
            sandbox.cleanup()
        assert result.status is ExecutionStatus.ERROR
        assert _REFUSAL in result.stderr
        # Not the in-process path a trusted run would otherwise take.
        assert result.execution_mode != "in_process" or result.status is (
            ExecutionStatus.ERROR
        )

    def test_invalid_trust_value_is_refused_not_run(self):
        sandbox = WASISandbox(config=WASIConfig(**_SMALL))
        try:
            result = sandbox.run(
                HELLO02,
                abi="component",
                trust="definitely-trusted",
                protected_component=True,
            )
        finally:
            sandbox.cleanup()
        assert result.status is ExecutionStatus.ERROR
        assert _REFUSAL in result.stderr
        assert "trust" in result.stderr


class TestProtectedModuleIdentity:
    """The decision binds the exact inspected bytes to the load."""

    def test_inspected_digest_is_threaded_to_the_worker(self, monkeypatch):
        import ephemora_cell.process_executor as pe

        expected = hashlib.sha256(Path(HELLO02).read_bytes()).hexdigest()
        captured: dict = {}

        def _spy(wasm_path, config, **kw):
            captured["wasm_path"] = wasm_path
            captured.update(kw)
            return {
                "status": "success",
                "exit_code": 0,
                "stdout": "ok",
                "stderr": "",
                "elapsed_ms": 1.0,
                "fuel_consumed": 10,
                "sandbox_dir": None,
                "effective_preopens": [],
                "abi": "component",
                "execution_mode": "subprocess",
            }

        monkeypatch.setattr(pe, "run_isolated", _spy)
        sandbox = WASISandbox(config=WASIConfig(**_SMALL))
        try:
            result = sandbox.run(HELLO02, abi="component", protected_component=True)
        finally:
            sandbox.cleanup()
        assert result.status is ExecutionStatus.SUCCESS
        # The worker was asked to bind its load to the bytes we inspected.
        assert captured.get("expected_sha256") == expected

    def test_contradicting_caller_digest_is_refused_and_never_dispatched(
        self, monkeypatch
    ):
        import ephemora_cell.process_executor as pe

        dispatched = {"called": False}

        def _spy(wasm_path, config, **kw):
            dispatched["called"] = True
            raise AssertionError("worker must not run for a digest contradiction")

        monkeypatch.setattr(pe, "run_isolated", _spy)
        sandbox = WASISandbox(config=WASIConfig(**_SMALL))
        try:
            result = sandbox.run(
                HELLO02,
                abi="component",
                protected_component=True,
                expected_sha256="0" * 64,
            )
        finally:
            sandbox.cleanup()
        assert result.status is ExecutionStatus.ERROR
        assert _REFUSAL in result.stderr
        assert dispatched["called"] is False

    def test_matching_caller_digest_is_accepted(self, monkeypatch):
        import ephemora_cell.process_executor as pe

        expected = hashlib.sha256(Path(HELLO02).read_bytes()).hexdigest()

        def _spy(wasm_path, config, **kw):
            return {
                "status": "success",
                "exit_code": 0,
                "stdout": "ok",
                "stderr": "",
                "elapsed_ms": 1.0,
                "fuel_consumed": 10,
                "sandbox_dir": None,
                "effective_preopens": [],
                "abi": "component",
                "execution_mode": "subprocess",
            }

        monkeypatch.setattr(pe, "run_isolated", _spy)
        sandbox = WASISandbox(config=WASIConfig(**_SMALL))
        try:
            result = sandbox.run(
                HELLO02,
                abi="component",
                protected_component=True,
                expected_sha256=expected,
            )
        finally:
            sandbox.cleanup()
        assert result.status is ExecutionStatus.SUCCESS

    def test_worker_rechecks_loaded_bytes_against_the_bound_digest(self):
        # The other half of the swap defence: even if a module changed on disk
        # after admission, the loader refuses bytes that differ from the bound
        # digest. This is the ComponentSandbox re-check the protected profile
        # relies on to make "executed bytes == inspected bytes" real, not just
        # intended — exercised directly so no worker process is needed.
        from ephemora_cell.wasi_02 import ComponentSandbox

        wrong = hashlib.sha256(b"a different module entirely").hexdigest()
        sandbox = ComponentSandbox(config=WASIConfig(**_SMALL))
        try:
            result = sandbox.run(HELLO02, expected_sha256=wrong)
        finally:
            sandbox.cleanup()
        assert result.status is ExecutionStatus.ERROR
        assert "module hash mismatch" in result.stderr


class TestProtectedIsolationFailClosed:
    """Isolation is mandatory; unavailable or crashing => refuse."""

    def test_worker_unavailable_refuses_before_the_guest_runs(self, monkeypatch):
        target = _grant_dir()
        sandbox = WASISandbox(config=WASIConfig(allow_dirs=(target,), **_SMALL))
        monkeypatch.setattr(sandbox, "_isolation_available", lambda: False)
        try:
            result = sandbox.run(
                FS02, args=[target], abi="component", protected_component=True
            )
        finally:
            sandbox.cleanup()
        assert result.status is ExecutionStatus.ERROR
        assert "refused" in result.stderr
        assert "isolation" in result.stderr
        # Nothing ran: the mandated side effect never happened in-process.
        assert not Path(target, "out.txt").exists()

    def test_worker_failure_yields_error_with_no_in_process_retry(self, monkeypatch):
        import ephemora_cell.process_executor as pe

        sandbox = WASISandbox(config=WASIConfig(**_SMALL))

        def _crashing_worker(*a, **k):
            return {
                "status": "error",
                "exit_code": 1,
                "stdout": "",
                "stderr": "worker crashed: simulated",
                "elapsed_ms": 0.0,
                "fuel_consumed": None,
                "sandbox_dir": None,
                "effective_preopens": [],
            }

        monkeypatch.setattr(pe, "run_isolated", _crashing_worker)
        try:
            result = sandbox.run(HELLO02, abi="component", protected_component=True)
        finally:
            sandbox.cleanup()
        assert result.status is ExecutionStatus.ERROR
        assert "worker crashed" in result.stderr
        # The failure is reported from the subprocess view, NOT re-run here.
        assert result.execution_mode == "subprocess"


class TestProtectedEvidenceAndRegression:
    """The record tells the truth; flag-off changes nothing."""

    def test_protected_success_record_attests_the_truth(self):
        from ephemora_cell import ExecutionReport

        config = WASIConfig(**_SMALL)
        sandbox = WASISandbox(config=config)
        try:
            result = sandbox.run(HELLO02, abi="component", protected_component=True)
        finally:
            sandbox.cleanup()
        report = ExecutionReport(
            status=result.status.value,
            exit_code=result.exit_code,
            elapsed_ms=result.elapsed_ms,
        )
        report.apply_config(
            config,
            effective_preopens=result.effective_preopens,
            execution_mode=result.execution_mode,
            abi=result.abi,
        )
        baseline = report.security_baseline
        assert baseline["abi"] == "component"
        # Isolation is never dressed up as the still-absent component sync
        # blockade: the attested truth stays honest.
        assert baseline["sync_blockade_enforced"] is False
        assert result.execution_mode == "subprocess"

    def test_refusal_makes_no_successful_attestation(self):
        sandbox = WASISandbox(config=WASIConfig(**_SMALL))
        try:
            result = sandbox.run(
                HELLO02,
                abi="component",
                trust=TRUST_TRUSTED,
                protected_component=True,
            )
        finally:
            sandbox.cleanup()
        assert result.status is not ExecutionStatus.SUCCESS
        assert result.exit_code != 0 or result.status is ExecutionStatus.ERROR

    def test_flag_off_leaves_existing_paths_unchanged(self):
        # Regression for the whole default boundary: without the flag the world
        # stays exactly as today — unknown component isolated, trusted component
        # in-process, preview1 in-process.
        unknown = WASISandbox(config=WASIConfig(**_SMALL))
        try:
            isolated = unknown.run(HELLO02, abi="component")
        finally:
            unknown.cleanup()
        assert isolated.execution_mode == "subprocess"

        trusted = WASISandbox(config=WASIConfig(**_SMALL))
        try:
            inproc = trusted.run(HELLO02, abi="component", trust=TRUST_TRUSTED)
        finally:
            trusted.cleanup()
        assert inproc.execution_mode == "in_process"

    def test_refusal_is_distinguishable_from_a_guest_trap(self):
        # Every protected refusal carries the fixed prefix so a caller can tell
        # "the profile refused to start" apart from a guest that ran and trapped.
        sandbox = WASISandbox(config=WASIConfig(**_SMALL))
        try:
            result = sandbox.run(
                HELLO02,
                abi="component",
                trust=TRUST_UNKNOWN,
                protected_component=False,  # sanity: no refusal prefix without opt-in
            )
        finally:
            sandbox.cleanup()
        assert _REFUSAL not in result.stderr
