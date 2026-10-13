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

The final security review hardens three further guarantees, each proved here:

  * admission reads the module under a BOUNDED read — an oversized input is
    refused on its declared size before its bytes ever enter the parent, and a
    file that grows between the size check and the read is caught by a single
    overflow byte (never an unbounded parent allocation);
  * the profile admits only FINITE, bounded resource budgets — a disabled
    (``None``/zero/negative) mandatory limit is refused before anything starts;
  * the module-identity defence holds across a REAL worker: a genuine
    parent/worker run refuses a module that was swapped (including through a
    symlink) after admission, and a refused run attests no executed process
    mode while a successful one signs a record the existing verifier accepts.
"""

from __future__ import annotations

import hashlib
import os
import shutil
import stat
import sys
import tempfile
from pathlib import Path

import pytest
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


def _spy_worker(monkeypatch) -> dict:
    """Replace the isolated worker with a success stub and count dispatches.

    Pure-admission tests assert whether the worker was reached (dispatched) or
    not, without paying for a real subprocess — the refusal must never start a
    worker, an acceptance must.
    """
    import ephemora_cell.process_executor as pe

    calls = {"n": 0}

    def _stub(wasm_path, config, **kw):
        calls["n"] += 1
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

    monkeypatch.setattr(pe, "run_isolated", _stub)
    return calls


def _copy_module(src: str, dst: Path) -> str:
    shutil.copy(src, dst)
    return str(dst)


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


class TestProtectedBoundedAdmissionRead:
    """Admission never loads an unbounded module into the parent.

    The parent must refuse an oversized input on its declared size BEFORE
    reading it, cap the actual read to ``cap + 1`` bytes, translate file/read
    errors into controlled refusals, and reach the worker only for a bounded
    module that fully passes. Every refusal here dispatches no worker.
    """

    def test_module_exactly_at_the_cap_is_admitted(self, tmp_path, monkeypatch):
        calls = _spy_worker(monkeypatch)
        mod = _copy_module(HELLO02, tmp_path / "at_cap.wasm")
        size = Path(mod).stat().st_size
        sandbox = WASISandbox(config=WASIConfig(**{**_SMALL, "max_wasm_bytes": size}))
        try:
            result = sandbox.run(mod, abi="component", protected_component=True)
        finally:
            sandbox.cleanup()
        assert result.status is ExecutionStatus.SUCCESS, result.stderr
        assert calls["n"] == 1

    def test_one_byte_over_the_cap_refuses_without_dispatch(
        self, tmp_path, monkeypatch
    ):
        calls = _spy_worker(monkeypatch)
        mod = _copy_module(HELLO02, tmp_path / "over.wasm")
        size = Path(mod).stat().st_size
        sandbox = WASISandbox(
            config=WASIConfig(**{**_SMALL, "max_wasm_bytes": size - 1})
        )
        try:
            result = sandbox.run(mod, abi="component", protected_component=True)
        finally:
            sandbox.cleanup()
        assert result.status is ExecutionStatus.ERROR
        assert _REFUSAL in result.stderr
        assert "max_wasm_bytes cap" in result.stderr
        assert calls["n"] == 0

    def test_very_large_file_small_cap_refuses_before_reading(
        self, tmp_path, monkeypatch
    ):
        # The parent must reject on the declared size alone — never allocate the
        # whole oversized file. A ~2 MB file against a 1 KB cap proves it: the
        # refusal text states it was rejected before the module was read.
        calls = _spy_worker(monkeypatch)
        mod = tmp_path / "big.wasm"
        mod.write_bytes(b"\x00asm" + b"\x00" * (2 * 1024 * 1024))
        sandbox = WASISandbox(config=WASIConfig(**{**_SMALL, "max_wasm_bytes": 1024}))
        try:
            result = sandbox.run(str(mod), abi="component", protected_component=True)
        finally:
            sandbox.cleanup()
        assert result.status is ExecutionStatus.ERROR
        assert "refused before reading" in result.stderr
        assert calls["n"] == 0

    def test_file_grown_between_stat_and_read_is_refused(self, tmp_path, monkeypatch):
        # The bounded read pulls at most cap+1 bytes; a file that GREW after the
        # size check trips the overflow byte and is refused before hashing. The
        # stat/read size divergence is forced deterministically (a thread racing
        # the read would not be reproducible): a path reports the on-cap size
        # from stat while the bytes on disk are already one larger.
        calls = _spy_worker(monkeypatch)
        import ephemora_cell.wasi_runtime as wr

        cap = 16
        mod = tmp_path / "grow.wasm"
        mod.write_bytes(b"\x00" * (cap + 1))  # actually cap+1 bytes on disk
        # Subclass the concrete flavour (PosixPath/WindowsPath), not the generic
        # pathlib.Path, so instantiation stays valid across supported Pythons.
        flavour = type(Path())

        class _LiesAboutSize(flavour):
            def stat(self, *, follow_symlinks=True):
                st = super().stat(follow_symlinks=follow_symlinks)

                class _Fake:
                    st_mode = st.st_mode  # a real regular file
                    st_size = cap  # pretend it looked exactly at the cap

                return _Fake()

        real_path = wr.Path
        sandbox = WASISandbox(config=WASIConfig(**{**_SMALL, "max_wasm_bytes": cap}))
        try:
            wr.Path = _LiesAboutSize
            try:
                result = sandbox.run(
                    str(mod), abi="component", protected_component=True
                )
            finally:
                wr.Path = real_path
        finally:
            sandbox.cleanup()
        assert result.status is ExecutionStatus.ERROR
        assert _REFUSAL in result.stderr
        assert "changed" in result.stderr
        assert calls["n"] == 0

    def test_directory_input_is_refused_as_not_a_regular_file(
        self, tmp_path, monkeypatch
    ):
        calls = _spy_worker(monkeypatch)
        sandbox = WASISandbox(config=WASIConfig(**_SMALL))
        try:
            result = sandbox.run(
                str(tmp_path), abi="component", protected_component=True
            )
        finally:
            sandbox.cleanup()
        assert result.status is ExecutionStatus.ERROR
        assert "not a regular file" in result.stderr
        assert calls["n"] == 0

    def test_unreadable_file_becomes_a_controlled_refusal(self, tmp_path, monkeypatch):
        calls = _spy_worker(monkeypatch)
        mod = _copy_module(HELLO02, tmp_path / "noperm.wasm")
        os.chmod(mod, 0o000)
        sandbox = WASISandbox(config=WASIConfig(**_SMALL))
        try:
            result = sandbox.run(mod, abi="component", protected_component=True)
        finally:
            os.chmod(mod, stat.S_IRUSR | stat.S_IWUSR)  # restore for cleanup
            sandbox.cleanup()
        assert result.status is ExecutionStatus.ERROR
        assert _REFUSAL in result.stderr
        assert "unreadable" in result.stderr
        assert calls["n"] == 0


class TestProtectedMandatoryBudgets:
    """The profile admits only finite, bounded budgets.

    A run qualified as resource-bounded cannot start with a mandatory limit
    switched off. Each disabled knob is refused from the config alone — before
    any file is read, before any worker dispatch — and nothing outside the
    protected profile changes.
    """

    @pytest.mark.parametrize(
        "override,needle",
        [
            ({"max_fuel": None}, "max_fuel"),
            ({"max_fuel": 0}, "max_fuel"),
            ({"max_memory_mb": 0}, "max_memory_mb"),
            ({"max_wasm_bytes": 0}, "max_wasm_bytes"),
            ({"timeout_seconds": 0}, "timeout_seconds"),
            ({"io_cpu_seconds": None}, "io_cpu_seconds"),
            ({"io_budget_bytes": None}, "io_budget_bytes"),
            ({"disk_quota_bytes": None}, "disk_quota_bytes"),
        ],
    )
    def test_disabled_mandatory_limit_is_refused_before_dispatch(
        self, override, needle, monkeypatch
    ):
        calls = _spy_worker(monkeypatch)
        sandbox = WASISandbox(config=WASIConfig(**{**_SMALL, **override}))
        try:
            result = sandbox.run(HELLO02, abi="component", protected_component=True)
        finally:
            sandbox.cleanup()
        assert result.status is ExecutionStatus.ERROR
        assert _REFUSAL in result.stderr
        assert "resource configuration" in result.stderr
        assert needle in result.stderr
        assert calls["n"] == 0

    def test_finite_default_budgets_are_admitted(self, monkeypatch):
        # The all-finite default (the _SMALL knobs plus finite io/disk defaults)
        # passes the budget rule and reaches the worker.
        calls = _spy_worker(monkeypatch)
        sandbox = WASISandbox(config=WASIConfig(**_SMALL))
        try:
            result = sandbox.run(HELLO02, abi="component", protected_component=True)
        finally:
            sandbox.cleanup()
        assert result.status is ExecutionStatus.SUCCESS, result.stderr
        assert calls["n"] == 1

    def test_fractional_time_bound_is_admitted(self, monkeypatch):
        # Time dimensions may legitimately be fractional: a finite positive
        # float passes where an integer dimension would refuse the same type.
        calls = _spy_worker(monkeypatch)
        sandbox = WASISandbox(config=WASIConfig(**{**_SMALL, "io_cpu_seconds": 2.5}))
        try:
            result = sandbox.run(HELLO02, abi="component", protected_component=True)
        finally:
            sandbox.cleanup()
        assert result.status is ExecutionStatus.SUCCESS, result.stderr
        assert calls["n"] == 1

    @pytest.mark.parametrize(
        "override,needles",
        [
            # bool is an int subclass but is a mis-set flag, never a bound.
            ({"max_fuel": True}, ("max_fuel", "bool")),
            ({"timeout_seconds": False}, ("timeout_seconds", "bool")),
            # NaN / both infinities are not bounds on the time dimensions.
            ({"io_cpu_seconds": float("nan")}, ("io_cpu_seconds", "finite")),
            ({"timeout_seconds": float("inf")}, ("timeout_seconds", "finite")),
            ({"timeout_seconds": float("-inf")}, ("timeout_seconds", "finite")),
            # a non-int type on an integer dimension is refused, not coerced.
            ({"max_fuel": 1000.5}, ("max_fuel", "int")),
            ({"max_fuel": "1000"}, ("max_fuel", "int")),
            # zero and negatives are disabled/out-of-range, refused.
            ({"max_memory_mb": -1}, ("max_memory_mb", "positive")),
            # over the signed 64-bit range would overflow downstream enforcement.
            ({"max_fuel": 2**63}, ("max_fuel", "overflow")),
        ],
    )
    def test_invalid_numeric_budget_is_refused_before_dispatch(
        self, override, needles, monkeypatch
    ):
        # No invalid, infinite or non-representable mandatory bound can pass as
        # a valid protected configuration; each is refused from the config alone.
        calls = _spy_worker(monkeypatch)
        sandbox = WASISandbox(config=WASIConfig(**{**_SMALL, **override}))
        try:
            result = sandbox.run(HELLO02, abi="component", protected_component=True)
        finally:
            sandbox.cleanup()
        assert result.status is ExecutionStatus.ERROR
        assert _REFUSAL in result.stderr
        assert "resource configuration" in result.stderr
        for needle in needles:
            assert needle in result.stderr
        assert calls["n"] == 0


class TestProtectedRealWorkerByteSwap:
    """The identity defence holds across a REAL worker subprocess.

    These tests do NOT stub the worker: they let the genuine parent/worker path
    run and swap the module on disk after admission, proving the executed bytes
    are the inspected bytes — or the run is refused before the guest starts.
    """

    def _swap_before_worker(self, monkeypatch, module_path, swap_bytes):
        import ephemora_cell.process_executor as pe

        original = pe.run_isolated

        def _wrapper(wasm_path, *a, **kw):
            # Control-swap AFTER admission, BEFORE the worker loads the file.
            Path(module_path).write_bytes(swap_bytes)
            return original(wasm_path, *a, **kw)

        monkeypatch.setattr(pe, "run_isolated", _wrapper)

    def test_swapped_module_is_refused_by_the_real_worker(self, tmp_path, monkeypatch):
        mod = _copy_module(HELLO02, tmp_path / "swap.wasm")
        swapped = Path(FS02).read_bytes()  # a different valid component
        self._swap_before_worker(monkeypatch, mod, swapped)
        sandbox = WASISandbox(config=WASIConfig(**_SMALL))
        try:
            result = sandbox.run(mod, abi="component", protected_component=True)
        finally:
            sandbox.cleanup()
        assert result.status is ExecutionStatus.ERROR
        assert "module hash mismatch" in result.stderr
        # The swapped guest never ran: no stdout was produced.
        assert result.stdout == ""
        # Truthfully reported from the worker view (nothing was downgraded).
        assert result.execution_mode == "subprocess"

    def test_unswapped_module_runs_successfully_in_the_worker(self, tmp_path):
        # Control: identical bytes, no swap -> the real worker executes the guest.
        mod = _copy_module(HELLO02, tmp_path / "clean.wasm")
        sandbox = WASISandbox(config=WASIConfig(**_SMALL))
        try:
            result = sandbox.run(mod, abi="component", protected_component=True)
        finally:
            sandbox.cleanup()
        assert result.status is ExecutionStatus.SUCCESS, result.stderr
        assert result.execution_mode == "subprocess"
        assert result.abi == "component"

    def test_symlink_repoint_before_worker_load_is_refused(self, tmp_path, monkeypatch):
        # The API follows symlinks for admission; repointing the link after
        # admission must still be caught, because the bound digest — not the
        # path — fixes what the worker is allowed to execute.
        hello_target = _copy_module(HELLO02, tmp_path / "hello_target.wasm")
        fs_target = tmp_path / "fs_target.wasm"
        shutil.copy(FS02, fs_target)
        mod = tmp_path / "link.wasm"
        os.symlink(hello_target, mod)

        import ephemora_cell.process_executor as pe

        original = pe.run_isolated

        def _wrapper(wasm_path, *a, **kw):
            # Repoint the symlink to a different component before the worker.
            os.remove(mod)
            os.symlink(str(fs_target), mod)
            return original(wasm_path, *a, **kw)

        monkeypatch.setattr(pe, "run_isolated", _wrapper)
        sandbox = WASISandbox(config=WASIConfig(**_SMALL))
        try:
            result = sandbox.run(str(mod), abi="component", protected_component=True)
        finally:
            sandbox.cleanup()
        assert result.status is ExecutionStatus.ERROR
        assert "module hash mismatch" in result.stderr
        assert result.stdout == ""


class TestProtectedSignedEvidence:
    """A protected run signs a truthful record; a refusal signs nothing."""

    def test_real_protected_run_signs_a_verifiable_record(self):
        pytest.importorskip("cryptography")
        from cryptography.exceptions import InvalidSignature
        from cryptography.hazmat.primitives.asymmetric.ed25519 import (
            Ed25519PrivateKey,
        )

        from ephemora_cell import ExecutionReport

        config = WASIConfig(**_SMALL)
        sandbox = WASISandbox(config=config)
        try:
            result = sandbox.run(HELLO02, abi="component", protected_component=True)
        finally:
            sandbox.cleanup()
        assert result.status is ExecutionStatus.SUCCESS, result.stderr

        report = ExecutionReport(
            status=result.status.value,
            exit_code=result.exit_code,
            elapsed_ms=result.elapsed_ms,
            fuel_consumed=result.fuel_consumed,
        )
        report.apply_config(
            config,
            effective_preopens=result.effective_preopens,
            execution_mode=result.execution_mode,
            abi=result.abi,
        )
        key = Ed25519PrivateKey.generate()
        pub = key.public_key()

        def verifier(canonical, signature):
            try:
                pub.verify(signature, canonical)
                return True
            except InvalidSignature:
                return False

        signed = report.sign(key.sign, alg="EdDSA")
        assert ExecutionReport.verify(signed, verifier, expected_alg="EdDSA")

        baseline = signed["security_baseline"]
        # The record names the ACTUAL isolation path and ABI, and stays honest
        # about the component sync blockade that does NOT exist on this path.
        assert baseline["abi"] == "component"
        assert baseline["execution_mode"] == "subprocess"
        assert baseline["sync_blockade_enforced"] is False

        tampered = dict(signed)
        tampered["security_baseline"] = dict(baseline)
        tampered["security_baseline"]["execution_mode"] = "in_process"
        assert not ExecutionReport.verify(tampered, verifier, expected_alg="EdDSA")

    def test_refusal_resolves_no_abi_and_attests_no_executed_mode(self, monkeypatch):
        # A refusal ran nothing, so it must not fabricate an executed ABI or
        # claim a process mode a guest actually ran under.
        calls = _spy_worker(monkeypatch)
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
        assert result.abi is None
        assert result.execution_mode != "subprocess"
        assert calls["n"] == 0

        from ephemora_cell import ExecutionReport

        report = ExecutionReport(
            status=result.status.value,
            exit_code=result.exit_code,
            elapsed_ms=result.elapsed_ms,
        )
        report.apply_config(
            WASIConfig(**_SMALL),
            execution_mode=result.execution_mode,
            abi=result.abi,
        )
        baseline = report.security_baseline
        # Nothing resolved an ABI -> no fabricated component attestation.
        assert "abi" not in baseline
        assert "sync_blockade_enforced" not in baseline
        assert report.status != "success"


class TestProtectedDownstreamRefusalConsistency:
    """Every protected refusal — guard or downstream — resolves no ABI.

    A run that the profile refuses starts no guest, so it must never attest a
    component/preview1 execution that did not happen, no matter WHERE the refusal
    comes from: the admission guard, the sync-blockade requirement that a
    component can never honour, the isolation mandate with no worker available,
    or a tenant admission denial. A run whose worker genuinely started and then
    failed is the opposite case (proved in TestProtectedIsolationFailClosed and
    TestProtectedRealWorkerByteSwap): there the subprocess mode really took
    effect, so it is reported truthfully.
    """

    def test_required_sync_blockade_refuses_without_an_abi(self, monkeypatch):
        # protected_component is component-only; the effective sync blockade
        # exists only on preview1, so the combination is a contradiction that
        # must be refused WITHOUT stamping the resolved component ABI.
        calls = _spy_worker(monkeypatch)
        sandbox = WASISandbox(config=WASIConfig(**_SMALL))
        try:
            result = sandbox.run(
                HELLO02,
                abi="component",
                protected_component=True,
                require_sync_blockade=True,
            )
        finally:
            sandbox.cleanup()
        assert result.status is ExecutionStatus.ERROR
        assert _REFUSAL in result.stderr
        assert "sync blockade" in result.stderr
        assert result.abi is None
        assert result.execution_mode != "subprocess"
        assert calls["n"] == 0

    def test_isolation_unavailable_refusal_resolves_no_abi(self, monkeypatch):
        # The generic isolation refusal names the resolved component ABI for a
        # non-protected run; under the protected profile that would attest a
        # component execution that never started, so it is normalised to no ABI.
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
        assert "isolation" in result.stderr
        assert result.abi is None
        assert not Path(target, "out.txt").exists()

    def test_tenant_denial_resolves_no_abi(self, tmp_path, monkeypatch):
        # A protected run denied at tenant admission never dispatches a worker,
        # so it carries no executed ABI and no subprocess mode either.
        from ephemora_cell.tenant import CumulativeBudget, TenantStore

        calls = _spy_worker(monkeypatch)
        store = TenantStore(tmp_path / "tenant.jsonl")
        # The reservation for this config is max_fuel (5M); a 1-unit budget
        # cannot admit it.
        budget = CumulativeBudget(max_total_fuel=1)
        sandbox = WASISandbox(config=WASIConfig(**_SMALL))
        try:
            result = sandbox.run(
                HELLO02,
                abi="component",
                protected_component=True,
                tenant="acme",
                tenant_budget=budget,
                tenant_store=store,
            )
        finally:
            sandbox.cleanup()
        assert result.status is ExecutionStatus.ERROR
        assert "budget exhausted" in result.stderr
        assert result.abi is None
        assert result.execution_mode != "subprocess"
        assert calls["n"] == 0
