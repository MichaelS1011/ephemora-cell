"""ADR-015 — untrusted/unknown process-isolation mandate (1.2.0 decision).

The original measured threat (V1, ``benchmarks/results/2026-09-29/datetime_overflow_
ghsa_j2g9.json``): a crafted ``fd_filestat_set_times(u64::MAX)`` component panics
the wasmtime host line with SIGABRT — returncode -6, HOST DIES in-process, but
the identical guest run in the disposable worker reports ``parent_survived``.
Process isolation is exactly that boundary.

The 1.2.0 isolation mandate (ADR-015) WIDENS the rule: an untrusted or
unknown run MUST be isolated for BOTH ABIs -- a foreign/unclassified guest never
lands on the weaker in-process path merely because it happens to be preview1.
Only an explicit host ``trusted`` posture keeps the in-process fast path.

These tests observe REAL behaviour (which process ran the guest, whether the
guest ran at all), not config flags:

  Option A (central gate, WASISandbox.run choke point)
    * unknown / untrusted component  -> forced into the worker (execution_mode
      "subprocess"), even when the caller asked for in-process.
    * unknown / untrusted preview1   -> ALSO forced into the worker (1.2.0).
    * trusted (any ABI)              -> host-authorised in-process stays.
    * abi="auto" resolving component -> no bypass through auto-dispatch.
    * isolation unavailable          -> refused BEFORE the guest runs (no file
      written), never downgraded to in-process.
    * worker crash under a forced run -> ERROR, no in-process fallback.
    * invalid trust value            -> ValueError (a typo must not widen it).

  Option B (MCP host-controlled trust posture, engine.execute)
    * a tool outside trusted_tools runs isolated (preview1 or component);
    * a tool the host explicitly trusts runs in-process;
    * an isolated tool that ALSO has a sidecar-egress surface is REFUSED
      up front (no silent capability loss, no in-process downgrade);
    * a guest cannot self-elevate: ToolSpec carries no trust channel.

  Evidence integrity (ADR-014 unchanged)
    * an isolated component record attests execution_mode subprocess + abi
      component + sync_blockade_enforced False — isolation is never dressed up
      as the still-absent component sync blockade.
"""

from __future__ import annotations

import os
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
    TRUST_UNTRUSTED,
)

FIXTURES = os.path.join(os.path.dirname(__file__), "fixtures")
HELLO02 = os.path.join(FIXTURES, "hello02.wasm")
FS02 = os.path.join(FIXTURES, "fs02.wasm")

_SMALL = dict(max_fuel=5_000_000, timeout_seconds=30)

PREVIEW1_WAT = '(module (func (export "_start")))'


def _preview1_wasm(tmp_path: Path) -> str:
    p = tmp_path / "hello_p1.wasm"
    p.write_bytes(wasmtime.wat2wasm(PREVIEW1_WAT))
    return str(p)


def _grant_dir() -> str:
    return tempfile.mkdtemp(prefix="ephemora_wpl41_grant_")


class TestCentralGate:
    """Option A: the mandate fires at the single WASISandbox.run choke point."""

    def test_unknown_component_is_forced_into_the_worker(self):
        sandbox = WASISandbox(config=WASIConfig(**_SMALL))
        try:
            # Caller asked for in-process (use_subprocess=False, the default).
            result = sandbox.run(HELLO02, abi="component", use_subprocess=False)
        finally:
            sandbox.cleanup()
        assert result.status is ExecutionStatus.SUCCESS, result.stderr
        # The gate flipped it: the guest ACTUALLY ran in the worker, not here.
        assert result.execution_mode == "subprocess"
        assert result.abi == "component"

    def test_untrusted_component_is_forced_into_the_worker(self):
        sandbox = WASISandbox(config=WASIConfig(**_SMALL))
        try:
            result = sandbox.run(HELLO02, abi="component", trust=TRUST_UNTRUSTED)
        finally:
            sandbox.cleanup()
        assert result.execution_mode == "subprocess"

    def test_trusted_component_keeps_the_in_process_path(self):
        sandbox = WASISandbox(config=WASIConfig(**_SMALL))
        try:
            result = sandbox.run(HELLO02, abi="component", trust=TRUST_TRUSTED)
        finally:
            sandbox.cleanup()
        assert result.status is ExecutionStatus.SUCCESS, result.stderr
        # Explicit host authorisation is the ONLY way to keep it in-process.
        assert result.execution_mode == "in_process"

    def test_preview1_is_not_the_mandate_class(self):
        # superseded by the 1.2.0 mandate: preview1 untrusted is now isolated too.
        pytest.skip("superseded by test_untrusted_preview1_is_forced_into_the_worker")

    def test_untrusted_preview1_is_forced_into_the_worker(self):
        # The 1.2.0 isolation mandate: preview1 is no longer exempt.
        # A foreign/unclassified preview1 run is forced to the worker even when
        # the caller asked for in-process -- the ABI does not buy a weaker path.
        with tempfile.TemporaryDirectory() as td:
            wasm = _preview1_wasm(Path(td))
            sandbox = WASISandbox(config=WASIConfig(**_SMALL))
            try:
                result = sandbox.run(
                    wasm, abi="preview1", trust=TRUST_UNTRUSTED, use_subprocess=False
                )
            finally:
                sandbox.cleanup()
            assert result.execution_mode == "subprocess"
            assert result.abi == "preview1"
            # The mandate is about WHERE it ran, not the guest's exit: a bare
            # no-op core fixture under the worker is proof enough the preview1
            # run was NOT demoted to in-process.

    def test_unknown_default_preview1_is_forced_into_the_worker(self):
        # The default posture is unknown (fail-closed); a bare preview1 run with
        # no explicit trust is isolated exactly like an untrusted one.
        with tempfile.TemporaryDirectory() as td:
            wasm = _preview1_wasm(Path(td))
            sandbox = WASISandbox(config=WASIConfig(**_SMALL))
            try:
                result = sandbox.run(wasm, abi="preview1", use_subprocess=False)
            finally:
                sandbox.cleanup()
            assert result.execution_mode == "subprocess"

    def test_trusted_preview1_keeps_the_in_process_path(self):
        # Only explicit host authorisation keeps the in-process fast path.
        with tempfile.TemporaryDirectory() as td:
            wasm = _preview1_wasm(Path(td))
            sandbox = WASISandbox(config=WASIConfig(**_SMALL))
            try:
                result = sandbox.run(wasm, abi="preview1", trust=TRUST_TRUSTED)
            finally:
                sandbox.cleanup()
            assert result.execution_mode == "in_process"

    def test_auto_dispatch_on_a_component_cannot_bypass_the_gate(self):
        # abi="auto" is explicitly called out: the gate must
        # resolve component and isolate it, not honour the in-process request.
        sandbox = WASISandbox(config=WASIConfig(**_SMALL))
        try:
            result = sandbox.run(HELLO02, abi="auto", use_subprocess=False)
        finally:
            sandbox.cleanup()
        assert result.abi == "component"
        assert result.execution_mode == "subprocess"

    def test_isolation_unavailable_refuses_before_the_guest_runs(self, monkeypatch):
        target = _grant_dir()
        sandbox = WASISandbox(config=WASIConfig(allow_dirs=(target,), **_SMALL))
        monkeypatch.setattr(sandbox, "_isolation_available", lambda: False)
        try:
            result = sandbox.run(FS02, args=[target], abi="component")
        finally:
            sandbox.cleanup()
        assert result.status is ExecutionStatus.ERROR
        assert "refused" in result.stderr
        assert "isolation" in result.stderr
        # Nothing ran: the guest never got to write its file in-process.
        assert not Path(target, "out.txt").exists()

    def test_forced_run_never_falls_back_to_in_process_on_worker_crash(
        self, monkeypatch
    ):
        # The mandate forces subprocess; if the worker dies, the result is a
        # fail-closed ERROR — the guest is NOT re-run in-process.
        import ephemora_cell.process_executor as pe

        sandbox = WASISandbox(config=WASIConfig(**_SMALL))

        def _crashing_worker(*a, **k):
            # Stand-in for a worker that died before printing a report: the
            # parent maps this to a fail-closed ERROR and must NOT retry
            # the guest in-process.
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
            result = sandbox.run(HELLO02, abi="component")
        finally:
            sandbox.cleanup()
        assert result.status is ExecutionStatus.ERROR
        assert "worker crashed" in result.stderr
        assert result.execution_mode == "subprocess"

    def test_invalid_trust_value_is_rejected(self):
        sandbox = WASISandbox(config=WASIConfig(**_SMALL))
        try:
            with pytest.raises(ValueError, match="trust"):
                sandbox.run(HELLO02, abi="component", trust="definitely-trusted")
        finally:
            sandbox.cleanup()


class TestEvidenceIntegrity:
    """Isolation never disguises itself as the still-absent sync blockade."""

    def test_isolated_component_record_attests_the_truth(self):
        from ephemora_cell import ExecutionReport

        config = WASIConfig(**_SMALL)
        sandbox = WASISandbox(config=config)
        try:
            result = sandbox.run(HELLO02, abi="component")
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
        # A component run STILL cannot claim the sync blockade, isolated or not.
        assert baseline["sync_blockade_enforced"] is False
        # And the record states it ran isolated (process isolation is honest,
        # not conflated with the sync guarantee).
        assert result.execution_mode == "subprocess"


class TestMcpTrustPosture:
    """Option B: host-controlled trust on the MCP engine, no guest elevation."""

    @staticmethod
    def _engine(**kw):
        from ephemora_cell_mcp.engine import CellToolEngine

        return CellToolEngine(**kw)

    @staticmethod
    def _spec(wasm_path, name="comp"):
        from ephemora_cell_mcp.tool_registry import ToolSpec

        return ToolSpec(name=name, wasm_path=wasm_path, description="d", profile="llm")

    def test_unlisted_component_tool_runs_isolated(self):
        eng = self._engine()
        outcome = eng.execute(self._spec(HELLO02), {})
        assert outcome.result.abi == "component"
        assert outcome.result.execution_mode == "subprocess"

    def test_host_trusted_component_tool_stays_in_process(self):
        eng = self._engine(trusted_tools=["comp"])
        outcome = eng.execute(self._spec(HELLO02), {})
        assert outcome.result.execution_mode == "in_process"

    def test_preview1_tool_is_untouched(self):
        # superseded by the 1.2.0 mandate: an unlisted preview1 tool is isolated.
        with tempfile.TemporaryDirectory() as td:
            wasm = _preview1_wasm(Path(td))
            eng = self._engine()
            outcome = eng.execute(self._spec(wasm, name="p1"), {})
            # Unknown posture -> protected worker for BOTH ABIs (1.2.0).
            assert outcome.result.execution_mode == "subprocess"

    def test_host_trusted_preview1_tool_stays_in_process(self):
        # Only the explicit host trust list keeps a preview1 tool in-process.
        with tempfile.TemporaryDirectory() as td:
            wasm = _preview1_wasm(Path(td))
            eng = self._engine(trusted_tools=["p1"])
            outcome = eng.execute(self._spec(wasm, name="p1"), {})
            assert outcome.result.execution_mode == "in_process"

    def test_component_with_egress_surface_is_refused(self):
        from ephemora_cell.egress_sidecar import EgressPolicy
        from ephemora_cell_mcp.engine import ToolExecutionError

        eng = self._engine(egress_policy=EgressPolicy(allowed_endpoints=()))
        with pytest.raises(ToolExecutionError, match="egress"):
            eng.execute(self._spec(HELLO02), {})

    def test_trusted_component_with_egress_is_not_refused(self):
        # The refusal is scoped to the mandate class; a host-trusted component
        # keeps today's in-process egress path (no regression of §2 boundary).
        from ephemora_cell.egress_sidecar import EgressPolicy

        eng = self._engine(
            egress_policy=EgressPolicy(allowed_endpoints=()),
            trusted_tools=["comp"],
        )
        # No raise: it proceeds (in-process); the run itself may fail on the
        # fixture but that is not a policy refusal.
        outcome = eng.execute(self._spec(HELLO02), {})
        assert outcome.result.execution_mode == "in_process"

    def test_guest_has_no_channel_to_elevate_its_own_trust(self):
        # ToolSpec is the tool-registration surface; it must carry no trust
        # field the guest/publisher could set. Trust lives only on the host
        # engine (trusted_tools). If this attribute ever appears on ToolSpec,
        # the "guest cannot self-elevate" invariant needs re-examination.
        from dataclasses import fields

        from ephemora_cell_mcp.tool_registry import ToolSpec

        names = {f.name for f in fields(ToolSpec)}
        assert "trust" not in names
        assert not any("trust" in n for n in names)
