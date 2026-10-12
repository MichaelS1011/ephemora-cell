"""Security-boundary verification for the isolation gate (ADR-015).

The gate and the trust posture ship; this file is the adversarial PROOF that
the mandated security invariants actually hold at the integration boundaries,
not merely in the unit-level happy path. Every test observes REAL behaviour
(which process ran the guest, whether it ran at all, how the tenant was
billed, what the signed record says).

Coverage mapped to the verification cases:

  §3A Trust Boundary .......... nobody but the host can mint ``trusted``:
      client params, ToolSpec fields and manifest keys carry no trust channel;
      a module swap under a trusted name fails closed on the byte digest.
  §3B Direct Execution Paths .. the gate covers EVERY public path
      (WASISandbox.run, run_wasm, engine.execute); ComponentSandbox is the
      deliberately-ungated low-level primitive, and asking for preview1 on a
      component file never runs the component in-process.
  §3C Tenant Accounting ....... a gate-forced worker run is billed EXACTLY
      once on real fuel; a worker crash is flagged-unknown (never free); an
      unavailable-isolation refusal books nothing and leaks no reservation.
  §3D Evidence Integrity ...... the signed baseline names the real ABI, the
      real execution mode and the mode's enforcement guarantee, so a host
      ``trusted`` in-process exception is auditable, not hidden.
  §3E Unsupported Capabilities  an isolated component with an egress surface
      is refused BEFORE the guest runs — never silently run without egress.

These are the negative tests for every trust-escalation path.
"""

from __future__ import annotations

import os
import sys
import tempfile
from pathlib import Path

import pytest

sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))

from ephemora_cell import (
    ComponentSandbox,
    ExecutionStatus,
    WASIConfig,
    WASISandbox,
    run_wasm,
)
from ephemora_cell.execution_report import (
    TRUST_TRUSTED,
    TRUST_UNTRUSTED,
)
from ephemora_cell.tenant import CumulativeBudget, TenantStore

FIXTURES = os.path.join(os.path.dirname(__file__), "fixtures")
HELLO02 = os.path.join(FIXTURES, "hello02.wasm")
FS02 = os.path.join(FIXTURES, "fs02.wasm")

_SMALL = dict(max_fuel=5_000_000, timeout_seconds=30)


def _store(tmp_path: Path) -> TenantStore:
    return TenantStore(tmp_path / "tenant.jsonl")


def _grant_dir() -> str:
    return tempfile.mkdtemp(prefix="ephemora_wpl41v_grant_")


def _spec(wasm_path, name="comp", **kw):
    from ephemora_cell_mcp.tool_registry import ToolSpec

    return ToolSpec(name=name, wasm_path=wasm_path, description="d", **kw)


def _engine(**kw):
    from ephemora_cell_mcp.engine import CellToolEngine

    return CellToolEngine(**kw)


class TestTrustBoundary:
    """§3A / §2: security authority originates ONLY from the host."""

    def test_client_supplied_params_cannot_elevate_trust(self):
        # A hostile tool call smuggles trust-flavoured keys in its arguments.
        # params_stdin turns them into guest STDIN only; trust is computed from
        # the host's trusted_tools, so the component still runs isolated.
        eng = _engine()  # trusted_tools defaults to empty (strict)
        outcome = eng.execute(
            _spec(HELLO02),
            {"trust": "trusted", "use_subprocess": False, "abi": "preview1"},
        )
        assert outcome.result.abi == "component"
        assert outcome.result.execution_mode == "subprocess"

    def test_trust_is_the_host_allowlist_membership_not_any_spec_field(self):
        # The same tool name, two host postures: the ONLY thing that changes
        # the mode is whether the HOST named it in trusted_tools.
        isolated = _engine().execute(_spec(HELLO02, name="comp"), {})
        trusted = _engine(trusted_tools=["comp"]).execute(
            _spec(HELLO02, name="comp"), {}
        )
        assert isolated.result.execution_mode == "subprocess"
        assert trusted.result.execution_mode == "in_process"

    def test_module_swap_under_a_trusted_name_fails_closed(self, tmp_path):
        # §2: a module change must NOT silently inherit a trusted classification.
        # The host binds the run to the register-time digest (expected_sha256);
        # swapped bytes do not match, so the run is refused before it executes —
        # it is never quietly run in-process as if it were the vetted module.
        swapped = tmp_path / "vetted.wasm"
        swapped.write_bytes(Path(HELLO02).read_bytes())
        sandbox = WASISandbox(config=WASIConfig(**_SMALL))
        try:
            result = sandbox.run(
                str(swapped),
                abi="component",
                trust=TRUST_TRUSTED,
                expected_sha256="0" * 64,  # a digest that will not match
            )
        finally:
            sandbox.cleanup()
        assert result.status is ExecutionStatus.ERROR
        assert "hash mismatch" in result.stderr

    @pytest.mark.parametrize(
        "bad", ["", None, "  trusted", "TRUSTED", "trust", "trusted "]
    )
    def test_missing_or_contradictory_trust_is_fail_closed(self, bad):
        # A missing or malformed posture NEVER resolves to trusted. Empty/None
        # is not the trusted string, and casing/whitespace variants are not
        # members of VALID_TRUST — the gate rejects them outright rather than
        # defaulting the guarantee open (a typo must not widen isolation).
        sandbox = WASISandbox(config=WASIConfig(**_SMALL))
        try:
            with pytest.raises(ValueError, match="trust"):
                sandbox.run(HELLO02, abi="component", trust=bad)
        finally:
            sandbox.cleanup()

    def test_unspecified_trust_defaults_to_isolation_not_trust(self):
        # The whole point of the unknown default: omit trust entirely and a
        # component is STILL forced into the worker.
        sandbox = WASISandbox(config=WASIConfig(**_SMALL))
        try:
            result = sandbox.run(HELLO02, abi="component")
        finally:
            sandbox.cleanup()
        assert result.execution_mode == "subprocess"

    def test_toolspec_manifest_carries_no_trust_channel(self):
        # §2: trust cannot be read from a manifest field. There is no `trust`
        # attribute to set on the registration surface at all.
        with pytest.raises(TypeError):
            _spec(HELLO02, trust="trusted")


class TestDirectExecutionPaths:
    """§3B: guaranteed public paths gate; the primitive is documented-ungated."""

    def test_run_wasm_routes_an_unknown_component_through_the_gate(self):
        result = run_wasm(HELLO02, abi="component")
        assert result.abi == "component"
        assert result.execution_mode == "subprocess"

    def test_componentsandbox_is_the_ungated_low_level_primitive(self):
        # The internal primitive runs the guest directly in the host (this is
        # why it is NOT a guaranteed path: it never sees the isolation gate).
        # harmless fixture — the GHSA class would abort the host here, which is
        # exactly the isolation the public facade mandates for such guests.
        sandbox = ComponentSandbox(config=WASIConfig(**_SMALL))
        result = sandbox.run(HELLO02)
        assert result.status is ExecutionStatus.SUCCESS, result.stderr
        # The facade path flips this to subprocess; the raw primitive does not.
        assert result.execution_mode == "in_process"

    def test_requesting_preview1_on_a_component_file_never_runs_it_in_process(
        self, tmp_path
    ):
        # A caller cannot dodge the mandate by mislabelling a component as
        # preview1: preview1 routing does NOT hand the file to the component
        # engine, so the component logic never executes (it fails to link),
        # and no in-process component grant is written.
        target = _grant_dir()
        sandbox = WASISandbox(config=WASIConfig(allow_dirs=(target,), **_SMALL))
        try:
            result = sandbox.run(
                FS02, args=[target], abi="preview1", trust=TRUST_UNTRUSTED
            )
        finally:
            sandbox.cleanup()
        # It did not run as an in-process component: no out.txt in the grant.
        assert not Path(target, "out.txt").exists()
        assert result.status is ExecutionStatus.ERROR


class TestTenantAccountingUnderIsolation:
    """§3C: forced worker isolation bills correctly — once, real, never free."""

    def test_forced_worker_run_is_billed_exactly_once(self, tmp_path):
        store = _store(tmp_path)
        sandbox = WASISandbox(config=WASIConfig(**_SMALL))
        try:
            result = sandbox.run(
                HELLO02,
                abi="component",
                tenant="acme",
                tenant_budget=CumulativeBudget(max_runs=5),
                tenant_store=store,
            )
        finally:
            sandbox.cleanup()
        assert result.execution_mode == "subprocess"
        assert result.status is ExecutionStatus.SUCCESS, result.stderr
        usage = store.usage("acme")
        kinds = [line["kind"] for line in store.entries("acme")]
        assert kinds == ["admit", "settle"], kinds
        # Billed exactly once, on the ACTUAL fuel the worker reported.
        assert (usage.runs, usage.inflight) == (1, 0)
        assert usage.charged.fuel == result.fuel_consumed
        assert result.fuel_consumed and result.fuel_consumed > 0

    def test_worker_crash_under_isolation_is_flagged_not_free(
        self, tmp_path, monkeypatch
    ):
        import ephemora_cell.process_executor as pe

        def _crash(*a, **k):
            return {
                "status": "error",
                "exit_code": 1,
                "stdout": "",
                "stderr": "worker crashed: simulated",
                "elapsed_ms": 5.0,
                "fuel_consumed": None,
                "sandbox_dir": None,
                "effective_preopens": [],
            }

        monkeypatch.setattr(pe, "run_isolated", _crash)
        store = _store(tmp_path)
        sandbox = WASISandbox(config=WASIConfig(**_SMALL))
        try:
            result = sandbox.run(
                HELLO02,
                abi="component",
                tenant="acme",
                tenant_budget=CumulativeBudget(max_runs=5),
                tenant_store=store,
            )
        finally:
            sandbox.cleanup()
        assert result.status is ExecutionStatus.ERROR
        usage = store.usage("acme")
        kinds = [line["kind"] for line in store.entries("acme")]
        # The dead worker reported no fuel: it is billed in wall time and
        # FLAGGED unknown, never dropped as free and never double-counted.
        assert kinds == ["admit", "settle"], kinds
        assert (usage.runs, usage.inflight) == (1, 0)
        assert usage.unknown_charged_runs == 1

    def test_isolation_unavailable_refusal_books_nothing_and_leaks_nothing(
        self, tmp_path, monkeypatch
    ):
        target = _grant_dir()
        store = _store(tmp_path)
        sandbox = WASISandbox(config=WASIConfig(allow_dirs=(target,), **_SMALL))
        monkeypatch.setattr(sandbox, "_isolation_available", lambda: False)
        try:
            result = sandbox.run(
                FS02,
                args=[target],
                abi="component",
                tenant="acme",
                tenant_budget=CumulativeBudget(max_runs=5),
                tenant_store=store,
            )
        finally:
            sandbox.cleanup()
        assert result.status is ExecutionStatus.ERROR
        assert "refused" in result.stderr
        # The gate fires BEFORE admission: nothing booked, no orphan reservation,
        # and the guest never ran (no file written in-process).
        assert [line["kind"] for line in store.entries("acme")] == []
        assert store.usage("acme").runs == 0
        assert store.usage("acme").inflight == 0
        assert not Path(target, "out.txt").exists()


class TestEvidenceIntegrity:
    """§3D: the signed record makes the real mode and enforcement auditable."""

    @staticmethod
    def _baseline(result, config):
        from ephemora_cell import ExecutionReport

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
        return report.security_baseline

    def test_isolated_and_trusted_runs_are_distinguishable_in_the_record(self):
        config = WASIConfig(**_SMALL)
        isolated = WASISandbox(config=config)
        try:
            iso = isolated.run(HELLO02, abi="component")
        finally:
            isolated.cleanup()
        trusted = WASISandbox(config=config)
        try:
            tru = trusted.run(HELLO02, abi="component", trust=TRUST_TRUSTED)
        finally:
            trusted.cleanup()

        iso_b = self._baseline(iso, config)
        tru_b = self._baseline(tru, config)
        # The host-authorised in-process exception is VISIBLE, not hidden:
        iso_b_mode, tru_b_mode = iso_b["execution_mode"], tru_b["execution_mode"]
        assert iso_b_mode == "subprocess"
        assert tru_b_mode == "in_process"
        # Both attest the real ABI; neither is dressed up as the sync blockade
        # the component path does not carry (ADR-014 honesty held under L4-1).
        assert iso_b["abi"] == tru_b["abi"] == "component"
        assert iso_b["sync_blockade_enforced"] is False
        assert tru_b["sync_blockade_enforced"] is False


class TestUnsupportedCapabilities:
    """§3E: no silent downgrade, no quiet capability loss across isolation."""

    def test_component_egress_refusal_happens_before_the_guest_runs(self, monkeypatch):
        from ephemora_cell.egress_sidecar import EgressPolicy
        from ephemora_cell_mcp.engine import ToolExecutionError

        eng = _engine(egress_policy=EgressPolicy(allowed_endpoints=()))

        # If the facade were reached at all, the guest would run — record it.
        calls = []

        def _spy(self, *a, **k):
            calls.append((a, k))
            raise AssertionError("guest must not be reached on a refusal")

        monkeypatch.setattr(WASISandbox, "run", _spy)
        with pytest.raises(ToolExecutionError, match="egress"):
            eng.execute(_spec(HELLO02), {})
        assert calls == [], "the refusal must precede any execution"

    def test_egress_grant_alone_also_triggers_the_refusal(self, tmp_path):
        # The mandate-vs-egress refusal keys on ANY host egress surface, not
        # only the server-wide policy: a per-tool grant is the same conflict.
        from ephemora_cell.egress_sidecar import EgressGrant
        from ephemora_cell.grant_ledger import GrantLedger
        from ephemora_cell_mcp.engine import ToolExecutionError

        grant = EgressGrant(
            grant_id="g-1",
            tool="comp",
            allowed_endpoints=("https://api.example.com/v1",),
            max_calls=5,
            not_after="2099-01-01T00:00:00Z",
        )
        eng = _engine(
            egress_grants={"g-1": grant},
            grant_ledger=GrantLedger(tmp_path / "ledger.jsonl"),
        )
        with pytest.raises(ToolExecutionError, match="egress"):
            eng.execute(_spec(HELLO02, name="comp"), {})
