# SPDX-License-Identifier: BUSL-1.1
# Copyright 2026 Michael Soppa

"""Cell execution engine for MCP tools.

Every tool is a WASM module running inside the Ephemora Cell. The engine
implements the stdin/stdout contract:

* the guest receives ``{"params": <tool arguments>}`` on fd 0;
* on success it writes exactly one JSON value on fd 1 and exits 0;
* the engine parses that JSON and returns it to the MCP layer.

The cell's :class:`ephemora_cell.ExecutionReport` (fuel, timing, status,
security baseline) is preserved so the MCP layer can attach it as
``_meta`` — the "Verified. Not claimed." hook.
"""

from __future__ import annotations

import dataclasses
import json
import logging
import os
from dataclasses import asdict, dataclass
from pathlib import Path
from typing import Any

from ephemora_cell import (
    ExecutionReport,
    ExecutionResult,
    WASISandbox,
    is_component_binary,
)
from ephemora_cell._fsutil import atomic_write_text, read_regular_nofollow
from ephemora_cell.egress_sidecar import (
    REQUEST_FILENAME,
    REQUEST_MAX_BYTES,
    RESPONSE_FILENAME,
    EgressAuditEntry,
    EgressGrant,
    EgressPolicy,
    mediate,
    mediate_with_grant,
)
from ephemora_cell.grant_ledger import GrantLedger
from ephemora_cell.profiles import get as get_profile

from .tool_registry import ToolSpec


@dataclass
class CellOutcome:
    """A cell execution: raw result plus its enriched ExecutionReport.

    ``egress`` carries zero or more mediated egress decisions for the run
    (ADR-002 host-sidecar pattern). Each entry is an audit dict —
    url/method/decision/reason/status/bytes/hops plus the response document.
    It is empty unless the operator enabled an egress policy AND the guest
    wrote a request artifact, so an unaccounted run's ``_meta`` is unchanged.
    """

    result: ExecutionResult
    report: ExecutionReport
    egress: tuple[dict[str, Any], ...] = ()


class ToolExecutionError(Exception):
    """A tool could not be executed at all (config, missing module).

    Distinct from a cell *failure* (fuel/timeout/memory), which is
    returned as a :class:`CellOutcome` with a non-success status and is
    reported to the client as ``isError`` with full ``_meta``.
    """


def params_stdin(params: Any) -> str:
    """The stdin JSON contract for WASM MCP tools."""
    return json.dumps({"params": params}, ensure_ascii=False)


def parse_tool_stdout(stdout: str) -> tuple[Any, bool]:
    """Parse guest stdout per the contract.

    Returns ``(payload, is_error)``. The payload is the parsed JSON value
    when stdout is a single JSON document, else the raw text. A parsed
    object carrying a string ``"error"`` key counts as an error (the
    tool-level failure convention).
    """
    if not stdout:
        return "", False
    try:
        payload = json.loads(stdout)
    except ValueError:
        return stdout, False
    if isinstance(payload, dict) and isinstance(payload.get("error"), str):
        return payload, True
    return payload, False


def build_report(result: ExecutionResult, config: Any) -> ExecutionReport:
    """Fold a cell result + effective WASIConfig into an ExecutionReport.

    This is the enrichment attached to MCP results as ``_meta``:
    fuel_consumed, fuel_budget, elapsed_ms, status and the
    security_baseline (incl. wasmtime_version).
    """
    report = ExecutionReport(
        status=result.status.value,
        exit_code=result.exit_code,
        elapsed_ms=result.elapsed_ms,
        fuel_consumed=result.fuel_consumed,
        fuel_budget=config.max_fuel,
        stdout_bytes=len(result.stdout.encode("utf-8")),
        stderr_bytes=len(result.stderr.encode("utf-8")),
        module_path="",
        sandbox_dir=result.sandbox_dir or "",
    )
    report.apply_config(
        config,
        effective_preopens=result.effective_preopens,
        tenant=result.tenant,
        tenant_budget_ref=result.tenant_budget_ref,
    )
    return report


class CellToolEngine:
    """Runs a ToolSpec's WASM module inside the Ephemora Cell."""

    def __init__(
        self,
        profile: str = "llm",
        pooled: bool = False,
        egress_policy: EgressPolicy | None = None,
        egress_grants: dict[str, EgressGrant] | None = None,
        grant_ledger: GrantLedger | None = None,
        grants_required: bool = False,
    ) -> None:
        self.default_profile = profile
        # Trusted fast path (decision D3, 2026-09-12): disabling the
        # sandbox-dir byte wall re-enables the pooled engine (~0.5 ms/call
        # instead of ~12 ms — ADR-002 forces a per-run engine while a byte
        # wall is active). An explicit operator choice; the default stays
        # walled. The knob flows through _config_for, so get-policy
        # attests exactly what execution enforces.
        self.pooled = pooled
        # ADR-002 host-sidecar egress: when set, a guest that wrote a
        # sidecar.request.json into its sandbox is mediated by the HOST after
        # the run and the decision is surfaced in _meta. None (default) means
        # the mediator is never invoked — the receipts and _meta of an
        # unaccounted deployment stay byte-for-byte as they were.
        self.egress_policy = egress_policy
        # ADR-013 grant enforcement (Prio 1): tool name -> a SIGNED grant whose
        # window/cap/revocation a GrantLedger reads. When a run's tool has a
        # grant AND a ledger is attached, mediation is grant-gated (the grant's
        # allowlist + a charged call) instead of the server-wide policy path. A
        # tool with no grant keeps the plain egress_policy path; no policy and
        # no grant means no mediation at all.
        self.egress_grants = egress_grants or {}
        self.grant_ledger = grant_ledger
        # Strict posture (ADR-013): a tool with no signed grant is DENIED
        # mediation instead of falling back to the server-wide allowlist. Opt-in,
        # because the fallback is what existing deployments configured; with it
        # off, renaming or deleting one grant file quietly removes one cap.
        self.grants_required = grants_required
        if self.grants_required and (
            not self.egress_grants or self.grant_ledger is None
        ):
            raise ValueError(
                "grants_required is meaningful only with grants AND a ledger — "
                "set --egress-grants-dir and --grant-ledger as well"
            )
        if self.egress_grants and self.grant_ledger is None:
            raise ValueError(
                "egress_grants require a grant_ledger to enforce their "
                "window/cap/revocation — a grant without a consumer would "
                "silently downgrade to allowlist-only"
            )

    def _config_for(self, spec: ToolSpec) -> Any:
        try:
            base = get_profile(spec.profile)
        except ValueError as e:
            # Unknown profiles are a metadata bug — fail loudly, never
            # silently downgrade to the default profile.
            raise ToolExecutionError(
                f"tool {spec.name!r} declares unknown profile {spec.profile!r}"
            ) from e
        if spec.allow_dirs:
            # The sidecar can only NARROW the profile's grants, never
            # widen them - intersect with the profile's allow_dirs. Non-
            # empty grants are logged so deployments can audit who got
            # filesystem access.
            granted = tuple(d for d in spec.allow_dirs if d in base.allow_dirs)
            logging.getLogger(__name__).info(
                "tool %r grants preopens %s (sidecar requested %s, profile "
                "allows %s)",
                spec.name,
                granted,
                spec.allow_dirs,
                base.allow_dirs,
            )
            base = dataclasses.replace(base, allow_dirs=granted)
        if self.pooled:
            base = dataclasses.replace(base, io_budget_bytes=None)
        return base

    def policy_for(self, spec: ToolSpec) -> dict[str, Any]:
        """Effective sandbox policy for one tool, WITHOUT executing it.

        Derived from the same ``_config_for()`` path :meth:`execute` uses,
        so the reported policy and the enforced policy cannot drift.
        Preopens attest the filesystem surface execution will actually
        grant: the profile's configured ``allow_dirs`` plus the sandbox
        dir the sandbox layer preopens as ``/sandbox`` on every core
        (Preview1) run — exactly what the run's ``effective_preopens``
        records. WASI 0.2 components get no ``/sandbox`` mount, matching
        the component execution path. Also attests the execution
        topology: the default engine runs a fresh sandbox per call, the
        pooled fast path reuses a cached engine.
        """
        config = self._config_for(spec)
        report = ExecutionReport(status="configured", exit_code=0, elapsed_ms=0.0)
        report.apply_config(config)
        baseline = report.security_baseline
        try:
            component = is_component_binary(spec.wasm_path)
        except OSError:
            # Unreadable module — execution fails before any preopen
            # matters; report the core-module surface (the wider one).
            component = False
        preopens = list(baseline["preopens"])
        if not component and "/sandbox" not in preopens:
            preopens.append("/sandbox")
        baseline["preopens"] = preopens
        baseline["sandbox_lifecycle"] = "pooled" if self.pooled else "fresh-per-call"
        return baseline

    def execute(self, spec: ToolSpec, params: Any) -> CellOutcome:
        """Run ``spec`` with ``params`` in the cell.

        Returns a :class:`CellOutcome` for every executed run — success
        and cell failures alike (fuel exhausted, timeout, memory
        exceeded, non-zero exit). Raises :class:`ToolExecutionError` only
        when execution cannot start (config or sandbox setup errors).
        """
        stdin = params_stdin(params)
        config = self._config_for(spec)
        try:
            sandbox = WASISandbox(config=config)
        except ValueError as e:
            raise ToolExecutionError(str(e)) from e
        egress: tuple[dict[str, Any], ...] = ()
        try:
            result = sandbox.run(
                spec.wasm_path,
                stdin_data=stdin,
                use_subprocess=False,
                abi="auto",
                # Signed mode: bind the executed bytes to the digest
                # verified at register time (per-call module binding).
                expected_sha256=spec.wasm_sha256,
            )
            # Mediate AFTER the run but BEFORE cleanup — the request artifact
            # lives in the sandbox dir, which cleanup() removes. Reading it
            # here is the whole point of the trace: this is the one line that
            # turns the mediator from a reference module into an executed call.
            egress = self._mediate_egress(result.sandbox_dir, spec.name)
        finally:
            sandbox.cleanup()
        return CellOutcome(
            result=result,
            report=build_report(result, config),
            egress=egress,
        )

    def _mediate_egress(
        self, sandbox_dir: str | None, tool_name: str
    ) -> tuple[dict[str, Any], ...]:
        """Host-sidecar mediation of one run's request artifact, if any.

        Returns [] (no egress attempted, no _meta key) unless the run has an
        egress surface AND the guest wrote ``sidecar.request.json``. There are
        two surfaces (ADR-013): a tool with a signed grant and an attached
        ledger is mediated grant-gated — the grant's allowlist, INTERSECTED with
        the server-wide policy when one is also configured (a grant narrows, never
        enlarges), plus a charged call (revocation/window/cap enforced); any other
        tool falls back to the server-wide ``egress_policy`` allowlist path, and no
        surface at all means no mediation. With ``grants_required`` that fallback is
        gone: no grant, no egress. A present-but-unreadable artifact still yields an
        audit: the mediator parses untrusted bytes fail-closed, so a malformed
        request — or an artifact the host refuses to open — becomes a ``denied``
        entry rather than silence. An ABSENT file is the only case that stays
        quiet.
        """
        grant = self.egress_grants.get(tool_name)
        ledger = self.grant_ledger
        use_grant = grant is not None and ledger is not None
        policy: EgressPolicy | None = (
            grant.policy() if grant and use_grant else self.egress_policy
        )
        if policy is None or not sandbox_dir:
            return ()
        request_path = Path(sandbox_dir) / REQUEST_FILENAME
        if not os.path.lexists(request_path):
            return ()
        # Strict posture, checked AFTER the surface exists: a tool with no signed
        # grant that DID ask for egress is denied here rather than mediated on the
        # allowlist. A tool that asked for nothing keeps reporting no egress in
        # either mode — the flag changes what may be reached, not what a run says.
        if grant is None and self.grants_required:
            # Audited, because a denial that leaves no trace is indistinguishable
            # from a missing feature.
            return (
                {
                    **asdict(
                        EgressAuditEntry(
                            url="<unmediated>",
                            method="?",
                            decision="denied",
                            reason=(
                                f"tool {tool_name!r} has no signed grant and "
                                "--egress-grants-required is set"
                            ),
                            limit="grant-required",
                        )
                    ),
                    "response": {"ok": False, "error": "no grant for this tool"},
                },
            )
        try:
            # The artifact NAME lives in a directory the guest writes to, and WASI
            # refuses absolute symlink targets but accepts a relative one — so
            # ``sidecar.request.json -> ../../../../…`` is a guest-authored pointer
            # out of the sandbox that an ordinary open() would follow. Never
            # follow, and require the descriptor to be a regular file (ADR-013).
            raw = read_regular_nofollow(request_path, REQUEST_MAX_BYTES)
        except OSError as e:
            # The host log gets the full path; the audit line the client reads
            # gets the reason only. An absolute sandbox path in a tool response
            # is host information the caller has no use for.
            logging.getLogger(__name__).warning(
                "egress request artifact refused at %s: %s", request_path, e
            )
            reason = "request artifact refused: " + (
                getattr(e, "strerror", None) or str(e)
            )
            return (
                {
                    **asdict(
                        EgressAuditEntry(
                            url="<unreadable>",
                            method="?",
                            decision="denied",
                            reason=reason,
                        )
                    ),
                    "response": {"ok": False, "error": reason},
                },
            )
        if use_grant and grant is not None and ledger is not None:
            # A grant narrows the server-wide policy; it never widens it.
            outcome = mediate_with_grant(grant, ledger, raw, ceiling=self.egress_policy)
        else:
            outcome = mediate(policy, raw)
        # Produce the response artifact per the pattern. With a fresh sandbox
        # per call it does NOT survive cleanup — delivery to a follow-up run
        # is the host's job (state store or an explicit preopen), and the
        # audit + response below are what this call surfaces. The write is
        # best-effort and never fails the run — but it publishes atomically and
        # replaces whatever name is there, so it never writes THROUGH a link the
        # guest planted at that path.
        try:
            atomic_write_text(
                Path(sandbox_dir) / RESPONSE_FILENAME,
                json.dumps(outcome.response_doc),
            )
        except OSError as e:
            logging.getLogger(__name__).warning(
                "egress response artifact not written: %s", e
            )
        return ({**asdict(outcome.audit), "response": outcome.response_doc},)
