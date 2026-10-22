# SPDX-License-Identifier: BUSL-1.1
# Copyright 2026 Michael Soppa

"""Shared adapter result shaping — the ONE construction site for the language
adapters' result dict.

Before this module the six base keys plus the parsed ``output`` were built in
four places (python component / python preview1 / javascript module /
javascript source) and the ``guest_reported_error`` marker rule lived in
two of them — three drift-prone copies of an integrity-relevant record. The
observable shape per path is unchanged and pinned by
``tests/test_adapter_result_shape.py``: the two paths that were marker-less
stay marker-less (``user_error_marker=None``); wiring the marker into them is
a separate, explicitly labelled contract change, never part of this refactor.

The marker stays a *guest-supplied diagnostic*: it is recorded under
``guest_reported_error`` only and never touches ``status`` or ``exit_code``
(execution-record integrity).

``exit_status_fidelity`` states, per route, how much of the *script's own* exit
status can reach the host at all — ``"exact"`` (the Preview1 interpreter's
``proc_exit`` arrives as the run's exit code), ``"non_zero_only"`` (a component
leaves through ``wasi:cli/exit`` and only the non-zero fact survives) or
``"none"`` (the guest's harness does not report it, so ``status``/``exit_code``
attest the export, not the script). It is a statement about the CHANNEL, not a
new verdict: it never changes ``status``, never invents a code, and a caller
that ignores it reads exactly what it read before.
"""

from __future__ import annotations

import json
from typing import Any

from .execution_report import ExecutionReport
from .execution_report import exit_status_fidelity as derive_fidelity

__all__ = ["shape_result"]


def shape_result(
    result: Any,
    *,
    user_error_marker: str | None = None,
    exit_status_fidelity: str | None = None,
    config: Any,
) -> dict[str, Any]:
    """Normalise an ``ExecutionResult`` into the shared adapter result shape.

    Args:
        result: an ``ExecutionResult`` (any object with the six documented
            attributes; ``fuel_consumed`` / ``elapsed_ms`` degrade to ``None``
            when absent, matching the historical helper).
        user_error_marker: the adapter's ``EPHEMORA_USER_ERROR``-style marker;
            when given, the flag is derived from the *untrusted* stderr
            content and recorded separately — never as a status signal.
        exit_status_fidelity: how much of the *program the caller handed over*
            can reach the host. Leave it unset to derive the word from the run's
            own facts (``result.abi`` and the raw ``guest_exit_observed``) through
            the one function the CLI, the signed record and MCP ``_meta`` use —
            that is right wherever the guest IS the program (a WASM module, a
            caller-built JavaScript module). Name it on the two harness-mediated
            routes, and only there: when a CPython component loader or the QuickJS
            harness swallows the script's own exit, the guest can leave through
            its exit interface and the SCRIPT's status still never arrives, so the
            channel this field describes is closed no matter what the raw fact
            says. A literal that is not reasoned from that difference is how a
            route ends up claiming ``exact`` for a fuel stop with no guest exit.
        config: the effective ``WASIConfig`` this adapter built for the run.
            Required, not optional: the measurement fields of the shared
            document (``security_baseline``, budgets, byte counts) describe
            THAT configuration, and a language run that reported none of them
            while ``run module.wasm`` reported all of them left a consumer with
            two shapes behind one command. They are produced through the same
            :class:`~ephemora_cell.execution_report.ExecutionReport` the wasm
            path and the signed record use, so the base of this dict cannot
            drift from the record shape it is meant to match.

    The adapter keeps its own published ``status`` form (``str(ExecutionStatus…)``)
    — that is the library's existing contract; ``run --json`` normalises it to the
    short form for every route. What a language run adds on top of the shared base
    (``stdout``/``stderr`` text, the parsed ``output``, ``guest_reported_error``,
    and the CLI's ``language``/``script``) is stated in ``docs/languages.md``.
    """
    stdout = getattr(result, "stdout", "") or ""
    stderr = getattr(result, "stderr", "") or ""
    fuel_consumed = getattr(result, "fuel_consumed", None)
    elapsed_ms = getattr(result, "elapsed_ms", None)
    claim = exit_status_fidelity or derive_fidelity(
        abi=getattr(result, "abi", None),
        guest_exit_observed=bool(getattr(result, "guest_exit_observed", False)),
    )
    probe = ExecutionReport(
        # the base fields come from the record class, byte for byte as a wasm run
        # would attest them; `status` is overwritten below with the adapter's form
        status=str(result.status),
        exit_code=result.exit_code,
        # the dataclass needs a number where a duck-typed stub has none; the
        # caller-visible field is restored to `None` after to_dict() (same
        # degradation the helper has always promised for an absent measurement)
        elapsed_ms=elapsed_ms if elapsed_ms is not None else 0.0,
        fuel_consumed=fuel_consumed,
        fuel_budget=getattr(config, "max_fuel", None),
        stdout_bytes=len(stdout.encode("utf-8")),
        stderr_bytes=len(stderr.encode("utf-8")),
        exit_status_fidelity=claim,
    ).apply_config(
        config,
        effective_preopens=getattr(result, "effective_preopens", None),
        tenant=getattr(result, "tenant", None),
        tenant_budget_ref=getattr(result, "tenant_budget_ref", None),
        execution_mode=getattr(result, "execution_mode", None),
        abi=getattr(result, "abi", None),
    )
    out: dict[str, Any] = probe.to_dict()
    out["status"] = str(result.status)
    out["elapsed_ms"] = elapsed_ms
    out["stdout"] = stdout
    out["stderr"] = stderr
    try:
        out["output"] = json.loads(stdout)
    except (TypeError, ValueError):
        out["output"] = None
    if user_error_marker is not None:
        out["guest_reported_error"] = user_error_marker in (out.get("stderr") or "")
    return out
