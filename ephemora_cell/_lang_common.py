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

from ._sandbox_common import _MAX_OUTPUT_BYTES, _OUTPUT_TRUNCATION_MARKER
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
        output_files_exceeded=bool(getattr(result, "output_files_exceeded", False)),
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
    if getattr(result, "output_files_exceeded", False):
        out["output_files_exceeded"] = True
        out["warnings"] = [
            *(out.get("warnings") or []),
            "guest output exceeded the host on-disk output cap",
        ]
    if getattr(result, "worker_crashed", False):
        out["worker_crashed"] = True
        out["warnings"] = [
            *(out.get("warnings") or []),
            "worker crashed — this is not a guest access denial",
        ]
    if getattr(result, "first_attempt_crashed", False):
        out["worker_attempts"] = int(getattr(result, "worker_attempts", 1))
        out["first_attempt_crashed"] = True
        out["warnings"] = [
            *(out.get("warnings") or []),
            "worker crashed on the first attempt; the run was retried",
        ]
    attempts = int(getattr(result, "worker_attempts", 1) or 1)
    if attempts > 1:
        out["worker_attempts"] = attempts
    first_error = str(getattr(result, "first_attempt_error", "") or "")
    if first_error:
        out["first_attempt_error"] = first_error
    if (
        attempts > 1
        or getattr(result, "first_attempt_crashed", False)
        or getattr(result, "first_attempt_output_unknown", False)
    ):
        out["first_attempt_fuel_consumed"] = getattr(
            result, "first_attempt_fuel_consumed", None
        )
        first_stdout = getattr(result, "first_attempt_stdout_bytes", None)
        first_stderr = getattr(result, "first_attempt_stderr_bytes", None)
        out["first_attempt_output_bytes"] = (
            first_stdout + first_stderr
            if first_stdout is not None and first_stderr is not None
            else None
        )
        if getattr(result, "first_attempt_output_unknown", False):
            out["first_attempt_output_unknown"] = True
        if getattr(result, "first_attempt_execution_started", None) is not None:
            out["first_attempt_execution_started"] = (
                result.first_attempt_execution_started
            )
        report_bytes = getattr(result, "first_attempt_report_bytes", None)
        if report_bytes:
            out["first_attempt_report_bytes"] = int(report_bytes)
        worker_stderr_bytes = getattr(result, "first_attempt_worker_stderr_bytes", None)
        if worker_stderr_bytes:
            out["first_attempt_worker_stderr_bytes"] = int(worker_stderr_bytes)
        out["first_attempt_wall_ms"] = int(
            getattr(result, "first_attempt_wall_ms", 0) or 0
        )
    retry_reason = str(getattr(result, "retry_suppressed_reason", "") or "")
    if retry_reason:
        out["retry_suppressed_reason"] = retry_reason
    if "MemoryError" in stderr:
        # The component guest can catch a failed linear-memory growth as a
        # Python exception and still return normally. The host saw no trap, so
        # this must NOT be reported as MEMORY_EXCEEDED; it is a guest-reported
        # diagnostic, kept separate from the host verdict.
        out["memory_limit_suspected"] = True
        out["warnings"] = [
            *(out.get("warnings") or []),
            "guest reported MemoryError; the host observed no memory-limit trap",
        ]
    # The host sink writes this marker when it refuses a write at the output
    # budget. Only the sink writes it; a guest that prints the same text is
    # still reporting a truncation-shaped output, so the flag is conservative
    # in the safe direction (it never turns a truncated capture into a clean
    # one). It is set only on truncation so the normal record keeps its shape.
    marker = _OUTPUT_TRUNCATION_MARKER.decode("ascii")
    if marker in stdout or marker in stderr:
        out["output_truncated"] = True
        out["output_limit_bytes"] = _MAX_OUTPUT_BYTES
        out["warnings"] = [
            *(out.get("warnings") or []),
            f"output truncated at the host output budget "
            f"({_MAX_OUTPUT_BYTES} bytes)",
        ]
    try:
        out["output"] = json.loads(stdout)
    except (TypeError, ValueError):
        out["output"] = None
    if user_error_marker is not None:
        out["guest_reported_error"] = user_error_marker in (out.get("stderr") or "")
    return out
