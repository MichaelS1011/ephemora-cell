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
from dataclasses import dataclass
from typing import Any

from ephemora_cell import ExecutionReport, ExecutionResult, WASISandbox
from ephemora_cell.profiles import get as get_profile

from .tool_registry import ToolSpec


@dataclass
class CellOutcome:
    """A cell execution: raw result plus its enriched ExecutionReport."""

    result: ExecutionResult
    report: ExecutionReport


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
    report.apply_config(config, effective_preopens=result.effective_preopens)
    return report


class CellToolEngine:
    """Runs a ToolSpec's WASM module inside the Ephemora Cell."""

    def __init__(self, profile: str = "llm") -> None:
        self.default_profile = profile

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
        return base

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
        try:
            result = sandbox.run(
                spec.wasm_path,
                stdin_data=stdin,
                use_subprocess=False,
                abi="auto",
            )
        finally:
            sandbox.cleanup()
        return CellOutcome(result=result, report=build_report(result, config))