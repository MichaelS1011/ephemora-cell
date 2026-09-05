"""ephemora-cell-mcp Server — MCP stdio host whose tools are Cell WASM modules.

Protocol surface (dependency-free JSON-RPC 2.0 over NDJSON lines):

* ``initialize``                  -> protocolVersion/capabilities/serverInfo
* ``notifications/initialized``   -> (accepted silently)
* ``tools/list``                  -> tools discovered in the registry
* ``tools/call``                  -> WASM execution, result + ``_meta``
* ``tools/call get-policy``       -> native meta tool: effective sandbox
  policy per tool / for the registry (read-only; no WASM run)

Every ``tools/call`` runs the tool's ``.wasm`` in the Ephemora Cell with
``{"params": ...}`` on stdin and enriches the result with the execution
report under ``_meta``:

.. code-block:: json

    {
      "content": [{"type": "text", "text": "{\"echo\": ...}"}],
      "_meta": {"execution": {"status": "success", "fuel_consumed": ...,
                              "fuel_budget": ..., "elapsed_ms": ...,
                              "security_baseline": {"wasmtime_version": ...}}}
    }

Cell failures (FUEL_EXHAUSTED, TIMEOUT, MEMORY_EXCEEDED, ERROR) are
returned as ``isError: true`` results with status + message and the same
``_meta``; only protocol-level problems use JSON-RPC errors.
"""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any

from . import protocol
from .engine import CellOutcome, CellToolEngine, ToolExecutionError, parse_tool_stdout
from .tool_registry import ToolRegistry
from .transport import StdioTransport

_PACKAGE_TOOLS = Path(__file__).resolve().parent / "tools"

_NETWORK_POLICY = (
    "disabled - the WASI surface exposes no socket APIs; egress only via a "
    "host-side mediator (ADR-002)"
)

# Native (host-implemented) meta tools. They appear in tools/list after the
# registry tools and are dispatched without touching the WASM engine. A
# registry tool colliding with a native name is shadowed by the native tool.
_NATIVE_TOOLS = (
    {
        "name": "get-policy",
        "description": (
            'Returns the effective sandbox policy for Cell tools ("Verified. '
            'Not claimed."): fuel budget, memory limit, threads, preopens '
            "(configured), network policy and the security baseline incl. "
            'wasmtime version. Pass {"tool": "<name>"} for one tool or no '
            "arguments for the whole registry."
        ),
        "inputSchema": {
            "type": "object",
            "properties": {"tool": {"type": "string"}},
            "additionalProperties": False,
        },
    },
)
_NATIVE_NAMES = frozenset(t["name"] for t in _NATIVE_TOOLS)


class Server:
    """MCP stdio server for WASM-backed tools."""

    def __init__(
        self,
        tools_dir: str | Path | None = None,
        transport=None,
        engine: CellToolEngine | None = None,
    ) -> None:
        """Create the server.

        Args:
            tools_dir: Registry directory with ``<toolname>.wasm`` (and
                optional ``<toolname>.json`` metadata). Defaults to the
                tools bundled with the package; relative paths resolve
                against the current working directory.
            transport: Object with ``read_line() -> str|None`` and
                ``send(dict)``. Defaults to real stdio.
            engine: Cell execution engine (injectable for tests).
        """
        if tools_dir is None:
            tools_dir = _PACKAGE_TOOLS
        elif not Path(tools_dir).is_absolute():
            tools_dir = Path(tools_dir).resolve()
        self.tools_dir = Path(tools_dir)
        self.transport = transport if transport is not None else StdioTransport()
        self.engine = engine if engine is not None else CellToolEngine()
        self.registry = ToolRegistry(self.tools_dir)

    # --- public API -------------------------------------------------

    def serve(self) -> None:
        """Run the stdio loop until stdin closes.

        BrokenPipeError on send means the client went away — shut down
        cleanly instead of crashing with a traceback.
        """
        while True:
            line = self.transport.read_line()
            if line is None:
                return
            try:
                messages = self.handle_line(line)
            except Exception:
                # handle_line has its own catch-all; this is belt and braces
                # for the loop itself.
                continue
            for message in messages:
                try:
                    self.transport.send(message)
                except BrokenPipeError:
                    return

    def handle_line(self, line: str) -> list[dict[str, Any]]:
        """Process one raw NDJSON line; returns messages to send.

        Never raises: any unexpected failure is answered as JSON-RPC
        -32603 so one bad tool call or malformed line can never kill the
        server.
        """
        try:
            message = protocol.parse_line(line)
        except protocol.InvalidRequest as e:
            return [protocol.make_error(None, protocol.INVALID_REQUEST, str(e))]
        except ValueError:
            return [protocol.make_error(None, protocol.PARSE_ERROR, "parse error")]
        if message is None:
            return []
        try:
            return self.handle_message(message)
        except Exception as e:
            return [
                protocol.make_error(
                    message, protocol.INTERNAL_ERROR, f"internal error: {e}"
                )
            ]

    def handle_message(self, message: dict[str, Any]) -> list[dict[str, Any]]:
        """Dispatch one JSON-RPC message (in-process entry point)."""
        if "method" not in message or not isinstance(message.get("method"), str):
            return [
                protocol.make_error(
                    message, protocol.INVALID_REQUEST, "invalid request"
                )
            ]
        if protocol.is_notification(message):
            return self._handle_notification(message)
        method = message["method"]
        handler = {
            "initialize": self._handle_initialize,
            "tools/list": self._handle_tools_list,
            "tools/call": self._handle_tools_call,
        }.get(method)
        if handler is None:
            return [
                protocol.make_error(
                    message, protocol.METHOD_NOT_FOUND, f"method not found: {method}"
                )
            ]
        try:
            return [protocol.make_result(message, handler(message.get("params")))]
        except _InvalidParams as e:
            return [protocol.make_error(message, protocol.INVALID_PARAMS, str(e))]
        except Exception as e:
            return [
                protocol.make_error(
                    message, protocol.INTERNAL_ERROR, f"internal error: {e}"
                )
            ]

    # --- handlers ---------------------------------------------------

    def _handle_notification(self, message: dict[str, Any]) -> list[dict[str, Any]]:
        method = message.get("method")
        if method == "notifications/initialized":
            # Client announces readiness — nothing to answer (per MCP).
            return []
        if method == "notifications/cancelled":
            return []
        # Unknown notifications are silently ignored per JSON-RPC 2.0.
        return []

    def _handle_initialize(self, params: Any) -> dict[str, Any]:
        # Version negotiation: echo the client's requested version when we
        # support it, otherwise answer with our own so the client decides
        # whether to proceed (per MCP initialization).
        requested = None
        if isinstance(params, dict):
            requested = params.get("protocolVersion")
        version = (
            requested
            if requested in protocol.SUPPORTED_PROTOCOL_VERSIONS
            else protocol.MCP_PROTOCOL_VERSION
        )
        return {
            "protocolVersion": version,
            "capabilities": protocol.CAPABILITIES,
            "serverInfo": {
                "name": protocol.SERVER_NAME,
                "version": protocol.SERVER_VERSION,
            },
        }

    def _handle_tools_list(self, params: Any) -> dict[str, Any]:
        _ = params
        tools = [spec.to_mcp() for spec in self.registry.list_tools()]
        tools.extend(dict(tool) for tool in _NATIVE_TOOLS)
        return {"tools": tools}

    def _handle_tools_call(self, params: Any) -> dict[str, Any]:
        if not isinstance(params, dict) or "name" not in params:
            raise _InvalidParams("tools/call requires params.name")
        name = params.get("name")
        if not isinstance(name, str) or not name:
            raise _InvalidParams(
                "tools/call requires params.name to be a non-empty string"
            )
        if name in _NATIVE_NAMES:
            return self._handle_native_call(name, params.get("arguments"))
        spec = self.registry.get(name)
        if spec is None:
            raise _InvalidParams(f"unknown tool: {name}")
        arguments = params.get("arguments")
        try:
            outcome = self.engine.execute(spec, arguments)
        except ToolExecutionError as e:
            return {
                "content": [
                    {
                        "type": "text",
                        "text": json.dumps({"error": str(e)}, ensure_ascii=False),
                    }
                ],
                "isError": True,
            }
        return self._build_call_result(outcome)

    def _handle_native_call(self, name: str, arguments: Any) -> dict[str, Any]:
        """Dispatch a native meta tool (no WASM execution involved)."""
        if name == "get-policy":
            return self._handle_get_policy(arguments)
        raise _InvalidParams(f"unknown native tool: {name}")

    def _handle_get_policy(self, arguments: Any) -> dict[str, Any]:
        """Report the effective sandbox policy for one tool or the registry.

        Read-only by design: capability changes are host decisions, never
        chat decisions (see docs/decisions/ADR-006-governed-tool-loading).
        """
        if arguments is None:
            arguments = {}
        if not isinstance(arguments, dict):
            raise _InvalidParams("get-policy arguments must be an object")
        tool_name = arguments.get("tool")
        if tool_name is not None:
            if not isinstance(tool_name, str) or not tool_name:
                raise _InvalidParams(
                    "get-policy requires params.tool to be a non-empty string"
                )
            spec = self.registry.get(tool_name)
            if spec is None:
                raise _InvalidParams(f"unknown tool: {tool_name}")
            payload = self._policy_entry(spec)
            payload["tool"] = spec.name
        else:
            payload = {
                "server": {
                    "name": protocol.SERVER_NAME,
                    "version": protocol.SERVER_VERSION,
                },
                "tools": [
                    self._policy_entry(spec) for spec in self.registry.list_tools()
                ],
                "native_tools": [dict(t) for t in _NATIVE_TOOLS],
            }
        return {
            "content": [
                {"type": "text", "text": json.dumps(payload, ensure_ascii=False)}
            ]
        }

    def _policy_entry(self, spec: Any) -> dict[str, Any]:
        return {
            "name": spec.name,
            "profile": spec.profile,
            "allow_dirs_configured": list(spec.allow_dirs),
            "network": _NETWORK_POLICY,
            "security_baseline": self.engine.policy_for(spec),
        }

    def _build_call_result(self, outcome: CellOutcome) -> dict[str, Any]:
        result = outcome.result
        payload, tool_error = parse_tool_stdout(result.stdout)
        if isinstance(payload, str):
            text = payload
        else:
            text = json.dumps(payload, ensure_ascii=False)

        meta = {"execution": outcome.report.to_dict()}
        failed = (
            result.exit_code != 0 or tool_error
        ) or outcome.report.status != "success"
        message: dict[str, Any] = {
            "content": [{"type": "text", "text": text}],
            "_meta": meta,
        }
        if failed:
            detail = (
                payload if isinstance(payload, dict) else {"message": result.stderr}
            )
            message["content"] = [
                {
                    "type": "text",
                    "text": json.dumps(
                        {
                            "status": outcome.report.status,
                            "exit_code": result.exit_code,
                            **detail,
                        },
                        ensure_ascii=False,
                    ),
                }
            ]
            message["isError"] = True
        return message


class _InvalidParams(Exception):
    """Internal marker mapped to JSON-RPC -32602."""
