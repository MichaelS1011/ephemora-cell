"""ephemora-cell-mcp Server — MCP stdio host whose tools are Cell WASM modules.

Protocol surface (dependency-free JSON-RPC 2.0 over NDJSON lines), dual-era
per the 2026-07-28 revision ("Versioning and Compatibility"):

* ``server/discover``            -> supported versions/capabilities/identity
* ``initialize``                 -> protocolVersion/capabilities/serverInfo
  (legacy era, unchanged; selects legacy semantics even with ``_meta``)
* ``notifications/initialized``   -> (accepted silently)
* ``tools/list``                  -> tools discovered in the registry
* ``tools/call``                  -> WASM execution, result + ``_meta``
* ``tools/call get-policy``       -> native meta tool: effective sandbox
  policy per tool / for the registry (read-only; no WASM run)

Requests carrying ``_meta`` with
``io.modelcontextprotocol/protocolVersion: "2026-07-28"`` are served
statelessly: no initialize handshake, no session — every request stands
alone, results gain ``resultType: "complete"`` and
``_meta['io.modelcontextprotocol/serverInfo']``, and list endpoints carry
the CacheableResult fields (``ttlMs``/``cacheScope``). An unsupported
version is rejected with ``-32022`` naming the supported versions so the
client can retry. Requests without per-request ``_meta`` keep the exact
pre-2026-07-28 behavior for handshake-era clients. MRTR never occurs: this
server issues no server-initiated requests (sampling/elicitation/roots are
deprecated in 2026-07-28 and unused here), so ``"complete"`` is the only
result type it can produce.

Every ``tools/call`` runs the tool's ``.wasm`` in the Ephemera Cell with
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
import sys
from collections.abc import Callable
from pathlib import Path
from typing import Any

from ephemora_cell._fsutil import atomic_write_bytes, atomic_write_json
from ephemora_cell.profiles import get as get_profile

from . import protocol
from .engine import CellOutcome, CellToolEngine, ToolExecutionError, parse_tool_stdout
from .tool_registry import (
    TOOL_REQUEST_SUFFIX,
    ToolRegistry,
    tool_wasm_sha256_bytes,
    verify_manifest,
)
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
        pooled: bool = False,
        manifest_verifier: Callable[[bytes, bytes], bool] | None = None,
        tool_requests_dir: str | Path | None = None,
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
            pooled: Trusted fast path (decision D3) — disable the
                sandbox-dir I/O byte wall so the pooled engine serves each
                call (~0.5 ms/call). Explicit operator choice; ``get-policy``
                attests the relaxed wall. Ignored when ``engine`` is given.
            manifest_verifier: ADR-006 verify-before-register: when given,
                every tool sidecar must carry a valid manifest signature
                (``tool_registry.sign_manifest``) and unsigned/tampered
                tools are rejected at load. See
                ``tool_registry.ed25519_verifier_from_pem``.
            tool_requests_dir: Governed-load requests directory (ADR-006).
                The host drops or allows guests to drop
                ``<name>.tool.request.json`` files here; the HOST invokes
                :meth:`process_tool_requests` to evaluate them
                (verify-before-register), install accepted tools and emit
                ``notifications/tools/list_changed``. When set,
                ``initialize`` advertises ``listChanged: True``.
        """
        if tools_dir is None:
            tools_dir = _PACKAGE_TOOLS
        elif not Path(tools_dir).is_absolute():
            tools_dir = Path(tools_dir).resolve()
        self.tools_dir = Path(tools_dir)
        self.tool_requests_dir = (
            Path(tool_requests_dir).resolve() if tool_requests_dir else None
        )
        self.transport = transport if transport is not None else StdioTransport()
        self.engine = engine if engine is not None else CellToolEngine(pooled=pooled)
        self.registry = ToolRegistry(
            self.tools_dir, manifest_verifier=manifest_verifier
        )

    # --- public API -------------------------------------------------

    def serve(self) -> None:
        """Run the stdio loop until stdin closes.

        With ``--tool-requests-dir`` configured (ADR-006), dropped tool
        requests are evaluated on every message boundary, so the shipped
        stdio server honors governed loading without a custom embedding
        host — verify-before-register still gates each install and a
        rejected request stays on disk.

        BrokenPipeError on send means the client went away — shut down
        cleanly instead of crashing with a traceback.
        """
        while True:
            line = self.transport.read_line()
            if line is None:
                return
            if self.tool_requests_dir is not None:
                try:
                    report = self.process_tool_requests()
                except BrokenPipeError:
                    return
                except Exception:
                    # Governed loading must never break the serve loop; an
                    # unevaluated request stays on disk for the next message.
                    pass
                else:
                    # "Never silent" (ADR-006): on stdio there is no report
                    # consumer, so rejections surface on stderr.
                    for entry in report.get("rejected", []):
                        print(
                            f"ephemora-cell-mcp: tool request rejected: " f"{entry}",
                            file=sys.stderr,
                        )
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
            "server/discover": self._handle_server_discover,
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
            # initialize selects legacy semantics even when _meta is present
            # (era selection is driven by how the client opens, not by
            # per-request metadata) — 2026-07-28 "Versioning and
            # Compatibility".
            if method != "initialize":
                self._check_request_version(message)
            result = handler(message.get("params"))
            if method != "initialize" and self._request_is_modern(message):
                result = self._modernize_result(method, result)
            return [protocol.make_result(message, result)]
        except _UnsupportedProtocolVersion as e:
            return [
                protocol.make_error(
                    message,
                    protocol.UNSUPPORTED_PROTOCOL_VERSION,
                    "Unsupported protocol version",
                    data={
                        "supported": list(protocol.SUPPORTED_PROTOCOL_VERSIONS),
                        "requested": e.requested,
                    },
                )
            ]
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

    # --- protocol era (2026-07-28 stateless, dual-era) ------------------

    @staticmethod
    def _request_meta(message: dict[str, Any]) -> dict[str, Any]:
        params = message.get("params")
        if isinstance(params, dict) and isinstance(params.get("_meta"), dict):
            return params["_meta"]
        return {}

    def _request_is_modern(self, message: dict[str, Any]) -> bool:
        version = self._request_meta(message).get(protocol.META_PROTOCOL_VERSION)
        return version == protocol.MODERN_PROTOCOL_VERSION

    def _check_request_version(self, message: dict[str, Any]) -> None:
        """Validate the per-request protocol version (2026-07-28 stateless).

        Requests without ``_meta`` protocol metadata keep legacy behavior
        (handshake-era clients); requests carrying it are served statelessly
        under the requested revision. Unsupported versions are rejected with
        ``UnsupportedProtocolVersion`` (-32022) naming what this server does
        support, so a modern client can retry on a mutually supported
        version. Modern-era requests must also declare client capabilities
        (required ``_meta`` field; missing -> -32602 per spec).
        """
        meta = self._request_meta(message)
        if protocol.META_PROTOCOL_VERSION not in meta:
            return
        requested = meta.get(protocol.META_PROTOCOL_VERSION)
        if not isinstance(requested, str) or not requested:
            raise _InvalidParams(
                f"_meta.{protocol.META_PROTOCOL_VERSION} must be a non-empty string"
            )
        if requested not in protocol.SUPPORTED_PROTOCOL_VERSIONS:
            raise _UnsupportedProtocolVersion(requested)
        if (
            requested == protocol.MODERN_PROTOCOL_VERSION
            and protocol.META_CLIENT_CAPABILITIES not in meta
        ):
            raise _InvalidParams(
                "2026-07-28 requests require "
                f"_meta.{protocol.META_CLIENT_CAPABILITIES}"
            )

    @property
    def _registry_ttl_ms(self) -> int:
        """Freshness hint for cacheable results that describe the registry.

        One source of truth for every endpoint that advertises tool metadata
        (``tools/list`` and ``server/discover``). A static registry cannot
        change during a process lifetime, so a long TTL is the honest value.
        A governed registry can (ADR-006), so both endpoints must shorten it
        together — a host that cached ``listChanged: False`` for an hour would
        otherwise never act on ``notifications/tools/list_changed``.
        """
        return (
            protocol.CACHE_TTL_MS_GOVERNED
            if self.tool_requests_dir is not None
            else protocol.CACHE_TTL_MS_STATIC
        )

    def _modernize_result(self, method: str, result: Any) -> Any:
        """Apply the 2026-07-28 result envelope to a modern-era result.

        Legacy-era responses keep the exact pre-2026-07-28 shape: clients of
        older revisions must treat an absent ``resultType`` as ``"complete"``
        — this server simply never adds it there.
        """
        if not isinstance(result, dict):
            return result
        enriched = dict(result)
        enriched.setdefault("resultType", protocol.RESULT_TYPE_COMPLETE)
        meta = enriched.get("_meta")
        merged = dict(meta) if isinstance(meta, dict) else {}
        merged.setdefault(
            protocol.META_SERVER_INFO,
            {"name": protocol.SERVER_NAME, "version": protocol.SERVER_VERSION},
        )
        enriched["_meta"] = merged
        if method == "tools/list":
            # CacheableResult (2026-07-28): list endpoints carry the
            # registry's freshness hint.
            enriched.setdefault("ttlMs", self._registry_ttl_ms)
            enriched.setdefault("cacheScope", protocol.CACHE_SCOPE)
        return enriched

    def _handle_server_discover(self, params: Any) -> dict[str, Any]:
        """``server/discover`` (2026-07-28): versions, capabilities, identity.

        Answered with or without request ``_meta``: a dual-era client's
        stdio probe must receive a DiscoverResult (not an error) to identify
        this server as modern-capable before falling back to ``initialize``.
        The result is fully self-describing (``resultType`` + ``serverInfo``)
        regardless of the caller's era.
        """
        _ = params
        return {
            "resultType": protocol.RESULT_TYPE_COMPLETE,
            "supportedVersions": list(protocol.SUPPORTED_PROTOCOL_VERSIONS),
            "capabilities": {
                "tools": {
                    "listChanged": self.tool_requests_dir is not None,
                }
            },
            "instructions": (
                "Tools run as WASM modules inside the Ephemora Cell "
                "(deterministic, fuel-metered, no network). The native "
                '"get-policy" tool reports the enforced sandbox policy — '
                '"Verified. Not claimed."'
            ),
            "ttlMs": self._registry_ttl_ms,
            "cacheScope": protocol.CACHE_SCOPE,
            "_meta": {
                protocol.META_SERVER_INFO: {
                    "name": protocol.SERVER_NAME,
                    "version": protocol.SERVER_VERSION,
                }
            },
        }

    def _handle_initialize(self, params: Any) -> dict[str, Any]:
        # Version negotiation: echo the client's requested version when we
        # support it, otherwise answer with our own so the client decides
        # whether to proceed (per MCP initialization). The handshake
        # negotiates the legacy revisions only — 2026-07-28 is stateless
        # (no initialize); modern clients announce their version per request
        # in _meta instead.
        requested = None
        if isinstance(params, dict):
            requested = params.get("protocolVersion")
        version = (
            requested
            if requested in protocol.LEGACY_PROTOCOL_VERSIONS
            else protocol.LEGACY_DEFAULT_PROTOCOL_VERSION
        )
        return {
            "protocolVersion": version,
            "capabilities": {
                "tools": {
                    # listChanged flips True only once governed loading is
                    # enabled (ADR-006): a static registry has nothing to
                    # announce.
                    "listChanged": self.tool_requests_dir
                    is not None
                }
            },
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

    # --- governed loading (ADR-006) ----------------------------------

    def process_tool_requests(self) -> dict[str, Any]:
        """Evaluate ``*.tool.request.json`` in the allowlisted requests dir.

        The host invokes this — capability changes are host decisions, not
        chat decisions (ADR-006); a guest can only WRITE a request file,
        never approve one. Every request goes through verify-before-
        register: path allowlist, manifest signature (covering the module
        digest), module hash re-check and registry policy. Accepted
        requests are installed into the registry directory, the file is
        consumed, the registry rescans and
        ``notifications/tools/list_changed`` is emitted when the tool set
        changed. Rejected requests stay on disk with a reason in the
        report — never silent, per ADR-006.
        """
        report: dict[str, Any] = {"accepted": [], "rejected": []}
        requests_dir = self.tool_requests_dir
        if requests_dir is None or not requests_dir.is_dir():
            return report
        before = {spec.name for spec in self.registry.list_tools()}
        installed = 0
        for request_path in sorted(requests_dir.glob(f"*{TOOL_REQUEST_SUFFIX}")):
            ok, detail = self._evaluate_tool_request(request_path, requests_dir, before)
            if ok:
                report["accepted"].append(detail)
                installed += 1
                request_path.unlink(missing_ok=True)
            else:
                report["rejected"].append(
                    {"request": request_path.name, "reason": detail}
                )
        if installed:
            try:
                self.registry = ToolRegistry(
                    self.tools_dir,
                    manifest_verifier=self.registry.manifest_verifier,
                )
            except Exception as e:
                # A rescan failure must surface, never silently shrink the
                # tool set (ADR-006 consequence).
                report["error"] = f"registry rescan failed: {e}"
                return report
            if {spec.name for spec in self.registry.list_tools()} != before:
                self.transport.send(
                    {
                        "jsonrpc": protocol.JSONRPC_VERSION,
                        "method": "notifications/tools/list_changed",
                    }
                )
        return report

    def _evaluate_tool_request(
        self,
        request_path: Path,
        requests_dir: Path,
        current_names: set[str],
    ) -> tuple[bool, str]:
        """Validate one request file; returns (accepted, name-or-reason).

        ``requests_dir`` is the caller's resolved, non-None allowlist root.
        """
        try:
            request = json.loads(request_path.read_text(encoding="utf-8"))
        except (OSError, ValueError) as e:
            return False, f"unreadable request: {e}"
        if not isinstance(request, dict):
            return False, "request must be a JSON object"
        wasm_ref = request.get("wasm_path")
        manifest = request.get("manifest")
        if not isinstance(wasm_ref, str) or not wasm_ref:
            return False, "request requires a non-empty wasm_path"
        if not isinstance(manifest, dict):
            return False, "request requires a manifest object"
        # (a) Path allowlist: the module must live INSIDE the allowlisted
        # requests dir — a request can never reference host FS paths.
        try:
            wasm_abs = Path(wasm_ref).resolve(strict=True)
        except OSError as e:
            return False, f"wasm_path unresolvable: {e}"
        if not wasm_abs.is_relative_to(requests_dir):
            return False, (
                f"wasm_path {wasm_ref!r} resolves outside the allowlisted "
                "requests dir"
            )
        if wasm_abs.suffix != ".wasm":
            return False, "wasm_path must point at a .wasm module"
        # (b) Verify-before-register: signed-tools mode is mandatory for
        # dynamic loads, and the manifest must describe THESE bytes.
        verifier = self.registry.manifest_verifier
        if verifier is None:
            return False, (
                "tool requests require signed-tools mode "
                "(--require-signed-tools / manifest_verifier)"
            )
        if not verify_manifest(manifest, verifier):
            return False, "manifest signature invalid (unsigned/tampered)"
        declared = manifest.get("wasm_sha256")
        # Read the module ONCE and hash the in-memory copy: the digest we
        # verify is the digest of the exact bytes published below — no
        # swap between verification and installation can diverge them.
        try:
            wasm_bytes = wasm_abs.read_bytes()
        except OSError as e:
            return False, f"module unreadable: {e}"
        if not isinstance(declared, str) or declared.lower() != (
            tool_wasm_sha256_bytes(wasm_bytes)
        ):
            return False, (
                "module hash mismatch — the signed manifest does not "
                "describe these bytes"
            )
        # (c) Registry policy: the profile must exist; sidecar grants can
        # only narrow the profile (enforced in engine._config_for).
        profile = manifest.get("profile", "llm")
        try:
            get_profile(profile)
        except ValueError as e:
            return False, str(e)
        stem = wasm_abs.stem
        if stem in current_names or (self.tools_dir / f"{stem}.wasm").exists():
            return False, f"tool name collision: {stem!r} already registered"
        # Install: publish the signed sidecar FIRST and the module LAST,
        # both atomically (temp file + fsync + os.replace). A scan racing
        # the install then only ever sees either nothing or a bare .wasm
        # without a sidecar — which signed-tools mode rejects — never a
        # half-written file.
        atomic_write_json(self.tools_dir / f"{stem}.json", manifest)
        atomic_write_bytes(self.tools_dir / f"{stem}.wasm", wasm_bytes)
        return True, stem

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


class _UnsupportedProtocolVersion(Exception):
    """Internal marker mapped to MCP -32022 (UnsupportedProtocolVersion)."""

    def __init__(self, requested: str) -> None:
        super().__init__(requested)
        self.requested = requested
