"""Minimal JSON-RPC 2.0 + MCP stdio conventions for ephemora-cell-mcp.

This is a deliberate, dependency-free subset of the Model Context
Protocol (https://modelcontextprotocol.io/specification). Only the
messages the server speaks are modelled here; anything else is rejected
with the standard JSON-RPC error codes.
"""

from __future__ import annotations

import json
from typing import Any

JSONRPC_VERSION = "2.0"

# MCP protocol version(s) this server implements. The newest is the
# default answer when a client requests an unsupported version.
MCP_PROTOCOL_VERSION = "2025-06-18"
SUPPORTED_PROTOCOL_VERSIONS = ("2025-06-18", "2025-03-26", "2024-11-05")

SERVER_NAME = "ephemora-cell-mcp"
SERVER_VERSION = "0.1.0"

# JSON-RPC 2.0 error codes (section 5.1).
PARSE_ERROR = -32700
INVALID_REQUEST = -32600
METHOD_NOT_FOUND = -32601
INVALID_PARAMS = -32602
INTERNAL_ERROR = -32603

# MCP capabilities we advertise.
CAPABILITIES: dict[str, Any] = {"tools": {"listChanged": False}}


class InvalidRequest(ValueError):
    """Structurally invalid JSON-RPC request object (maps to -32600).

    Distinct from malformed JSON, which maps to -32700.
    """


def parse_line(line: str) -> dict[str, Any] | None:
    """Parse one NDJSON line into a JSON-RPC message.

    Returns None for empty/whitespace-only lines. Raises
    ``json.JSONDecodeError`` for malformed JSON (mapped to PARSE_ERROR,
    -32700) and :class:`InvalidRequest` for structurally invalid request
    objects (mapped to INVALID_REQUEST, -32600).
    """
    if not line.strip():
        return None
    message = json.loads(line)
    if not isinstance(message, dict):
        raise InvalidRequest("JSON-RPC message must be an object")
    # jsonrpc version member: required, must be "2.0". A wrong value is a
    # structurally invalid request (-32600), not a parse error (-32700).
    if message.get("jsonrpc") != JSONRPC_VERSION:
        raise InvalidRequest(f"jsonrpc member must be {JSONRPC_VERSION!r}")
    # id: string, number, or null when present; absent means notification.
    # Objects/arrays/booleans are invalid per JSON-RPC 2.0.
    if "id" in message:
        id_value = message["id"]
        if not (
            id_value is None
            or isinstance(id_value, str)
            or (
                isinstance(id_value, (int, float))
                and not isinstance(id_value, bool)
            )
        ):
            raise InvalidRequest("id must be a string, number, or null")
    return message


def is_notification(message: dict[str, Any]) -> bool:
    """JSON-RPC notifications carry no ``id`` and get no response."""
    return "id" not in message


def make_result(request: dict[str, Any], result: Any) -> dict[str, Any]:
    return {"jsonrpc": JSONRPC_VERSION, "id": request.get("id"), "result": result}


def make_error(
    request: dict[str, Any] | None,
    code: int,
    message: str,
    data: Any = None,
) -> dict[str, Any]:
    """Build a JSON-RPC error response (id ``None`` for parse errors)."""
    error: dict[str, Any] = {"code": code, "message": message}
    if data is not None:
        error["data"] = data
    return {
        "jsonrpc": JSONRPC_VERSION,
        "id": request.get("id") if request is not None else None,
        "error": error,
    }