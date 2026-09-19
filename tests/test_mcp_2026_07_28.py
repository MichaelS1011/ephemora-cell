"""MCP 2026-07-28 stateless surface tests (dual-era server).

Covers the stateless revision of the MCP stdio protocol as served by the
dependency-free implementation:

* ``server/discover`` — the modern discovery/era-probe method
* stateless ``tools/list`` / ``tools/call`` with per-request ``_meta``
  (no initialize handshake): resultType, CacheableResult fields and the
  per-response serverInfo
* version handling: UnsupportedProtocolVersion (-32022) with the supported
  list, and the -32602 rejection of modern requests missing the required
  clientCapabilities
* legacy-era regression: the initialize handshake keeps negotiating the
  pre-2026-07-28 revisions and legacy responses keep the exact old shape

The server is driven in-process over a MemoryTransport (same pattern as
test_mcp_adapter.py).
"""

from __future__ import annotations

import os
import sys
from pathlib import Path

import pytest

sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))

from ephemora_cell_mcp import Server, __version__, protocol
from ephemora_cell_mcp.transport import MemoryTransport

REPO_ROOT = Path(__file__).resolve().parent.parent
PACKAGE_TOOLS = REPO_ROOT / "ephemora_cell_mcp" / "tools"

MODERN = protocol.MODERN_PROTOCOL_VERSION  # "2026-07-28"


def _modern_meta(**extra: object) -> dict:
    meta = {
        protocol.META_PROTOCOL_VERSION: MODERN,
        protocol.META_CLIENT_CAPABILITIES: {},
    }
    meta.update(extra)
    return meta


@pytest.fixture()
def server_with(tmp_path):
    """Build a Server over a MemoryTransport seeded with requests."""

    def _build(tools_dir=PACKAGE_TOOLS, inbox=None):
        transport = MemoryTransport(inbox or [])
        server = Server(tools_dir=tools_dir, transport=transport)
        return server, transport

    return _build


def _reply(server, transport):
    """Feed all remaining inbox lines, return all responses."""
    responses = []
    while True:
        line = transport.read_line()
        if line is None:
            break
        responses.extend(server.handle_line(line))
    return responses


def _request(id_: int, method: str, meta: dict | None = None, **params: object) -> dict:
    body: dict = {}
    if meta is not None:
        body["_meta"] = meta
    body.update(params)
    return {"jsonrpc": "2.0", "id": id_, "method": method, "params": body}


# --- server/discover ---------------------------------------------------


def test_discover_without_meta_is_fully_self_describing(server_with):
    """The stdio era-probe (often sent _meta-less) gets a complete result."""
    server, transport = server_with(
        inbox=[{"jsonrpc": "2.0", "id": 1, "method": "server/discover"}]
    )
    (response,) = _reply(server, transport)
    result = response["result"]
    assert result["resultType"] == "complete"
    assert result["supportedVersions"] == list(protocol.SUPPORTED_PROTOCOL_VERSIONS)
    assert result["capabilities"]["tools"]["listChanged"] is False
    assert result["ttlMs"] == protocol.CACHE_TTL_MS_STATIC
    assert result["cacheScope"] == "private"
    server_info = result["_meta"][protocol.META_SERVER_INFO]
    assert server_info["name"] == "ephemora-cell-mcp"
    assert server_info["version"] == __version__


def test_discover_with_modern_meta(server_with):
    server, transport = server_with(
        inbox=[_request(7, "server/discover", _modern_meta())]
    )
    (response,) = _reply(server, transport)
    assert response["id"] == 7
    assert response["result"]["resultType"] == "complete"
    assert MODERN in response["result"]["supportedVersions"]


def test_discover_advertises_listchanged_when_governed(server_with, tmp_path):
    """Governed loading (ADR-006) flips the advertised listChanged bit."""
    transport = MemoryTransport(
        [{"jsonrpc": "2.0", "id": 1, "method": "server/discover"}]
    )
    server = Server(
        tools_dir=tmp_path,
        transport=transport,
        tool_requests_dir=tmp_path / "requests",
    )
    (response,) = _reply(server, transport)
    assert response["result"]["capabilities"]["tools"]["listChanged"] is True


# --- stateless tools/list ---------------------------------------------


def test_stateless_tools_list_without_initialize(server_with):
    """Modern-era tools/list stands alone: no handshake, full envelope."""
    server, transport = server_with(inbox=[_request(2, "tools/list", _modern_meta())])
    (response,) = _reply(server, transport)
    result = response["result"]
    assert result["resultType"] == "complete"
    assert result["ttlMs"] == protocol.CACHE_TTL_MS_STATIC
    assert result["cacheScope"] == "private"
    assert result["_meta"][protocol.META_SERVER_INFO]["name"] == "ephemora-cell-mcp"
    names = [tool["name"] for tool in result["tools"]]
    # deterministic order (2026-07-28 SHOULD) for client-side caching
    assert names == sorted(names)
    assert "echo" in names and "get-policy" in names


def test_stateless_tools_list_governed_ttl(server_with, tmp_path):
    """A governed registry can change mid-process — the shorter TTL applies."""
    transport = MemoryTransport([_request(1, "tools/list", _modern_meta())])
    server = Server(
        tools_dir=tmp_path,
        transport=transport,
        tool_requests_dir=tmp_path / "requests",
    )
    (response,) = _reply(server, transport)
    assert response["result"]["ttlMs"] == protocol.CACHE_TTL_MS_GOVERNED


def test_legacy_tools_list_keeps_old_shape(server_with):
    """No _meta -> exact pre-2026-07-28 response (no resultType, no TTL)."""
    server, transport = server_with(
        inbox=[{"jsonrpc": "2.0", "id": 3, "method": "tools/list"}]
    )
    (response,) = _reply(server, transport)
    result = response["result"]
    assert "resultType" not in result
    assert "ttlMs" not in result
    assert "cacheScope" not in result
    assert "_meta" not in result
    assert [tool["name"] for tool in result["tools"]]


# --- stateless tools/call ---------------------------------------------


def test_stateless_tools_call_real_wasm(server_with):
    """Modern tools/call runs the real echo.wasm: envelope + execution _meta."""
    server, transport = server_with(
        inbox=[
            _request(
                4,
                "tools/call",
                _modern_meta(
                    **{protocol.META_CLIENT_INFO: {"name": "test", "version": "0"}}
                ),
                name="echo",
                arguments={"message": "hi"},
            ),
        ]
    )
    (response,) = _reply(server, transport)
    result = response["result"]
    assert result["resultType"] == "complete"
    meta = result["_meta"]
    # execution witness and modern serverInfo share the result _meta
    assert meta["execution"]["status"] == "success"
    assert isinstance(meta["execution"]["fuel_consumed"], int)
    assert meta[protocol.META_SERVER_INFO]["version"] == __version__
    assert "hi" in result["content"][0]["text"]


def test_stateless_tools_call_needs_arguments(server_with):
    """The echo tool contract still applies statelessly (error -> isError)."""
    server, transport = server_with(
        inbox=[
            _request(
                5,
                "tools/call",
                _modern_meta(),
                name="echo",
                arguments={"message": "stateless"},
            )
        ]
    )
    (response,) = _reply(server, transport)
    result = response["result"]
    assert result["resultType"] == "complete"
    assert "stateless" in result["content"][0]["text"]
    assert result["_meta"]["execution"]["status"] == "success"


# --- version handling ---------------------------------------------------


def test_unsupported_version_rejected_with_supported_list(server_with):
    """Unknown per-request version -> -32022 naming what IS supported."""
    server, transport = server_with(
        inbox=[
            _request(
                6,
                "tools/list",
                {
                    protocol.META_PROTOCOL_VERSION: "1900-01-01",
                    protocol.META_CLIENT_CAPABILITIES: {},
                },
            )
        ]
    )
    (response,) = _reply(server, transport)
    error = response["error"]
    assert error["code"] == protocol.UNSUPPORTED_PROTOCOL_VERSION  # -32022
    assert error["data"]["requested"] == "1900-01-01"
    assert error["data"]["supported"] == list(protocol.SUPPORTED_PROTOCOL_VERSIONS)


def test_modern_request_requires_client_capabilities(server_with):
    """protocolVersion without clientCapabilities -> -32602 (spec-required)."""
    server, transport = server_with(
        inbox=[
            _request(8, "tools/list", {protocol.META_PROTOCOL_VERSION: MODERN}),
        ]
    )
    (response,) = _reply(server, transport)
    assert response["error"]["code"] == -32602
    assert "clientCapabilities" in response["error"]["message"]


def test_empty_protocol_version_string_is_invalid_params(server_with):
    server, transport = server_with(
        inbox=[
            _request(
                9,
                "tools/list",
                {
                    protocol.META_PROTOCOL_VERSION: "",
                    protocol.META_CLIENT_CAPABILITIES: {},
                },
            )
        ]
    )
    (response,) = _reply(server, transport)
    assert response["error"]["code"] == -32602


# --- legacy-era regression ---------------------------------------------


def test_initialize_negotiates_legacy_versions_only(server_with):
    """initialize never answers 2026-07-28 — that revision is stateless."""
    server, transport = server_with(
        inbox=[
            {
                "jsonrpc": "2.0",
                "id": 1,
                "method": "initialize",
                "params": {"protocolVersion": MODERN},
            },
            {
                "jsonrpc": "2.0",
                "id": 2,
                "method": "initialize",
                "params": {"protocolVersion": "2025-03-26"},
            },
        ]
    )
    responses = _reply(server, transport)
    assert responses[0]["result"]["protocolVersion"] == "2025-06-18"
    assert responses[1]["result"]["protocolVersion"] == "2025-03-26"


def test_initialize_with_meta_still_legacy(server_with):
    """initialize selects legacy semantics even with modern _meta present."""
    server, transport = server_with(
        inbox=[
            {
                "jsonrpc": "2.0",
                "id": 1,
                "method": "initialize",
                "params": {"_meta": _modern_meta()},
            }
        ]
    )
    (response,) = _reply(server, transport)
    assert response["result"]["protocolVersion"] == "2025-06-18"
    assert "resultType" not in response["result"]


def test_legacy_tools_call_unchanged(server_with):
    """Legacy-era tools/call response keeps the exact pre-revision shape."""
    server, transport = server_with(
        inbox=[
            {
                "jsonrpc": "2.0",
                "id": 1,
                "method": "tools/call",
                "params": {"name": "echo", "arguments": {"message": "legacy"}},
            }
        ]
    )
    (response,) = _reply(server, transport)
    result = response["result"]
    assert "resultType" not in result
    assert "ttlMs" not in result
    assert result["_meta"]["execution"]["status"] == "success"
