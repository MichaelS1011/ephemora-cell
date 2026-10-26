"""Regression checks for the MCP SDK advisory set pinned by this release.

Python SDK floor 2.2.0 closes GHSA-w4fh-qvv9-3v23, GHSA-fmmv-w9g8-j3gc,
GHSA-84m7-p3x7-pcfv, GHSA-rwrf-2pqf-9j8j and GHSA-5h93-6whr-6q8j.
GHSA-jpw9-pfvf-9f58 is 1.x-only. The bridge is stateless, authenticates with
its own bearer token and talks to a stdio child, so SDK-managed stateful
sessions and HTTP-client redirects are not part of its configured path.
The TypeScript SDK advisories have no Node MCP server here; the JavaScript
guest is a QuickJS/WASM guest, not a Node runtime.
"""

from __future__ import annotations

import asyncio
import importlib.metadata as md
import inspect

import pytest

pytest.importorskip("mcp", reason="the advisory pin applies to the official SDK")
pytest.importorskip("starlette", reason="the bridge composes a Starlette app")

from mcp.server.lowlevel import Server

from ephemora_cell_mcp.http_bridge import BridgePolicy, build_app

MIN_SDK = (2, 2)


def test_pinned_sdk_is_past_the_python_advisory_ranges():
    version = md.version("mcp")
    assert tuple(int(part) for part in version.split(".")[:2]) >= MIN_SDK


def test_bridge_uses_stateless_http_and_the_sdk_body_cap(monkeypatch):
    captured: dict = {}
    original = Server.streamable_http_app

    def spy(self, **kwargs):
        captured.update(kwargs)
        return original(self, **kwargs)

    sdk_body_cap = (
        inspect.signature(original).parameters["max_request_body_size"].default
    )
    monkeypatch.setattr(Server, "streamable_http_app", spy)
    policy = BridgePolicy(
        host="127.0.0.1",
        port=8765,
        token="x" * 32,
        allow_non_loopback=False,
        token_env="EPHEMORA_MCP_BRIDGE_TOKEN",
    )
    build_app(policy, [], 1.0, allow_no_tools=True)

    # GHSA-84m7 safe configuration: no SDK session registry, no retained
    # initialize payloads. json_response is the bridge's documented shape.
    assert captured["stateless_http"] is True
    assert captured["json_response"] is True

    # GHSA-fmmv fix: the SDK's 4 MiB request-body cap stays in force. The
    # bridge deliberately does not override it.
    assert "max_request_body_size" not in captured
    assert sdk_body_cap == 4 * 1024 * 1024


def _send_through_body_limit(body: bytes) -> tuple[int | None, bool]:
    from mcp.server.transport_security import (
        DEFAULT_MAX_REQUEST_BODY_SIZE,
        RequestBodyLimitMiddleware,
    )

    inner_called = False

    async def inner(scope, receive, send):
        nonlocal inner_called
        inner_called = True
        await send({"type": "http.response.start", "status": 200, "headers": []})
        await send({"type": "http.response.body", "body": b"ok"})

    middleware = RequestBodyLimitMiddleware(
        inner, max_body_size=DEFAULT_MAX_REQUEST_BODY_SIZE
    )
    sent: list[dict] = []

    async def receive():
        return {"type": "http.request", "body": body, "more_body": False}

    async def send(message):
        sent.append(message)

    scope = {"type": "http", "method": "POST", "path": "/mcp", "headers": []}
    asyncio.run(middleware(scope, receive, send))
    status = next(
        (m["status"] for m in sent if m["type"] == "http.response.start"), None
    )
    return status, inner_called


def test_sdk_body_limit_rejects_above_4mib_before_the_app():
    status, inner_called = _send_through_body_limit(b"x" * (4 * 1024 * 1024 + 1))
    assert status == 413
    assert inner_called is False


def test_sdk_body_limit_accepts_below_4mib_positive_control():
    status, inner_called = _send_through_body_limit(b"x" * 1024)
    assert status == 200
    assert inner_called is True
