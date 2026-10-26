# SPDX-License-Identifier: BUSL-1.1
# Copyright 2026 Michael Soppa
"""The MCP HTTP bridge may only ever be an authenticated loopback door.

n8n's MCP client cannot spawn a stdio child (measured: every shipped
``mcpClientTool`` version offers only ``httpStreamable``/``sse``), so a
transport bridge is required to reach the product's stdio server. A bridge is
also the exact shape that could turn a local sandbox into an open execution
endpoint, so these tests pin the refusal paths rather than the happy path:
no token, weak token, non-loopback bind without an explicit override, missing
or forged credentials, and a wrong-scheme header must all fail closed.

The live roundtrip (real stdio child behind the bridge) is opt-in through
``EPHEMORA_MCP_BRIDGE_LIVE`` because it binds a socket; the posture checks above
run anywhere.
"""

from __future__ import annotations

import asyncio
import json
import os
import socket
import subprocess
import sys
import time
import urllib.error
import urllib.request
from typing import ClassVar

import pytest

from ephemora_cell_mcp import http_bridge
from ephemora_cell_mcp.http_bridge import (
    BearerAuthMiddleware,
    BridgePolicy,
    build_app,
    is_loopback,
    main,
    upstream_health,
)

GOOD_TOKEN = "a" * 48


def _policy(**kw) -> BridgePolicy:
    base = {
        "host": "127.0.0.1",
        "port": 8765,
        "token": GOOD_TOKEN,
        "allow_non_loopback": False,
        "token_env": "EPHEMORA_MCP_BRIDGE_TOKEN",
    }
    base.update(kw)
    return BridgePolicy(**base)  # type: ignore[arg-type]


# --- startup posture (nothing binds a socket until these pass) ---


def test_loopback_detection():
    assert is_loopback("127.0.0.1") and is_loopback("localhost") and is_loopback("::1")
    assert is_loopback("127.42.42.42")  # whole 127/8 is local
    assert not is_loopback("0.0.0.0")
    assert not is_loopback("192.168.1.20")
    assert not is_loopback("evil.example.com")


def test_missing_token_refuses_to_start():
    problems = _policy(token=None).violations()
    assert any("no bearer token" in p for p in problems)


def test_short_token_refuses_to_start():
    problems = _policy(token="guessme").violations()
    assert any("shorter than 32 characters" in p for p in problems)


def test_whitespace_only_token_refuses_at_the_posture_check():
    """A secret that is only whitespace must be refused HERE, not later.

    ``violations()`` is what the CLI reports before anything is composed. It
    used to treat 40 spaces as a valid secret (length passes), so the refusal
    came from the ASGI gate — i.e. after the optional imports had already run,
    and as a traceback instead of the rule that was broken.
    """
    problems = _policy(token=" " * 40).violations()
    assert any("no bearer token" in p for p in problems), problems
    assert _policy(token="\t" * 40).violations(), "tabs are not a secret either"


def test_non_loopback_bind_requires_explicit_override():
    assert any("not loopback" in p for p in _policy(host="0.0.0.0").violations())
    # even with the override, the token is still mandatory
    assert _policy(host="0.0.0.0", allow_non_loopback=True).violations() == []
    assert any(
        "no bearer token" in p
        for p in _policy(
            host="0.0.0.0", allow_non_loopback=True, token=None
        ).violations()
    )


@pytest.mark.parametrize("bad_port", [0, 70000])
def test_out_of_range_port_refuses(bad_port):
    assert _policy(port=bad_port).violations()


def test_healthy_loopback_posture_starts():
    assert _policy().violations() == []


def test_cli_exits_two_on_bad_posture(monkeypatch, capsys):
    monkeypatch.delenv("EPHEMORA_MCP_BRIDGE_TOKEN", raising=False)
    assert main(["--port", "8765"]) == 2
    err = capsys.readouterr().err
    assert "refused to start" in err and "no bearer token" in err


# --- per-request credential gate (pure ASGI, no socket needed) ---


class _Inner:
    """Records that a request actually reached the MCP layer."""

    calls: ClassVar[list[str]] = []

    async def __call__(self, scope, receive, send):
        _Inner.calls.append(scope.get("type", "?"))
        await send({"type": "http.response.start", "status": 200, "headers": []})
        await send({"type": "http.response.body", "body": b"ok"})


def _call(middleware: BearerAuthMiddleware, headers: list[tuple[bytes, bytes]]):
    scope = {"type": "http", "path": "/mcp", "headers": headers, "method": "POST"}
    sent: list[dict] = []

    async def receive():
        return {"type": "http.request", "body": b"{}", "more_body": False}

    async def send(message):
        sent.append(message)

    async def run():
        await middleware(scope, receive, send)

    asyncio.run(run())
    status = next(
        (m["status"] for m in sent if m["type"] == "http.response.start"), None
    )
    return status, sent


def test_anonymous_and_forged_credentials_never_reach_the_mcp_layer():
    _Inner.calls.clear()
    mw = BearerAuthMiddleware(_Inner(), GOOD_TOKEN)
    for headers in (
        [],  # no Authorization at all
        [(b"authorization", b"Bearer " + b"0" * 48)],  # wrong token
        [(b"authorization", b"Basic " + GOOD_TOKEN.encode())],  # wrong scheme
        [(b"authorization", b"Bearer " + GOOD_TOKEN[:16].encode())],  # prefix of it
        [(b"authorization", b"bearer " + GOOD_TOKEN.encode() + b" trailing")],  # padded
    ):
        status, sent = _call(mw, headers)
        assert status == 401, headers
        assert any(
            b"www-authenticate" in k for m in sent for k, _ in m.get("headers", [])
        )
    assert _Inner.calls == []  # nothing was forwarded


def test_valid_bearer_reaches_the_mcp_layer_once():
    _Inner.calls.clear()
    mw = BearerAuthMiddleware(_Inner(), GOOD_TOKEN)
    status, _ = _call(mw, [(b"authorization", b"Bearer " + GOOD_TOKEN.encode())])
    assert status == 200
    assert _Inner.calls == ["http"]


def test_a_token_pasted_with_a_trailing_newline_still_authenticates():
    """The presentation is stripped, so the secret must be stripped too.

    A secret read from a file arrives with a newline more often than not. With
    an unstripped stored token, ``presented.strip()`` could never equal it: the
    operator was locked out of their own bridge, fail-closed but permanently.
    """
    _Inner.calls.clear()
    mw = BearerAuthMiddleware(_Inner(), GOOD_TOKEN + "\n")
    status, _ = _call(mw, [(b"authorization", b"Bearer " + GOOD_TOKEN.encode())])
    assert status == 200
    assert _Inner.calls == ["http"]


def test_upstream_health_accepts_a_real_tool_set():
    assert upstream_health(["clock", "echo", "get-policy"]) == []


def test_upstream_health_refuses_a_policy_only_upstream():
    """`get-policy` is served even when no WASM tool loaded, so a non-empty
    tools/list proves nothing about executability — measured on 2026-10-15 with a
    wrong --tools-dir, where the endpoint came up authenticated and served zero
    tools. The bridge refuses that half-open state unless told otherwise."""
    problems = upstream_health(["get-policy"])
    assert len(problems) == 1
    assert "no WASM tools" in problems[0]
    assert "--allow-no-tools" in problems[0]
    assert upstream_health([]) == problems


def test_upstream_health_is_wired_into_the_app_factory():
    """The refusal must be reachable from the composition, not only the helper."""
    import inspect

    src = inspect.getsource(build_app)
    assert "upstream_health" in src
    assert "allow_no_tools" in src


def test_non_http_scope_is_passed_through():
    # lifespan/websocket scopes are the ASGI app's business, not a 401 source
    _Inner.calls.clear()
    mw = BearerAuthMiddleware(_Inner(), GOOD_TOKEN)
    called: list[dict] = []

    async def receive():
        return {"type": "lifespan.startup"}

    async def send(message):
        called.append(message)

    async def run():
        await mw({"type": "lifespan"}, receive, send)

    asyncio.run(run())
    # the gate handed the scope down untouched (it does not speak lifespan), and
    # the inner app answered — i.e. a non-http scope can never be 401-wrapped
    assert _Inner.calls == ["lifespan"]
    assert called and called[0]["status"] == 200


# --- the composition itself must be unable to build an open endpoint ---
#
# Measured on 2026-10-20 during the independent pre-push review: the posture
# rules lived only behind the CLI's `main()`. `build_app()` composed the gate
# with `policy.token or ""`, so a library caller that passed an empty token got
# a `BearerAuthMiddleware` whose secret was the empty string — and an
# `Authorization: Bearer ` request (empty value) then compared equal to it. The
# probe reached a real WASM `tools/call` through that route and got
# `status: "success"`. "no token, no start" is therefore pinned here at the
# place the refusal belongs: the composition, not the argument parser.


def test_build_app_refuses_every_posture_the_cli_would_refuse():
    """The library entry cannot compose an execution endpoint without a secret."""
    for bad in (
        _policy(token=""),
        _policy(token=None),
        _policy(token="guessable"),
        _policy(token=GOOD_TOKEN, host="0.0.0.0"),
        _policy(token=GOOD_TOKEN, port="not-a-port"),
    ):
        with pytest.raises(ValueError) as excinfo:
            build_app(bad, [], 60.0)
        message = str(excinfo.value)
        assert "token" in message or "loopback" in message or "integer" in message


def test_refusal_does_not_require_the_mcp_sdk(monkeypatch):
    """The posture check runs first, so it is reachable with no SDK installed.

    Proven by behaviour, not by reading source: while the refusal is expected,
    any import of the optional `mcp` package is an assertion failure.
    """
    import builtins

    real_import = builtins.__import__

    def guarded(name, *args, **kwargs):
        if name == "mcp" or name.startswith("mcp."):
            raise AssertionError(f"build_app imported {name!r} before refusing")
        return real_import(name, *args, **kwargs)

    monkeypatch.setattr(builtins, "__import__", guarded)
    try:
        with pytest.raises(ValueError):
            build_app(_policy(token=""), [], 60.0)
    finally:
        monkeypatch.undo()


def test_bearer_middleware_refuses_an_empty_secret():
    """A gate with no secret is not a gate; refuse to build it at all."""
    with pytest.raises(ValueError):
        BearerAuthMiddleware(_Inner(), "")
    with pytest.raises(ValueError):
        BearerAuthMiddleware(_Inner(), "   ")


def test_child_env_never_carries_the_bridge_token(monkeypatch):
    """The stdio child is the product server; it has no use for the bearer secret.

    Passing it through means every tool the child loads, and anything that can
    read the child's environment, holds the credential that opens the bridge.
    """
    monkeypatch.setenv("EPHEMORA_MCP_BRIDGE_TOKEN", GOOD_TOKEN)
    monkeypatch.setenv("SOME_OPERATOR_SECRET", "still-needed")
    env = http_bridge._child_env(_policy())
    assert "EPHEMORA_MCP_BRIDGE_TOKEN" not in env
    assert env["PYTHONUNBUFFERED"] == "1"
    assert env["SOME_OPERATOR_SECRET"] == "still-needed"


def test_upstream_call_is_bound_by_the_bridges_own_wall_clock():
    """Both upstream calls, not only tools/call, must be time-bounded."""

    async def hang(*args, **kwargs):
        await asyncio.sleep(5)
        return "never"

    with pytest.raises(http_bridge.BridgeTimeout):
        asyncio.run(http_bridge._session_call(hang, 0.05, "tools/list"))


def test_upstream_errors_propagate_instead_of_becoming_empty_results():
    async def boom(*args, **kwargs):
        raise RuntimeError("child died")

    with pytest.raises(RuntimeError):
        asyncio.run(http_bridge._session_call(boom, 1.0, "tools/call"))


def test_session_call_returns_the_upstream_value_on_time():
    async def quick():
        return "result"

    assert asyncio.run(http_bridge._session_call(quick, 1.0, "tools/list")) == "result"


# --- opt-in live roundtrip through a real socket and the real stdio server ---


@pytest.mark.skipif(
    not os.environ.get("EPHEMORA_MCP_BRIDGE_LIVE"),
    reason="set EPHEMORA_MCP_BRIDGE_LIVE=1 to bind a socket and run the live bridge",
)
def test_live_bridge_executes_a_real_tool_and_keeps_host_meta(tmp_path):
    """The whole documented n8n path, once, for real: bearer-authenticated
    HTTP -> bridge -> stdio server -> WASM tool -> untouched host ``_meta``.

    Opt-in because it binds a loopback socket and starts a child process. The
    two refusal halves (no token at startup, no Authorization on the wire) are
    asserted here as well — a "live" test that only ever showed the happy path
    would not be evidence of the gate that makes the path safe.
    """
    from pathlib import Path

    pytest.importorskip("mcp", reason="the live path drives the official SDK")
    from mcp.client.session import ClientSession
    from mcp.client.streamable_http import (
        create_mcp_http_client,
        streamable_http_client,
    )

    repo = Path(__file__).resolve().parent.parent
    tools_dir = repo / "ephemora_cell_mcp" / "tools"
    assert (tools_dir / "echo.wasm").is_file()

    # Since 1.2 the child defaults to DENY (no policy → no tool runs). This probe
    # is the documented SECURE path, so it authorizes through a real policy bound
    # to a host-set subject — not by re-opening the old allow-all. The single
    # bearer token stands for one service identity; the child runs as `svc` which
    # the grant permits to call every shipped tool.
    grant = tmp_path / "bridge-grant.json"
    grant.write_text(
        json.dumps(
            {
                "policy_version": "1.2.0-1",
                "subjects": [
                    {
                        "subject": "svc",
                        "permissions": [
                            {"tool": "clock"},
                            {"tool": "echo"},
                            {"tool": "get-policy", "action": "read"},
                        ],
                    }
                ],
            }
        ),
        encoding="utf-8",
    )

    with socket.socket() as probe:
        probe.bind(("127.0.0.1", 0))
        port = probe.getsockname()[1]
    url = f"http://127.0.0.1:{port}/mcp"
    token = "live-" + "t" * 44  # >= 32 chars, the documented minimum

    def bridge_cmd() -> list[str]:
        return [
            sys.executable,
            "-m",
            "ephemora_cell_mcp.http_bridge",
            "--port",
            str(port),
            "--",
            "--tools-dir",
            str(tools_dir),
            "--tool-policy",
            str(grant),
            "--subject",
            "svc",
        ]

    # N1: no token env -> refuse to start (exit 2), nothing binds
    env_no_token = {
        k: v for k, v in os.environ.items() if k != "EPHEMORA_MCP_BRIDGE_TOKEN"
    }
    refused = subprocess.run(
        bridge_cmd(),
        cwd=str(repo),
        env=env_no_token,
        capture_output=True,
        text=True,
        timeout=60,
    )
    assert refused.returncode == 2
    assert "no bearer token" in refused.stderr

    # P1: with token -> serve on loopback
    port_released: bool | None = None
    env = {**os.environ, "EPHEMORA_MCP_BRIDGE_TOKEN": token}
    err_path = tmp_path / "bridge.stderr.txt"
    with err_path.open("wb") as err:
        server = subprocess.Popen(
            bridge_cmd(), cwd=str(repo), env=env, stdout=subprocess.DEVNULL, stderr=err
        )
    try:
        deadline = time.monotonic() + 25.0
        up = False
        while time.monotonic() < deadline:
            with socket.socket() as probe:
                probe.settimeout(0.5)
                up = probe.connect_ex(("127.0.0.1", port)) == 0
            if up:
                break
            time.sleep(0.2)
        assert up, err_path.read_text(encoding="utf-8", errors="replace")

        # N2: no Authorization -> 401 before any MCP message is parsed
        body = b'{"jsonrpc":"2.0","id":1,"method":"tools/list","params":{}}'
        request = urllib.request.Request(url, data=body, method="POST")
        request.add_header("Content-Type", "application/json")
        request.add_header("Accept", "application/json, text/event-stream")
        try:
            with urllib.request.urlopen(request, timeout=10) as response:
                status = response.status
        except urllib.error.HTTPError as exc:
            status = exc.code
        assert status == 401

        # P2: the official SDK over streamable HTTP with the bearer token
        async def roundtrip():
            client = create_mcp_http_client(
                headers={"Authorization": f"Bearer {token}"}
            )
            async with streamable_http_client(url, http_client=client) as (
                read,
                write,
            ):
                async with ClientSession(read, write) as session:
                    init = await session.initialize()
                    listed = await session.list_tools()
                    called = await session.call_tool(
                        "echo", {"greeting": "live-check", "n": 3}
                    )
                    return init, listed, called

        init, listed, called = asyncio.run(asyncio.wait_for(roundtrip(), timeout=60))
        # The bridge announces itself (the client talks to the bridge, not to
        # the stdio child); the tool results below are still host-authored.
        assert init.server_info.name == "ephemora-cell-mcp-http-bridge"
        assert [tool.name for tool in listed.tools] == ["clock", "echo", "get-policy"]
        assert '"greeting": "live-check"' in called.content[0].text
        execution = (dict(called.meta or {})).get("execution") or {}
        assert execution.get("status") == "success"
        assert isinstance(execution.get("fuel_consumed"), int)
    finally:
        server.terminate()
        try:
            server.wait(timeout=10)
        except subprocess.TimeoutExpired:
            server.kill()
            server.wait(timeout=10)
        # measured during teardown, so a failure above cannot skip the proof
        # that the bridge gave the port back; asserted outside, so the real
        # failure stays the reported one
        with socket.socket() as probe:
            probe.settimeout(1.0)
            port_released = probe.connect_ex(("127.0.0.1", port)) != 0

    assert port_released is True, f"the bridge still holds port {port} after teardown"


class TestTransportSecurity:
    """Exercise the exact Host/Origin settings ``build_app`` composes.

    The SDK's transport-security middleware is used directly; the same settings
    object is what the product hands to ``streamable_http_app``. A foreign Host
    must be refused with 421 and a foreign Origin with 403 before any MCP
    message is parsed.
    """

    @staticmethod
    def _request(host: str, origin: str | None = None):
        from starlette.requests import Request

        headers = [
            (b"host", host.encode()),
            (b"content-type", b"application/json"),
        ]
        if origin is not None:
            headers.append((b"origin", origin.encode()))
        return Request(
            {
                "type": "http",
                "method": "POST",
                "path": "/mcp",
                "query_string": b"",
                "headers": headers,
            }
        )

    def _validate(self, request, *, protection: bool = True):
        from mcp.server.transport_security import TransportSecurityMiddleware

        from ephemora_cell_mcp.http_bridge import _transport_security_settings

        settings = _transport_security_settings(_policy())
        settings.enable_dns_rebinding_protection = protection
        middleware = TransportSecurityMiddleware(settings)
        return settings, asyncio.run(middleware.validate_request(request, is_post=True))

    def test_foreign_host_is_refused_with_421(self):
        pytest.importorskip("mcp")
        _, response = self._validate(self._request("evil.example"))
        assert response is not None and response.status_code == 421

    def test_foreign_origin_is_refused_with_403(self):
        pytest.importorskip("mcp")
        _, response = self._validate(
            self._request("127.0.0.1:8765", "http://evil.example")
        )
        assert response is not None and response.status_code == 403

    def test_local_host_and_origin_pass_positive_control(self):
        pytest.importorskip("mcp")
        _, response = self._validate(
            self._request("127.0.0.1:8765", "http://127.0.0.1:8765")
        )
        assert response is None

    def test_disabling_the_wall_makes_a_foreign_host_pass_mutation_control(self):
        pytest.importorskip("mcp")
        _, response = self._validate(self._request("evil.example"), protection=False)
        assert response is None, (
            "the refusal above must come from the protection switch, not from "
            "an unrelated parser error"
        )


def test_two_sdk_clients_with_their_own_tokens_are_authorized_per_subject(tmp_path):
    """v1.2 — multi-client authorization over the real bridge + child + SDK.

    tokenA→alice (echo), tokenB→bob (clock). Each official-SDK client, presenting
    its own bearer token over streamable HTTP, must be authorized as ITS OWN
    subject: alice runs echo but is refused clock, bob runs clock but is refused
    echo — and a refusal must execute nothing. This is the reference-client proof
    of the identity chain the unit and cross-agent tests cover in-process.
    """
    pytest.importorskip("mcp")
    from pathlib import Path

    from mcp import ClientSession
    from mcp.client.streamable_http import (
        create_mcp_http_client,
        streamable_http_client,
    )

    repo = Path(__file__).resolve().parent.parent
    tools_dir = repo / "ephemora_cell_mcp" / "tools"
    token_a, token_b = "tokA-" + "a" * 40, "tokB-" + "b" * 40

    subjects = tmp_path / "token_subjects.json"
    subjects.write_text(
        json.dumps({token_a: "alice", token_b: "bob"}), encoding="utf-8"
    )
    grant = tmp_path / "grant.json"
    grant.write_text(
        json.dumps(
            {
                "policy_version": "1.2.0-1",
                "subjects": [
                    {"subject": "alice", "permissions": [{"tool": "echo"}]},
                    {"subject": "bob", "permissions": [{"tool": "clock"}]},
                ],
            }
        ),
        encoding="utf-8",
    )

    with socket.socket() as probe:
        probe.bind(("127.0.0.1", 0))
        port = probe.getsockname()[1]
    url = f"http://127.0.0.1:{port}/mcp"

    bridge_cmd = [
        sys.executable,
        "-m",
        "ephemora_cell_mcp.http_bridge",
        "--port",
        str(port),
        "--token-subjects",
        str(subjects),
        "--",
        "--tools-dir",
        str(tools_dir),
        "--tool-policy",
        str(grant),
    ]
    env = {k: v for k, v in os.environ.items() if k != "EPHEMORA_MCP_BRIDGE_TOKEN"}
    err_path = tmp_path / "bridge.err.txt"
    with err_path.open("wb") as err:
        proc = subprocess.Popen(
            bridge_cmd,
            cwd=str(repo),
            env=env,
            stdout=subprocess.DEVNULL,
            stderr=err,
        )
    try:
        deadline = time.monotonic() + 25.0
        up = False
        while time.monotonic() < deadline:
            with socket.socket() as probe:
                probe.settimeout(0.5)
                up = probe.connect_ex(("127.0.0.1", port)) == 0
            if up:
                break
            time.sleep(0.2)
        assert up, err_path.read_text(encoding="utf-8", errors="replace")

        async def call(token: str, tool: str, meta: dict | None = None):
            client = create_mcp_http_client(
                headers={"Authorization": f"Bearer {token}"}
            )
            async with streamable_http_client(url, http_client=client) as (
                read,
                write,
            ):
                async with ClientSession(read, write) as session:
                    await session.initialize()
                    res = await session.call_tool(tool, {}, meta=meta)
                    return res.content[0].text, bool(res.is_error)

        def run(token, tool, meta=None):
            return asyncio.run(asyncio.wait_for(call(token, tool, meta), timeout=60))

        alice_echo_text, alice_echo_err = run(token_a, "echo")
        assert not alice_echo_err, alice_echo_text
        alice_clock_text, alice_clock_err = run(token_a, "clock")
        assert (
            alice_clock_err and "not authorized" in alice_clock_text
        ), alice_clock_text
        bob_echo_text, bob_echo_err = run(token_b, "echo")
        assert bob_echo_err and "not authorized" in bob_echo_text, bob_echo_text
        bob_clock_text, bob_clock_err = run(token_b, "clock")
        assert not bob_clock_err, bob_clock_text

        # v1.2 / v1.2 over the real stack: alice presents her OWN token but
        # forges bob's identity in `_meta`. The bridge re-stamps the subject from
        # the authenticated bearer and does NOT forward a client `_meta`, so the
        # forged bob is dropped and the call is still authorized as alice — clock
        # (bob's tool) stays denied. If the bridge trusted the client field this
        # would run clock, proving escalation.
        forged = {"_ephemora_subject": "bob"}
        forge_text, forge_err = run(token_a, "clock", meta=forged)
        assert forge_err and "not authorized" in forge_text, forge_text
    finally:
        proc.terminate()
        try:
            proc.wait(timeout=10)
        except subprocess.TimeoutExpired:
            proc.kill()
            proc.wait()
