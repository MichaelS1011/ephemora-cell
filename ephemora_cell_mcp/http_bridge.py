# SPDX-License-Identifier: BUSL-1.1
# Copyright 2026 Michael Soppa

"""Bearer-authenticated, loopback-only MCP streamable-HTTP bridge.

Why this exists (measured, not assumed): n8n's MCP Client Tool node — every
shipped version of ``@n8n/n8n-nodes-langchain`` (v1 … v1.4) offers exactly two
transports, ``httpStreamable`` and ``sse``, and has no stdio option at all. The
Ephemora-cell MCP server speaks MCP over stdio (``python -m ephemora_cell_mcp``),
which is the right default for a local child process but is unreachable from a
workflow engine that can only dial an HTTP endpoint.

This bridge closes exactly that gap and nothing else. It is a *transport*
adapter: it spawns the same stdio server as a child process, forwards
``tools/list`` and ``tools/call`` to it, and hands the upstream answer back
untouched — including the ``_meta`` execution record, so the host-observed
status a caller sees through HTTP is the same authoritative record as through
stdio (execution-record integrity). It re-implements no tool logic and adds no
execution path.

Security posture is fail-closed, and ``preflight()`` is the machine-checked
version of it:

* no token, no start — the bearer secret must come from an environment
  variable (``--token-env``), never a command-line flag, because argv is visible
  to every local user through ``ps``/``/proc``;
* tokens are compared with ``secrets.compare_digest``, and the check runs on
  every request before any MCP message is parsed;
* the default bind is loopback. A non-loopback bind needs an explicit
  ``--allow-non-loopback`` *and* a token — an unprotected execution endpoint is
  the failure mode this file exists to prevent, so it is not offered as a
  default;
* ``Host``/``Origin`` are validated (DNS-rebinding protection) so a browser on
  this machine cannot be pointed at the bridge by a remote page.

Usage (operator-side):

    export EPHEMORA_MCP_BRIDGE_TOKEN="$(openssl rand -hex 32)"
    python -m ephemora_cell_mcp.http_bridge --port 8765 -- \
        --tools-dir /srv/ephemora/tools

then point the MCP client at ``http://127.0.0.1:8765/mcp`` with a bearer token.
"""

from __future__ import annotations

import argparse
import asyncio
import ipaddress
import os
import secrets
import sys
from dataclasses import dataclass

#: Environment variable read for the bearer token when ``--token-env`` is unset.
DEFAULT_TOKEN_ENV = "EPHEMORA_MCP_BRIDGE_TOKEN"
#: Shortest tolerable secret; shorter values are guessable by a local attacker.
MIN_TOKEN_LENGTH = 32
#: Default per-call upstream wall. The guest's own fuel/timeout bounds execution;
#: this only stops a wedged child from holding the HTTP request open forever.
DEFAULT_CALL_TIMEOUT = 60.0

_MISSING_SDK = (
    "the MCP SDK is required for the HTTP bridge: "
    'pip install "ephemora-cell[integration]" (provides mcp, uvicorn)'
)


def _bridge_version() -> str:
    from . import __version__

    return __version__


def is_loopback(host: str) -> bool:
    """True for addresses that are reachable only from this machine."""
    if host in ("localhost", "::1"):
        return True
    try:
        return ipaddress.ip_address(host).is_loopback
    except ValueError:
        return False


@dataclass(frozen=True)
class BridgePolicy:
    """The startup posture a bridge run must satisfy before it binds a socket."""

    host: str
    port: int
    token: str | None
    allow_non_loopback: bool
    token_env: str

    def violations(self) -> list[str]:
        """Every reason this posture must refuse to start, in plain words.

        A list (not an exception) so the CLI can report all of them at once and
        tests can assert on each rule independently of the others.
        """
        problems: list[str] = []
        # Strip once, here: a token pasted from a template can arrive as
        # whitespace, and a posture check that accepts "   " while the ASGI gate
        # later refuses it would report "startable" for something that cannot
        # start — and it would refuse only after the optional imports ran.
        secret = (self.token or "").strip()
        if not secret:
            problems.append(
                f"no bearer token in ${self.token_env}: refusing to start an "
                "execution endpoint that anyone on this machine can call"
            )
        elif len(secret) < MIN_TOKEN_LENGTH:
            problems.append(
                f"bearer token is shorter than {MIN_TOKEN_LENGTH} characters: "
                "a guessable secret on a bridge that runs arbitrary WASM tools"
            )
        if not is_loopback(self.host) and not self.allow_non_loopback:
            problems.append(
                f"bind address {self.host!r} is not loopback: pass "
                "--allow-non-loopback only when the endpoint is genuinely meant "
                "to leave this machine (and keep the token + a firewall rule)"
            )
        try:
            port = int(self.port)
        except (TypeError, ValueError):
            problems.append(f"port {self.port!r} is not an integer")
        else:
            if not 1 <= port <= 65535:
                problems.append(f"port {port} is outside 1-65535")
        return problems


class BridgeTimeout(RuntimeError):
    """One upstream call exceeded the bridge's own wall bound.

    A distinct type because the two call sites must react differently: a timed
    out ``tools/call`` is reported to the client as a failed tool result (the
    documented shape), while a timed out ``tools/list`` has no result to
    degrade into and must surface as an error rather than hang the session.
    """

    def __init__(self, what: str, timeout: float) -> None:
        super().__init__(f"upstream {what} timed out after {timeout}s")
        self.what = what
        self.timeout = timeout


async def _session_call(awaitable_factory, call_timeout: float, what: str) -> object:
    """Run one upstream call under the bridge's own wall clock.

    The bound exists because the bridge owns exactly one serialised upstream
    session: an unbounded await on a wedged child holds the lock, and with it
    every later request on the endpoint. The child's own fuel/timeout bounds
    execution; this bounds the *bridge's* exposure to a child that stopped
    answering. Errors from the child propagate untouched — this never converts
    a failure into an empty result.
    """
    try:
        return await asyncio.wait_for(awaitable_factory(), call_timeout)
    except asyncio.TimeoutError:
        raise BridgeTimeout(what, call_timeout) from None


def _child_env(policy: BridgePolicy) -> dict[str, str]:
    """Environment for the stdio child, with the bridge's own secret removed.

    The child is the product server; it reads no bearer token, so handing it
    ``EPHEMORA_MCP_BRIDGE_TOKEN`` would put the credential that opens the HTTP
    gate inside every tool process it spawns — and anywhere that can read the
    child's environment. Everything else the upstream needs still arrives.
    """
    env = {k: v for k, v in os.environ.items() if k != policy.token_env}
    env["PYTHONUNBUFFERED"] = "1"
    return env


class BearerAuthMiddleware:
    """Plain ASGI bearer gate, applied before any MCP message is touched."""

    def __init__(self, app, token: str) -> None:
        # A gate whose secret is empty accepts the empty presentation: with
        # ``compare_digest(b"", b"")`` an ``Authorization: Bearer `` request
        # walks straight through to execution. Measured on 2026-10-20 through a
        # real WASM tools/call. Refuse to build such a gate at all.
        if not token or not token.strip():
            raise ValueError(
                "bearer auth middleware refuses an empty token: an unprotected "
                "execution endpoint must never be composed"
            )
        self._app = app
        # Stored stripped, because the presentation is stripped below: a secret
        # written from a file with a trailing newline would otherwise never
        # authenticate (fail-closed, but a pinned-out operator).
        self._token = token.strip().encode("utf-8")

    async def __call__(self, scope, receive, send) -> None:
        if scope["type"] != "http":
            await self._app(scope, receive, send)
            return
        header = b""
        for key, value in scope.get("headers", ()):
            if key.lower() == b"authorization":
                header = value
                break
        prefix, _, presented = header.partition(b" ")
        if prefix.lower() != b"bearer" or not secrets.compare_digest(
            presented.strip(), self._token
        ):
            await _unauthorized(send)
            return
        await self._app(scope, receive, send)


async def _unauthorized(send) -> None:
    body = b'{"error":"unauthorized"}'
    await send(
        {
            "type": "http.response.start",
            "status": 401,
            "headers": [
                (b"content-type", b"application/json"),
                (b"content-length", str(len(body)).encode()),
                (b"www-authenticate", b'Bearer realm="ephemora-cell-mcp"'),
            ],
        }
    )
    await send({"type": "http.response.body", "body": body})


#: The one tool the MCP server always serves, even with no WASM tools loaded —
#: so "tools/list is non-empty" is NOT proof that any executable tool exists.
_POLICY_ONLY_TOOL = "get-policy"


def upstream_health(tool_names: list[str]) -> list[str]:
    """Reasons the upstream is too healthy-looking to serve, empty when it is fine.

    A misconfigured tools directory still answers ``initialize`` and lists
    ``get-policy``, so an authenticated endpoint can be up while nothing
    executable exists behind it — measured, not theoretical. The bridge refuses
    that half-open state unless the operator explicitly allows it.
    """
    executable = [name for name in tool_names if name != _POLICY_ONLY_TOOL]
    if not executable:
        return [
            "upstream server exposes no WASM tools (only "
            f"{_POLICY_ONLY_TOOL!r}): a typo in --tools-dir would otherwise "
            "present a live, authenticated endpoint that can execute nothing; "
            "pass --allow-no-tools if an empty tool set is intended"
        ]
    return []


def build_app(
    policy: BridgePolicy,
    upstream_args: list[str],
    call_timeout: float,
    *,
    event_stream: bool = False,
    allow_no_tools: bool = False,
):
    """Compose the ASGI app: bearer gate -> MCP HTTP surface -> one stdio child.

    The stdio child is the product server, started as ``sys.executable -m
    ephemora_cell_mcp <upstream_args>``; the bridge owns exactly one upstream
    session (serialised), so a client cannot multiply sandbox processes by
    opening many HTTP sessions.

    ``event_stream=False`` (the default) answers each POST with
    ``application/json`` instead of holding an SSE stream open. Both are legal
    streamable-HTTP responses, and the bridge sends no server-initiated
    notifications, so JSON is the honest minimum — measured necessary, too:
    n8n's MCP client wraps fetch in its own redirect-following helper, which
    waits for the body to end and therefore never resolved against an SSE
    response, while the plain SDK client (which consumes the stream) did.

    The startup posture is checked HERE, before anything is composed: the CLI
    checks it too, but a library caller going straight to ``build_app()`` used
    to be able to assemble a gate whose token was the empty string.
    """
    problems = policy.violations()
    if problems:
        raise ValueError("HTTP bridge refused to start: " + " ".join(problems))
    # ``violations()`` above has already refused an absent or short token; this
    # binding exists so the type of the gate's secret is explicit, not optional.
    token = policy.token or ""
    try:
        import anyio
        from mcp import types
        from mcp.client.session import ClientSession
        from mcp.client.stdio import StdioServerParameters, stdio_client
        from mcp.server.lowlevel import Server
        from mcp.server.transport_security import TransportSecuritySettings
        from starlette.applications import Starlette
    except ImportError as exc:  # pragma: no cover - depends on the optional extra
        raise SystemExit(f"{_MISSING_SDK} ({exc})") from exc

    bind = f"{policy.host}:{policy.port}"
    inner = None
    state: dict[str, object] = {"session": None}
    # One upstream session, one at a time: MCP stdio is a single ordered stream.
    upstream_lock = anyio.Lock()

    async def on_list_tools(_ctx, _params):
        session = state["session"]
        if session is None:
            raise RuntimeError("upstream server is not running")
        async with upstream_lock:
            result = await _session_call(
                lambda: session.list_tools(), call_timeout, "tools/list"
            )
        return types.ListToolsResult(tools=result.tools)

    async def on_call_tool(_ctx, params):
        session = state["session"]
        if session is None:
            raise RuntimeError("upstream server is not running")
        async with upstream_lock:
            try:
                result = await _session_call(
                    lambda: session.call_tool(params.name, params.arguments),
                    call_timeout,
                    "tools/call",
                )
            except BridgeTimeout as exc:
                # Report the timeout as a failed tool result; never as a success.
                return types.CallToolResult(
                    content=[
                        types.TextContent(
                            type="text",
                            text=f"upstream call timed out after {exc.timeout}s",
                        )
                    ],
                    is_error=True,
                )
        # Pass the upstream result through verbatim: its _meta.execution record is
        # host-observed and must not be re-authored here (integrity rule).
        return result

    server = Server(
        "ephemora-cell-mcp-http-bridge",
        on_list_tools=on_list_tools,
        on_call_tool=on_call_tool,
    )
    server.version = _bridge_version()
    # Host/Origin allowlist is explicit — never a wildcard. A client reaching
    # this bridge presents one of these authorities; anything else (a page in a
    # browser on this machine being tricked into POSTing here, i.e. DNS rebinding)
    # is refused by the SDK's transport-security layer before the message runs.
    local_authorities = {
        bind,
        policy.host,
        "localhost",
        "127.0.0.1",
        f"localhost:{policy.port}",
        f"127.0.0.1:{policy.port}",
        f"[::1]:{policy.port}",
    }
    inner = server.streamable_http_app(
        stateless_http=True,
        json_response=not event_stream,
        transport_security=TransportSecuritySettings(
            enable_dns_rebinding_protection=True,
            allowed_hosts=sorted(local_authorities),
            allowed_origins=sorted(
                f"http://{authority}" for authority in local_authorities
            ),
        ),
    )

    async def lifespan(app):
        params = StdioServerParameters(
            command=sys.executable,
            args=["-m", "ephemora_cell_mcp", *upstream_args],
            env=_child_env(policy),
        )
        async with stdio_client(params) as (read, write):
            async with ClientSession(read, write) as session:
                await session.initialize()
                if not allow_no_tools:
                    listed = await session.list_tools()
                    problems = upstream_health([t.name for t in listed.tools])
                    if problems:
                        raise RuntimeError(
                            "HTTP bridge refused to serve: " + " ".join(problems)
                        )
                state["session"] = session
                try:
                    async with inner.router.lifespan_context(inner):
                        yield
                finally:
                    state["session"] = None

    outer = Starlette(routes=list(inner.routes), lifespan=_as_context_manager(lifespan))
    return BearerAuthMiddleware(outer, token)


def _as_context_manager(lifespan):
    """Starlette 1.6 wants a CM-style lifespan, not a bare async generator."""
    from contextlib import asynccontextmanager

    return asynccontextmanager(lifespan)


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(
        prog="ephemora_cell_mcp.http_bridge",
        description=(
            "Expose the Ephemora-cell MCP stdio server over a loopback, "
            "bearer-authenticated streamable-HTTP endpoint (for clients that "
            "cannot spawn a child process, e.g. n8n's MCP Client Tool node)"
        ),
    )
    parser.add_argument("--host", default="127.0.0.1")
    parser.add_argument("--port", type=int, default=8765)
    parser.add_argument(
        "--token-env",
        default=DEFAULT_TOKEN_ENV,
        help=(
            "environment variable holding the required bearer token; never a "
            "command-line value, which every local user could read"
        ),
    )
    parser.add_argument(
        "--allow-non-loopback",
        action="store_true",
        help="permit a non-loopback bind (still requires a token)",
    )
    parser.add_argument(
        "--call-timeout",
        type=float,
        default=DEFAULT_CALL_TIMEOUT,
        help=f"per-call upstream wall in seconds (default {DEFAULT_CALL_TIMEOUT})",
    )
    parser.add_argument(
        "--event-stream",
        action="store_true",
        help=(
            "answer POSTs with an SSE stream instead of application/json. Only "
            "needed by clients that require server-initiated streams; it is known "
            "to stall n8n's redirect-following fetch, so leave it off for n8n"
        ),
    )
    parser.add_argument(
        "--allow-no-tools",
        action="store_true",
        help=(
            "serve even when the upstream lists no WASM tools. Off by default: a "
            "wrong --tools-dir otherwise yields a live, authenticated endpoint "
            "that can execute nothing"
        ),
    )
    parser.add_argument(
        "upstream",
        nargs=argparse.REMAINDER,
        help=(
            "arguments for the stdio server, after --, e.g. -- --tools-dir DIR "
            "--require-signed-tools key.pem"
        ),
    )
    args = parser.parse_args(argv)

    upstream_args = list(args.upstream)
    if upstream_args[:1] == ["--"]:
        upstream_args = upstream_args[1:]

    token = os.environ.get(args.token_env)
    policy = BridgePolicy(
        host=args.host,
        port=args.port,
        token=token,
        allow_non_loopback=args.allow_non_loopback,
        token_env=args.token_env,
    )
    problems = policy.violations()
    if problems:
        print("error: HTTP bridge refused to start:", file=sys.stderr)
        for problem in problems:
            print(f"  - {problem}", file=sys.stderr)
        return 2

    try:
        import uvicorn
    except ImportError:
        print(f"error: {_MISSING_SDK}", file=sys.stderr)
        return 2

    app = build_app(
        policy,
        upstream_args,
        args.call_timeout,
        event_stream=args.event_stream,
        allow_no_tools=args.allow_no_tools,
    )
    print(
        f"ephemora-cell MCP HTTP bridge on http://{args.host}:{args.port}/mcp "
        f"(bearer via ${args.token_env}; upstream: {upstream_args or 'default tools'})",
        file=sys.stderr,
        flush=True,
    )
    uvicorn.run(app, host=args.host, port=args.port, log_level="warning")
    return 0


if __name__ == "__main__":
    sys.exit(main())
