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
import json
import os
import secrets
import sys
from contextvars import ContextVar
from dataclasses import dataclass
from pathlib import Path

from .subject_binding import (
    ENV_SUBJECT_FROM_UPSTREAM,
    ENV_SUBJECT_SECRET,
    SUBJECT_KEY,
    SUBJECT_PROOF_KEY,
    subject_proof,
)

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


#: The host-established identity of the request currently being served. Set by
#: :class:`BearerAuthMiddleware` from the authenticated token and read by the
#: tool-call path — never from a request body field. A plain ASGI middleware
#: runs in the request's own task, so the value set before ``await app(...)``
#: is visible downstream (this is not BaseHTTPMiddleware).
CURRENT_SUBJECT: ContextVar[str | None] = ContextVar(
    "ephemora_mcp_bridge_subject", default=None
)


@dataclass(frozen=True)
class TokenDirectory:
    """A bearer token -> subject map. The bridge's identity authority.

    A single-token bridge has one entry; a multi-client bridge lists one token
    per client. The presented token is matched against every entry (no early
    exit) so the comparison cost does not depend on which — or whether any —
    entry matched.
    """

    entries: tuple[tuple[bytes, str], ...]

    @classmethod
    def from_mapping(cls, mapping: dict[str, str]) -> TokenDirectory:
        if not mapping:
            raise ValueError("a token directory needs at least one token")
        entries: list[tuple[bytes, str]] = []
        for token, subject in mapping.items():
            secret = (token or "").strip()
            if not secret:
                raise ValueError("a token directory entry has an empty token")
            if len(secret) < MIN_TOKEN_LENGTH:
                raise ValueError(
                    f"token for {subject!r} is shorter than {MIN_TOKEN_LENGTH} "
                    "characters"
                )
            if not isinstance(subject, str) or not subject:
                raise ValueError("a token directory entry has an empty subject")
            entries.append((secret.encode("utf-8"), subject))
        return cls(tuple(entries))

    def subject_for(self, presented: bytes) -> str | None:
        """The subject whose token equals ``presented``, or ``None``."""
        match: str | None = None
        for token, subject in self.entries:
            if secrets.compare_digest(presented, token):
                match = subject
        return match


def load_token_subjects(path: str | Path) -> TokenDirectory:
    """Load a ``{"<token>": "<subject>"}`` JSON file into a directory."""
    data = json.loads(Path(path).read_text(encoding="utf-8"))
    if not isinstance(data, dict):
        raise ValueError("token-subject file must be a JSON object")
    return TokenDirectory.from_mapping({str(k): str(v) for k, v in data.items()})


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
    #: True when a multi-client token directory supplies the secrets instead of
    #: a single env token. The "must present a secret" rule is then satisfied by
    #: the directory's own validation, so it is not reported as missing here.
    has_token_directory: bool = False

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
        if not secret and not self.has_token_directory:
            problems.append(
                f"no bearer token in ${self.token_env}: refusing to start an "
                "execution endpoint that anyone on this machine can call"
            )
        elif secret and len(secret) < MIN_TOKEN_LENGTH:
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


def _child_env(
    policy: BridgePolicy, subject_secret: str | None = None
) -> dict[str, str]:
    """Environment for the stdio child, with the bridge's own secret removed.

    The child is the product server; it reads no bearer token, so handing it
    ``EPHEMORA_MCP_BRIDGE_TOKEN`` would put the credential that opens the HTTP
    gate inside every tool process it spawns — and anywhere that can read the
    child's environment. Everything else the upstream needs still arrives.

    In multi-client mode a per-instance subject secret is added so the child
    can verify the per-request subject the bridge carries (see
    :mod:`subject_binding`); a pre-existing value in the operator's own
    environment is overwritten by the bridge's own.
    """
    env = {k: v for k, v in os.environ.items() if k != policy.token_env}
    env["PYTHONUNBUFFERED"] = "1"
    if subject_secret is not None:
        env[ENV_SUBJECT_FROM_UPSTREAM] = "1"
        env[ENV_SUBJECT_SECRET] = subject_secret
    return env


def _subject_meta(secret: str | None, subject: str | None) -> dict[str, str] | None:
    """The ``meta`` the bridge attaches to an upstream ``tools/call``, or None.

    Only in multi-client mode (a secret is configured) and only for an
    authenticated subject. Single-token bridges keep the pre-1.2 upstream
    shape (no meta), and the child then enforces its own single subject.
    """
    if secret is None or not subject:
        return None
    return {
        SUBJECT_KEY: subject,
        SUBJECT_PROOF_KEY: subject_proof(secret, subject),
    }


class BearerAuthMiddleware:
    """Plain ASGI bearer gate, applied before any MCP message is touched."""

    def __init__(
        self,
        app,
        token: str | None = None,
        *,
        tokens: TokenDirectory | None = None,
    ) -> None:
        # A gate whose secret is empty accepts the empty presentation: with
        # ``compare_digest(b"", b"")`` an ``Authorization: Bearer `` request
        # walks straight through to execution. Measured on 2026-10-20 through a
        # real WASM tools/call. Refuse to build such a gate at all.
        if tokens is None and (not token or not token.strip()):
            raise ValueError(
                "bearer auth middleware refuses an empty token: an unprotected "
                "execution endpoint must never be composed"
            )
        if tokens is not None and token is not None:
            raise ValueError(
                "pass either a single token or a token directory, not both"
            )
        self._app = app
        # Stored stripped, because the presentation is stripped below: a secret
        # written from a file with a trailing newline would otherwise never
        # authenticate (fail-closed, but a pinned-out operator).
        if tokens is not None:
            self._tokens = tokens
        else:
            self._tokens = TokenDirectory.from_mapping(
                {(token or "").strip(): "default"}
            )

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
        stripped = presented.strip()
        subject = (
            self._tokens.subject_for(stripped) if prefix.lower() == b"bearer" else None
        )
        if subject is None:
            await _unauthorized(send)
            return
        token = CURRENT_SUBJECT.set(subject)
        try:
            await self._app(scope, receive, send)
        finally:
            CURRENT_SUBJECT.reset(token)


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


def _transport_security_settings(policy: BridgePolicy):
    """Build the exact Host/Origin allowlist the bridge hands to the SDK.

    Factored out so tests exercise the settings the product composes, not a
    re-implementation of them. The allowlist is explicit; a wildcard would
    turn the DNS-rebinding wall into decoration.
    """
    from mcp.server.transport_security import TransportSecuritySettings

    bind = f"{policy.host}:{policy.port}"
    local_authorities = {
        bind,
        policy.host,
        "localhost",
        "127.0.0.1",
        f"localhost:{policy.port}",
        f"127.0.0.1:{policy.port}",
        f"[::1]:{policy.port}",
    }
    return TransportSecuritySettings(
        enable_dns_rebinding_protection=True,
        allowed_hosts=sorted(local_authorities),
        allowed_origins=sorted(
            f"http://{authority}" for authority in local_authorities
        ),
    )


def build_app(
    policy: BridgePolicy,
    upstream_args: list[str],
    call_timeout: float,
    *,
    event_stream: bool = False,
    allow_no_tools: bool = False,
    token_directory: TokenDirectory | None = None,
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
    subject_secret = secrets.token_hex(32) if token_directory is not None else None
    try:
        import anyio
        from mcp import types
        from mcp.client.session import ClientSession
        from mcp.client.stdio import StdioServerParameters, stdio_client
        from mcp.server.lowlevel import Server
        from starlette.applications import Starlette
    except ImportError as exc:  # pragma: no cover - depends on the optional extra
        raise SystemExit(f"{_MISSING_SDK} ({exc})") from exc

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
        # The subject is read in THIS task (the middleware set it) and bound
        # before any await: the authenticated identity travels with the call,
        # never from a client-supplied field.
        meta = _subject_meta(subject_secret, CURRENT_SUBJECT.get())
        async with upstream_lock:
            try:
                result = await _session_call(
                    lambda: session.call_tool(params.name, params.arguments, meta=meta),
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
    inner = server.streamable_http_app(
        # Advisory-84m7-safe configuration: no SDK session registry and no
        # retained initialize payloads. mcp>=2.2.0 also carries the 4 MiB
        # request-body cap (fmmv) and the client-side $ref fix (rwrf).
        stateless_http=True,
        json_response=not event_stream,
        transport_security=_transport_security_settings(policy),
    )

    async def lifespan(app):
        params = StdioServerParameters(
            command=sys.executable,
            args=["-m", "ephemora_cell_mcp", *upstream_args],
            env=_child_env(policy, subject_secret),
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
    if token_directory is not None:
        return BearerAuthMiddleware(outer, tokens=token_directory)
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
        "--token-subjects",
        metavar="PATH",
        help=(
            "JSON file mapping bearer token -> subject for a multi-client "
            "bridge; each client then presents its own token and the bridge "
            "records which identity a request came from. Replaces the single "
            "--token-env secret."
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

    token_directory = None
    if args.token_subjects:
        try:
            token_directory = load_token_subjects(args.token_subjects)
        except (OSError, ValueError, TypeError) as e:
            print(f"error: --token-subjects: {e}", file=sys.stderr)
            return 2

    token = os.environ.get(args.token_env)
    policy = BridgePolicy(
        host=args.host,
        port=args.port,
        token=token,
        allow_non_loopback=args.allow_non_loopback,
        token_env=args.token_env,
        has_token_directory=token_directory is not None,
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
        token_directory=token_directory,
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
