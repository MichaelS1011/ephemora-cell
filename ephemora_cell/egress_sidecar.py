# Ephemora Cell — Host-sidecar egress mediator (ADR-002)
# SPDX-License-Identifier: BUSL-1.1
# Copyright 2026 Michael Soppa
"""Mediated API egress for sandboxed tools (the host-sidecar pattern).

The guest has NO sockets. A tool that needs an API writes a request
artifact into its sandbox dir (``sidecar.request.json``); the HOST
validates it against an explicit allowlist policy, executes the call,
and produces a response artifact. This module is the host-side
mediator — dependency-free (urllib), policy-first, fail-closed.

Security properties:
  * the request document is UNTRUSTED input (unknown top-level keys are
    rejected, not ignored);
  * the URL must match an allowlist entry (scheme + host + port + path),
    where a path entry is a SEGMENT prefix: ``/v1`` admits ``/v1`` and
    ``/v1/x`` but never ``/v1-admin/x``;
  * userinfo, fragments, non-allowlisted schemes and dot-segment paths
    (``..``, ``%2e%2e``) are rejected before any socket is opened;
  * redirects are revalidated per hop against the same policy and must keep
    the scheme — an off-policy ``Location:`` is refused, not fetched (the
    stdlib default opener would otherwise follow it, including to link-local
    metadata addresses, while the audit entry still said "allowed");
  * the HOST sends no credentials: ``Authorization``/``Cookie``-style headers
    from the artifact are refused (see _ALLOWED_HEADER_NAMES) — header
    injection is not implemented, so nothing claims it;
  * response bodies are size-capped and clocked by a timeout;
  * every decision (allowed or denied) yields an audit entry carrying the
    hops actually attempted — callers attach these to their execution
    reports (MCP ``_meta``).
"""

from __future__ import annotations

import http.client
import ipaddress
import json
import os
import socket
import threading
import time
import urllib.error
import urllib.parse
import urllib.request
from collections.abc import Callable
from contextlib import contextmanager
from dataclasses import dataclass
from pathlib import Path
from typing import TYPE_CHECKING

from ._fsutil import read_regular_nofollow

if TYPE_CHECKING:
    from ephemora_cell.grant_ledger import GrantLedger

REQUEST_FILENAME = "sidecar.request.json"

#: Hard bound on the request artifact a host will read. The guest writes it into
#: its own sandbox, and ``io_budget_bytes`` bounds the sandbox in aggregate — the
#: parser still must not be handed an arbitrarily large document.
REQUEST_MAX_BYTES = 1024 * 1024
RESPONSE_FILENAME = "sidecar.response.json"
_MAX_REQUEST_BYTES = 64 * 1024
_ALLOWED_HEADER_NAMES = {"accept", "content-type", "user-agent"}
_DEFAULT_PORTS = {"https": 443, "http": 80}


class _EgressDeadline(RuntimeError):
    """The one wall-clock budget for a mediated fetch ran out."""

    def __init__(self, limit_seconds: float) -> None:
        super().__init__(
            f"egress deadline exceeded: the fetch did not finish within "
            f"{limit_seconds}s of wall-clock time"
        )


class _SSRFBlocked(Exception):
    """A host resolved (via the guarded resolver) only to forbidden addresses.

    Raised from inside the socket resolution the SAME connection then uses, so
    the decision and the connect are one atomic step — there is no window for a
    DNS answer to rebind to a private/link-local address between "checked" and
    "connected". It deliberately does NOT subclass OSError: urllib's transport
    wraps OSError into URLError, which would blur this policy denial into a
    generic fetch failure. Keeping it a plain Exception lets it surface raw to
    :func:`execute_request`, which reports it as a ``denied`` audit.
    """

    def __init__(self, host: str, reason: str) -> None:
        super().__init__(f"egress host {host!r}: {reason}")
        self.host = host
        self.reason = reason


#: Addresses an egress host may never resolve to. An allowlist entry that is an
#: IP *literal* is operator intent and bypasses this; only hostnames — the
#: surface a rebinding attack drives — are filtered.
_CGNAT = ipaddress.ip_network("100.64.0.0/10")


def _ip_blocked(ip: str) -> bool:
    try:
        addr = ipaddress.ip_address(ip)
    except ValueError:
        return True  # unparseable — fail closed
    if (
        addr.is_private
        or addr.is_loopback
        or addr.is_link_local
        or addr.is_multicast
        or addr.is_reserved
        or addr.is_unspecified
    ):
        return True
    # RFC 6598 CGNAT is not flagged is_private on every Python release, but it
    # routes to provider-side space no egress should reach.
    return addr.version == 4 and addr in _CGNAT


def _is_ip_literal(host: str) -> bool:
    try:
        ipaddress.ip_address(host)
    except ValueError:
        return False
    return True


_real_getaddrinfo = socket.getaddrinfo
_egress_tls = threading.local()


def _guarded_getaddrinfo(host, *args, **kwargs):
    """A ``socket.getaddrinfo`` shim active only inside a mediated fetch.

    Outside :func:`_egress_context` the thread has no egress context and this is
    a transparent pass-through to the real resolver. Inside it, a hostname is
    resolved through the injected resolver and every forbidden address is
    dropped; a name with no public answer raises :class:`_SSRFBlocked`. Because
    the connection is then made from THIS returned list, the check and the use
    are the same call — the rebinding TOCTOU the redirect fix left open is
    closed here. IP-literal hosts are the operator's explicit choice and pass
    unfiltered (so a deliberate localhost/metadata endpoint still works).
    """
    ctx = getattr(_egress_tls, "ctx", None)
    if ctx is None:
        return _real_getaddrinfo(host, *args, **kwargs)
    infos = ctx["resolver"](host, *args, **kwargs)
    if host is None or _is_ip_literal(str(host)):
        return infos
    safe = [entry for entry in infos if not _ip_blocked(entry[4][0])]
    if not safe:
        raise _SSRFBlocked(str(host), "resolves only to blocked/private addresses")
    return safe


def _install_getaddrinfo_guard() -> None:
    """Swap the guard in once; idempotent, and transparent when no ctx is set."""
    if socket.getaddrinfo is not _guarded_getaddrinfo:
        socket.getaddrinfo = _guarded_getaddrinfo


@contextmanager
def _egress_context(resolver: Callable):
    """Activate the resolver shim for this thread for one mediated fetch."""
    previous = getattr(_egress_tls, "ctx", None)
    _egress_tls.ctx = {"resolver": resolver}
    try:
        yield
    finally:
        _egress_tls.ctx = previous


def _has_dot_segment(path: str) -> bool:
    """True if any path segment is ``.``/``..`` — before or after decoding.

    Checked on the raw path AND on the percent-decoded path: the writer of an
    allowlist prefix cannot know which form a client or a redirect will use,
    and ``%2e%2e`` reaches the same file as ``..`` once anything normalizes it.
    """
    for candidate in (path, urllib.parse.unquote(path)):
        segments = candidate.split("/")
        if any(segment in (".", "..") for segment in segments):
            return True
    return False


def _path_allowed(request_path: str, entry_path: str) -> bool:
    """Segment-boundary prefix match, not a string prefix match.

    ``/v1`` as an entry admits ``/v1`` and ``/v1/anything``. It used to admit
    ``/v1-admin/keys`` too, because ``"/v1-admin/keys".startswith("/v1")`` —
    and on API gateways ``-admin`` is a routinely routable sibling prefix. An
    entry with no path means the whole host, which is the operator's own
    decision and is stated as such rather than reached by accident.
    """
    if not entry_path or entry_path == "/":
        return True
    if request_path == entry_path:
        return True
    boundary = entry_path if entry_path.endswith("/") else entry_path + "/"
    return request_path.startswith(boundary)


@dataclass(frozen=True)
class EgressPolicy:
    """Host-side egress policy — never guest-controlled (ADR-002)."""

    allowed_endpoints: tuple[str, ...] = ()
    allowed_methods: tuple[str, ...] = ("GET", "POST")
    max_response_bytes: int = 64 * 1024
    timeout_seconds: float = 10.0
    # Resolver used to resolve an egress hostname before connecting (SSRF guard).
    # None -> the real socket.getaddrinfo. Injectable so a deployment can supply
    # an internal resolver and tests can drive it deterministically; it never
    # changes the allowlist decision, only the address a name resolves to.
    resolver: Callable | None = None

    def __post_init__(self) -> None:
        for endpoint in self.allowed_endpoints:
            parsed = urllib.parse.urlsplit(endpoint)
            if parsed.scheme not in ("https", "http") or not parsed.hostname:
                raise ValueError(
                    f"allowed_endpoints entry {endpoint!r} must be "
                    "scheme://host/path-prefix (https/http)"
                )
            if parsed.username or parsed.password or parsed.fragment:
                raise ValueError(
                    f"allowed_endpoints entry {endpoint!r} must not carry "
                    "userinfo or a fragment"
                )
            if parsed.query:
                raise ValueError(
                    f"allowed_endpoints entry {endpoint!r} must not carry a "
                    "query — a path prefix never matches on query parameters"
                )
            if _has_dot_segment(parsed.path) or "%" in parsed.path:
                raise ValueError(
                    f"allowed_endpoints entry {endpoint!r} must be a literal "
                    "path prefix without dot segments or percent-encoding"
                )
        for method in self.allowed_methods:
            if method.upper() not in ("GET", "POST", "PUT", "DELETE", "HEAD"):
                raise ValueError(f"method {method!r} not allowed in policy")


@dataclass(frozen=True)
class EgressRequest:
    url: str
    method: str
    headers: dict
    body: str | None


@dataclass(frozen=True)
class EgressAuditEntry:
    url: str
    method: str
    decision: str  # "allowed" | "denied"
    reason: str
    status: int | None = None
    bytes: int | None = None
    elapsed_ms: float | None = None
    # Redirect targets actually followed (success) or attempted (refusal).
    # Without this, an audit line that says "allowed, 200" cannot tell whether
    # the bytes came from the allowlisted URL or two hops away from it.
    hops: tuple[str, ...] = ()
    # For a grant-enforced denial: which gate refused (``revoked`` /
    # ``not_before`` / ``expired`` / ``max_calls``), so a transport layer can
    # report it without parsing prose. None for allowlist/plain-policy denials.
    limit: str | None = None


class _RedirectTrail:
    """What the redirect revalidator saw, for the audit entry."""

    def __init__(self) -> None:
        self.attempted: list[str] = []
        self.followed: list[str] = []
        self.denied_reason: str | None = None


class _RevalidatingRedirectHandler(urllib.request.HTTPRedirectHandler):
    """Follow a redirect only when the target passes the SAME policy.

    The stdlib default opener follows 301/302/303/307/308 by itself (up to 10
    hops) and hands every scheme except ``http``/``https``/``ftp`` to the
    error path — which means an allowlisted host answering
    ``Location: http://169.254.169.254/latest/meta-data/`` used to reach the
    link-local metadata interface while our audit entry still reported
    "allowed". Refusing here is the minimal correct fix: return None and the
    stdlib raises HTTPError instead of dispatching the new request.
    """

    def __init__(self, policy: EgressPolicy, trail: _RedirectTrail) -> None:
        self._policy = policy
        self._trail = trail

    def redirect_request(self, req, fp, code, msg, headers, newurl):
        self._trail.attempted.append(newurl)
        if _url_matches_allowlist(self._policy, newurl) is None:
            self._trail.denied_reason = (
                f"redirect ({code}) to {newurl!r} is not on the egress allowlist"
            )
            return None
        origin_scheme = urllib.parse.urlsplit(req.full_url).scheme
        if urllib.parse.urlsplit(newurl).scheme != origin_scheme:
            self._trail.denied_reason = (
                f"redirect ({code}) changes scheme to {newurl!r}"
            )
            return None
        nxt = super().redirect_request(req, fp, code, msg, headers, newurl)
        if nxt is None:
            return None
        # `redirect_request` is called BEFORE the stdlib applies its own loop
        # limits, so a returned request is still not a dispatched one: recording
        # it here would put a hop in the audit that no socket ever opened. Mirror
        # the same two checks (repeats per URL, total hops) and refuse on the
        # stdlib's behalf.
        visited = getattr(req, "redirect_dict", None)
        if visited is not None and (
            visited.get(newurl, 0) >= self.max_repeats
            or len(visited) >= self.max_redirections
        ):
            self._trail.denied_reason = (
                f"redirect loop limit reached at {newurl!r} "
                f"({self.max_redirections} hops)"
            )
            return None
        self._trail.followed.append(newurl)
        return nxt


@dataclass(frozen=True)
class EgressResult:
    response_doc: dict
    audit: EgressAuditEntry


def parse_request_document(raw: bytes | str) -> EgressRequest:
    """Parse the guest-produced request artifact (UNTRUSTED, fail-closed)."""
    try:
        if isinstance(raw, bytes):
            raw = raw.decode("utf-8")
        if len(raw) > _MAX_REQUEST_BYTES:
            raise ValueError("request artifact too large")
        doc = json.loads(raw)
    except (UnicodeDecodeError, json.JSONDecodeError) as e:
        raise ValueError(f"request artifact is not valid JSON: {e}") from e
    if not isinstance(doc, dict):
        raise ValueError("request artifact must be a JSON object")
    unknown = set(doc) - {"url", "method", "headers", "body"}
    if unknown:
        raise ValueError(f"unknown request fields: {sorted(unknown)}")
    url = doc.get("url")
    if not isinstance(url, str) or not url:
        raise ValueError("url must be a non-empty string")
    method = doc.get("method", "GET")
    if not isinstance(method, str):
        raise ValueError("method must be a string")
    headers = doc.get("headers", {})
    if not isinstance(headers, dict) or not all(
        isinstance(k, str) and isinstance(v, str) for k, v in headers.items()
    ):
        raise ValueError("headers must be an object of string pairs")
    body = doc.get("body")
    if body is not None and not isinstance(body, str):
        raise ValueError("body must be a string or null")
    return EgressRequest(url=url, method=method.upper(), headers=headers, body=body)


def _url_matches_allowlist(policy: EgressPolicy, url: str) -> str | None:
    """Return the matching endpoint entry, or None (fail closed)."""
    try:
        parsed = urllib.parse.urlsplit(url)
    except ValueError:
        return None
    if parsed.scheme not in ("https", "http"):
        return None
    # Not `if parsed.username`: an EMPTY userinfo ("http://:@host") is falsy
    # but is still carried in the netloc and on the wire, so the presence of
    # the separator is what must be refused.
    if "@" in parsed.netloc or parsed.fragment:
        return None
    if _has_dot_segment(parsed.path):
        return None
    path = parsed.path or "/"
    for endpoint in policy.allowed_endpoints:
        entry = urllib.parse.urlsplit(endpoint)
        if (
            parsed.scheme == entry.scheme
            and parsed.hostname == entry.hostname
            and (parsed.port or _DEFAULT_PORTS[parsed.scheme])
            == (entry.port or _DEFAULT_PORTS[entry.scheme])
            and _path_allowed(path, entry.path)
        ):
            return endpoint
    return None


def validate_request(policy: EgressPolicy, request: EgressRequest) -> EgressAuditEntry:
    """Validate a parsed request against the policy (no network)."""
    if request.method not in {m.upper() for m in policy.allowed_methods}:
        return EgressAuditEntry(
            url=request.url,
            method=request.method,
            decision="denied",
            reason=f"method {request.method!r} not allowed by egress policy",
        )
    match = _url_matches_allowlist(policy, request.url)
    if match is None:
        try:
            path = urllib.parse.urlsplit(request.url).path
        except ValueError:
            path = ""
        if _has_dot_segment(path):
            reason = (
                "path contains a dot segment (.. or %2e%2e) — refused before "
                "any socket is opened"
            )
        else:
            reason = "url not allowed by egress policy"
        return EgressAuditEntry(
            url=request.url,
            method=request.method,
            decision="denied",
            reason=reason,
        )
    bad_headers = [k for k in request.headers if k.lower() not in _ALLOWED_HEADER_NAMES]
    if bad_headers:
        return EgressAuditEntry(
            url=request.url,
            method=request.method,
            decision="denied",
            reason=f"headers not allowed by egress policy: {bad_headers}",
        )
    return EgressAuditEntry(
        url=request.url,
        method=request.method,
        decision="allowed",
        reason=f"matches allowlist entry {match!r}",
    )


def execute_request(
    policy: EgressPolicy, request: EgressRequest, *, audit: EgressAuditEntry
) -> EgressResult:
    """Execute an already-validated request (host-side, trusted context)."""
    started = time.monotonic()
    trail = _RedirectTrail()
    # A custom opener, not urlopen: the default one follows redirects without
    # asking the policy. Only http/https can be reached at all — the allowlist
    # rejects every other scheme up front, and _RevalidatingRedirectHandler
    # rejects a redirect that leaves the scheme or the allowlist.
    #
    # ProxyHandler({}) is load-bearing, not cosmetics: with an environment
    # ``http_proxy`` set, urllib resolves and connects to the PROXY and never
    # asks for the target hostname (measured 2026-10-04 — the shim was called
    # with ``('proxy.internal', 8080)`` for a URL pointing at
    # ``api.example.com``). The resolve-time IP guard would then vet the proxy
    # address while the actual name resolution happened somewhere else, which
    # voids both the SSRF filter and the "checked IP == connected IP" claim.
    # A mediated egress goes direct to the allowlisted origin; if a deployment
    # needs a proxy, that is an explicit operator decision, never one inherited
    # from the ambient environment.
    opener = urllib.request.build_opener(
        urllib.request.ProxyHandler({}),
        _RevalidatingRedirectHandler(policy, trail),
    )
    _install_getaddrinfo_guard()
    resolver = policy.resolver or _real_getaddrinfo
    try:
        req = urllib.request.Request(
            request.url,
            data=request.body.encode("utf-8") if request.body else None,
            method=request.method,
            headers=request.headers or {},
        )
        # The SSRF guard is active only for this fetch (this thread): every
        # connect — the request and each followed redirect — resolves through
        # it, so a hostname that answers with a private/link-local address is
        # dropped before the socket opens, and a name with no public answer is
        # refused. validate-and-use are the same getaddrinfo call, so there is
        # no rebinding window between checking the URL and connecting.
        with (
            _egress_context(resolver),
            opener.open(  # nosec B310 — scheme is
                # pinned to http/https by _url_matches_allowlist (request) and the
                # redirect revalidator (every hop); no file:/ftp: path reaches here.
                req,
                timeout=policy.timeout_seconds,
            ) as resp,
        ):
            status = int(resp.status)
            # ``timeout_seconds`` on open() bounds a single socket operation, not
            # the request: a server trickling one byte every nap keeps the thread
            # past the budget, and each of up to ten redirect hops got a fresh
            # one. Read in chunks against ONE wall-clock deadline for the whole
            # mediated fetch, and deliver nothing if it runs out.
            chunks: list[bytes] = []
            total = 0
            while True:
                if (time.monotonic() - started) > policy.timeout_seconds:
                    raise _EgressDeadline(policy.timeout_seconds)
                room = policy.max_response_bytes + 1 - total
                # read1(): one buffer's worth, returning as soon as anything
                # arrives. `read(n)` blocks until n bytes are in hand, which is
                # exactly how a trickling peer outlives a per-op timeout.
                reader = getattr(resp, "read1", None) or resp.read
                chunk = reader(min(room, 65536))
                if not chunk:
                    break
                chunks.append(chunk)
                total += len(chunk)
                if total > policy.max_response_bytes:
                    break
            body = b"".join(chunks)
    except _EgressDeadline as e:
        elapsed = (time.monotonic() - started) * 1000
        reason = str(e)
        return EgressResult(
            response_doc={
                "ok": False,
                "error": reason,
                "elapsed_ms": round(elapsed, 3),
            },
            audit=EgressAuditEntry(
                url=request.url,
                method=request.method,
                decision="denied",
                reason=reason,
                elapsed_ms=elapsed,
                hops=tuple(trail.attempted),
                limit="timeout",
            ),
        )
    except http.client.HTTPException as e:
        # http.client's own failures subclass neither OSError nor ValueError, so
        # they used to leave mediate() entirely: a tab inside the URL that the
        # allowlist still matched (InvalidURL), a >100-header response, a junk
        # status line. No bytes were delivered, so this is a refusal, and it is
        # audited as one.
        elapsed = (time.monotonic() - started) * 1000
        reason = f"transport refused: {type(e).__name__}: {e}"
        return EgressResult(
            response_doc={
                "ok": False,
                "error": reason,
                "elapsed_ms": round(elapsed, 3),
            },
            audit=EgressAuditEntry(
                url=request.url,
                method=request.method,
                decision="denied",
                reason=reason,
                elapsed_ms=elapsed,
                hops=tuple(trail.attempted),
                limit="transport",
            ),
        )
    except _SSRFBlocked as e:
        elapsed = (time.monotonic() - started) * 1000
        reason = f"egress host blocked (SSRF): {e.reason}"
        return EgressResult(
            response_doc={
                "ok": False,
                "error": reason,
                "elapsed_ms": round(elapsed, 3),
            },
            audit=EgressAuditEntry(
                url=request.url,
                method=request.method,
                decision="denied",
                reason=reason,
                elapsed_ms=elapsed,
                hops=tuple(trail.attempted),
                limit="ssrf",
            ),
        )
    except (urllib.error.URLError, OSError, ValueError) as e:
        elapsed = (time.monotonic() - started) * 1000
        if trail.denied_reason:
            # A policy refusal is not a transport failure.
            return EgressResult(
                response_doc={
                    "ok": False,
                    "error": trail.denied_reason,
                    "elapsed_ms": round(elapsed, 3),
                },
                audit=EgressAuditEntry(
                    url=request.url,
                    method=request.method,
                    decision="denied",
                    reason=trail.denied_reason,
                    elapsed_ms=elapsed,
                    hops=tuple(trail.attempted),
                ),
            )
        entry = EgressAuditEntry(
            url=request.url,
            method=request.method,
            decision="allowed",
            reason="fetch failed (see response doc)",
            elapsed_ms=elapsed,
            hops=tuple(trail.followed),
        )
        return EgressResult(
            response_doc={
                "ok": False,
                "error": f"fetch failed: {e}",
                "elapsed_ms": round(elapsed, 3),
            },
            audit=entry,
        )
    elapsed = (time.monotonic() - started) * 1000
    truncated = len(body) > policy.max_response_bytes
    if truncated:
        body = body[: policy.max_response_bytes]
    entry = EgressAuditEntry(
        url=request.url,
        method=request.method,
        decision="allowed",
        reason="fetched",
        status=status,
        bytes=len(body),
        elapsed_ms=elapsed,
        hops=tuple(trail.followed),
    )
    try:
        payload = json.loads(body.decode("utf-8"))
    except (UnicodeDecodeError, json.JSONDecodeError):
        payload = None
    response_doc = {
        "ok": True,
        "status": status,
        "bytes": len(body),
        "truncated": truncated,
        "content": (
            payload if payload is not None else body.decode("utf-8", errors="replace")
        ),
        "elapsed_ms": round(elapsed, 3),
    }
    return EgressResult(response_doc=response_doc, audit=entry)


def mediate(policy: EgressPolicy, raw: bytes | str) -> EgressResult:
    """Full cycle: parse (untrusted) → validate → execute → audit."""
    try:
        request = parse_request_document(raw)
    except ValueError as e:
        entry = EgressAuditEntry(
            url="<unparsed>",
            method="?",
            decision="denied",
            reason=f"invalid request artifact: {e}",
        )
        return EgressResult(
            response_doc={"ok": False, "error": f"invalid request artifact: {e}"},
            audit=entry,
        )
    audit = validate_request(policy, request)
    if audit.decision == "denied":
        return EgressResult(
            response_doc={
                "ok": False,
                "error": f"denied by egress policy: {audit.reason}",
            },
            audit=audit,
        )
    return execute_request(policy, request, audit=audit)


def run_sidecar_cycle(
    policy: EgressPolicy, raw: bytes | str
) -> tuple[dict, EgressAuditEntry]:
    """Convenience: mediate and return (response_doc, audit_entry)."""
    result = mediate(policy, raw)
    return result.response_doc, result.audit


def mediate_with_grant(
    grant: EgressGrant,
    ledger: GrantLedger,
    raw: bytes | str,
    *,
    now=None,
    ceiling: EgressPolicy | None = None,
) -> EgressResult:
    """Mediate a request under a SIGNED grant whose window/cap/revocation are
    enforced by ``ledger`` (ADR-013) — not the allowlist-only :func:`mediate`.

    Order matters for honesty about what a grant slot costs:
      1. parse the untrusted artifact and validate it against the grant's own
         allowlist (:meth:`EgressGrant.policy`) — a request that fails here is
         refused WITHOUT spending a grant call, so a caller probing endpoints
         cannot drain a cap it will never reach;
      2. charge one call via :meth:`GrantLedger.record_call` (revocation /
         ``not_before`` / ``not_after`` / ``max_calls`` decided and written in
         one critical section);
      3. only on approval, execute the fetch.

    ``ceiling`` is the server-wide policy (`--egress-allow`) when one is also
    configured. A grant then NARROWS it and never widens it: the request must
    clear both allowlists, checked after the grant's own and BEFORE the ledger
    charge, so a call the operator's policy refuses cannot spend a grant slot.
    Without a ceiling the grant is the whole authority for its tool, which is the
    documented behaviour of a grant-only deployment.

    The grant's ``not_*``/``max_calls`` fields stop being schema-only here:
    this is the shipped consumer that reads them. Revocation is effective at
    THIS call, not an in-flight one.
    """
    policy = grant.policy()
    try:
        request = parse_request_document(raw)
    except ValueError as e:
        entry = EgressAuditEntry(
            url="<unparsed>",
            method="?",
            decision="denied",
            reason=f"invalid request artifact: {e}",
        )
        return EgressResult(
            response_doc={"ok": False, "error": f"invalid request artifact: {e}"},
            audit=entry,
        )
    audit = validate_request(policy, request)
    if audit.decision == "denied":
        return EgressResult(
            response_doc={
                "ok": False,
                "error": f"denied by egress policy: {audit.reason}",
            },
            audit=audit,
        )
    if ceiling is not None:
        # Grant ∩ server policy: a signed document cannot enlarge what the
        # operator allowlisted. Refused here, so no slot is spent on a call that
        # the deployment would never have made.
        ceiling_audit = validate_request(ceiling, request)
        if ceiling_audit.decision == "denied":
            reason = (
                f"granted endpoint is outside the server-wide allowlist: "
                f"{ceiling_audit.reason}"
            )
            return EgressResult(
                response_doc={"ok": False, "error": reason},
                audit=EgressAuditEntry(
                    url=request.url,
                    method=request.method,
                    decision="denied",
                    reason=reason,
                    limit="server-policy",
                ),
            )
    try:
        decision = ledger.record_call(grant, now=now)
    except (OSError, ValueError, RuntimeError) as e:
        # The book is the enforcement. A ledger that cannot be read or written —
        # a tampered line, an unwritable path, a vanished directory — must refuse
        # the call WITH an audit entry, not raise past the mediator: an
        # unhandled exception means no audit line, no ``_meta.egress`` and one
        # corrupt record switching off every grant in the process.
        reason = f"grant ledger unreadable, call refused: {e}"
        return EgressResult(
            response_doc={"ok": False, "error": reason},
            audit=EgressAuditEntry(
                url=request.url,
                method=request.method,
                decision="denied",
                reason=reason,
                limit="ledger",
            ),
        )
    if not decision.allowed:
        grant_entry = EgressAuditEntry(
            url=request.url,
            method=request.method,
            decision="denied",
            reason=f"egress grant: {decision.reason}",
            limit=decision.limit,
        )
        return EgressResult(
            response_doc={"ok": False, "error": f"egress grant: {decision.reason}"},
            audit=grant_entry,
        )
    return execute_request(policy, request, audit=audit)


#: Schema tag of the frozen grant envelope. A future version coexists by tag.
GRANT_SCHEMA_VERSION = "egress-grant.v1"

#: A grant file is recognised by this exact suffix — and by nothing looser, because a
#: loader that installs authority must not be guessing which files were meant.
GRANT_FILE_SUFFIX = ".egress.grant.json"


@dataclass(frozen=True)
class EgressGrant:
    """A SIGNED egress allowance — the envelope an enforcement consumer reads.

    This freezes the SHAPE of a grant (who, to what, until when, how much,
    under which key) so the schema can be published and interoperated on.
    :meth:`policy` yields the :class:`EgressPolicy` the mediator checks;
    ``not_before`` / ``not_after`` / ``max_calls`` and revocation are ENFORCED
    by :class:`~ephemora_cell.grant_ledger.GrantLedger`, the shipped consumer
    that reads them (ADR-013, Prio 1). :func:`mediate_with_grant` is the path
    that applies all of it; :func:`mediate` alone stays allowlist-only.

    What is still NOT claimed, and stays true with a ledger attached: a
    revocation or a cap bites at the NEXT mediated call, never an in-flight
    one, and a delivered response is not recalled. The grant in isolation is
    only ever the allowlist — the window/cap/revocation only mean something
    while a :class:`GrantLedger` is reading them.

    ``canonical_bytes()`` is RFC 8785 (JCS) over the grant's fields — the exact
    bytes an issuer signs and a verifier recomputes with the same recipe as
    every other Cell record. The startup path DOES verify them:
    :class:`~ephemora_cell.grant_trust.GrantTrustRoot` authenticates the envelope
    against keys anchored outside the grants directory, so a file an attacker
    dropped into that directory is not an authority (ADR-013). What that does
    not claim: the ``enforced`` tag below describes the allowlist the document
    itself carries, and the window/cap/revocation only bite while a
    :class:`GrantLedger` reads them.
    """

    grant_id: str
    tool: str
    allowed_endpoints: tuple[str, ...]
    allowed_methods: tuple[str, ...] = ("GET", "POST")
    not_before: str | None = None  # ISO-8601 UTC, or None = no lower bound
    not_after: str | None = None  # ISO-8601 UTC, or None = does not expire
    max_calls: int | None = None  # None = uncapped (and NOT enforced today)
    key_id: str | None = None  # which operator key is expected to sign it

    def __post_init__(self) -> None:
        if not self.grant_id:
            raise ValueError("grant_id must be non-empty")
        if not self.tool:
            raise ValueError("tool must be non-empty")
        # Fail closed on the ONE part that is real today: the allowlist the
        # mediator will actually apply. The time/usage fields above are
        # schema-only and validated no further than that.
        self.policy()

    def policy(self) -> EgressPolicy:
        """The endpoint/method allowlist this grant describes (the enforced part)."""
        return EgressPolicy(
            allowed_endpoints=self.allowed_endpoints,
            allowed_methods=self.allowed_methods,
        )

    def to_dict(self) -> dict:
        return {
            "grant_version": GRANT_SCHEMA_VERSION,
            "grant_id": self.grant_id,
            "tool": self.tool,
            "allowed_endpoints": list(self.allowed_endpoints),
            "allowed_methods": list(self.allowed_methods),
            "not_before": self.not_before,
            "not_after": self.not_after,
            "max_calls": self.max_calls,
            "key_id": self.key_id,
            # Stated in the payload itself: a verifier must never infer more
            # assurance than the schema currently carries.
            "enforced": "allowlist-only",
        }

    def canonical_bytes(self) -> bytes:
        from ephemora_cell.execution_report import canonical_bytes

        return canonical_bytes(self.to_dict())

    @classmethod
    def from_document(cls, doc: dict) -> EgressGrant:
        """Rebuild a grant from its :meth:`to_dict` shape — fail closed.

        The inverse of ``to_dict``: a stored grant file is read back through
        this, so the loader accepts exactly what an issuer serialises. The
        schema tag is checked (an unknown ``grant_version`` is refused, not
        guessed), ``enforced`` is ignored (it is a description of the running
        enforcement, not a grant input), and the allowlist re-validates through
        :meth:`__post_init__`.
        """
        if not isinstance(doc, dict):
            raise ValueError("grant document must be a JSON object")
        version = doc.get("grant_version")
        if version != GRANT_SCHEMA_VERSION:
            raise ValueError(
                f"unsupported grant_version {version!r} (expected "
                f"{GRANT_SCHEMA_VERSION!r})"
            )
        for field in ("grant_id", "tool", "allowed_endpoints", "allowed_methods"):
            if field not in doc:
                raise ValueError(f"grant document is missing {field!r}")
        return cls(
            grant_id=doc["grant_id"],
            tool=doc["tool"],
            allowed_endpoints=tuple(doc["allowed_endpoints"]),
            allowed_methods=tuple(doc["allowed_methods"]),
            not_before=doc.get("not_before"),
            not_after=doc.get("not_after"),
            max_calls=doc.get("max_calls"),
            key_id=doc.get("key_id"),
        )


def load_egress_grants(
    grants_dir, trust_root
) -> tuple[dict[str, EgressGrant], list[str]]:
    """Read signed ``*.egress.grant.json`` envelopes into tool-name -> grant.

    Returns ``(grants, errors)`` — the loader is deliberately not silent: every
    file it could not accept is reported, so a caller can refuse to start rather
    than run with a cap or expiry the operator believed was in force.

    A grant is authority, so nothing here trusts the file it reads (ADR-013):
    every document must be a DSSE envelope over the grant's canonical bytes,
    signed by a key the out-of-band ``trust_root`` names, for the grant audience,
    inside both the key's and the grant's own window. Anything else — an unsigned
    legacy document, a re-signed edit, an unknown or retired key, an expired
    grant — is an error entry, and an error entry means the server does not start.
    """
    from .grant_trust import GrantTrustError

    if trust_root is None:
        raise ValueError(
            "load_egress_grants requires a GrantTrustRoot — grants without a "
            "verified signer are not an authority the loader may install"
        )
    directory = Path(grants_dir)
    if not directory.is_dir():
        raise NotADirectoryError(f"grants directory does not exist: {directory}")
    # The design says the root lives OUTSIDE the directory an authority-granting
    # write can reach. That is only a claim if it is checked: a root parked in the
    # grants dir is overwritable by whoever can write grants, and every grant would
    # then verify against the attacker's key.
    root_source = getattr(trust_root, "source", None)
    if root_source and root_source != "<in-memory>":
        root_path = Path(root_source).resolve()
        if root_path.is_relative_to(directory.resolve()):
            raise ValueError(
                f"trust root {root_path} sits inside the grants directory {directory} — "
                "a key that travels with the artefact proves nothing about it; keep "
                "the root outside the directory grants are read from"
            )
    grants: dict[str, EgressGrant] = {}
    errors: list[str] = []
    # ``Path.glob`` swallows OSError — on an unreadable directory it yields
    # NOTHING and reports no error, which for a loader that installs authority
    # means a server that starts with zero grants and still attests "every grant
    # file verified". Enumerate instead, and let the failure be seen.
    try:
        entries = sorted(
            (
                entry
                for entry in os.scandir(directory)
                if entry.name.endswith(GRANT_FILE_SUFFIX)
                and len(entry.name) > len(GRANT_FILE_SUFFIX)
            ),
            key=lambda entry: entry.name,
        )
    except OSError as e:
        raise OSError(f"grants directory is not readable: {directory}: {e}") from e
    for entry in entries:
        file = Path(entry.path)
        try:
            # Never follow a link a writable-directory owner (or a guest that
            # escaped into this path space) can plant, and accept a regular file
            # only: the bytes that are verified must be the bytes that were read.
            envelope = json.loads(
                read_regular_nofollow(file).decode("utf-8", errors="strict")
            )
            grant = trust_root.verify_envelope(envelope)
        except (OSError, UnicodeDecodeError, ValueError, GrantTrustError) as e:
            errors.append(f"{file.name}: {e}")
            continue
        if grant.tool in grants:
            errors.append(
                f"{file.name}: duplicate grant for tool {grant.tool!r} "
                f"(already from {grants[grant.tool]})"
            )
            continue
        grants[grant.tool] = grant
    if not entries:
        errors.append(
            f"{directory}: no grant files found (looked for *{GRANT_FILE_SUFFIX}) — an empty "
            "grants directory is a misconfiguration, not an empty authority set"
        )
    return grants, errors
