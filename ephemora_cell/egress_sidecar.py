# Ephemora Cell — Host-sidecar egress mediator (ADR-002)
# SPDX-License-Identifier: Apache-2.0
"""Mediated API egress for sandboxed tools (the host-sidecar pattern).

The guest has NO sockets. A tool that needs an API writes a request
artifact into its sandbox dir (``sidecar.request.json``); the HOST
validates it against an explicit allowlist policy, executes the call,
and produces a response artifact. This module is the host-side
mediator — dependency-free (urllib), policy-first, fail-closed.

Security properties:
  * the request document is UNTRUSTED input (unknown top-level keys are
    rejected, not ignored);
  * the URL must match an allowlist entry (scheme + host + path prefix);
    userinfo, fragments and non-allowlisted schemes are rejected;
  * credentials are added by the HOST, never taken from the artifact;
  * response bodies are size-capped and clocked by a timeout;
  * every decision (allowed or denied) yields an audit entry — callers
    attach these to their execution reports (MCP ``_meta``).
"""

from __future__ import annotations

import json
import time
import urllib.error
import urllib.parse
import urllib.request
from dataclasses import dataclass

REQUEST_FILENAME = "sidecar.request.json"
RESPONSE_FILENAME = "sidecar.response.json"
_MAX_REQUEST_BYTES = 64 * 1024
_ALLOWED_HEADER_NAMES = {"accept", "content-type", "user-agent"}


@dataclass(frozen=True)
class EgressPolicy:
    """Host-side egress policy — never guest-controlled (ADR-002)."""

    allowed_endpoints: tuple[str, ...] = ()
    allowed_methods: tuple[str, ...] = ("GET", "POST")
    max_response_bytes: int = 64 * 1024
    timeout_seconds: float = 10.0

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
    parsed = urllib.parse.urlsplit(url)
    if parsed.scheme not in ("https", "http"):
        return None
    if parsed.username or parsed.password or parsed.fragment:
        return None
    path = parsed.path or "/"
    for endpoint in policy.allowed_endpoints:
        entry = urllib.parse.urlsplit(endpoint)
        if (
            parsed.scheme == entry.scheme
            and parsed.hostname == entry.hostname
            and (entry.port or {"https": 443, "http": 80}[entry.scheme])
            == (parsed.port or {"https": 443, "http": 80}[parsed.scheme])
            and path.startswith(entry.path or "/")
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
        return EgressAuditEntry(
            url=request.url,
            method=request.method,
            decision="denied",
            reason="url not allowed by egress policy",
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
    try:
        req = urllib.request.Request(
            request.url,
            data=request.body.encode("utf-8") if request.body else None,
            method=request.method,
            headers=request.headers or {},
        )
        # nosec B310 below — urlopen's file:/custom-scheme reach is closed
        # upstream: audit_request() → _url_matches_allowlist() rejects every
        # scheme except http/https before this executes; this function's
        # contract is "already-validated request".
        with urllib.request.urlopen(  # nosec B310 — allowlist enforces http/https only
            req, timeout=policy.timeout_seconds
        ) as resp:
            body = resp.read(policy.max_response_bytes + 1)
            status = int(resp.status)
    except (urllib.error.URLError, OSError, ValueError) as e:
        elapsed = (time.monotonic() - started) * 1000
        entry = EgressAuditEntry(
            url=request.url,
            method=request.method,
            decision="allowed",
            reason="fetch failed (see response doc)",
            elapsed_ms=elapsed,
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
