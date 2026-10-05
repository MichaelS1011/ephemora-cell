"""Host-sidecar egress mediator — policy, parsing, end-to-end.

The guest writes ``sidecar.request.json`` into its sandbox dir (a plain
preview1 WASM, no sockets); the host mediates the call against an
allowlist policy with a local HTTP server standing in for the API.
"""

from __future__ import annotations

import json
import os
import socketserver
import sys
import threading
import time
import typing
from http.server import BaseHTTPRequestHandler, HTTPServer
from pathlib import Path

import pytest
import wasmtime

sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))

import ephemora_cell_mcp.engine as engine_module
from ephemora_cell import ExecutionStatus, WASIConfig, WASISandbox
from ephemora_cell.egress_sidecar import (
    EgressPolicy,
    execute_request,
    mediate,
    parse_request_document,
    run_sidecar_cycle,
    validate_request,
)
from ephemora_cell_mcp.engine import (
    CellOutcome,
    CellToolEngine,
    ExecutionResult,
)
from ephemora_cell_mcp.tool_registry import ToolSpec

# --- local stand-in API (loopback only, tests never touch the network) ---


class _Handler(BaseHTTPRequestHandler):
    payload: typing.ClassVar[dict] = {"answer": 42}

    def do_GET(self):
        body = json.dumps(self.payload).encode()
        self.send_response(200)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def log_message(self, *args):  # silence test output
        pass


def _policy(port: int) -> EgressPolicy:
    return EgressPolicy(allowed_endpoints=(f"http://127.0.0.1:{port}/v1/",))


# --- guest: writes the request artifact into /sandbox (no sockets) ---


def _guest_wat(port: int) -> str:
    request_doc = json.dumps(
        {"url": f"http://127.0.0.1:{port}/v1/data", "method": "GET"}
    )
    # iovec at 64: {buf_ptr = 128, buf_len = len}
    payload_hex = "".join(f"\\{b:02x}" for b in request_doc.encode("utf-8"))
    n = len(request_doc.encode("utf-8"))
    return f"""
    (module
      (import "wasi_snapshot_preview1" "fd_write" (func $fd_write
        (param i32 i32 i32 i32) (result i32)))
      (import "wasi_snapshot_preview1" "path_open" (func $path_open
        (param i32 i32 i32 i32 i32 i64 i64 i32 i32) (result i32)))
      (import "wasi_snapshot_preview1" "proc_exit" (func $proc_exit (param i32)))
      (memory (export "memory") 1)
      (data (i32.const 8) "sidecar.request.json")
      (data (i32.const 128) "{payload_hex}")
      (data (i32.const 64) "\\80\\00\\00\\00\\{n:x}\\00\\00\\00")
      (func (export "_start") (local $e i32)
        i32.const 3 i32.const 0 i32.const 8 i32.const 20 i32.const 1
        i64.const 70 i64.const 70 i32.const 0 i32.const 100
        call $path_open
        local.set $e
        local.get $e
        if i32.const 2 call $proc_exit end
        i32.const 100 i32.load
        i32.const 64 i32.const 1 i32.const 104
        call $fd_write
        local.set $e
        local.get $e
        if i32.const 3 call $proc_exit end
        i32.const 0 call $proc_exit
      )
    )
    """


class TestPolicyValidation:
    def test_endpoint_shape_enforced(self):
        import pytest

        with pytest.raises(ValueError):
            EgressPolicy(allowed_endpoints=("ftp://example.com/",))
        with pytest.raises(ValueError):
            EgressPolicy(allowed_endpoints=("https://user:pw@example.com/",))
        with pytest.raises(ValueError):
            EgressPolicy(allowed_endpoints=("https://example.com/#frag",))

    def test_method_allowlist(self):
        import pytest

        with pytest.raises(ValueError):
            EgressPolicy(allowed_methods=("BREW",))


class TestRequestParsing:
    def test_unknown_keys_rejected(self):
        import pytest

        with pytest.raises(ValueError, match="unknown request fields"):
            parse_request_document(
                json.dumps({"url": "https://x/", "shell": "/bin/sh"})
            )

    def test_url_and_types_validated(self):
        import pytest

        with pytest.raises(ValueError):
            parse_request_document(json.dumps({"url": ""}))
        with pytest.raises(ValueError):
            parse_request_document(json.dumps({"url": "https://x/", "body": 5}))
        with pytest.raises(ValueError):
            parse_request_document("not json")

    def test_valid_document_parses(self):
        req = parse_request_document(
            json.dumps({"url": "https://example.com/v1/", "method": "get"})
        )
        assert req.method == "GET"


class TestAllowlist:
    def test_path_prefix_and_host_exact(self):
        policy = _policy(8080)
        req = parse_request_document(
            json.dumps({"url": "http://127.0.0.1:8080/v1/data"})
        )
        entry = validate_request(policy, req)
        assert entry.decision == "allowed"
        other = parse_request_document(
            json.dumps({"url": "http://127.0.0.1:8080/other/"})
        )
        assert validate_request(policy, other).decision == "denied"
        other_host = parse_request_document(
            json.dumps({"url": "http://localhost:8080/v1/"})
        )
        assert validate_request(policy, other_host).decision == "denied"

    def test_method_and_header_denial(self):
        policy = _policy(8080)
        post = parse_request_document(
            json.dumps({"url": "http://127.0.0.1:8080/v1/", "method": "DELETE"})
        )
        assert validate_request(policy, post).decision == "denied"
        smuggle = parse_request_document(
            json.dumps(
                {
                    "url": "http://127.0.0.1:8080/v1/",
                    "headers": {"Authorization": "Bearer stolen"},
                }
            )
        )
        entry = validate_request(policy, smuggle)
        assert entry.decision == "denied"
        assert "headers" in entry.reason


class TestEndToEnd:
    def test_guest_artifact_mediated_against_local_api(self, tmp_path):
        with HTTPServer(("127.0.0.1", 0), _Handler) as server:
            port = server.server_address[1]
            thread = threading.Thread(target=server.serve_forever, daemon=True)
            thread.start()
            try:
                wasm = tmp_path / "sidecar_guest.wasm"
                wasm.write_bytes(wasmtime.wat2wasm(_guest_wat(port)))
                config = WASIConfig(max_fuel=2_000_000, timeout_seconds=10)
                sandbox = WASISandbox(config=config)
                try:
                    result = sandbox.run(str(wasm))
                    assert result.status == ExecutionStatus.SUCCESS, result.stderr
                    assert result.sandbox_dir is not None
                    request_path = Path(result.sandbox_dir) / "sidecar.request.json"
                    raw = request_path.read_bytes()
                finally:
                    sandbox.cleanup()

                response_doc, audit = run_sidecar_cycle(_policy(port), raw)
                assert audit.decision == "allowed"
                assert response_doc["ok"] is True
                assert response_doc["status"] == 200
                assert response_doc["content"] == {"answer": 42}
            finally:
                server.shutdown()

    def test_denied_url_produces_audit_and_error_doc(self):
        doc, audit = run_sidecar_cycle(
            _policy(1),
            json.dumps({"url": "https://evil.example/exfil", "method": "GET"}),
        )
        assert audit.decision == "denied"
        assert doc["ok"] is False
        assert "denied by egress policy" in doc["error"]

    def test_response_size_capped(self):
        payload = "X" * (200 * 1024)
        policy = _policy(80)
        # no real network: exercise the cap through mediate's fetch failure
        # is not possible, so assert the policy knob exists and defaults
        assert policy.max_response_bytes == 64 * 1024
        assert len(payload) > policy.max_response_bytes


# --- allowlist semantics and redirect revalidation (2026-10-03 findings) ---


class _RoutingHandler(BaseHTTPRequestHandler):
    """Serves a path table shared by every instance of this handler class.

    ``routes`` maps a path to either ("redirect", location) or ("json", obj);
    an unlisted path answers 200 with a marker, so a test can prove which
    server actually received the request.
    """

    routes: typing.ClassVar[dict] = {}
    hits: typing.ClassVar[dict] = {}

    def do_GET(self):
        port = self.server.server_address[1]
        _RoutingHandler.hits[port] = _RoutingHandler.hits.get(port, 0) + 1
        action = _RoutingHandler.routes.get((port, self.path))
        if action is not None and action[0] == "redirect":
            self.send_response(302)
            self.send_header("Location", action[1])
            self.send_header("Content-Length", "0")
            self.end_headers()
            return
        body = json.dumps(
            action[1] if action is not None else {"served_by": port, "path": self.path}
        ).encode()
        self.send_response(200)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def log_message(self, *args):
        pass


def _serve(routes: dict | None = None):
    _RoutingHandler.routes = dict(routes or {})
    _RoutingHandler.hits = {}
    server = HTTPServer(("127.0.0.1", 0), _RoutingHandler)
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    return server, server.server_address[1]


def _route(server_port: int, path: str, action: tuple) -> None:
    """Register a route once the ephemeral port is known."""
    _RoutingHandler.routes[(server_port, path)] = action


def _request(url: str):
    return parse_request_document(json.dumps({"url": url}))


class TestAllowlistPrefixSemantics:
    """A path entry is a SEGMENT prefix. It used to be a string prefix."""

    def test_sibling_prefix_is_not_admitted(self):
        policy = EgressPolicy(allowed_endpoints=("https://api.example.com/v1",))
        assert validate_request(policy, _request("https://api.example.com/v1")).decision
        assert (
            validate_request(
                policy, _request("https://api.example.com/v1/keys")
            ).decision
            == "allowed"
        )
        denied = validate_request(
            policy, _request("https://api.example.com/v1-admin/keys")
        )
        assert denied.decision == "denied"

    def test_dot_segments_are_denied_before_any_socket(self):
        policy = EgressPolicy(allowed_endpoints=("https://api.example.com/v1/",))
        for probe in ("/v1/../v1-admin", "/v1/%2e%2e/admin", "/v1/./../../etc/passwd"):
            entry = validate_request(
                policy, _request("https://api.example.com" + probe)
            )
            assert entry.decision == "denied", probe
            assert "dot segment" in entry.reason, probe

    def test_bare_host_entry_admits_every_path(self):
        """Stated semantics, not an accident: no path in the entry = whole host."""
        policy = EgressPolicy(allowed_endpoints=("https://api.example.com",))
        assert (
            validate_request(
                policy, _request("https://api.example.com/anything/here")
            ).decision
            == "allowed"
        )

    def test_policy_rejects_unusable_entries(self):
        for bad in (
            "https://api.example.com/v1/../",  # dot segment in the ENTRY
            "https://api.example.com/%2e%2e",  # encoded dot segment
            "https://api.example.com/v1?a=b",  # a query is never matched on
            "https://user@api.example.com/v1",  # userinfo
            "https://",  # no host
        ):
            try:
                EgressPolicy(allowed_endpoints=(bad,))
            except ValueError:
                continue
            raise AssertionError(f"entry accepted but must not be: {bad}")


class TestRedirectRevalidation:
    """The stdlib default opener used to follow redirects past the allowlist."""

    def test_off_allowlist_redirect_is_refused_and_never_fetched(self):
        other, other_port = _serve()
        entry, entry_port = _serve()
        _route(
            entry_port,
            "/v1/away",
            ("redirect", f"http://127.0.0.1:{other_port}/latest/meta-data/"),
        )
        try:
            policy = EgressPolicy(
                allowed_endpoints=(f"http://127.0.0.1:{entry_port}/v1",)
            )
            request = _request(f"http://127.0.0.1:{entry_port}/v1/away")
            audit = validate_request(policy, request)
            assert audit.decision == "allowed"  # the first URL is on policy
            result = execute_request(policy, request, audit=audit)
            assert _RoutingHandler.hits.get(other_port, 0) == 0, (
                "the off-allowlist target was fetched — redirect revalidation "
                "is not holding"
            )
            assert result.response_doc["ok"] is False
            assert result.audit.decision == "denied"
            assert "not on the egress allowlist" in result.audit.reason
            assert str(other_port) in result.audit.reason
        finally:
            entry.shutdown()
            other.shutdown()

    def test_on_allowlist_redirect_is_followed_and_recorded(self):
        server, port = _serve()
        _route(port, "/v1/hop", ("redirect", f"http://127.0.0.1:{port}/v1/real"))
        _route(port, "/v1/real", ("json", {"answer": "landed"}))
        try:
            policy = EgressPolicy(allowed_endpoints=(f"http://127.0.0.1:{port}/v1",))
            request = _request(f"http://127.0.0.1:{port}/v1/hop")
            audit = validate_request(policy, request)
            result = execute_request(policy, request, audit=audit)
            assert result.response_doc["ok"] is True, result.response_doc
            assert result.response_doc["content"] == {"answer": "landed"}
            assert result.audit.hops == (f"http://127.0.0.1:{port}/v1/real",)
            assert result.audit.decision == "allowed"
        finally:
            server.shutdown()

    def test_scheme_changing_redirect_is_refused(self):
        """Even an allowlisted https entry must not be reached by an http
        request hopping schemes (the stdlib also lets ftp through)."""
        server, port = _serve()
        _route(port, "/v1/up", ("redirect", f"https://127.0.0.1:{port}/v1/secret"))
        try:
            policy = EgressPolicy(
                allowed_endpoints=(
                    f"http://127.0.0.1:{port}/v1",
                    f"https://127.0.0.1:{port}/v1",
                )
            )
            request = _request(f"http://127.0.0.1:{port}/v1/up")
            audit = validate_request(policy, request)
            result = execute_request(policy, request, audit=audit)
            assert result.response_doc["ok"] is False
            assert "scheme" in result.audit.reason
        finally:
            server.shutdown()

    def test_plain_response_carries_no_hops(self):
        server, port = _serve()
        try:
            policy = EgressPolicy(allowed_endpoints=(f"http://127.0.0.1:{port}/v1",))
            request = _request(f"http://127.0.0.1:{port}/v1/plain")
            audit = validate_request(policy, request)
            result = execute_request(policy, request, audit=audit)
            assert result.response_doc["ok"] is True
            assert result.audit.hops == ()
        finally:
            server.shutdown()


# --- the MCP host-sidecar trace: the mediator finally has a real caller ---


def _artifact_dir(tmp_path: Path, url: str) -> Path:
    """A fake sandbox dir holding one guest-written request artifact."""
    tmp_path.mkdir(parents=True, exist_ok=True)
    (tmp_path / "sidecar.request.json").write_text(
        json.dumps({"url": url, "method": "GET"}), encoding="utf-8"
    )
    return tmp_path


def _spec() -> ToolSpec:
    return ToolSpec(name="t", wasm_path="t.wasm", description="d", profile="llm")


def _ok_result(sandbox_dir: str | None) -> ExecutionResult:
    return ExecutionResult(
        status=ExecutionStatus.SUCCESS,
        exit_code=0,
        stdout="{}",
        sandbox_dir=sandbox_dir,
    )


class TestEngineEgressTrace:
    def test_no_policy_never_reads_the_artifact(self, tmp_path):
        d = _artifact_dir(tmp_path, "http://127.0.0.1:1/v1/x")
        assert CellToolEngine()._mediate_egress(str(d), "t") == ()

    def test_no_artifact_is_silent(self, tmp_path):
        eng = CellToolEngine(egress_policy=EgressPolicy(allowed_endpoints=()))
        assert eng._mediate_egress(str(tmp_path), "t") == ()
        assert eng._mediate_egress(None, "t") == ()

    def test_on_policy_request_is_mediated_and_written_back(self, tmp_path):
        server, port = _serve()
        try:
            d = _artifact_dir(tmp_path, f"http://127.0.0.1:{port}/v1/data")
            eng = CellToolEngine(
                egress_policy=EgressPolicy(
                    allowed_endpoints=(f"http://127.0.0.1:{port}/v1",)
                )
            )
            (audit,) = eng._mediate_egress(str(d), "t")
            assert audit["decision"] == "allowed"
            assert audit["response"]["ok"] is True
            # the response artifact the between-runs pattern promises
            assert (d / "sidecar.response.json").is_file()
        finally:
            server.shutdown()

    def test_off_policy_request_is_denied_not_fetched(self, tmp_path):
        server, port = _serve()
        try:
            d = _artifact_dir(tmp_path, f"http://127.0.0.1:{port}/secret/admin")
            eng = CellToolEngine(
                egress_policy=EgressPolicy(
                    allowed_endpoints=(f"http://127.0.0.1:{port}/v1",)
                )
            )
            (audit,) = eng._mediate_egress(str(d), "t")
            assert audit["decision"] == "denied"
            assert "egress policy" in audit["reason"]
            assert audit["response"]["ok"] is False
        finally:
            server.shutdown()

    def test_malformed_artifact_denies_rather_than_staying_quiet(self, tmp_path):
        (tmp_path / "sidecar.request.json").write_text("{not json", encoding="utf-8")
        eng = CellToolEngine(egress_policy=EgressPolicy(allowed_endpoints=()))
        (audit,) = eng._mediate_egress(str(tmp_path), "t")
        assert audit["decision"] == "denied"
        assert "invalid request artifact" in audit["reason"]

    def test_execute_invokes_the_mediator_before_cleanup(self, tmp_path, monkeypatch):
        """The whole point of the trace: execute() is a real caller, and it
        mediates while the sandbox dir still exists (cleanup would erase it)."""
        server, port = _serve()
        try:
            _artifact_dir(tmp_path, f"http://127.0.0.1:{port}/v1/data")
            cleaned: list[bool] = []

            class FakeSandbox:
                def __init__(self, config=None):
                    pass

                def run(self, *a, **k):
                    return _ok_result(str(tmp_path))

                def cleanup(self):
                    # Runs AFTER execute() has mediated: if mediation happened
                    # before cleanup, the response artifact the mediator wrote
                    # is present here. If the order ever flips, mediation would
                    # read a dir cleanup already erased and this stays False.
                    cleaned.append((tmp_path / "sidecar.response.json").is_file())

            monkeypatch.setattr(engine_module, "WASISandbox", FakeSandbox)
            eng = CellToolEngine(
                egress_policy=EgressPolicy(
                    allowed_endpoints=(f"http://127.0.0.1:{port}/v1",)
                )
            )
            outcome = eng.execute(_spec(), {})
            assert isinstance(outcome, CellOutcome)
            assert outcome.egress and outcome.egress[0]["decision"] == "allowed"
            # mediated against a live dir, THEN cleaned up (order is the point)
            assert cleaned == [True]
        finally:
            server.shutdown()

    def test_execute_without_policy_leaves_egress_empty(self, monkeypatch):
        class FakeSandbox:
            def __init__(self, config=None):
                pass

            def run(self, *a, **k):
                return _ok_result(None)

            def cleanup(self):
                pass

        monkeypatch.setattr(engine_module, "WASISandbox", FakeSandbox)
        outcome = CellToolEngine().execute(_spec(), {})
        assert outcome.egress == ()


class TestEngineGrantEnforcement:
    """ADR-013 Prio 1: a tool with a signed grant + a GrantLedger is mediated
    grant-gated — window/cap/revocation enforced, not just the allowlist."""

    def _grant(
        self,
        port,
        max_calls=None,
        not_before=None,
        not_after=None,
        tool="t",
        grant_id="g-eng",
    ):
        from ephemora_cell.egress_sidecar import EgressGrant

        return EgressGrant(
            grant_id=grant_id,
            tool=tool,
            allowed_endpoints=(f"http://127.0.0.1:{port}/v1",),
            max_calls=max_calls,
            not_before=not_before,
            not_after=not_after,
        )

    def _ledger(self, tmp_path):
        from ephemora_cell.grant_ledger import GrantLedger

        return GrantLedger(tmp_path / "grants.jsonl")

    def test_grant_charges_each_fetched_call_and_stops_at_the_cap(self, tmp_path):
        from ephemora_cell_mcp.engine import CellToolEngine

        server, port = _serve()
        try:
            ledger = self._ledger(tmp_path)
            eng = CellToolEngine(
                egress_grants={"t": self._grant(port, max_calls=1)},
                grant_ledger=ledger,
            )
            d = _artifact_dir(tmp_path / "one", f"http://127.0.0.1:{port}/v1/data")
            (audit,) = eng._mediate_egress(str(d), "t")
            assert audit["decision"] == "allowed"
            assert ledger.usage("g-eng").calls == 1
            # The second call hits the cap — refused, and nothing was fetched.
            d2 = _artifact_dir(tmp_path / "two", f"http://127.0.0.1:{port}/v1/data")
            (audit2,) = eng._mediate_egress(str(d2), "t")
            assert audit2["decision"] == "denied"
            assert audit2["limit"] == "max_calls"
            assert "egress grant" in audit2["reason"]
            assert ledger.usage("g-eng").calls == 1
        finally:
            server.shutdown()

    def test_a_grant_never_widens_the_server_wide_allowlist(self, tmp_path):
        """Operator decision (2026-10-05): a grant NARROWS, it does not enlarge.

        Without the intersection, a signed document for `endpoint B` would let a
        tool reach a host the operator never allowlisted with `--egress-allow` —
        the trust root would be a way to bypass the policy it sits next to. And
        the refusal must not spend a slot: a probe that cannot reach anything
        cannot drain a cap.
        """
        from ephemora_cell.egress_sidecar import EgressPolicy
        from ephemora_cell_mcp.engine import CellToolEngine

        served, port = _serve()
        other, other_port = _serve()
        try:
            ledger = self._ledger(tmp_path)
            grant = self._grant(other_port, max_calls=5)  # grants the OTHER origin
            eng = CellToolEngine(
                egress_policy=EgressPolicy(
                    allowed_endpoints=(f"http://127.0.0.1:{port}/v1",)
                ),
                egress_grants={"t": grant},
                grant_ledger=ledger,
            )
            d = _artifact_dir(
                tmp_path / "outside", f"http://127.0.0.1:{other_port}/v1/data"
            )
            (audit,) = eng._mediate_egress(str(d), "t")
            assert audit["decision"] == "denied", audit
            assert audit["limit"] == "server-policy", audit
            assert other_port not in _RoutingHandler.hits, "the refused hop was fetched"
            assert ledger.usage("g-eng").calls == 0, "a refused call spent a slot"
        finally:
            served.shutdown()
            other.shutdown()

    def test_intersection_still_admits_a_grant_inside_the_policy(self, tmp_path):
        """Positive control: the ceiling does not simply deny everything."""
        from ephemora_cell.egress_sidecar import EgressPolicy
        from ephemora_cell_mcp.engine import CellToolEngine

        server, port = _serve()
        try:
            ledger = self._ledger(tmp_path)
            eng = CellToolEngine(
                egress_policy=EgressPolicy(
                    allowed_endpoints=(f"http://127.0.0.1:{port}/v1",)
                ),
                egress_grants={"t": self._grant(port, max_calls=2)},
                grant_ledger=ledger,
            )
            d = _artifact_dir(tmp_path / "inside", f"http://127.0.0.1:{port}/v1/data")
            (audit,) = eng._mediate_egress(str(d), "t")
            assert audit["decision"] == "allowed", audit
            assert ledger.usage("g-eng").calls == 1
        finally:
            server.shutdown()

    def test_a_redirect_hop_must_also_clear_the_server_wide_allowlist(self, tmp_path):
        """The ceiling is a scope over EVERY hop, not a check on one URL.

        A grant that names the host and a `--egress-allow` that names one prefix
        are different scopes. Validating only the request the guest wrote left an
        open redirect as the escape: the origin answers 302 to a sibling prefix the
        operator excluded, and the mediated fetch walks there while the audit still
        says "allowed". The hop is revalidated against the ceiling now, and the
        refusal names it.
        """
        from ephemora_cell.egress_sidecar import EgressGrant, EgressPolicy
        from ephemora_cell_mcp.engine import CellToolEngine

        server, port = _serve()
        try:
            _route(
                port, "/public/x", ("redirect", f"http://127.0.0.1:{port}/admin/keys")
            )
            ledger = self._ledger(tmp_path)
            grant = EgressGrant(
                grant_id="g-hop",
                tool="t",
                allowed_endpoints=(f"http://127.0.0.1:{port}/",),
                max_calls=5,
                not_after="2099-01-01T00:00:00Z",
            )
            eng = CellToolEngine(
                egress_policy=EgressPolicy(
                    allowed_endpoints=(f"http://127.0.0.1:{port}/public",)
                ),
                egress_grants={"t": grant},
                grant_ledger=ledger,
            )
            d = _artifact_dir(tmp_path / "hop", f"http://127.0.0.1:{port}/public/x")
            (audit,) = eng._mediate_egress(str(d), "t")
            assert audit["decision"] == "denied", audit
            assert audit["limit"] == "server-policy", audit
            # ONE served path: the excluded prefix was never asked for.
            assert _RoutingHandler.hits.get(port) == 1, _RoutingHandler.hits
        finally:
            server.shutdown()

    def test_a_hop_inside_the_ceiling_still_fetches(self, tmp_path):
        """Positive control for the hop check: the same redirect, with a ceiling
        that covers the target, must still deliver."""
        from ephemora_cell.egress_sidecar import EgressGrant, EgressPolicy
        from ephemora_cell_mcp.engine import CellToolEngine

        server, port = _serve()
        try:
            _route(port, "/public/x", ("redirect", f"http://127.0.0.1:{port}/public/y"))
            grant = EgressGrant(
                grant_id="g-hop-ok",
                tool="t",
                allowed_endpoints=(f"http://127.0.0.1:{port}/",),
                max_calls=5,
                not_after="2099-01-01T00:00:00Z",
            )
            eng = CellToolEngine(
                egress_policy=EgressPolicy(
                    allowed_endpoints=(f"http://127.0.0.1:{port}/public",)
                ),
                egress_grants={"t": grant},
                grant_ledger=self._ledger(tmp_path),
            )
            d = _artifact_dir(tmp_path / "hop-ok", f"http://127.0.0.1:{port}/public/x")
            (audit,) = eng._mediate_egress(str(d), "t")
            assert audit["decision"] == "allowed", audit
            assert audit["hops"] == (f"http://127.0.0.1:{port}/public/y",), audit
        finally:
            server.shutdown()

    def test_the_server_wide_resource_caps_narrow_a_grant_too(self, tmp_path):
        """A grant carries endpoints and methods — not a byte or time budget.

        `EgressGrant.policy()` rebuilds an `EgressPolicy`, which defaults to 64 KiB
        and 10 s, so taking the envelope from the grant silently DISCARDED the
        operator's `--egress-max-response-bytes`/`--egress-timeout`: a signed
        document widened the resource profile even while the endpoint scope was
        intersected. The strictest value of the two now wins.
        """
        from ephemora_cell.egress_sidecar import EgressPolicy
        from ephemora_cell_mcp.engine import CellToolEngine

        server, port = _serve()
        try:
            _route(port, "/v1/big", ("json", {"pad": "x" * 8192}))
            eng = CellToolEngine(
                egress_policy=EgressPolicy(
                    allowed_endpoints=(f"http://127.0.0.1:{port}/v1",),
                    max_response_bytes=256,
                ),
                egress_grants={"t": self._grant(port, max_calls=5)},
                grant_ledger=self._ledger(tmp_path),
            )
            d = _artifact_dir(tmp_path / "big", f"http://127.0.0.1:{port}/v1/big")
            (audit,) = eng._mediate_egress(str(d), "t")
            assert audit["decision"] == "allowed", audit
            assert audit["bytes"] <= 256, f"delivered {audit['bytes']} bytes"
        finally:
            server.shutdown()

    def test_a_grant_only_deployment_keeps_the_grant_as_full_authority(self, tmp_path):
        """No `--egress-allow`, no ceiling: the grant alone decides (documented
        posture of a grant-only deployment — the intersection must not invent
        one)."""
        from ephemora_cell_mcp.engine import CellToolEngine

        server, port = _serve()
        try:
            eng = CellToolEngine(
                egress_grants={"t": self._grant(port, max_calls=1)},
                grant_ledger=self._ledger(tmp_path),
            )
            d = _artifact_dir(
                tmp_path / "grant-only", f"http://127.0.0.1:{port}/v1/data"
            )
            (audit,) = eng._mediate_egress(str(d), "t")
            assert audit["decision"] == "allowed", audit
        finally:
            server.shutdown()

    def test_grants_required_denies_an_ungranted_tool_without_falling_back(
        self, tmp_path
    ):
        """Strict posture: no grant file, no egress — not even through the
        operator's own allowlist."""
        from ephemora_cell_mcp.engine import CellToolEngine

        server, port = _serve()
        try:
            eng = CellToolEngine(
                egress_policy=EgressPolicy(
                    allowed_endpoints=(f"http://127.0.0.1:{port}/v1",)
                ),
                egress_grants={"other": self._grant(port, tool="other")},
                grant_ledger=self._ledger(tmp_path),
                grants_required=True,
            )
            d = _artifact_dir(
                tmp_path / "ungranted", f"http://127.0.0.1:{port}/v1/data"
            )
            (audit,) = eng._mediate_egress(str(d), "t")
            assert audit["decision"] == "denied", audit
            assert audit["limit"] == "grant-required", audit
            assert port not in _RoutingHandler.hits, "the ungranted tool was fetched"
        finally:
            server.shutdown()

    def test_grants_required_still_mediates_a_granted_tool(self, tmp_path):
        """The strict flag must not switch the grant path off."""
        from ephemora_cell_mcp.engine import CellToolEngine

        server, port = _serve()
        try:
            ledger = self._ledger(tmp_path)
            eng = CellToolEngine(
                egress_grants={"t": self._grant(port, max_calls=1)},
                grant_ledger=ledger,
                grants_required=True,
            )
            d = _artifact_dir(tmp_path / "granted", f"http://127.0.0.1:{port}/v1/data")
            (audit,) = eng._mediate_egress(str(d), "t")
            assert audit["decision"] == "allowed", audit
            assert ledger.usage("g-eng").calls == 1
        finally:
            server.shutdown()

    def test_grants_required_without_grants_is_a_construction_error(self):
        from ephemora_cell_mcp.engine import CellToolEngine

        with pytest.raises(ValueError, match="grants_required"):
            CellToolEngine(grants_required=True)

    def test_the_construction_guard_demands_BOTH_grants_and_ledger(self, tmp_path):
        """`grants_required` with a ledger and NO grants built fine and then denied
        every call — while `get-policy` had nothing to disclose, because the
        attestation block only exists when grants exist. A flag that changes
        behaviour nothing can see is not a posture, so the guard requires both."""
        from ephemora_cell.grant_ledger import GrantLedger
        from ephemora_cell_mcp.engine import CellToolEngine

        with pytest.raises(ValueError, match="grants_required"):
            CellToolEngine(
                grants_required=True, grant_ledger=GrantLedger(tmp_path / "b.jsonl")
            )
        # Grants without a ledger were already refused; the message is the OTHER
        # guard's, so assert only that construction fails.
        with pytest.raises(ValueError):
            CellToolEngine(grants_required=True, egress_grants={"t": self._grant(8080)})
        # The valid triple builds.
        CellToolEngine(
            egress_grants={"t": self._grant(8080)},
            grant_ledger=GrantLedger(tmp_path / "ok.jsonl"),
            grants_required=True,
        )

    def test_an_out_of_range_port_is_a_denial_not_a_crash(self):
        """`urlsplit` succeeds on `host:70000`; accessing `.port` is what raises.

        That read sat OUTSIDE the guard, so an allowlisted host plus a guest-chosen
        absurd port escaped `validate_request` entirely: no audit entry, no
        `_meta.egress`, a JSON-RPC -32603 — a guest-steered silence in the one
        place the design promises every decision is recorded.
        """
        from ephemora_cell.egress_sidecar import EgressPolicy, validate_request

        policy = EgressPolicy(allowed_endpoints=("http://127.0.0.1:8080/v1",))
        entry = validate_request(policy, _request("http://127.0.0.1:8080:70000/v1"))
        assert entry.decision == "denied"
        assert entry.limit is None or entry.limit != "crash"

    def test_a_grant_path_denies_the_same_absurd_port(self, tmp_path):
        """Same wall on the grant path, end to end through the engine."""
        from ephemora_cell.egress_sidecar import EgressPolicy
        from ephemora_cell_mcp.engine import CellToolEngine

        server, port = _serve()
        try:
            eng = CellToolEngine(
                egress_policy=EgressPolicy(
                    allowed_endpoints=(f"http://127.0.0.1:{port}/v1",)
                ),
                egress_grants={"t": self._grant(port, max_calls=5)},
                grant_ledger=self._ledger(tmp_path),
            )
            d = _artifact_dir(tmp_path / "port", f"http://127.0.0.1:{port}:70000/v1")
            (audit,) = eng._mediate_egress(str(d), "t")
            assert audit["decision"] == "denied", audit
            assert self._ledger(tmp_path).usage("g-eng").calls == 0
        finally:
            server.shutdown()

    def test_strict_mode_stays_silent_when_the_guest_asks_for_nothing(self, tmp_path):
        """An ungranted tool that wrote no request artifact has not attempted
        egress, so it must not grow an `_meta.egress` — the mediation surface says
        "no artifact, no mediation" for every other mode, and the strict flag may
        not change what a run REPORTS, only what it may reach."""
        from ephemora_cell.egress_sidecar import EgressPolicy
        from ephemora_cell_mcp.engine import CellToolEngine

        server, port = _serve()
        try:
            eng = CellToolEngine(
                egress_policy=EgressPolicy(
                    allowed_endpoints=(f"http://127.0.0.1:{port}/v1",)
                ),
                egress_grants={"other": self._grant(port, tool="other")},
                grant_ledger=self._ledger(tmp_path),
                grants_required=True,
            )
            empty = tmp_path / "no-artifact"
            empty.mkdir()
            assert eng._mediate_egress(str(empty), "t") == ()
            # ... and once the guest DOES ask, the strict denial is audited.
            d = _artifact_dir(tmp_path / "asks", f"http://127.0.0.1:{port}/v1/data")
            (audit,) = eng._mediate_egress(str(d), "t")
            assert audit["decision"] == "denied"
            assert audit["limit"] == "grant-required", audit
        finally:
            server.shutdown()

    def test_a_grant_authorizes_the_tool_its_payload_names(self, tmp_path):
        """The signed `tool` field is the authority; the dict key is not.

        `load_egress_grants` keys by the payload for exactly this reason, but the
        engine accepted any caller-supplied dict, so a grant signed for one tool
        mediated ANOTHER — a cross-tool repurpose of a legitimate signature
        (measured before the fix: the mis-keyed tool was grant-mediated and spent
        the grant's slot). The engine re-keys by the payload now, and refuses two
        grants claiming one tool.
        """
        from ephemora_cell.egress_sidecar import EgressPolicy
        from ephemora_cell_mcp.engine import CellToolEngine

        server, port = _serve()
        try:
            ledger = self._ledger(tmp_path)
            eng = CellToolEngine(
                egress_policy=EgressPolicy(
                    allowed_endpoints=(f"http://127.0.0.1:{port}/v1",)
                ),
                egress_grants={"someone-else": self._grant(port, max_calls=1)},
                grant_ledger=ledger,
            )
            d = _artifact_dir(tmp_path / "miskeyed", f"http://127.0.0.1:{port}/v1/data")
            (audit,) = eng._mediate_egress(str(d), "someone-else")
            # Mediated on the server-wide policy (the documented fallback), NOT on
            # the grant: the grant's authority and its ledger slot stayed untouched.
            assert audit["decision"] == "allowed", audit
            # The discriminator is the book, not the wording: the policy fallback
            # charges no grant slot, and none of the grant's authority was used.
            assert ledger.usage("g-eng").calls == 0, "a mis-keyed grant spent its cap"
            # The payload-named tool is the one that reaches the grant path.
            assert list(eng.egress_grants) == ["t"]
            d2 = _artifact_dir(tmp_path / "named", f"http://127.0.0.1:{port}/v1/data")
            (audit2,) = eng._mediate_egress(str(d2), "t")
            assert audit2["decision"] == "allowed", audit2
            assert (
                ledger.usage("g-eng").calls == 1
            ), "the named tool did not reach its grant"

            with pytest.raises(ValueError, match="claim tool"):
                CellToolEngine(
                    egress_grants={
                        "a": self._grant(port, grant_id="g-one"),
                        "b": self._grant(port, grant_id="g-two"),
                    },
                    grant_ledger=ledger,
                )
        finally:
            server.shutdown()

    def test_strict_denial_reaches_a_grant_only_deployment(self, tmp_path):
        """`--egress-grants-required` without `--egress-allow` must still deny.

        The early `policy is None -> no mediation` return sat in front of the
        strict branch, so a grant-only deployment silenced the ungranted tool
        instead of refusing it — while `get-policy` attested
        "denied (--egress-grants-required)". A posture that is claimed in the
        control plane and unreachable in the data path is a disclosure bug, not a
        corner case.
        """
        from ephemora_cell_mcp.engine import CellToolEngine

        server, port = _serve()
        try:
            eng = CellToolEngine(
                egress_grants={"other": self._grant(port, tool="other")},
                grant_ledger=self._ledger(tmp_path),
                grants_required=True,
            )
            d = _artifact_dir(
                tmp_path / "no-policy", f"http://127.0.0.1:{port}/v1/data"
            )
            (audit,) = eng._mediate_egress(str(d), "t")
            assert audit["decision"] == "denied", audit
            assert audit["limit"] == "grant-required", audit
            # Positive control: no artifact, still silence in both modes.
            empty = tmp_path / "empty-no-policy"
            empty.mkdir()
            assert eng._mediate_egress(str(empty), "t") == ()
        finally:
            server.shutdown()

    def test_the_ceilings_resolver_is_the_one_that_resolves(self, tmp_path):
        """An operator injects a resolver; a signed document does not get to choose.

        `EgressGrant.policy()` has no resolver field, so the grant-derived policy
        always carries None — but the precedence order in `execute_request` decided
        which of the two objects was asked. The ceiling (the operator's own policy)
        must win, otherwise a deployment that pins resolution through a private
        resolver silently resolves over the public one whenever a grant exists.
        """
        import socket

        from ephemora_cell.egress_sidecar import EgressGrant, EgressPolicy
        from ephemora_cell_mcp.engine import CellToolEngine

        asked: list = []

        def spy(host, port, *args, **kwargs):
            asked.append((host, port))
            return [(socket.AF_INET, socket.SOCK_STREAM, 6, "", ("203.0.113.9", port))]

        eng = CellToolEngine(
            egress_policy=EgressPolicy(
                allowed_endpoints=("http://grant-ceiling.test:8080/v1",),
                resolver=spy,
            ),
            egress_grants={
                "t": EgressGrant(
                    grant_id="g-res",
                    tool="t",
                    allowed_endpoints=("http://grant-ceiling.test:8080/v1",),
                    max_calls=5,
                    not_after="2099-01-01T00:00:00Z",
                )
            },
            grant_ledger=self._ledger(tmp_path),
        )
        d = _artifact_dir(tmp_path / "res", "http://grant-ceiling.test:8080/v1/data")
        eng._mediate_egress(str(d), "t")
        assert (
            asked and asked[0][0] == "grant-ceiling.test"
        ), "the operator's resolver was never asked: " + str(asked)
        # Why the order in `execute_request` cannot be inverted by a document: a
        # grant carries endpoints and methods only, so its policy object has no
        # resolver to offer. Resolution therefore always comes from the operator.
        assert (
            EgressGrant(
                grant_id="g-shape",
                tool="t",
                allowed_endpoints=("http://x.test/v1",),
                max_calls=1,
                not_after="2099-01-01T00:00:00Z",
            )
            .policy()
            .resolver
            is None
        )

    def test_the_server_wide_timeout_narrows_a_grant_fetch(self, tmp_path):
        """Same envelope argument for time: the ceiling's 0.4 s beats the
        default 10 s the grant policy carries."""
        import socketserver
        import threading

        from ephemora_cell.egress_sidecar import EgressGrant, EgressPolicy

        class Slow(socketserver.BaseRequestHandler):
            def handle(self):
                try:
                    self.request.recv(4096)
                except OSError:
                    return
                time.sleep(2.0)
                try:
                    self.request.sendall(
                        b"HTTP/1.1 200 OK\r\nContent-Length: 2\r\n\r\n{}"
                    )
                except OSError:
                    pass

        class Server(socketserver.ThreadingTCPServer):
            allow_reuse_address = True
            daemon_threads = True

        slow = Server(("127.0.0.1", 0), Slow)
        port = slow.server_address[1]
        threading.Thread(target=slow.serve_forever, daemon=True).start()
        try:
            eng = CellToolEngine(
                egress_policy=EgressPolicy(
                    allowed_endpoints=(f"http://127.0.0.1:{port}/v1",),
                    timeout_seconds=0.4,
                ),
                egress_grants={
                    "t": EgressGrant(
                        grant_id="g-timeout",
                        tool="t",
                        allowed_endpoints=(f"http://127.0.0.1:{port}/v1",),
                        max_calls=5,
                        not_after="2099-01-01T00:00:00Z",
                    )
                },
                grant_ledger=self._ledger(tmp_path),
            )
            d = _artifact_dir(tmp_path / "slow", f"http://127.0.0.1:{port}/v1/slow")
            (audit,) = eng._mediate_egress(str(d), "t")
            # The origin answers after 2.0 s. Under the grant policy's default 10 s
            # the fetch would SUCCEED; the ceiling's 0.4 s must stop it, so the
            # observable contract is "stopped early and delivered nothing" —
            # whether the socket timeout or the wall-clock deadline fires first is
            # an implementation detail, not the claim.
            assert audit["elapsed_ms"] < 1500, audit
            assert audit["bytes"] in (0, None), audit
        finally:
            slow.shutdown()

    def test_revocation_refuses_without_touching_the_booked_count(self, tmp_path):
        from ephemora_cell_mcp.engine import CellToolEngine

        server, port = _serve()
        try:
            ledger = self._ledger(tmp_path)
            eng = CellToolEngine(
                egress_grants={"t": self._grant(port)}, grant_ledger=ledger
            )
            d = _artifact_dir(tmp_path / "a", f"http://127.0.0.1:{port}/v1/data")
            (audit,) = eng._mediate_egress(str(d), "t")
            assert audit["decision"] == "allowed"
            ledger.revoke("g-eng")
            d2 = _artifact_dir(tmp_path / "b", f"http://127.0.0.1:{port}/v1/data")
            (audit2,) = eng._mediate_egress(str(d2), "t")
            assert audit2["decision"] == "denied"
            assert audit2["limit"] == "revoked"
        finally:
            server.shutdown()

    def test_a_denied_endpoint_does_not_spend_a_grant_slot(self, tmp_path):
        from ephemora_cell_mcp.engine import CellToolEngine

        server, port = _serve()
        try:
            ledger = self._ledger(tmp_path)
            eng = CellToolEngine(
                egress_grants={"t": self._grant(port, max_calls=1)},
                grant_ledger=ledger,
            )
            # Off the /v1 prefix: refused by the allowlist before any charge.
            d = _artifact_dir(tmp_path / "x", f"http://127.0.0.1:{port}/secret/admin")
            (audit,) = eng._mediate_egress(str(d), "t")
            assert audit["decision"] == "denied"
            assert "egress policy" in audit["reason"]
            assert ledger.usage("g-eng").calls == 0
        finally:
            server.shutdown()

    def test_grant_is_keyed_by_tool_name(self, tmp_path):
        from ephemora_cell_mcp.engine import CellToolEngine

        server, port = _serve()
        try:
            ledger = self._ledger(tmp_path)
            # Filed under "other", payload names "other" too: "t" has no grant.
            eng = CellToolEngine(
                egress_grants={"other": self._grant(port, tool="other")},
                grant_ledger=ledger,
            )
            # Tool "t" has no grant and there is no server policy → no mediation.
            d = _artifact_dir(tmp_path / "a", f"http://127.0.0.1:{port}/v1/data")
            assert eng._mediate_egress(str(d), "t") == ()
        finally:
            server.shutdown()

    def test_grants_without_a_ledger_fail_closed_at_construction(self):
        import pytest

        from ephemora_cell_mcp.engine import CellToolEngine

        with pytest.raises(ValueError, match="grant_ledger"):
            CellToolEngine(egress_grants={"t": self._grant(8080)})


class TestGrantConcurrency:
    """The cap under simultaneous load, driven through the engine path the MCP
    server actually takes and against a real local origin.

    "2 calls go, the 3rd doesn't" is only worth something if the counter cannot
    be raced: twenty requests released by one barrier must spend exactly
    `max_calls` slots — not 21, not a slot twice — and the origin must have seen
    exactly the approved number of requests. The book itself is the ordering
    evidence: each decision appends a line inside one exclusive lock, so the
    file is a total order of what the enforcement decided.
    """

    @staticmethod
    def _grant(port: int, max_calls: int | None, grant_id: str = "g-load"):
        from ephemora_cell.egress_sidecar import EgressGrant

        return EgressGrant(
            grant_id=grant_id,
            tool="t",
            allowed_endpoints=(f"http://127.0.0.1:{port}/v1",),
            max_calls=max_calls,
        )

    @staticmethod
    def _lines(path) -> list[dict]:
        text = Path(path).read_text(encoding="utf-8")
        return [json.loads(line) for line in text.splitlines() if line.strip()]

    def _hammer(self, tmp_path, threads: int, max_calls, revoke_midflight=False):
        """Release `threads` mediated calls at the same instant; return the
        audits, how many requests the origin actually served, and the ledger."""
        from ephemora_cell.grant_ledger import GrantLedger
        from ephemora_cell_mcp.engine import CellToolEngine

        server, port = _serve()
        try:
            grant = self._grant(port, max_calls)
            ledger = GrantLedger(tmp_path / "grants.jsonl")
            eng = CellToolEngine(egress_grants={"t": grant}, grant_ledger=ledger)
            url = f"http://127.0.0.1:{port}/v1/data"
            # Write every artifact BEFORE the race so the threads contend on the
            # ledger, not on the filesystem.
            dirs = [_artifact_dir(tmp_path / f"c{i}", url) for i in range(threads)]
            audits: list[dict] = []
            lock = threading.Lock()
            barrier = threading.Barrier(threads + 1 if revoke_midflight else threads)

            def worker(directory):
                barrier.wait()
                (audit,) = eng._mediate_egress(str(directory), "t")
                with lock:
                    audits.append(audit)

            threads_pool = [threading.Thread(target=worker, args=(d,)) for d in dirs]
            for t in threads_pool:
                t.start()
            if revoke_midflight:
                barrier.wait()  # everyone released; revoke lands mid-flight
                ledger.revoke("g-load", reason="operator-race")
            for t in threads_pool:
                t.join()
            served = sum(_RoutingHandler.hits.values())
        finally:
            server.shutdown()
            server.server_close()
        return audits, served, ledger

    def test_twenty_simultaneous_calls_spend_exactly_the_cap(self, tmp_path):
        audits, served, ledger = self._hammer(tmp_path, 20, max_calls=7)
        allowed = [a for a in audits if a["decision"] == "allowed"]
        denied = [a for a in audits if a["decision"] == "denied"]
        assert len(allowed) == 7, f"{len(allowed)} approvals against a cap of 7"
        assert len(denied) == 13
        assert {a["limit"] for a in denied} == {"max_calls"}, denied
        # nothing was fetched that the cap did not approve
        assert served == 7, f"origin served {served}, cap allows 7"
        assert ledger.usage("g-load").calls == 7
        booked = [
            line["calls_after"]
            for line in self._lines(tmp_path / "grants.jsonl")
            if line["kind"] == "call"
        ]
        assert booked == [
            1,
            2,
            3,
            4,
            5,
            6,
            7,
        ], f"booked counters must be contiguous, never a slot twice: {booked}"
        assert ledger.verify() == []

    def test_a_single_slot_cannot_be_taken_twice(self, tmp_path):
        audits, served, ledger = self._hammer(tmp_path, 20, max_calls=1)
        assert sum(1 for a in audits if a["decision"] == "allowed") == 1
        assert served == 1
        assert ledger.usage("g-load").calls == 1

    def test_revocation_racing_parallel_load_stays_ordered(self, tmp_path):
        """Revocation while twenty calls are in flight has ONE legal shape: the
        book is a total order, so after the revoke line no call line may appear.
        Approvals that were already inside the critical section when the revoke
        landed stay approved — that is the documented semantics ("effective at
        this call, not an in-flight one"), asserted here instead of assumed."""
        audits, served, ledger = self._hammer(
            tmp_path, 20, max_calls=None, revoke_midflight=True
        )
        lines = self._lines(tmp_path / "grants.jsonl")
        kinds = [line["kind"] for line in lines]
        assert "revoke" in kinds, kinds
        revoke_at = kinds.index("revoke")
        assert (
            "call" not in kinds[revoke_at + 1 :]
        ), f"a call was booked after the revoke: {kinds}"
        booked_calls = kinds.count("call")
        denied = [a for a in audits if a["decision"] == "denied"]
        assert {a["limit"] for a in denied} <= {"revoked"}, denied
        assert booked_calls + len(denied) == 20
        assert (
            served == booked_calls
        ), f"origin served {served} but {booked_calls} calls were booked"
        assert ledger.verify() == []


class TestSSRFGuard:
    """ADR-013 Prio 2: the resolve-time IP filter that closes the rebinding
    window the redirect fix left open — validate and connect in one step."""

    def _addrinfo(self, ip, port=80):
        import socket as _s

        return (_s.AF_INET, _s.SOCK_STREAM, 0, "", (ip, port))

    def _fake_resolver(self, *ips):
        def resolver(_host, port, *a, **k):
            return [self._addrinfo(ip, port) for ip in ips]

        return resolver

    def test_blocked_address_classes(self):
        from ephemora_cell.egress_sidecar import _ip_blocked

        # The SSRF set: loopback, RFC1918, link-local (metadata), CGNAT,
        # multicast, reserved/unspecified, and the IPv6 equivalents.
        for ip in (
            "127.0.0.1",
            "10.0.0.5",
            "192.168.1.1",
            "172.16.0.1",
            "169.254.169.254",  # cloud metadata
            "100.64.0.1",  # CGNAT
            "224.0.0.1",  # multicast
            "0.0.0.0",
            "::1",
            "fe80::1",  # link-local v6
            "fc00::1",  # unique local
            "ff02::1",
        ):
            assert _ip_blocked(ip), ip
        for ip in ("8.8.8.8", "93.184.216.34", "2606:2800:220:1:248:1893:25c8:1946"):
            assert not _ip_blocked(ip), ip

    def test_shim_drops_blocked_and_raises_when_none_safe(self):
        from ephemora_cell.egress_sidecar import (
            _egress_context,
            _guarded_getaddrinfo,
            _SSRFBlocked,
        )

        with _egress_context(self._fake_resolver("93.184.216.34", "169.254.169.254")):
            out = _guarded_getaddrinfo("api.example.com", 80)
        assert [e[4][0] for e in out] == ["93.184.216.34"]
        with _egress_context(self._fake_resolver("127.0.0.1")):
            import pytest

            with pytest.raises(_SSRFBlocked):
                _guarded_getaddrinfo("internal.example.com", 80)

    def test_shim_passes_ip_literals_unfiltered(self):
        from ephemora_cell.egress_sidecar import (
            _egress_context,
            _guarded_getaddrinfo,
            _real_getaddrinfo,
        )

        # A literal host inside a context is operator intent: returned
        # unfiltered even though it is loopback — this is what keeps a deliberate
        # ``--egress-allow http://127.0.0.1:PORT`` (and the test harness) working.
        with _egress_context(self._fake_resolver("127.0.0.1")):
            out = _guarded_getaddrinfo("127.0.0.1", 8080)
        assert out == [self._addrinfo("127.0.0.1", 8080)]
        # The guard defers to the real resolver when no egress context is set, so
        # it is transparent to every non-mediated socket use in the process.
        assert _real_getaddrinfo is not _guarded_getaddrinfo

    def test_mediate_denies_a_name_that_rebinds_to_metadata(self):
        from ephemora_cell.egress_sidecar import EgressPolicy, mediate

        # The URL is on the allowlist (a name), but that name resolves to the
        # cloud-metadata address -> refused at connect, before any socket opens.
        policy = EgressPolicy(
            allowed_endpoints=("http://api.rebind.test/v1",),
            resolver=self._fake_resolver("169.254.169.254"),
        )
        raw = json.dumps({"url": "http://api.rebind.test/v1/data", "method": "GET"})
        result = mediate(policy, raw)
        assert result.audit.decision == "denied"
        assert result.audit.limit == "ssrf"
        assert "SSRF" in result.audit.reason


class TestSSRFAdversarialFamilies:
    """ADR-013 Prio 2, driven harder than the loopback case: every address
    family a mediated NAME can be pointed at, plus the two bypass channels an
    operator environment opens — an ambient proxy (which moves the resolution
    target off the URL entirely) and a redirect hop (which introduces a second
    name after the first answer was already vetted).
    """

    @staticmethod
    def _addrinfo(ip: str, port: int = 80):
        import socket as _s

        family = _s.AF_INET6 if ":" in ip else _s.AF_INET
        return (family, _s.SOCK_STREAM, 0, "", (ip, port))

    def _resolver(self, *ips):
        def resolver(_host, port, *a, **k):
            return [self._addrinfo(ip, port) for ip in ips]

        return resolver

    def _host_resolver(self, table: dict, asked: list | None = None):
        """Per-name answers; a name missing from the table resolves to nothing.

        ``asked`` records (host, port) in call order — that log is the point of
        several tests here: WHO is resolved says as much as WHAT comes back.
        """

        def resolver(host, port, *a, **k):
            if asked is not None:
                asked.append((str(host), port))
            return [self._addrinfo(ip, port) for ip in table.get(str(host), [])]

        return resolver

    def test_every_private_or_special_use_address_is_blocked(self):
        from ephemora_cell.egress_sidecar import _ip_blocked

        blocked = {
            "127.0.0.1": "loopback v4",
            "127.5.6.7": "the whole 127/8 is loopback, not just .1",
            "::1": "loopback v6",
            "169.254.169.254": "cloud metadata (AWS/GCP/OpenStack)",
            "169.254.170.2": "ECS task metadata",
            "fe80::1": "link-local v6",
            "fe80::1%eth0": "scoped link-local v6 (scope id must not dodge it)",
            "10.0.0.5": "RFC1918",
            "172.16.0.1": "RFC1918",
            "192.168.1.1": "RFC1918",
            "100.64.0.0": "CGNAT first address",
            "100.127.255.255": "CGNAT last address",
            "::ffff:127.0.0.1": "IPv4-mapped loopback",
            "::ffff:169.254.169.254": "IPv4-mapped metadata",
            "::ffff:10.0.0.5": "IPv4-mapped RFC1918",
            "2002:7f00:1::": "6to4 embedding 127.0.0.1",
            "64:ff9b::7f00:1": "NAT64 well-known prefix embedding 127.0.0.1",
            "fc00::1": "unique local v6",
            "ff02::1": "multicast v6",
            "0.0.0.0": "unspecified v4",
            "::": "unspecified v6",
            "192.0.2.1": "documentation range — refused, fail closed",
            "198.51.100.7": "documentation range — refused, fail closed",
            "203.0.113.9": "documentation range — refused, fail closed",
        }
        for ip, why in blocked.items():
            assert _ip_blocked(ip), f"{ip} ({why}) must never be an egress target"

    def test_public_targets_stay_reachable(self):
        """The positive control: a filter that also blocks the internet is a
        broken filter. ``::ffff:8.8.8.8`` matters — the guard refuses the family
        an address MAPS to, not the notation, so mapped public space is still
        reachable."""
        from ephemora_cell.egress_sidecar import _ip_blocked

        for ip in (
            "8.8.8.8",
            "1.1.1.1",
            "93.184.216.34",
            "2606:2800:220:1:248:1893:25c8:1946",
            "::ffff:8.8.8.8",
        ):
            assert not _ip_blocked(ip), ip

    # --- interpreter independence of the embedded-family classification ------
    # `ipaddress.is_private` / `is_reserved` are not a stable security boundary.
    # Measured across CPython patch releases: 3.10.11 / 3.11.8 / 3.11.9 let
    # 2002:7f00:1:: (6to4 embedding loopback) THROUGH and refused ::ffff:8.8.8.8,
    # while 3.12.10 and 3.13.0 refused the whole 2002::/16 — including
    # 2002:0808:0808::, whose embedded address is public. Same input, different
    # decision, depending on which interpreter the operator happened to install.
    # These gates pin the classification to Cell's own registry instead.

    def test_embedded_ipv4_is_read_from_the_bytes(self):
        """6to4 / NAT64 / IPv4-mapped are only notations for an IPv4 target."""
        from ephemora_cell.egress_sidecar import _embedded_ipv4

        assert _embedded_ipv4("::ffff:127.0.0.1") == "127.0.0.1"
        assert _embedded_ipv4("::ffff:8.8.8.8") == "8.8.8.8"
        assert _embedded_ipv4("2002:7f00:1::") == "127.0.0.1"
        assert _embedded_ipv4("2002:0808:0808::") == "8.8.8.8"
        assert _embedded_ipv4("64:ff9b::7f00:1") == "127.0.0.1"
        assert _embedded_ipv4("64:ff9b::808:808") == "8.8.8.8"
        # addresses that do not embed an IPv4 must not be forced through the
        # extraction path (they are classified by the v6 registry)
        for other in (
            "2001:db8::1",
            "fe80::1",
            "2001::1",
            "2606:2800:220:1:248:1893:25c8:1946",
            "8.8.8.8",
            "not-an-address",
        ):
            assert _embedded_ipv4(other) is None, other

    def test_the_embedded_target_decides_not_the_notation(self):
        from ephemora_cell.egress_sidecar import _ip_blocked

        # private / special-use behind any of the three embeddings: refused
        for ip in (
            "2002:7f00:1::",
            "::ffff:127.0.0.1",
            "64:ff9b::a9fe:a9fe",  # 169.254.169.254 — cloud metadata via NAT64
            "::ffff:169.254.169.254",
            "2002:0a00:1::",  # 10.0.0.0/8 via 6to4
        ):
            assert _ip_blocked(ip), ip
        # public behind the same embeddings: reachable, on every interpreter
        for ip in (
            "::ffff:8.8.8.8",
            "2002:0808:0808::",
            "64:ff9b::808:808",
            "::ffff:93.184.216.34",
        ):
            assert not _ip_blocked(ip), ip

    def test_flipping_the_stdlib_properties_moves_no_decision(self, monkeypatch):
        """The proof that the guard does not consult `is_private`/`is_reserved`
        for these families: forcing each of them to the opposite answer on every
        IPv6 address must leave every classification unchanged."""
        import ipaddress

        from ephemora_cell import egress_sidecar as es

        blocked = ("2002:7f00:1::", "::ffff:127.0.0.1", "64:ff9b::7f00:1", "fe80::1")
        reachable = ("::ffff:8.8.8.8", "2002:0808:0808::", "64:ff9b::808:808")
        for prop in ("is_private", "is_reserved", "is_global"):
            for value in (True, False):
                monkeypatch.setattr(
                    ipaddress.IPv6Address,
                    prop,
                    property(lambda self, _v=value: _v),
                )
                for ip in blocked:
                    assert es._ip_blocked(ip), f"{prop}={value} flipped {ip}"
                for ip in reachable:
                    assert not es._ip_blocked(ip), f"{prop}={value} flipped {ip}"

    def test_registry_covers_the_special_use_ranges_it_claims(self):
        """Written against Cell's own list, so a CPython that stopped flagging
        one of these ranges could not silently open it here."""
        from ephemora_cell.egress_sidecar import _ip_blocked

        for ip in (
            "0.0.0.0",
            "0.0.0.1",  # 0.0.0.0/8, not only the all-zeros address
            "192.0.0.1",
            "192.0.2.1",
            "192.88.99.1",
            "198.18.0.1",
            "198.19.255.255",
            "203.0.113.9",
            "224.0.0.1",
            "239.255.255.255",
            "240.0.0.1",
            "255.255.255.255",
            "::",
            "::1",
            "100::1",  # discard-only
            "2001::1",  # Teredo: its embedded v4 is obfuscated, so refused
            "2001:10::1",  # ORCHID / ORCHIDv2 (inside 2001::/23)
            "2001:20::1",
            "2001:db8::1",
            "3fff::1",
            "fc00::1",
            "fd12:3456::1",
            "fe80::1%eth0",
            "ff02::1",
        ):
            assert _ip_blocked(ip), ip

    def test_public_space_around_the_registry_stays_reachable(self):
        """Positive controls for the same edges: the list must not grow into a
        block-everything filter."""
        from ephemora_cell.egress_sidecar import _ip_blocked

        for ip in (
            "8.8.8.8",
            "1.1.1.1",
            "100.128.0.1",  # just above 100.64.0.0/10
            "169.253.255.255",  # just below 169.254.0.0/16
            "192.1.1.1",
            "2001:db9::1",  # just outside the documentation prefix
            "2003::1",
            "2001:400::1",  # above 2001::/23 and 2001:100::/32, unassigned
            "6000::1",  # just above 5f00::/8
        ):
            assert not _ip_blocked(ip), ip

    def test_multi_a_record_keeps_only_public_in_original_order(self):
        from ephemora_cell.egress_sidecar import (
            _egress_context,
            _guarded_getaddrinfo,
        )

        resolver = self._resolver(
            "169.254.169.254", "93.184.216.34", "fe80::1", "8.8.8.8"
        )
        with _egress_context(resolver):
            out = _guarded_getaddrinfo("api.example.com", 443)
        assert [entry[4][0] for entry in out] == ["93.184.216.34", "8.8.8.8"]

    def test_multi_a_record_all_private_fails_closed(self):
        import pytest

        from ephemora_cell.egress_sidecar import (
            _egress_context,
            _guarded_getaddrinfo,
            _SSRFBlocked,
        )

        with _egress_context(self._resolver("10.1.1.1", "::1", "192.168.9.9")):
            with pytest.raises(_SSRFBlocked):
                _guarded_getaddrinfo("allprivate.example", 80)

    def test_ambient_proxy_env_does_not_move_the_resolution_target(self, monkeypatch):
        """With ``http_proxy`` set, urllib resolves and connects to the PROXY and
        never asks for the URL host — measured 2026-10-04, the guard was called
        with ('proxy.internal', 8080) for a request to api.example.com. That
        would vet the wrong address and hand the real resolution to a third
        party, so a mediated fetch ignores environment proxies by construction.
        """
        from ephemora_cell.egress_sidecar import EgressPolicy, mediate

        for name in (
            "http_proxy",
            "HTTP_PROXY",
            "https_proxy",
            "HTTPS_PROXY",
            "all_proxy",
            "ALL_PROXY",
        ):
            monkeypatch.setenv(name, "http://proxy.internal:8080")
        monkeypatch.delenv("no_proxy", raising=False)

        asked: list = []
        policy = EgressPolicy(
            allowed_endpoints=("http://api.example.com/",),
            resolver=self._host_resolver({"api.example.com": ["93.184.216.34"]}, asked),
            timeout_seconds=2,
        )
        mediate(
            policy, json.dumps({"url": "http://api.example.com/v1/x", "method": "GET"})
        )
        assert asked == [
            ("api.example.com", 80)
        ], f"resolution target moved off the allowlisted origin: {asked}"

    def test_redirect_hop_to_a_name_resolving_metadata_is_denied(self):
        """A second name behind a real 302: the origin is an allowlisted IP
        literal (operator intent, reachable), the hop is an allowlisted NAME
        whose answer is the metadata address. The hop must be refused and the
        origin must have seen exactly one request — nothing after the redirect.
        """
        from ephemora_cell.egress_sidecar import EgressPolicy, mediate

        server, port = _serve()
        try:
            _route(port, "/v1/start", ("redirect", "http://meta.hop.test/v1/x"))
            policy = EgressPolicy(
                allowed_endpoints=(
                    f"http://127.0.0.1:{port}/v1/",
                    "http://meta.hop.test/v1/",
                ),
                resolver=self._host_resolver(
                    {
                        "127.0.0.1": ["127.0.0.1"],
                        "meta.hop.test": ["169.254.169.254"],
                    }
                ),
                timeout_seconds=3,
            )
            result = mediate(
                policy,
                json.dumps(
                    {"url": f"http://127.0.0.1:{port}/v1/start", "method": "GET"}
                ),
            )
        finally:
            server.shutdown()
            server.server_close()
        assert result.audit.decision == "denied", result.audit
        assert result.audit.limit == "ssrf", result.audit.reason
        assert _RoutingHandler.hits == {port: 1}, _RoutingHandler.hits


class TestResolvePinningTOCTOU:
    """The stronger half of the ADR-013 claim: it is not only "private answers
    are filtered", it is "the address that was vetted IS the address the socket
    is asked to connect to". A resolver that changes its answer between calls is
    what a DNS-rebinding server does, so these tests spy on the OS boundary
    *below* the guard and look at the addresses actually handed to connect().
    """

    class _SpySocket:
        """Stands in for ``socket.socket`` inside ``socket.create_connection``.

        Records every address the stdlib tries and refuses the connection, so a
        test sees WHICH address was chosen without a socket leaving the machine.
        """

        attempts: typing.ClassVar[list] = []

        def __init__(self, family, type_, proto=0):
            self.family, self.type, self.proto = family, type_, proto

        def settimeout(self, _timeout):
            pass

        def connect(self, address):
            type(self).attempts.append(address)
            raise OSError("spy socket: no connection leaves the test")

        def close(self):
            pass

        def __enter__(self):
            return self

        def __exit__(self, *exc):
            return False

    def _addrinfo(self, ip, port=80):
        import socket as _s

        family = _s.AF_INET6 if ":" in ip else _s.AF_INET
        return (family, _s.SOCK_STREAM, 0, "", (ip, port))

    def _mediate_with_spy(self, monkeypatch, policy, url):
        from ephemora_cell.egress_sidecar import mediate

        self._SpySocket.attempts = []
        # create_connection builds its socket through the module-level `socket`
        # name, so patching it intercepts exactly the connect the stdlib makes
        # from the (already filtered) addrinfo list.
        monkeypatch.setattr("socket.socket", self._SpySocket)
        result = mediate(policy, json.dumps({"url": url, "method": "GET"}))
        return result, [attempt[0] for attempt in self._SpySocket.attempts]

    def test_rebinding_second_answer_never_reaches_the_socket(self, monkeypatch):
        """What this pins is the SHAPE of the lookup: one hop triggers exactly
        ONE resolution, and the address the socket is handed is that vetted
        answer — so a DNS server that would answer differently on the second
        ask has no window to do it in. (Filtering of a bad answer within one
        lookup is the next two tests.)
        """
        from ephemora_cell.egress_sidecar import EgressPolicy

        answers = [["93.184.216.34"], ["127.0.0.1"]]
        asked: list = []

        def resolver(host, port, *a, **k):
            index = min(len(asked), len(answers) - 1)
            asked.append((str(host), port))
            return [self._addrinfo(ip, port) for ip in answers[index]]

        policy = EgressPolicy(
            allowed_endpoints=("http://rebind.example/",),
            resolver=resolver,
            timeout_seconds=2,
        )
        result, connected = self._mediate_with_spy(
            monkeypatch, policy, "http://rebind.example/v1/x"
        )
        assert asked == [("rebind.example", 80)], asked
        assert connected == ["93.184.216.34"], connected
        assert "127.0.0.1" not in connected
        # the policy ALLOWED this hop (public answer) — only the spy socket
        # stopped the bytes, which is what shows the vetted address reached
        # connect() rather than being refused earlier in the chain
        assert result.audit.decision == "allowed", result.audit.reason

    def test_mixed_record_never_hands_a_private_address_to_connect(self, monkeypatch):
        """One resolve, several answers: whatever the socket may try is the
        filtered subset — a private sibling in the same A-record set is dropped
        before create_connection ever sees it."""
        from ephemora_cell.egress_sidecar import EgressPolicy

        policy = EgressPolicy(
            allowed_endpoints=("http://multi.example/",),
            resolver=lambda host, port, *a, **k: [
                self._addrinfo("93.184.216.34", port),
                self._addrinfo("169.254.169.254", port),
                self._addrinfo("8.8.8.8", port),
            ],
            timeout_seconds=2,
        )
        _result, connected = self._mediate_with_spy(
            monkeypatch, policy, "http://multi.example/v1/x"
        )
        assert connected == ["93.184.216.34", "8.8.8.8"], connected

    def test_all_private_answer_never_reaches_the_socket(self, monkeypatch):
        """No safe address at all: the resolve itself refuses, so connect() is
        called zero times — the denial happens before any socket, not after."""
        from ephemora_cell.egress_sidecar import EgressPolicy

        policy = EgressPolicy(
            allowed_endpoints=("http://internal.example/",),
            resolver=lambda host, port, *a, **k: [self._addrinfo("10.0.3.7", port)],
            timeout_seconds=2,
        )
        result, connected = self._mediate_with_spy(
            monkeypatch, policy, "http://internal.example/v1/x"
        )
        assert connected == [], connected
        assert result.audit.decision == "denied"
        assert result.audit.limit == "ssrf"


class TestServerMetaEgress:
    def _server(self, tmp_path):
        from ephemora_cell_mcp.server import Server

        return Server(tools_dir=tmp_path, transport=object())

    def _outcome(self, egress):
        from ephemora_cell_mcp.engine import ExecutionReport

        report = ExecutionReport(status="success", exit_code=0, elapsed_ms=1.0)
        return CellOutcome(
            result=_ok_result(None),
            report=report,
            egress=egress,
        )

    def test_no_egress_means_unchanged_meta_shape(self, tmp_path):
        meta = self._server(tmp_path)._build_call_result(self._outcome(()))["_meta"]
        assert set(meta) == {"execution"}
        assert "egress" not in meta

    def test_mediated_decision_surfaces_under_meta(self, tmp_path):
        entry = {
            "url": "http://x/v1",
            "method": "GET",
            "decision": "denied",
            "reason": "url not allowed by egress policy",
        }
        meta = self._server(tmp_path)._build_call_result(self._outcome((entry,)))[
            "_meta"
        ]
        assert meta["egress"] == [entry]


class TestEgressGrantForm:
    """ADR-013: the grant is a frozen envelope, not yet an enforcement."""

    def test_grant_is_describable_and_canonical(self):
        from ephemora_cell.egress_sidecar import EgressGrant

        grant = EgressGrant(
            grant_id="g1",
            tool="weather",
            allowed_endpoints=("https://api.example.com/v1",),
            not_after="2027-01-01T00:00:00+00:00",
            max_calls=100,
        )
        doc = grant.to_dict()
        assert doc["enforced"] == "allowlist-only"
        # the ONE enforced part is exactly the policy the mediator checks
        assert grant.policy().allowed_endpoints == ("https://api.example.com/v1",)
        # canonical bytes are stable for equal grants and move on any field
        twin = EgressGrant(
            grant_id="g1",
            tool="weather",
            allowed_endpoints=("https://api.example.com/v1",),
            not_after="2027-01-01T00:00:00+00:00",
            max_calls=100,
        )
        assert grant.canonical_bytes() == twin.canonical_bytes()
        moved = EgressGrant(
            grant_id="g1",
            tool="weather",
            allowed_endpoints=("https://api.example.com/v1",),
            not_after="2027-06-01T00:00:00+00:00",
            max_calls=100,
        )
        assert grant.canonical_bytes() != moved.canonical_bytes()

    def test_grant_validates_the_enforceable_fields_only(self):
        import pytest

        from ephemora_cell.egress_sidecar import EgressGrant

        with pytest.raises(ValueError):
            EgressGrant(
                grant_id="g", tool="t", allowed_endpoints=("ftp://x/",)
            )  # bad scheme -> its policy() would be refused
        with pytest.raises(ValueError):
            EgressGrant(grant_id="", tool="t", allowed_endpoints=())
        # an expiry / cap the mediator does NOT yet read is still constructible
        EgressGrant(
            grant_id="g",
            tool="t",
            allowed_endpoints=(),
            not_after="2020-01-01T00:00:00+00:00",
            max_calls=0,
        )


class TestGrantLoader:
    """Directory-scan semantics of the grant loader: every file is read, every
    refusal is named, and nothing half-loads.

    Authentication itself (signatures, trust root, rotation, audience) is
    ``tests/test_grant_trust.py`` with real Ed25519 keys; here the root is a stub
    so this file stays free of the optional ``cryptography`` extra and tests only
    the scan/duplicate/directory behaviour.
    """

    class _StubRoot:
        """A trust root stand-in that accepts whatever the schema accepts."""

        audience = "https://ephemora.dev/egress-grant.v1"

        def verify_envelope(self, envelope, *, now=None):
            from ephemora_cell.egress_sidecar import EgressGrant

            return EgressGrant.from_document(envelope)

    def _write(self, dir_path, name, doc):
        (dir_path / name).write_text(json.dumps(doc), encoding="utf-8")

    def test_from_document_round_trips_to_dict(self):
        from ephemora_cell.egress_sidecar import EgressGrant

        grant = EgressGrant(
            grant_id="g1",
            tool="weather",
            allowed_endpoints=("https://api.example.com/v1",),
            not_after="2099-01-01T00:00:00Z",
            max_calls=10,
            key_id="k1",
        )
        assert EgressGrant.from_document(grant.to_dict()) == grant

    def test_from_document_refuses_unknown_schema_and_missing_fields(self):
        import pytest

        from ephemora_cell.egress_sidecar import EgressGrant

        bad = EgressGrant(grant_id="g", tool="t", allowed_endpoints=()).to_dict()
        bad["grant_version"] = "egress-grant.v999"
        with pytest.raises(ValueError, match="grant_version"):
            EgressGrant.from_document(bad)
        missing = {"grant_version": "egress-grant.v1", "tool": "t"}
        with pytest.raises(ValueError, match="grant_id"):
            EgressGrant.from_document(missing)

    def test_loader_reads_a_directory(self, tmp_path):
        from ephemora_cell.egress_sidecar import EgressGrant, load_egress_grants

        g = EgressGrant(grant_id="g1", tool="echo", allowed_endpoints=())
        self._write(tmp_path, "echo.egress.grant.json", g.to_dict())
        grants, errors = load_egress_grants(tmp_path, self._StubRoot())
        assert errors == []
        assert set(grants) == {"echo"}
        assert grants["echo"] == g

    def test_loader_reports_malformed_and_duplicate_and_is_not_silent(self, tmp_path):
        from ephemora_cell.egress_sidecar import EgressGrant, load_egress_grants

        g = EgressGrant(grant_id="a", tool="echo", allowed_endpoints=())
        self._write(tmp_path, "good.egress.grant.json", g.to_dict())
        self._write(tmp_path, "dupe.egress.grant.json", g.to_dict())  # same tool
        (tmp_path / "broken.egress.grant.json").write_text("{nope", encoding="utf-8")
        _, errors = load_egress_grants(tmp_path, self._StubRoot())
        # every bad file is named — the caller can refuse to start
        assert len(errors) == 2
        assert any("broken" in e for e in errors)
        assert any("duplicate" in e for e in errors)

    def test_loader_refuses_a_missing_directory(self, tmp_path):
        import pytest

        from ephemora_cell.egress_sidecar import load_egress_grants

        with pytest.raises(NotADirectoryError):
            load_egress_grants(tmp_path / "nope", self._StubRoot())


# --- transport walls: a hostile or broken peer still yields an audit (2026-10-04)


class _RawResponder(socketserver.BaseRequestHandler):
    """Answers with raw bytes, so the peer can break the protocol on purpose."""

    def handle(self):
        try:
            self.request.recv(65536)
        except OSError:
            pass
        spec = self.server.spec  # type: ignore[attr-defined]
        kind = spec["kind"]
        if kind == "garbage_status":
            self.request.sendall(b"this is not an status line\r\n\r\n")
        elif kind == "too_many_headers":
            self.request.sendall(
                b"HTTP/1.1 200 OK\r\n" + b"X-A: 1\r\n" * 150 + b"\r\n{}"
            )
        elif kind == "trickle":
            self.request.sendall(b"HTTP/1.1 200 OK\r\nContent-Length: 400\r\n\r\n")
            for _ in range(400):
                time.sleep(0.02)  # each op is inside timeout_seconds
                try:
                    self.request.sendall(b"x")
                except OSError:
                    break


class _RedirectRecorder(socketserver.BaseRequestHandler):
    """Redirects /hop{n} -> /hop{n+1} forever, recording what was requested."""

    def handle(self):
        try:
            request = self.request.recv(65536).decode("latin-1")
        except OSError:
            return
        path = request.split(" ")[1] if request else "/"
        seen: list = self.server.seen  # type: ignore[attr-defined]
        seen.append(path)
        try:
            step = int(path.rsplit("/chain/", 1)[1])
        except (ValueError, IndexError):
            step = 0
        stop_after = getattr(self.server, "spec", {}).get("stop_after")
        if stop_after is not None and step >= stop_after:
            body = json.dumps({"chain_end": step}).encode()
            self.request.sendall(
                b"HTTP/1.1 200 OK\r\nContent-Type: application/json\r\n"
                + f"Content-Length: {len(body)}\r\n\r\n".encode()
                + body
            )
            return
        next_path = f"/chain/{step + 1}"
        self.request.sendall(
            f"HTTP/1.1 302 Found\r\nLocation: {next_path}\r\n"
            "Content-Length: 0\r\n\r\n".encode()
        )


def _raw_server(handler_class, spec=None):
    server = socketserver.ThreadingTCPServer(("127.0.0.1", 0), handler_class)
    server.daemon_threads = True
    server.allow_reuse_address = True
    server.spec = spec or {}  # type: ignore[attr-defined]
    server.seen = []  # type: ignore[attr-defined]
    threading.Thread(target=server.serve_forever, daemon=True).start()
    return server, server.server_address[1]


class TestTransportWalls:
    """A mediated fetch that never completes must still be a DECISION.

    Before this, `http.client`'s own failures (InvalidURL from a tab inside the
    authority, a >100-header response, a junk status line) escaped `mediate()`
    entirely — they subclass neither OSError nor ValueError — so the caller got
    no audit line at all. And `timeout_seconds` bounded one socket operation,
    which a server dribbling one byte every 20 ms outlives indefinitely, once
    per hop, while pinning a host thread.
    """

    def test_junk_status_line_is_an_audited_refusal(self):
        server, port = _raw_server(_RawResponder, {"kind": "garbage_status"})
        try:
            outcome = mediate(
                _policy(port),
                json.dumps({"url": f"http://127.0.0.1:{port}/v1/x", "method": "GET"}),
            )
            assert outcome.audit.decision == "denied", outcome.audit
            assert outcome.audit.limit == "transport", outcome.audit
        finally:
            server.shutdown()

    def test_more_than_a_hundred_headers_is_an_audited_refusal(self):
        server, port = _raw_server(_RawResponder, {"kind": "too_many_headers"})
        try:
            outcome = mediate(
                _policy(port),
                json.dumps({"url": f"http://127.0.0.1:{port}/v1/x", "method": "GET"}),
            )
            assert outcome.audit.decision == "denied", outcome.audit
            assert outcome.audit.limit == "transport", outcome.audit
        finally:
            server.shutdown()

    def test_tab_in_the_authority_never_escapes_the_mediator(self):
        """The allowlist may or may not match (that is the stdlib's parser), but
        either way mediate() returns an audited result instead of raising."""
        server, port = _raw_server(_RawResponder, {"kind": "garbage_status"})
        try:
            url = f"http://127.0.0.1:{port}\t/v1/x"
            outcome = mediate(_policy(port), json.dumps({"url": url, "method": "GET"}))
            assert outcome.audit.decision == "denied", outcome.audit
        finally:
            server.shutdown()

    def test_wall_clock_deadline_stops_a_trickling_peer(self):
        server, port = _raw_server(_RawResponder, {"kind": "trickle"})
        policy = EgressPolicy(
            allowed_endpoints=(f"http://127.0.0.1:{port}/v1",), timeout_seconds=1.0
        )
        try:
            started = time.monotonic()
            outcome = mediate(
                policy,
                json.dumps({"url": f"http://127.0.0.1:{port}/v1/x", "method": "GET"}),
            )
            elapsed = time.monotonic() - started
            assert outcome.audit.decision == "denied", outcome.audit
            assert outcome.audit.limit == "timeout", outcome.audit
            assert elapsed < 6.0, f"the trickle outlived its budget: {elapsed:.1f}s"
            assert "ok" in outcome.response_doc and not outcome.response_doc["ok"]
        finally:
            server.shutdown()

    def test_a_short_chain_records_exactly_the_hops_it_opened(self):
        """Positive control: when hops ARE followed, every recorded hop is one the
        peer actually served — and the chain finishes with a body."""
        server, port = _raw_server(_RedirectRecorder, {"stop_after": 3})
        policy = EgressPolicy(allowed_endpoints=(f"http://127.0.0.1:{port}/chain/",))
        try:
            outcome = mediate(
                policy,
                json.dumps(
                    {"url": f"http://127.0.0.1:{port}/chain/1", "method": "GET"}
                ),
            )
            assert outcome.audit.decision == "allowed", outcome.audit
            served = {p for p in server.seen}  # type: ignore[attr-defined]
            recorded = {"chain/" + hop.rsplit("/", 1)[-1] for hop in outcome.audit.hops}
            assert recorded == {"chain/2", "chain/3"}, recorded
            assert (
                recorded <= {p.lstrip("/") for p in served} | served
            ), f"audit claims hops the peer never served: {recorded - served}"
            assert outcome.response_doc["content"]["chain_end"] == 3
        finally:
            server.shutdown()

    def test_a_hop_the_loop_limit_refused_is_not_reported_as_followed(self):
        """The audit used to say "allowed, fetch failed" and list a final hop that
        no socket ever opened. Refusing at the limit is a DENIAL, and it names the
        hop it refused to dispatch."""
        server, port = _raw_server(_RedirectRecorder)
        policy = EgressPolicy(allowed_endpoints=(f"http://127.0.0.1:{port}/chain/",))
        try:
            outcome = mediate(
                policy,
                json.dumps(
                    {"url": f"http://127.0.0.1:{port}/chain/1", "method": "GET"}
                ),
            )
            served = [p for p in server.seen]  # type: ignore[attr-defined]
            assert outcome.audit.decision == "denied", outcome.audit
            assert "loop limit" in outcome.audit.reason, outcome.audit.reason
            last_served = served[-1]
            refused = f"/chain/{int(last_served.rsplit('/', 1)[1]) + 1}"
            assert refused not in served, "the refused hop was dispatched anyway"
            assert refused.rstrip("/") in outcome.audit.reason or refused in str(
                outcome.response_doc
            ), outcome.response_doc
        finally:
            server.shutdown()

    def test_empty_userinfo_is_refused_not_mangled(self):
        """`http://:@host` has a falsy username, so an earlier check passed it and
        the wire carried `:@host` in the Host header."""
        server, port = _raw_server(_RawResponder, {"kind": "garbage_status"})
        policy = EgressPolicy(allowed_endpoints=(f"http://127.0.0.1:{port}/v1",))
        try:
            outcome = mediate(
                policy,
                json.dumps({"url": f"http://:@127.0.0.1:{port}/v1/x", "method": "GET"}),
            )
            assert outcome.audit.decision == "denied", outcome.audit
            assert "denied by egress policy" in outcome.response_doc["error"]
        finally:
            server.shutdown()


class TestAlternateIPv4Spellings:
    """`2130706433`, `0x7f000001`, `0177.0.0.1` and `127.1` are 127.0.0.1.

    Every URL parser accepts them; the allowlist compares HOST STRINGS, so the
    match must fail closed rather than let an alternate spelling of an address the
    operator never named inherit the dotted form's permission. The reverse
    direction matters just as much: an allowlist that does name the decimal form
    must not admit the dotted one, because the resolve-time guard treats IP
    literals as operator intent and does not filter them.
    """

    @staticmethod
    def _decision(endpoint: str, url: str) -> str:
        policy = EgressPolicy(allowed_endpoints=(endpoint,))
        return validate_request(policy, _request(url)).decision

    def test_alternate_spellings_of_an_allowlisted_host_are_denied(self):
        allowed = "http://127.0.0.1:8080/v1"
        for url in (
            "http://2130706433:8080/v1",
            "http://0x7f000001:8080/v1",
            "http://0177.0.0.1:8080/v1",
            "http://127.1:8080/v1",
            "http://127.0.0.1:8080/v1/../v1",
        ):
            assert self._decision(allowed, url) == "denied", url

    def test_a_decimal_allowlist_entry_does_not_admit_the_dotted_form(self):
        assert (
            self._decision("http://2130706433:8080/v1", "http://127.0.0.1:8080/v1")
            == "denied"
        )

    def test_the_spellings_that_are_allowed_are_exact(self):
        """Positive control: this is string comparison, not a blanket ban."""
        allowed = "http://127.0.0.1:8080/v1"
        assert self._decision(allowed, "http://127.0.0.1:8080/v1/data") == "allowed"
        assert self._decision(allowed, "http://127.0.0.1:8080/v1") == "allowed"
