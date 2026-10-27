# SPDX-License-Identifier: BUSL-1.1
# Copyright 2026 Michael Soppa
"""Transport hardening of the MCP HTTP bridge, measured through a real socket.

``tests/test_mcp_http_bridge.py`` pins the startup posture and the bearer gate
with an in-process ASGI call. This file exercises what an operator actually
exposes: ``build_app(...)`` served by uvicorn on a loopback port, reached with
``http.client`` over TCP — no ``TestClient`` shortcut, no hand-rolled body cap.

What is pinned here, and why each leg is a security property rather than a
happy path:

* a valid small ``tools/call`` is ``200`` and the host-authored
  ``_meta.execution`` record survives the transport untouched;
* an empty body is a JSON-RPC parse error, not an execution;
* an unknown tool is ``-32602``, never a fabricated success;
* a body larger than the MCP SDK's default 4 MiB cap is ``413`` and never
  reaches the upstream tool handler — proven with a recording stdio upstream
  (the HTTP stack, bearer gate and body limiter under test are the product's);
* concurrent connections each receive the result for their own request id;
* two clients do not share execution results or authentication state: the
  bridge is stateless HTTP, issues no session id, ignores a foreign one, and
  re-checks the bearer token on every request even on a kept-alive connection.

A tool result whose text looks like another ``tools/call`` is returned as data
and never re-enters the protocol. That is covered here at the HTTP boundary and
in ``tests/test_mcp_tool_response_injection.py`` at the stdio boundary.

Loopback only: the fixture binds ``127.0.0.1:0`` and every request targets that
socket; nothing leaves the machine. The suite is deterministic and, because the
bridge serialises one upstream child, completes in a few seconds.
"""

from __future__ import annotations

import concurrent.futures
import http.client
import json
import shlex
import socket
import sys
import threading
import time
from collections.abc import Iterator
from contextlib import contextmanager
from pathlib import Path

import pytest

pytest.importorskip("mcp", reason="the HTTP bridge needs the official MCP SDK")
uvicorn = pytest.importorskip("uvicorn", reason="the live bridge needs uvicorn")

from ephemora_cell_mcp.http_bridge import BridgePolicy, build_app  # noqa: E402

REPO = Path(__file__).resolve().parent.parent
TOOLS = REPO / "ephemora_cell_mcp" / "tools"
TOKEN = "s4-transport-" + "t" * 40
CALL_TIMEOUT = 30.0
BODY_CAP = 4 * 1024 * 1024


class LiveBridge:
    """A real uvicorn server around ``build_app`` on an ephemeral loopback port."""

    def __init__(self, upstream_args: list[str]) -> None:
        self._sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self._sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        self._sock.bind(("127.0.0.1", 0))
        self.port = self._sock.getsockname()[1]
        policy = BridgePolicy(
            host="127.0.0.1",
            port=self.port,
            token=TOKEN,
            allow_non_loopback=False,
            token_env="EPHEMORA_MCP_BRIDGE_TOKEN",
        )
        app = build_app(policy, upstream_args, CALL_TIMEOUT)
        config = uvicorn.Config(
            app, host="127.0.0.1", port=self.port, log_level="warning"
        )
        self._server = uvicorn.Server(config)
        self._thread = threading.Thread(
            target=self._server.run,
            kwargs={"sockets": [self._sock]},
            name="s4-live-bridge",
            daemon=True,
        )

    def start(self) -> LiveBridge:
        self._thread.start()
        deadline = time.monotonic() + 30.0
        while not self._server.started:
            if not self._thread.is_alive():
                raise RuntimeError("the bridge thread died during startup")
            if time.monotonic() > deadline:
                raise RuntimeError("the bridge did not start within 30s")
            time.sleep(0.02)
        return self

    def close(self) -> None:
        self._server.should_exit = True
        self._thread.join(timeout=30)
        if self._thread.is_alive():
            self._server.force_exit = True
            self._thread.join(timeout=10)
        try:
            self._sock.close()
        except OSError:
            pass

    @contextmanager
    def connection(
        self, *, timeout: float = CALL_TIMEOUT
    ) -> Iterator[http.client.HTTPConnection]:
        conn = http.client.HTTPConnection("127.0.0.1", self.port, timeout=timeout)
        try:
            yield conn
        finally:
            conn.close()

    def post(
        self,
        payload: object | None = None,
        *,
        raw: bytes | None = None,
        token: str | None = TOKEN,
        headers: dict[str, str] | None = None,
        timeout: float = CALL_TIMEOUT,
    ) -> tuple[int, dict[str, str], bytes]:
        """One POST over a fresh TCP connection; returns status, headers, body."""
        body = raw if raw is not None else json.dumps(payload).encode("utf-8")
        request_headers = {
            "Content-Type": "application/json",
            "Accept": "application/json, text/event-stream",
        }
        if token is not None:
            request_headers["Authorization"] = f"Bearer {token}"
        if headers:
            request_headers.update(headers)
        with self.connection(timeout=timeout) as conn:
            conn.request("POST", "/mcp", body=body, headers=request_headers)
            response = conn.getresponse()
            return (
                response.status,
                {k.lower(): v for k, v in response.getheaders()},
                response.read(),
            )

    def call(
        self, name: str, arguments: dict[str, object], *, request_id: int = 1
    ) -> tuple[int, dict[str, str], bytes]:
        return self.post(
            {
                "jsonrpc": "2.0",
                "id": request_id,
                "method": "tools/call",
                "params": {"name": name, "arguments": arguments},
            }
        )


@pytest.fixture(scope="module")
def bridge() -> Iterator[LiveBridge]:
    # The subject here is the transport/bridge/concurrency layer — and one test
    # pins the model "one bearer token reaches the whole registry", which only
    # holds under the explicit compatibility posture. Since 1.2 defaults to deny,
    # the child opts into --legacy-allow-all so these transport probes see the
    # tools run. Authorization itself is covered in test_mcp_subject_binding.py.
    live = LiveBridge(["--tools-dir", str(TOOLS), "--legacy-allow-all"]).start()
    try:
        yield live
    finally:
        live.close()


def _json(body: bytes) -> dict:
    return json.loads(body.decode("utf-8"))


def _result_text(body: dict) -> str:
    return body["result"]["content"][0]["text"]


# --- valid traffic, unknown tools, malformed bodies -------------------------


def test_valid_small_call_is_200_and_keeps_host_execution_meta(bridge):
    status, headers, raw = bridge.call("echo", {"greeting": "s4-small-call"})
    assert status == 200
    assert headers["content-type"].startswith("application/json")
    # stateless HTTP: no session is created, so nothing can be resumed later
    assert "mcp-session-id" not in headers
    body = _json(raw)
    assert body["id"] == 1
    assert "s4-small-call" in _result_text(body)
    execution = body["result"]["_meta"]["execution"]
    assert execution["status"] == "success"
    assert execution["exit_code"] == 0
    assert isinstance(execution["fuel_consumed"], int)
    assert execution["security_baseline"]["preopens"] == ["/sandbox"]


def test_empty_body_is_a_protocol_error_not_an_execution(bridge):
    status, _, raw = bridge.post(raw=b"")
    assert status == 400
    body = _json(raw)
    assert body["error"]["code"] == -32700
    assert "result" not in body


def test_one_bearer_token_reaches_every_listed_tool(bridge):
    """The current model: one token is a grant for the whole registry.

    This is pinned as measured behaviour, not as a recommendation. The S4
    authorization design (``S4_MCP_AUTHZ_DESIGN.md``) proposes replacing it
    with per-caller, per-tool grants; when that lands this test must change.
    """
    status, _, raw = bridge.post(
        {"jsonrpc": "2.0", "id": 10, "method": "tools/list", "params": {}}
    )
    assert status == 200
    listed = {tool["name"] for tool in _json(raw)["result"]["tools"]}
    assert {"clock", "echo", "get-policy"} <= listed

    for request_id, name in enumerate(sorted(listed), start=20):
        status, _, raw = bridge.call(name, {}, request_id=request_id)
        assert status == 200
        body = _json(raw)
        assert "error" not in body, (name, body.get("error"))
        assert body["result"]["content"]
        if name != "get-policy":
            assert body["result"]["_meta"]["execution"]["status"] == "success"


def test_unknown_tool_through_the_bridge_is_invalid_params(bridge):
    status, _, raw = bridge.call("no-such-tool", {"x": 1})
    assert status == 200
    body = _json(raw)
    assert "result" not in body
    assert body["error"]["code"] == -32602
    assert "unknown tool" in body["error"]["message"]


def test_tool_output_that_looks_like_a_call_is_returned_as_data(bridge):
    """A tool result is content, not a protocol frame: it cannot chain a call.

    ``echo`` returns its arguments verbatim. Feeding it a complete JSON-RPC
    ``tools/call`` for ``clock`` must produce one text result containing that
    JSON as inert text — no second execution, no ``clock`` payload.
    """
    nested = {
        "jsonrpc": "2.0",
        "id": 4242,
        "method": "tools/call",
        "params": {"name": "clock", "arguments": {}},
    }
    status, _, raw = bridge.call("echo", {"payload": nested})
    assert status == 200
    body = _json(raw)
    text = _result_text(body)
    assert '"method": "tools/call"' in text and '"name": "clock"' in text
    # clock's own stdout keys would only appear if the nested call had run
    assert "unix_ms" not in text and "utc" not in text
    assert body["result"]["_meta"]["execution"]["status"] == "success"
    assert len(body["result"]["content"]) == 1


# --- concurrency and isolation ---------------------------------------------


def test_parallel_connections_receive_only_their_own_result(bridge):
    """Concurrent clients must not cross results, ids or execution records."""
    count = 8
    nonce = f"{time.monotonic_ns():x}"

    def one(index: int):
        greeting = f"parallel-{nonce}-{index}"
        return (
            index,
            greeting,
            bridge.call("echo", {"greeting": greeting}, request_id=1000 + index),
        )

    with concurrent.futures.ThreadPoolExecutor(max_workers=count) as pool:
        outcomes = list(pool.map(one, range(count)))

    for index, greeting, (status, _, raw) in outcomes:
        assert status == 200
        body = _json(raw)
        assert body["id"] == 1000 + index
        text = _result_text(body)
        assert greeting in text
        assert body["result"]["_meta"]["execution"]["status"] == "success"
        for other in range(count):
            if other != index:
                assert (
                    f"parallel-{nonce}-{other}" not in text
                ), f"client {index} saw client {other}'s result"


def test_parallel_clients_reusing_one_request_id_do_not_cross(bridge):
    """Same JSON-RPC id on concurrent connections is still per-connection.

    Reusing an id is legal (ids are scoped to a client session), so a bridge
    that keyed responses by id alone would hand one client another's result.
    """
    count = 4
    nonce = f"{time.monotonic_ns():x}"

    def one(index: int):
        greeting = f"same-id-{nonce}-{index}"
        return (
            index,
            greeting,
            bridge.call("echo", {"greeting": greeting}, request_id=7),
        )

    with concurrent.futures.ThreadPoolExecutor(max_workers=count) as pool:
        outcomes = list(pool.map(one, range(count)))

    for index, greeting, (status, _, raw) in outcomes:
        assert status == 200
        body = _json(raw)
        assert body["id"] == 7
        text = _result_text(body)
        assert greeting in text
        for other in range(count):
            if other != index:
                assert f"same-id-{nonce}-{other}" not in text


def test_clients_do_not_share_results_sessions_or_auth_state(bridge):
    """Two callers on one bridge token still get request-scoped results.

    With stateless HTTP there is no server-side session to address, so a
    guessed/foreign ``Mcp-Session-Id`` cannot fetch another client's result,
    and the bearer gate re-runs on every request rather than authenticating a
    connection once.
    """
    marker_a = f"client-A-{time.monotonic_ns():x}"
    marker_b = f"client-B-{time.monotonic_ns():x}"

    status_a, headers_a, raw_a = bridge.call("echo", {"greeting": marker_a})
    status_b, headers_b, raw_b = bridge.call("echo", {"greeting": marker_b})
    assert status_a == status_b == 200
    text_a = _result_text(_json(raw_a))
    text_b = _result_text(_json(raw_b))
    assert marker_a in text_a and marker_b not in text_a
    assert marker_b in text_b and marker_a not in text_b
    assert "mcp-session-id" not in headers_a
    assert "mcp-session-id" not in headers_b

    # A foreign/guessed session id is not a capability: it is ignored, and the
    # answer is computed for THIS request only.
    status_c, _, raw_c = bridge.post(
        {
            "jsonrpc": "2.0",
            "id": 77,
            "method": "tools/call",
            "params": {"name": "echo", "arguments": {"greeting": "client-C"}},
        },
        headers={"Mcp-Session-Id": "client-a-session-guess"},
    )
    assert status_c == 200
    text_c = _result_text(_json(raw_c))
    assert "client-C" in text_c and marker_a not in text_c

    # The gate is per request: a kept-alive connection does not stay logged in.
    with bridge.connection() as conn:
        body = json.dumps(
            {"jsonrpc": "2.0", "id": 78, "method": "tools/list", "params": {}}
        )
        auth = {
            "Content-Type": "application/json",
            "Accept": "application/json, text/event-stream",
            "Authorization": f"Bearer {TOKEN}",
        }
        conn.request("POST", "/mcp", body=body, headers=auth)
        first = conn.getresponse()
        assert first.status == 200
        first.read()
        conn.request(
            "POST",
            "/mcp",
            body=body,
            headers={
                "Content-Type": "application/json",
                "Accept": "application/json, text/event-stream",
            },
        )
        second = conn.getresponse()
        assert second.status == 401
        assert b"unauthorized" in second.read()


# --- oversized body: the SDK cap, not a test-local imitation -----------------

#: Minimal MCP stdio server that records every ``tools/call`` it accepts.
#: Used only as an observation point: if the 4 MiB cap works, this file stays
#: empty; if a request slips past the cap, the call is recorded and the test
#: fails. The HTTP stack, bearer gate and body limiter are the product's.
_RECORDER = """
import json
import os
import sys

LOG = os.environ["EPHEMORA_RECORDER_LOG"]


def reply(message_id, result):
    sys.stdout.write(
        json.dumps({"jsonrpc": "2.0", "id": message_id, "result": result}) + "\\n"
    )
    sys.stdout.flush()


for line in sys.stdin:
    line = line.strip()
    if not line:
        continue
    try:
        message = json.loads(line)
    except ValueError:
        continue
    if "id" not in message:
        continue
    method = message.get("method")
    if method == "initialize":
        reply(message["id"], {
            "protocolVersion": "2025-06-18",
            "capabilities": {"tools": {}},
            "serverInfo": {"name": "s4-recording-upstream", "version": "0"},
        })
    elif method == "tools/list":
        reply(message["id"], {"tools": [
            {"name": "echo", "description": "recording upstream",
             "inputSchema": {"type": "object", "properties": {}}},
            {"name": "get-policy", "description": "recording upstream",
             "inputSchema": {"type": "object", "properties": {}}},
        ]})
    elif method == "tools/call":
        with open(LOG, "a", encoding="utf-8") as handle:
            handle.write(json.dumps(message["params"], sort_keys=True) + "\\n")
        reply(message["id"], {
            "content": [{
                "type": "text",
                "text": json.dumps(message["params"].get("arguments")),
            }],
            "isError": False,
        })
    else:
        reply(message["id"], {})
"""


@contextmanager
def recording_bridge(tmp_path: Path, monkeypatch) -> Iterator[LiveBridge]:
    """A live bridge whose stdio child is the recording upstream above.

    ``build_app`` spawns ``sys.executable -m ephemora_cell_mcp``; pointing
    ``sys.executable`` at a launcher that runs the recorder leaves every other
    layer (uvicorn, the SDK transport, bearer middleware, body limiter) real.
    """
    real_python = sys.executable
    recorder = tmp_path / "recorder_upstream.py"
    recorder.write_text(_RECORDER, encoding="utf-8")
    launcher = tmp_path / "recorder_upstream"
    launcher.write_text(
        f"#!/bin/sh\nexec {shlex.quote(real_python)} "
        f'{shlex.quote(str(recorder))} "$@"\n',
        encoding="utf-8",
    )
    launcher.chmod(0o755)
    log = tmp_path / "calls.ndjson"
    log.write_text("", encoding="utf-8")
    monkeypatch.setenv("EPHEMORA_RECORDER_LOG", str(log))
    monkeypatch.setattr(sys, "executable", str(launcher))
    live = LiveBridge(["--tools-dir", str(TOOLS), "--legacy-allow-all"]).start()
    try:
        yield live
    finally:
        live.close()


def test_oversized_body_is_413_before_the_upstream_handler_runs(tmp_path, monkeypatch):
    """>4 MiB is refused by the SDK's default cap, before any tool handler.

    Positive control first: the recorder is proven live by a small call. Then
    the log is cleared and a body larger than 4 MiB — still a valid JSON-RPC
    ``tools/call`` — is sent. The response must be 413 and the recorder must
    stay empty, which is only possible if the body limiter refused it before
    parsing and dispatch.
    """
    with recording_bridge(tmp_path, monkeypatch) as bridge:
        # The cap under test is the SDK's default, not a number invented here.
        from mcp.server.transport_security import DEFAULT_MAX_REQUEST_BODY_SIZE

        assert DEFAULT_MAX_REQUEST_BODY_SIZE == BODY_CAP

        status, _, raw = bridge.call("echo", {"greeting": "recorder-control"})
        assert status == 200
        assert "recorder-control" in _result_text(_json(raw))
        log_path = Path(tmp_path / "calls.ndjson")
        recorded = log_path.read_text(encoding="utf-8").strip().splitlines()
        assert len(recorded) == 1, "the recorder must observe the positive control"
        assert json.loads(recorded[0])["name"] == "echo"

        log_path.write_text("", encoding="utf-8")
        prefix = (
            b'{"jsonrpc":"2.0","id":99,"method":"tools/call","params":'
            b'{"name":"echo","arguments":{"greeting":"OVERSIZE-'
            b'MUST-NOT-RUN","pad":"'
        )
        suffix = b'"}}}'
        oversized = prefix + b"x" * BODY_CAP + suffix
        assert len(oversized) > BODY_CAP

        status, headers, raw = bridge.post(raw=oversized, timeout=60)
        assert status == 413
        assert raw == b"Request body too large"
        assert headers["content-length"] == str(len(raw))

        # No accepted ``tools/call`` may appear after the refusal. The bridge
        # serialises upstream calls, so a forwarded request would have been
        # recorded before its response was written.
        time.sleep(0.2)
        assert (
            log_path.read_text(encoding="utf-8") == ""
        ), "an oversized body reached the upstream tool handler"
