# SPDX-License-Identifier: BUSL-1.1
# Copyright 2026 Michael Soppa

"""HTTP-bridge identity mapping (v1.2 v1.2).

The bridge is the multi-client boundary, so it — not the request body — must
resolve the authenticated client's identity. These cases need no MCP SDK: the
middleware and the token directory are plain ASGI/data, so they run and are
verified in the qualified environment.
"""

from __future__ import annotations

import asyncio
import json
import os
import sys
from typing import ClassVar

sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))

import pytest

from ephemora_cell_mcp.http_bridge import (
    CURRENT_SUBJECT,
    BearerAuthMiddleware,
    TokenDirectory,
    load_token_subjects,
)

ALICE = "a" * 40
BOB = "b" * 40


class _Inner:
    calls: ClassVar[list[str]] = []
    seen_subject: ClassVar[str | None] = "unset"

    async def __call__(self, scope, receive, send):
        _Inner.calls.append(scope.get("type", "?"))
        _Inner.seen_subject = CURRENT_SUBJECT.get()
        await send({"type": "http.response.start", "status": 200, "headers": []})
        await send({"type": "http.response.body", "body": b"ok"})


def _call(middleware, headers):
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


# --- the directory ---------------------------------------------------------


def test_the_directory_resolves_each_token_to_its_own_subject():
    directory = TokenDirectory.from_mapping({ALICE: "alice", BOB: "bob"})
    assert directory.subject_for(ALICE.encode()) == "alice"
    assert directory.subject_for(BOB.encode()) == "bob"
    assert directory.subject_for(b"c" * 40) is None
    assert directory.subject_for(b"") is None


def test_the_directory_refuses_empty_and_short_tokens():
    with pytest.raises(ValueError):
        TokenDirectory.from_mapping({})
    with pytest.raises(ValueError):
        TokenDirectory.from_mapping({"": "alice"})
    with pytest.raises(ValueError):
        TokenDirectory.from_mapping({"short": "alice"})


def test_load_token_subjects_reads_a_json_object(tmp_path):
    path = tmp_path / "tokens.json"
    path.write_text(json.dumps({ALICE: "alice", BOB: "bob"}), encoding="utf-8")
    directory = load_token_subjects(path)
    assert directory.subject_for(BOB.encode()) == "bob"
    with pytest.raises(ValueError):
        bad = tmp_path / "bad.json"
        bad.write_text(json.dumps([1, 2, 3]), encoding="utf-8")
        load_token_subjects(bad)


# --- the middleware --------------------------------------------------------


def test_each_client_is_served_under_its_own_identity():
    """Two tokens reach the layer, each with its own subject — no crossover."""
    directory = TokenDirectory.from_mapping({ALICE: "alice", BOB: "bob"})
    mw = BearerAuthMiddleware(_Inner(), tokens=directory)

    _Inner.calls.clear()
    status, _ = _call(mw, [(b"authorization", b"Bearer " + ALICE.encode())])
    assert status == 200 and _Inner.seen_subject == "alice"

    status, _ = _call(mw, [(b"authorization", b"Bearer " + BOB.encode())])
    assert status == 200 and _Inner.seen_subject == "bob"
    assert _Inner.calls == ["http", "http"]


def test_an_unknown_token_is_refused_and_sets_no_identity():
    directory = TokenDirectory.from_mapping({ALICE: "alice"})
    mw = BearerAuthMiddleware(_Inner(), tokens=directory)
    _Inner.calls.clear()
    status, _ = _call(mw, [(b"authorization", b"Bearer " + BOB.encode())])
    assert status == 401
    assert _Inner.calls == []
    assert CURRENT_SUBJECT.get() is None


def test_a_single_token_bridge_keeps_the_default_subject():
    """Compatibility: the pre-1.2 single-token construction still authenticates."""
    _Inner.calls.clear()
    mw = BearerAuthMiddleware(_Inner(), ALICE)
    status, _ = _call(mw, [(b"authorization", b"Bearer " + ALICE.encode())])
    assert status == 200
    assert _Inner.seen_subject == "default"


def test_the_middleware_refuses_both_a_token_and_a_directory():
    directory = TokenDirectory.from_mapping({ALICE: "alice"})
    with pytest.raises(ValueError):
        BearerAuthMiddleware(_Inner(), ALICE, tokens=directory)


def test_the_subject_does_not_leak_across_requests():
    """After a request, the contextvar is reset — the next request starts clean."""
    directory = TokenDirectory.from_mapping({ALICE: "alice"})
    mw = BearerAuthMiddleware(_Inner(), tokens=directory)
    _call(mw, [(b"authorization", b"Bearer " + ALICE.encode())])
    assert CURRENT_SUBJECT.get() is None


# --- CLI wiring (the parts that need no MCP SDK) ---------------------------


def test_a_token_directory_satisfies_the_posture_check():
    from ephemora_cell_mcp.http_bridge import BridgePolicy

    assert (
        BridgePolicy(
            host="127.0.0.1",
            port=8765,
            token=None,
            allow_non_loopback=False,
            token_env="EPHEMORA_MCP_BRIDGE_TOKEN",
            has_token_directory=True,
        ).violations()
        == []
    )
    # Without the directory, a missing token is still refused.
    assert BridgePolicy(
        host="127.0.0.1",
        port=8765,
        token=None,
        allow_non_loopback=False,
        token_env="EPHEMORA_MCP_BRIDGE_TOKEN",
    ).violations()


def test_the_cli_refuses_a_malformed_token_subject_file(tmp_path):
    from ephemora_cell_mcp.http_bridge import main

    bad = tmp_path / "tokens.json"
    bad.write_text("{not json", encoding="utf-8")
    assert main(["--token-subjects", str(bad)]) == 2


def test_the_cli_refuses_a_token_file_with_a_short_secret(tmp_path):
    from ephemora_cell_mcp.http_bridge import main

    bad = tmp_path / "tokens.json"
    bad.write_text(json.dumps({"short": "alice"}), encoding="utf-8")
    assert main(["--token-subjects", str(bad)]) == 2
