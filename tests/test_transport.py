"""StdioTransport edge cases: oversized lines must never drop traffic.

Regression tests for the M-1 finding (Vollabnahme 2026-09-24): the old
drain loop consumed the message FOLLOWING an oversized line (text-stream
``readline()`` had already consumed the whole oversized line) and fed the
transport's own error string back through request parsing, so the sender
saw a generic ``-32600 invalid request`` instead of the transport-limit
error and silently lost a request.
"""

from __future__ import annotations

import io
import json
import os
import sys

sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))

import pytest

from ephemora_cell_mcp import Server
from ephemora_cell_mcp.protocol import InvalidRequest, parse_line
from ephemora_cell_mcp.transport import StdioTransport

OVERSIZED = "x" * (11 * 1024 * 1024) + "\n"  # > MAX_LINE_BYTES (10 MiB)


def _transport(*chunks: str) -> tuple[StdioTransport, io.StringIO]:
    out = io.StringIO()
    return (
        StdioTransport(stdin=io.StringIO("".join(chunks)), stdout=out),
        out,
    )


def test_oversized_line_gets_immediate_error_response():
    """No silent hang: the limit reply goes out before the next read."""
    transport, out = _transport(OVERSIZED)
    assert transport.read_line() is None  # EOF after the oversized line
    reply = json.loads(out.getvalue())
    assert reply["error"]["code"] == -32600
    assert "transport limit" in reply["error"]["message"]
    assert reply["id"] is None


def test_message_after_oversized_line_is_not_dropped():
    """The message following an oversized line survives the limit reply."""
    good = json.dumps({"jsonrpc": "2.0", "id": 2, "method": "tools/list"})
    transport, out = _transport(OVERSIZED, good, "\n")
    assert transport.read_line() == good
    assert json.loads(out.getvalue())["error"]["code"] == -32600


def test_limit_reply_is_never_reparsed_as_input():
    """The transport's own error string must not loop back as a request."""
    transport, out = _transport(OVERSIZED)
    transport.read_line()
    lines = out.getvalue().strip().splitlines()
    assert len(lines) == 1
    assert "transport limit" in lines[0]


def test_server_serves_valid_request_after_oversized_line():
    """End to end through the serve loop: limit reply, then the answer."""
    good = json.dumps({"jsonrpc": "2.0", "id": 7, "method": "tools/list"})
    transport, out = _transport(OVERSIZED, good, "\n")
    Server(transport=transport).serve()
    lines = [json.loads(line) for line in out.getvalue().strip().splitlines()]
    assert lines[0]["error"]["code"] == -32600
    assert lines[1]["id"] == 7
    assert "tools" in lines[1]["result"]


# --- the transport reads BYTES: one bad byte is a bad message, not a dead server


class _ByteStream:
    """Binary stdin stand-in: hands out data the way a buffered pipe does."""

    def __init__(self, data: bytes, chunk: int = 65536) -> None:
        self._data = data
        self._chunk = chunk
        self._pos = 0

    def read1(self, size: int) -> bytes:
        take = min(size, self._chunk, len(self._data) - self._pos)
        out = self._data[self._pos : self._pos + take]
        self._pos += take
        return out


def _byte_transport(
    data: bytes, chunk: int = 65536
) -> tuple[StdioTransport, io.StringIO]:
    out = io.StringIO()
    return StdioTransport(stdin=_ByteStream(data, chunk), stdout=out), out


def test_undecodable_byte_is_read_as_a_line_instead_of_killing_the_loop():
    """A text-mode stdin raises UnicodeDecodeError inside readline() under a
    utf-8 locale — uncatchable from here, so the process died with a traceback
    and lost the responses already buffered for the client. Undecodable input is
    a malformed message."""
    payload = (
        b'{"jsonrpc":"2.0","id":1,"method":"tools/list"}\n'
        + b"\xff"
        + b'X\n{"jsonrpc":"2.0","id":2,"method":"tools/list"}\n'
    )
    transport, _ = _byte_transport(payload)
    first = transport.read_line()
    assert first is not None and json.loads(first)["id"] == 1
    second = transport.read_line()
    assert second is not None and "\ufffd" in second  # replacement, not a crash
    third = transport.read_line()
    assert json.loads(third)["id"] == 2, third


def test_malformed_bytes_reach_the_parser_and_answer_parse_error():
    """End-to-end over the byte transport: the server answers -32700 and stays
    alive for the next message."""
    transport, out = _byte_transport(b'{"jsonrpc":\n\xff\n')
    server = Server(tools_dir=".", transport=transport)
    server.serve()
    replies = [json.loads(line) for line in out.getvalue().splitlines() if line]
    assert replies and replies[0]["error"]["code"] == -32700, replies


def test_no_bytes_are_swallowed_after_a_line_boundary():
    """Several messages arriving in one read must each be answered: the leftover
    after the newline belongs to the next request, not to the void."""
    data = (
        b'{"jsonrpc":"2.0","id":1,"method":"tools/list"}\n'
        b'{"jsonrpc":"2.0","id":2,"method":"tools/list"}\n'
    )
    transport, _ = _byte_transport(data, chunk=4096)
    assert json.loads(transport.read_line())["id"] == 1
    assert json.loads(transport.read_line())["id"] == 2
    assert transport.read_line() is None


def test_oversized_line_is_refused_without_being_held_in_memory():
    """The cap applies while reading, so a peer sending 40 MB with no newline
    cannot make the server hold it."""
    data = b"x" * (11 * 1024 * 1024) + b"\n"
    transport, out = _byte_transport(data, chunk=8192)
    assert transport.read_line() is None
    reply = json.loads(out.getvalue())
    assert reply["error"]["code"] == -32600
    assert "transport limit" in reply["error"]["message"]


def test_transport_never_emits_a_frame_a_strict_parser_would_reject():
    """JSON has no NaN; Python's json writes it by default. A response carrying
    NaN is a message the peer drops wholesale."""
    transport, _out = _byte_transport(b"")
    with pytest.raises(ValueError):
        transport.send({"jsonrpc": "2.0", "id": 1, "result": {"x": float("nan")}})


def test_non_finite_request_id_is_a_structural_error():
    """`json.loads` accepts NaN/Infinity, and the id would be echoed back —
    refuse at the edge instead."""
    for bad in ("NaN", "Infinity", "-Infinity"):
        with pytest.raises(InvalidRequest):
            parse_line(f'{{"jsonrpc":"2.0","id":{bad},"method":"tools/list"}}')
