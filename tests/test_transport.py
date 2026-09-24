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

from ephemora_cell_mcp import Server
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
