"""Transports for the ephemora-cell-mcp stdio loop.

The default transport is real stdio (MCP stdio server: NDJSON lines on
stdin, NDJSON lines on stdout). A memory transport is provided for tests
and embedding — the :class:`Server` accepts any object with
``read_line() -> str | None`` and ``send(dict) -> None``.
"""

from __future__ import annotations

import json
import sys
from typing import Any

# Maximum accepted NDJSON line size. A host that pushes megabyte-long
# lines is misbehaving (or attacking); the line is rejected rather than
# read into memory unbounded.
MAX_LINE_BYTES = 10 * 1024 * 1024


class StdioTransport:
    """Line-oriented NDJSON over the process' stdin/stdout."""

    def __init__(self, stdin=None, stdout=None, max_line_bytes: int = MAX_LINE_BYTES) -> None:
        self._stdin = stdin if stdin is not None else sys.stdin
        self._stdout = stdout if stdout is not None else sys.stdout
        self._max_line_bytes = max_line_bytes

    def read_line(self) -> str | None:
        """Return the next raw line, or None on EOF.

        Lines beyond ``max_line_bytes`` are drained and reported as a
        JSON-RPC error line so the sender gets a specification-conform
        reply instead of a silent hang.
        """
        line = self._stdin.readline()
        if not line:
            return None
        if len(line.encode("utf-8", errors="replace")) > self._max_line_bytes:
            # Drain the oversized line's remainder so the next read starts
            # at a fresh boundary; readline() may have stopped early.
            while True:
                chunk = self._stdin.readline()
                if not chunk or chunk.endswith("\n"):
                    break
            return '{"jsonrpc": "2.0", "id": null, "error": {"code": -32600, "message": "request line exceeds transport limit"}}'
        return line.rstrip("\r\n")

    def send(self, message: dict[str, Any]) -> None:
        self._stdout.write(json.dumps(message, ensure_ascii=False) + "\n")
        self._stdout.flush()


class MemoryTransport:
    """In-process transport for tests: preloaded inbox, captured outbox."""

    def __init__(self, inbox: list[dict[str, Any]] | None = None) -> None:
        self._inbox: list[str] = [
            json.dumps(message) for message in (inbox or [])
        ]
        self.outbox: list[dict[str, Any]] = []

    def read_line(self) -> str | None:
        if not self._inbox:
            return None
        return self._inbox.pop(0)

    def send(self, message: dict[str, Any]) -> None:
        self.outbox.append(message)