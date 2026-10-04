# SPDX-License-Identifier: BUSL-1.1
# Copyright 2026 Michael Soppa

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


class _Oversized:
    """Sentinel: this line is longer than the transport will hold."""


_OVERSIZED = _Oversized()


class StdioTransport:
    """Line-oriented NDJSON over the process' stdin/stdout."""

    def __init__(
        self, stdin=None, stdout=None, max_line_bytes: int = MAX_LINE_BYTES
    ) -> None:
        # Read BYTES, not text. A text-mode stdin with a utf-8 locale raises
        # UnicodeDecodeError inside readline() and that exception was never
        # catchable from here — one stray byte from the peer killed the process
        # with a traceback and lost the responses already buffered for the
        # client. Undecodable input is a malformed message, nothing more.
        self._stdin = stdin if stdin is not None else sys.stdin.buffer
        self._stdout = stdout if stdout is not None else sys.stdout
        self._max_line_bytes = max_line_bytes
        # Bytes read past a line boundary, kept for the next read.
        self._carry = b""

    def read_line(self) -> str | None:
        """Return the next raw line, or None on EOF.

        Lines beyond ``max_line_bytes`` are answered immediately with a
        JSON-RPC error response (id ``null``, ``-32600``) sent straight to
        the sender, then reading continues with the next line. The bound is
        applied WHILE reading: a peer that sends megabytes with no newline is
        refused without the server ever holding the line in memory.
        """
        while True:
            raw = self._readline_capped()
            if raw is None:
                return None
            if isinstance(raw, _Oversized):
                self.send(
                    {
                        "jsonrpc": "2.0",
                        "id": None,
                        "error": {
                            "code": -32600,
                            "message": "request line exceeds transport limit",
                        },
                    }
                )
                continue
            return raw.decode("utf-8", errors="replace").rstrip("\r\n")

    def _readline_capped(self) -> bytes | _Oversized | None:
        """One newline-terminated line, ``_OVERSIZED``, or None at EOF.

        Bytes read past the line boundary stay in ``self._carry`` — dropping
        them would silently swallow the peer's next messages.
        """
        stream: Any = self._stdin
        if not hasattr(stream, "read1"):  # a text stream from a test
            line = stream.readline()
            if not line:
                return None
            encoded = line.encode("utf-8", errors="replace")
            return _OVERSIZED if len(encoded) > self._max_line_bytes else encoded
        while True:
            index = self._carry.find(b"\n")
            if index != -1:
                line, self._carry = self._carry[: index + 1], self._carry[index + 1 :]
                return _OVERSIZED if len(line) > self._max_line_bytes else line
            if len(self._carry) > self._max_line_bytes:
                # No terminator inside the budget: refuse it and discard the
                # rest of the line so the NEXT message is read whole.
                self._carry = b""
                while True:
                    rest = stream.read1(64 * 1024)
                    if not rest:
                        break
                    if b"\n" in rest:
                        self._carry = rest[rest.index(b"\n") + 1 :]
                        break
                return _OVERSIZED
            chunk = stream.read1(64 * 1024)
            if not chunk:
                if self._carry:
                    line, self._carry = self._carry, b""
                    return line
                return None
            self._carry += chunk

    def send(self, message: dict[str, Any]) -> None:
        # ``allow_nan=False``: a JSON-RPC frame is not Python. A NaN that
        # somehow reaches here must be an error at our edge, not an invalid
        # message that strict parsers in the peer reject wholesale.
        self._stdout.write(
            json.dumps(message, ensure_ascii=False, allow_nan=False) + "\n"
        )
        self._stdout.flush()


class MemoryTransport:
    """In-process transport for tests: preloaded inbox, captured outbox."""

    def __init__(self, inbox: list[dict[str, Any]] | None = None) -> None:
        self._inbox: list[str] = [json.dumps(message) for message in (inbox or [])]
        self.outbox: list[dict[str, Any]] = []

    def read_line(self) -> str | None:
        if not self._inbox:
            return None
        return self._inbox.pop(0)

    def send(self, message: dict[str, Any]) -> None:
        self.outbox.append(message)
