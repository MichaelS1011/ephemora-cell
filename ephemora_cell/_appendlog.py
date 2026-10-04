# SPDX-License-Identifier: BUSL-1.1
# Copyright 2026 Michael Soppa
"""Shared append-only line log with a single writer (host-side state).

Two features need exactly this: the execution ledger chain (ADR-011) and
cumulative per-tenant budgets. Both are host-owned files a guest never sees a
path to, both must survive concurrent in-process threads and subprocess runs,
and both must fail loudly rather than silently fork into two histories.

The discipline lives here once:

* ``O_APPEND`` and one ``os.write`` per record — never the atomic-replace helper
  in :mod:`ephemora_cell._fsutil`, which renames a temp file over the target and
  would drop every earlier line;
* an exclusive ``flock`` for anything that reads-then-writes, so position
  assignment and accounting are decided by one writer at a time;
* ``fsync`` after each record, because a ledger that only exists in the page
  cache proves nothing after a crash;
* a bounded tail read, so a file we did not produce is refused instead of
  silently becoming the parent of a new chain.

``fcntl`` is POSIX-only. The import is guarded so that ``import
ephemora_cell`` still works where locking primitives differ; constructing an
:class:`AppendLog` there raises instead of pretending to serialize writers.
"""

from __future__ import annotations

import os
from collections.abc import Callable
from pathlib import Path
from typing import TypeVar

T = TypeVar("T")

try:
    import fcntl

    _HAVE_FCNTL = True
except ImportError:  # pragma: no cover - non-POSIX platform
    fcntl = None  # type: ignore[assignment]
    _HAVE_FCNTL = False

#: How far back from EOF a single line must fit.
TAIL_WINDOW_BYTES = 64 * 1024


class AppendLog:
    """A JSONL file written by one lock-holding record writer at a time."""

    def __init__(
        self, path: str | Path, *, tail_window: int = TAIL_WINDOW_BYTES
    ) -> None:
        self.path = Path(path)
        self.tail_window = tail_window
        if self.path.is_dir():
            raise IsADirectoryError(f"log path is a directory: {self.path}")
        if not self.path.parent.is_dir():
            raise NotADirectoryError(
                f"log directory does not exist: {self.path.parent}"
            )
        if not _HAVE_FCNTL:
            raise RuntimeError(
                f"this platform has no fcntl file locking, so {type(self).__name__} "
                f"cannot guarantee a single writer: {self.path}"
            )

    def _open(self, *, create: bool) -> int:
        # O_APPEND is not decoration: without it os.write lands at the file
        # offset (0 for a freshly opened O_RDWR descriptor) and overwrites the
        # history instead of extending it.
        if not create:
            return os.open(str(self.path), os.O_RDONLY)
        return os.open(str(self.path), os.O_RDWR | os.O_CREAT | os.O_APPEND)

    def tail_line(self, fd: int) -> bytes | None:
        """Last non-empty line, read backwards from EOF. None for an empty file.

        Raises when no line break appears inside the tail window: that is not a
        log this writer produced, and appending to it would silently start a
        second history.
        """
        size = os.fstat(fd).st_size
        if size == 0:
            return None
        start = max(0, size - self.tail_window)
        chunk = os.pread(fd, size - start, start)
        if start > 0 and b"\n" not in chunk:
            raise ValueError(
                f"log line longer than the {self.tail_window} byte tail window "
                f"— this file is not a log produced here: {self.path}"
            )
        lines = [line for line in chunk.split(b"\n") if line.strip()]
        if not lines:
            raise ValueError(f"no log line found in the last {size - start} bytes")
        return lines[-1]

    def read_lines(self) -> list[bytes]:
        """Every non-empty line. Missing file reads as empty, never created."""
        if not self.path.exists():
            return []
        with self.path.open("rb") as handle:
            return [line for line in handle if line.strip()]

    def read_tail(self) -> bytes | None:
        """The last record under a shared lock. Creates nothing, ever."""
        if not self.path.exists():
            return None
        fd = self._open(create=False)
        try:
            fcntl.flock(fd, fcntl.LOCK_SH)
            try:
                return self.tail_line(fd)
            finally:
                fcntl.flock(fd, fcntl.LOCK_UN)
        finally:
            os.close(fd)

    def decide_and_append(
        self, decide: Callable[[bytes | None], tuple[T, bytes]]
    ) -> tuple[T, bytes]:
        """Decide from the tail and append in ONE critical section.

        ``decide(last_line_or_None)`` returns ``(decision, payload_bytes)``.
        Splitting the read and the write across calls is the race: two writers
        would read the same chain head or the same balance and both consider
        themselves next. Returns the decision and what was written.
        """
        fd = self._open(create=True)
        try:
            fcntl.flock(fd, fcntl.LOCK_EX)
            try:
                decision, payload = decide(self.tail_line(fd))
                os.write(fd, payload)
                os.fsync(fd)
            finally:
                fcntl.flock(fd, fcntl.LOCK_UN)
        finally:
            os.close(fd)
        return decision, payload
