# SPDX-License-Identifier: BUSL-1.1
# Copyright 2026 Michael Soppa

"""Atomic file publication — temp file + fsync + ``os.replace``.

Every producer that publishes into a tools/ or requests/ directory goes
through these helpers: a partially-written file must never be visible
under its final name (a registry scan, a concurrent reader or a server
re-scan could otherwise pick up a truncated module). The temp file is
created in the destination's own directory, so ``os.replace`` — atomic
on POSIX and Windows within one volume — never crosses a filesystem
boundary. The destination either has its old content or the complete
new content, never anything in between.
"""

from __future__ import annotations

import json
import os
import stat
import tempfile
from pathlib import Path


def _fsync_dir(directory: Path) -> None:
    """Best-effort directory fsync so the rename itself is durable.

    POSIX-only in practice: opening a directory fails on Windows, which
    is fine — the rename is still atomic there, just not durable-pinned.
    """
    try:
        fd = os.open(directory, os.O_RDONLY)
    except OSError:
        return
    try:
        os.fsync(fd)
    except OSError:
        pass
    finally:
        os.close(fd)


def _atomic_write(path: str | Path, data: bytes) -> Path:
    path = Path(path)
    fd, tmp_name = tempfile.mkstemp(
        dir=path.parent, prefix=f".{path.name}.", suffix=".tmp"
    )
    tmp_path = Path(tmp_name)
    try:
        with os.fdopen(fd, "wb") as tmp:
            tmp.write(data)
            tmp.flush()
            os.fsync(tmp.fileno())
        os.replace(tmp_path, path)
    except BaseException:
        tmp_path.unlink(missing_ok=True)
        raise
    _fsync_dir(path.parent)
    return path


def atomic_write_bytes(path: str | Path, data: bytes) -> Path:
    """Publish ``data`` at ``path`` atomically (no partial file visible)."""
    return _atomic_write(path, data)


def atomic_write_text(path: str | Path, text: str, encoding: str = "utf-8") -> Path:
    """Publish ``text`` at ``path`` atomically."""
    return _atomic_write(path, text.encode(encoding))


def atomic_write_json(path: str | Path, obj: object) -> Path:
    """Publish ``obj`` as JSON with the registry sidecar convention
    (``indent=2``, ``ensure_ascii=False``, trailing newline)."""
    payload = json.dumps(obj, indent=2, ensure_ascii=False) + "\n"
    return _atomic_write(path, payload.encode("utf-8"))


def atomic_copyfile(src: str | Path, dst: str | Path) -> Path:
    """Copy ``src`` → ``dst`` atomically; ``dst`` appears only complete."""
    return _atomic_write(dst, Path(src).read_bytes())


def read_regular_nofollow(path: str | Path, max_bytes: int | None = None) -> bytes:
    """Read a file without ever following a symlink or a special file.

    Several surfaces take a path whose NAME a guest can create files under
    (``sidecar.request.json`` in a sandbox, grant files in a grants dir, the
    append-only books). WASI refuses an ABSOLUTE symlink target but accepts a
    relative one, and ``../../../../`` resolves outside the sandbox the moment
    the host opens the name with ordinary ``read_bytes()``. So the host opens
    with ``O_NOFOLLOW``, requires the descriptor it ACTUALLY got to be a regular
    file, and reads from that descriptor — the bytes are pinned at open, so a
    rename race cannot move them underneath the read.

    ``max_bytes`` bounds the read: a host-side parser must not be made to
    allocate whatever a guest decided to write, and stopping at the cap is
    cheaper than slurping the file and checking afterwards.

    Raises ``OSError`` for a link, a non-regular file or an oversize file:
    every caller has to decide what the refusal means, nobody gets a silent
    open-through.
    """
    flags = os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0)
    fd = os.open(str(path), flags)
    try:
        if not getattr(os, "O_NOFOLLOW", 0) and os.path.islink(str(path)):
            raise OSError("refusing to follow a symlink")
        if not stat.S_ISREG(os.fstat(fd).st_mode):
            raise OSError("not a regular file")
        limit = os.fstat(fd).st_size
        if max_bytes is not None and limit > max_bytes:
            raise OSError(f"file is {limit} bytes, above the {max_bytes} byte limit")
        chunks = []
        while True:
            chunk = os.read(fd, 65536)
            if not chunk:
                break
            chunks.append(chunk)
    finally:
        os.close(fd)
    return b"".join(chunks)


def read_stable_bytes(path: str | Path) -> bytes | None:
    """Read a file only if it is settled, i.e. two consecutive reads agree.

    Returns the content, or ``None`` when the file is unreadable, is not a file
    the host may read at all (a symlink, a device), or is still changing (a
    producer streaming it, or a publish racing the read). Consumers use that to
    defer — not reject — files a writer has not finished publishing.

    The reads go through ``read_regular_nofollow``, because "settled" is checked
    on paths a *other* writer owns: a proposal directory a client drops files into,
    an append book. An ordinary ``read_bytes()`` there resolves a planted link, and
    a stability check that follows links is a stability check on someone else's
    file.
    """
    try:
        data = read_regular_nofollow(path)
        if data != read_regular_nofollow(path):
            return None
    except OSError:
        return None
    return data
