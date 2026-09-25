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


def read_stable_bytes(path: str | Path) -> bytes | None:
    """Read a file only if it is settled, i.e. two consecutive reads agree.

    Returns the content, or ``None`` when the file is unreadable or still
    changing (a producer streaming it, or a publish racing the read).
    Consumers use this to defer — not reject — files that a writer has
    not finished publishing.
    """
    try:
        data = Path(path).read_bytes()
        if data != Path(path).read_bytes():
            return None
    except OSError:
        return None
    return data
