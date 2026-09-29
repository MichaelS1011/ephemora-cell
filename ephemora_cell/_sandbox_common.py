# Ephemora Cell — shared sandbox dir-guard policy (private module)
# SPDX-License-Identifier: BUSL-1.1
# Copyright 2026 Ephemora AG (in formation), Zug, Switzerland
"""Single source of truth for the preopen dir-guard policy.

The Preview1 sandbox (:class:`ephemora_cell.wasi_runtime.WASISandbox`) and
the component sandbox (:class:`ephemora_cell.wasi_02.ComponentSandbox`) must
enforce the SAME allowlist/denylist policy for ``allow_dirs``. This module
holds that policy once:

* the canonical (realpath) denylist and the macOS temp-root exception,
* the ``host::guest`` mapping split (validation always applies to the HOST
  side), and
* ``filter_dangerous_dirs`` — the ONE filter implementation both classes
  delegate to (canonical allowlist first, string denylist as pre-filter).

History: the component path used to re-implement the filter over the RAW
entry string without splitting ``host::guest`` mappings first, so an entry
like ``/etc::guest-etc`` bypassed the string-denylist layer there while
being filtered on the Preview1 path (denylist drift between ABI paths,
fixed 2026-09-29).
"""

from __future__ import annotations

import os
from collections.abc import Callable
from collections.abc import Set as AbstractSet

# macOS temp roots: /tmp and /var/folders are symlinks into /private, so the
# canonical allowlist would reject the very directories tempfile.mkdtemp()
# hands out — breaking parity with Linux, where /tmp is allowed. These two
# canonical prefixes are allowed explicitly; every other /private location
# (etc, usr, ...) stays forbidden. Shared by the preview1 and component paths.
CANONICAL_EXCEPTIONS: tuple[str, ...] = (
    "/private/tmp",
    "/private/var/folders",
)

# Dangerous directories that are NEVER preopened (P0 #2). These are
# system-critical directories that could expose host state.
# NOTE: "/private" is on the STRING denylist, but macOS temp roots
# (/private/tmp, /private/var/folders) are explicitly ALLOWED via the
# canonical exception list CANONICAL_EXCEPTIONS. The STRING check is only a
# pre-filter; the authority is the canonical realpath check in
# forbidden_canonical_match() which allows those two prefixes. This
# two-layer design (string denylist + canonical allowlist) is intentional:
# string matching is fast and catches obvious mistakes, canonical matching
# closes symlink bypasses (e.g. /tmp -> /private/tmp on macOS).
DANGEROUS_DIRS: frozenset[str] = frozenset(
    [
        "/dev",
        "/proc",
        "/sys",
        "/etc",
        "/root",
        "/usr",
        "/bin",
        "/sbin",
        "/lib",
        "/lib64",
        "/boot",
        "/snap",
        "/kernel",
        "/private",
    ]
)

# Canonical (realpath) locations that are NEVER allowed in allow_dirs.
# "/" is handled explicitly in forbidden_canonical_match.
FORBIDDEN_CANONICAL: tuple[str, ...] = (
    "/etc",
    "/usr",
    "/bin",
    "/sbin",
    "/lib",
    "/lib64",
    "/dev",
    "/proc",
    "/sys",
    "/boot",
    "/snap",
    "/kernel",
    "/root",
    "/private",
)


def under_canonical_exception(dir_path: str) -> bool:
    """True when ``dir_path`` names a macOS temp root.

    The dangerous-dirs STRING denylist contains "/private"; without this
    exception that string would filter out /private/tmp even though the
    canonical check (the authority) allows it.
    """
    return any(
        dir_path == exc or dir_path.startswith(exc + "/")
        for exc in CANONICAL_EXCEPTIONS
    )


def forbidden_canonical_match(canon: str) -> str | None:
    """Return the forbidden canonical location that ``canon`` resolves into.

    ``canon`` is expected to already be realpath-normalized. "/" is always
    forbidden; every other forbidden location is checked as a realpath
    prefix, closing symlink-based bypasses such as /private/etc on macOS.
    The macOS temp roots (``CANONICAL_EXCEPTIONS``) are allowed explicitly.
    """
    if canon == "/":
        return "/"
    for exc in CANONICAL_EXCEPTIONS:
        if canon == exc or canon.startswith(exc + "/"):
            return None
    for f in FORBIDDEN_CANONICAL:
        if canon == f or canon.startswith(f + "/"):
            return f
    return None


def split_dir_mapping(entry: str) -> tuple[str, str]:
    """Split an allow_dirs entry into (host_path, guest_name).

    Entries may use the wasmtime-style ``host::guest`` mapping (needed
    when the guest expects the preopen under a specific name, e.g. "/"
    for wasi-libc relative-path resolution); a plain entry preopens the
    host path under its own name. Validation always applies to the
    HOST side; the guest name is only a label inside the sandbox.
    """
    host, sep, guest = entry.partition("::")
    if not sep or not host or not guest:
        return entry, entry
    return host, guest


def canonicalize_dir(dir_path: str) -> str:
    """Realpath-normalize an allow_dirs entry (the canonical check input)."""
    return os.path.realpath(os.path.expanduser(dir_path))


def filter_dangerous_dirs(
    allow_dirs: tuple[str, ...],
    *,
    split_dir_mapping: Callable[[str], tuple[str, str]] = split_dir_mapping,
    canonicalize: Callable[[str], str] = canonicalize_dir,
    forbidden_canonical_match: Callable[[str], str | None] = forbidden_canonical_match,
    dangerous_dirs: AbstractSet[str] = DANGEROUS_DIRS,
    under_canonical_exception: Callable[[str], bool] = under_canonical_exception,
) -> tuple[str, ...]:
    """Filter allow_dirs down to entries that pass the canonical allowlist.

    ONE shared implementation for the Preview1 and the component sandbox:
    mapping-style ``host::guest`` entries are split FIRST and the HOST part
    is checked (canonical realpath allowlist, then the string denylist as
    pre-filter — except the macOS temp roots, which the canonical check
    decides). The ORIGINAL entry string is kept in the result; only the
    checks apply to the host side.

    The callables/sets are parameters (defaulting to this module's policy)
    so both sandbox classes can pass their own (test-patchable) helpers
    without this filter ever drifting between the two ABI paths again.
    """
    if not allow_dirs:
        return ()
    safe: list[str] = []
    for d in allow_dirs:
        host, _ = split_dir_mapping(d)
        canon = canonicalize(host)
        if forbidden_canonical_match(canon) is not None:
            continue
        if host in dangerous_dirs or any(
            host == dd or host.startswith(dd + "/") for dd in dangerous_dirs
        ):
            if not under_canonical_exception(host):
                continue
        safe.append(d)
    return tuple(safe)
