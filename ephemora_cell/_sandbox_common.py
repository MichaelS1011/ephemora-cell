# Ephemora Cell — shared sandbox dir-guard policy (private module)
# SPDX-License-Identifier: BUSL-1.1
# Copyright 2026 Ephemora AG (in formation), Zug, Switzerland
"""Single source of truth for the preopen dir-guard policy and the runtime
helpers shared by the two sandbox ABIs.

The Preview1 sandbox (:class:`ephemora_cell.wasi_runtime.WASISandbox`) and
the component sandbox (:class:`ephemora_cell.wasi_02.ComponentSandbox`) must
enforce the SAME allowlist/denylist policy for ``allow_dirs``. This module
holds that policy once:

* the canonical (realpath) denylist and the macOS temp-root exception,
* the ``host::guest`` mapping split (validation always applies to the HOST
  side), and
* ``filter_dangerous_dirs`` — the ONE filter implementation both classes
  delegate to (canonical allowlist first, string denylist as pre-filter).

It also hosts the runtime helpers the component path used to duplicate or
re-import as PRIVATE names from wasi_runtime (trap classification, fuel
accounting, output capture, epoch/interrupt timers, stdin cap, preopen
grant) — one implementation each, re-exported by wasi_runtime for its own
code and external references.

History: the component path used to re-implement the filter over the RAW
entry string without splitting ``host::guest`` mappings first, so an entry
like ``/etc::guest-etc`` bypassed the string-denylist layer there while
being filtered on the Preview1 path (denylist drift between ABI paths,
fixed 2026-09-29).
"""

from __future__ import annotations

import os
import threading
import warnings
from collections.abc import Callable
from collections.abc import Set as AbstractSet
from typing import TYPE_CHECKING, Any

if TYPE_CHECKING:
    from wasmtime import WasiConfig as WasmtimeWasiConfig

# --- Output Budget (max 10 KB of UTF-8 bytes per execution) ---
# One budget, byte-based everywhere: the guest-side fd_write sink,
# the host-side capture-file read-back, and in-memory string truncation
# all measure encoded bytes, so the cap means the same thing at every
# layer. (Previously the in-memory truncation counted characters while
# the sink counted bytes — a two-byte-per-char discrepancy.)
_MAX_OUTPUT_BYTES = 10_000
# Host-side stdin cap: wasmtime's WASI preview1 host feeds fd 0 from a fixed
# worker-thread buffer (crates/wasi/src/cli/worker_thread_stdin.rs), silently
# truncating anything larger. Ephemora Cell never passes more than this to a
# guest — larger input must be read from a preopened file instead.
STDIN_MAX_BYTES = 9_216
# WASI errno returned to the guest once the output budget is exhausted.
_WASI_ERRNO_NOSPC = 51

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


def validate_allow_dirs(
    allow_dirs: tuple[str, ...],
    *,
    split_dir_mapping: Callable[[str], tuple[str, str]] = split_dir_mapping,
    canonicalize: Callable[[str], str] = canonicalize_dir,
    forbidden_canonical_match: Callable[[str], str | None] = forbidden_canonical_match,
) -> None:
    """Fail fast if any allow_dirs entry is canonically forbidden.

    Config-time validation shared by both sandbox constructors: the HOST
    side of every (mapping) entry is realpath-resolved and checked against
    the canonical allowlist.

    Raises:
        ValueError: with the offending entry and its canonical path.
    """
    for d in allow_dirs:
        host, _ = split_dir_mapping(d)
        canon = canonicalize(host)
        match = forbidden_canonical_match(canon)
        if match is not None:
            raise ValueError(
                f"allow_dirs entry {d!r} is forbidden: canonical path "
                f"{canon!r} resolves into blocked location {match!r}"
            )


def check_dangerous_dirs(
    allow_dirs: tuple[str, ...],
    *,
    dangerous_dirs: AbstractSet[str] = DANGEROUS_DIRS,
    split_dir_mapping: Callable[[str], tuple[str, str]] = split_dir_mapping,
    under_canonical_exception: Callable[[str], bool] = under_canonical_exception,
    stacklevel: int = 3,
) -> None:
    """Warn if allow_dirs entries match the denylist by string.

    The canonical realpath check already rejects true forbidden paths;
    this remains as an additional visibility layer for suspicious strings.
    ``stacklevel`` lets each caller keep the warning attributed to ITS
    construction site.
    """
    if not allow_dirs:
        return
    for d in allow_dirs:
        host, _ = split_dir_mapping(d)
        if under_canonical_exception(host):
            continue
        if host in dangerous_dirs or any(
            host == dd or host.startswith(dd + "/") for dd in dangerous_dirs
        ):
            warnings.warn(
                f"Preopen directory '{d}' matches the dangerous dirs denylist. "
                "It will be filtered out at runtime.",
                RuntimeWarning,
                stacklevel=stacklevel,
            )


def grant_preopens(
    wasi_cfg: WasmtimeWasiConfig,
    safe_dirs: tuple[str, ...],
    sandbox_dir: str | None,
    *,
    split_dir_mapping: Callable[[str], tuple[str, str]] = split_dir_mapping,
    canonicalize: Callable[[str], str] = canonicalize_dir,
    forbidden_canonical_match: Callable[[str], str | None] = forbidden_canonical_match,
    stacklevel: int = 2,
) -> tuple[str, ...]:
    """Preopen the filtered dirs (plus the sandbox dir) and record what
    was ACTUALLY granted (S2 attestation input).

    TOCTOU: an entry validated at config time can be swapped before the
    grant happens (e.g. replaced with a symlink into a forbidden
    location). Every entry is therefore re-realpath'd immediately
    before ``preopen_dir`` and skipped with a warning when it now
    resolves into a forbidden canonical location. The guest-visible
    name stays the configured string; the host path is the canonical
    one. ``sandbox_dir=None`` grants no /sandbox mount (component ABI).
    ``stacklevel`` keeps the warnings attributed to each caller's grant
    line.
    """
    granted: list[str] = []
    for dir_path in safe_dirs:
        host_path, guest_name = split_dir_mapping(dir_path)
        canon = canonicalize(host_path)
        if forbidden_canonical_match(canon) is not None:
            warnings.warn(
                "Preopen skipped at grant time (TOCTOU revalidation): "
                f"{dir_path!r} now resolves to forbidden canonical path "
                f"{canon!r}",
                RuntimeWarning,
                stacklevel=stacklevel,
            )
            continue
        if not os.path.isdir(canon):
            warnings.warn(
                f"Preopen skipped: directory does not exist: {dir_path!r} "
                f"(canonical: {canon!r}) — guest path {guest_name!r} will not be available",
                RuntimeWarning,
                stacklevel=stacklevel,
            )
            continue
        wasi_cfg.preopen_dir(canon, guest_name)
        granted.append(canon)
    if sandbox_dir is not None:
        wasi_cfg.preopen_dir(sandbox_dir, "/sandbox")
        granted.append("/sandbox")
    return tuple(granted)


def is_memory_fault_trap(message: str) -> bool:
    """True when a wasmtime trap is a memory violation (OOB access, fault, or
    failed memory growth) — mapped to MEMORY_EXCEEDED instead of ERROR."""
    lowered = message.lower()
    return (
        "out of bounds memory access" in lowered
        or "memory fault" in lowered
        or "memory allocation failed" in lowered
        or "failed to grow memory" in lowered
    )


def read_capped_output(path: str, limit: int = _MAX_OUTPUT_BYTES) -> str:
    """Read a host-owned capture file, bounding it at ``limit`` chars.

    Defense-in-depth: reads at most ``limit + 1`` bytes and truncates the
    file on disk if it somehow grew past the budget.
    """
    if not os.path.exists(path):
        return ""
    try:
        with open(path, "rb") as f:
            raw = f.read(limit + 1)
    except OSError:
        return ""
    if len(raw) > limit:
        try:
            with open(path, "r+b") as f:
                f.truncate(limit)
        except OSError:
            pass
        return raw[:limit].decode("utf-8", errors="replace") + "\n[... truncated]"
    return raw.decode("utf-8", errors="replace")


def make_output_sink(
    file_path: str, budget: list[int]
) -> Callable[[bytes], int | None]:
    """Build a WASI stdout/stderr sink that enforces the byte budget.

    Returns None to accept a write. Once the shared budget is exhausted
    the sink returns a NEGATIVE errno so the guest's fd_write fails
    without further output being appended to the host-owned capture file.

    NOTE: positive errno returns are NOT usable here — wasmtime-py 47
    misinterprets them as byte counts and panics ("cannot advance past
    remaining"). Negative returns take the C error path (guest sees EIO).
    """

    def _sink(data: bytes) -> int | None:
        if len(data) > budget[0]:
            return -_WASI_ERRNO_NOSPC
        budget[0] -= len(data)
        try:
            with open(file_path, "ab") as f:
                f.write(data)
        except OSError:
            return -_WASI_ERRNO_NOSPC
        return None

    return _sink


def watch_external_interrupt(
    engine: Any,
    interrupt_event: threading.Event,
    timeout_event: threading.Event,
) -> None:
    """External watchdog loop (worker io_cpu_seconds): one increment fires
    the per-run engine's deadline=1 immediately."""
    while not timeout_event.is_set():
        if interrupt_event.is_set():
            engine.increment_epoch()
            return
        timeout_event.wait(0.02)


def start_interrupt_watch(
    engine: Any,
    interrupt_event: threading.Event,
    timeout_event: threading.Event,
) -> None:
    """Start the external watchdog thread (ADR-002 io_cpu_seconds)."""
    threading.Thread(
        target=watch_external_interrupt,
        args=(engine, interrupt_event, timeout_event),
        daemon=True,
    ).start()


def start_epoch_timer(
    engine: Any,
    timeout_event: threading.Event,
    timeout_seconds: int | float | None,
) -> threading.Thread:
    """Start the per-run epoch timeout daemon: increment the engine epoch
    once after ``timeout_seconds`` unless the run finished first
    (``timeout_event`` set) — triggers the epoch_interruption trap.

    ONLY for per-run engines: pooled engines share a pool ticker, and a
    per-run incrementing timer trips sibling runs' deadlines (S3 epoch
    crossfire).
    """

    def _epoch_timer() -> None:
        if not timeout_event.wait(timeout_seconds):
            engine.increment_epoch()

    timer = threading.Thread(target=_epoch_timer, daemon=True)
    timer.start()
    return timer


def fuel_consumed(
    max_fuel: int | None,
    store: Any,
    *,
    on_read_error: str = "none",
) -> int | None:
    """Fuel units consumed at call time (None = unmetered run).

    Single implementation for both ABIs: ``max_fuel - store.get_fuel()``
    with the per-path read-error policy as the only difference —

    * ``on_read_error="full_budget"`` (Preview1): an out-of-fuel trap
      proves the budget was spent; if the store refuses a fuel read past
      the trap, report the full budget instead of an unaccounted None.
    * ``on_read_error="none"`` (component): the remaining fuel cannot be
      read (trap state) — report None.
    """
    if max_fuel is None:
        return None
    try:
        return max_fuel - store.get_fuel()
    except Exception:
        return max_fuel if on_read_error == "full_budget" else None
