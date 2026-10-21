# SPDX-License-Identifier: BUSL-1.1
# Copyright 2026 Michael Soppa

"""Is this environment allowed to run guest code as the audited runtime?

The answer comes from distribution metadata, the sha256 of the exact native
file the bindings load (on the qualified platform), and one import probe, so it
stays reachable in an installation where ``wasmtime`` cannot even be imported —
the case where a diagnosis still has to be possible. The gate hashes the file
before its import probe and refuses a mismatch before any guest code executes.
Importing ``ephemora_cell`` in the current layout already imports ``wasmtime``,
so this is not a guarantee that the native library was never mapped; a local
actor who can write the package can patch the check, and a file swapped between
the hash and the load is a residual TOCTOU window. This is a detection control,
not a tamper-proof boundary.

One line, two ways to be wrong about it:

* ``49.0.0`` is the published PyPI build and carries the advisories the 49.0.3
  fix line exists to close; running a guest on it is not the configuration this
  release was audited against.
* a build that merely shares the ``49.0.3`` prefix (``.dirty``, a foreign wheel)
  is not the audited *distribution* either — ``requirements.lock`` pins the
  wheel by name and sha256. At runtime, however, the authority is the digest of
  the exact native file the bindings load: if a differently labelled wheel
  embedded those same audited bytes, the native check passes even though that
  wheel remains distributionally unqualified.

The gate is a precondition, and an operator who knowingly runs elsewhere can say
so out loud with :data:`UNQUALIFIED_RUNTIME_ENV`. That is an explicit,
logged opt-out, never a silent fallback.
"""

from __future__ import annotations

import hashlib
import importlib
import importlib.metadata as metadata
import importlib.util
import os
import platform
import sys
from dataclasses import dataclass
from pathlib import Path

__all__ = [
    "QUALIFIED_ENGINE_SHA256",
    "QUALIFIED_LINE",
    "UNQUALIFIED_RUNTIME_ENV",
    "NativeEngineIdentity",
    "import_error",
    "native_engine_identity",
    "native_library_path",
    "qualified_platform",
    "reported_runtime_version",
    "runtime_line_ok",
    "runtime_qualification",
    "unqualified_runtime_allowed",
    "version_tuple",
]

#: The controlled Wasmtime line this release is qualified against: ``[49.0.3, 50.0)``.
QUALIFIED_LINE = ((49, 0, 3), (50, 0))

#: sha256 of the qualified native engine build the 1.2.x line ships.
QUALIFIED_ENGINE_SHA256 = (
    "ab4f1ea6e77c30cf4458bed9e4c94ccb103c7b3f2ceb49681c721c985e80fb73"
)

#: Documented escape hatch for an operator who knowingly runs a guest on an
#: engine outside the audited line (development, a platform with no qualified
#: wheel). Read as a boolean flag; anything else is not an opt-in.
UNQUALIFIED_RUNTIME_ENV = "EPHEMORA_ALLOW_UNQUALIFIED_RUNTIME"

_TRUTHY = {"1", "true", "yes", "on"}


@dataclass(frozen=True)
class NativeEngineIdentity:
    """The exact native file the wasmtime bindings load, and its verdict.

    ``match`` is tri-state: ``True`` when the file is the qualified build,
    ``False`` when this platform has a reference build and the file is missing
    or different, and ``None`` when no reference build exists for the platform
    (the version-line gate is then the only available decision).
    """

    path: Path | None
    sha256: str | None
    match: bool | None
    reason: str


def _normalized_machine() -> str:
    machine = platform.machine()
    if machine == "AMD64":
        return "x86_64"
    if machine in ("arm64", "ARM64"):
        return "aarch64"
    return machine


def _loader_platform() -> str:
    # Same mapping as wasmtime/_ffi.py: PEP 738 exposes Android through sys
    # before Python 3.13, and the loader uses ``sys_platform-machine`` as the
    # directory name.
    if hasattr(sys, "getandroidapilevel"):
        return "android"
    return sys.platform


def qualified_platform() -> bool:
    """True only for the platform this release carries evidence for."""
    return _loader_platform() == "darwin" and _normalized_machine() == "aarch64"


def native_library_path() -> Path | None:
    """The exact ``_libwasmtime`` file the bindings will load, or None.

    Derived without importing ``wasmtime`` so the execution gate can hash the
    file before the native library is loaded. The mapping mirrors
    ``wasmtime/_ffi.py``; a layout change makes the gate fail closed on the
    qualified platform instead of silently checking nothing.
    """
    try:
        spec = importlib.util.find_spec("wasmtime")
    except (ImportError, AttributeError, ValueError):
        return None
    if spec is None or spec.origin is None:
        return None
    loader_platform = _loader_platform()
    if loader_platform in ("linux", "android"):
        libname = "_libwasmtime.so"
    elif loader_platform == "win32":
        libname = "_wasmtime.dll"
    elif loader_platform == "darwin":
        libname = "_libwasmtime.dylib"
    else:
        return None
    machine = _normalized_machine()
    if machine not in ("x86_64", "aarch64"):
        return None
    return Path(spec.origin).parent / f"{loader_platform}-{machine}" / libname


def _sha256_file(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        for chunk in iter(lambda: handle.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def native_engine_identity() -> NativeEngineIdentity:
    """Hash the exact native file the bindings load, against the reference.

    On the qualified platform a missing or different file is ``match=False``:
    the version string cannot tell two builds apart, so there is no other
    evidence to fall back to. Elsewhere ``match`` is ``None`` because no
    qualified engine build exists to compare against.
    """
    path = native_library_path()
    if path is None:
        return NativeEngineIdentity(
            None,
            None,
            False if qualified_platform() else None,
            "cannot locate the native library the wasmtime bindings load",
        )
    try:
        digest = _sha256_file(path)
    except OSError as exc:
        return NativeEngineIdentity(
            path,
            None,
            False if qualified_platform() else None,
            f"cannot read {path}: {exc}",
        )
    if not qualified_platform():
        return NativeEngineIdentity(
            path,
            digest,
            None,
            "no qualified engine build exists for this platform; "
            "only the version line is checked",
        )
    if digest == QUALIFIED_ENGINE_SHA256:
        return NativeEngineIdentity(
            path,
            digest,
            True,
            "engine artifact matches the qualified digest "
            f"{QUALIFIED_ENGINE_SHA256[:12]}...",
        )
    return NativeEngineIdentity(
        path,
        digest,
        False,
        f"engine artifact at {path} has sha256 {digest[:12]}..., the qualified "
        f"build has {QUALIFIED_ENGINE_SHA256[:12]}...",
    )


def version_tuple(version: str) -> tuple[int, ...]:
    """Leading numeric release fields of ``version``.

    ``"49.0.3.post2+git.1d21c90f"`` -> ``(49, 0, 3)``; stops at the first
    non-numeric field so a pre/post/local suffix never shifts the tuple.
    """
    head = version.split("+", 1)[0]
    fields: list[int] = []
    for token in head.split("."):
        if not token.isdigit():
            break
        fields.append(int(token))
    return tuple(fields)


def runtime_line_ok(version: str) -> bool:
    """True when ``version`` sits inside the controlled line.

    An empty or unparseable version is False: no evidence, no qualification.
    """
    parsed = version_tuple(version)
    if not parsed:
        return False
    floor, ceiling = QUALIFIED_LINE
    padded = parsed + (0,) * max(0, len(floor) - len(parsed))
    return floor <= padded < ceiling


def reported_runtime_version() -> str | None:
    """The installed ``wasmtime`` distribution version, or None when absent."""
    try:
        return metadata.version("wasmtime")
    except metadata.PackageNotFoundError:
        return None


def import_error() -> str | None:
    """Why ``import wasmtime`` would fail here, or None when it works.

    Metadata and importability are different facts: a distribution can be
    recorded at the qualified version while its native library is broken or
    shadowed by a foreign ``wasmtime`` on ``sys.path``. Checking the metadata
    alone would call such an installation qualified and let the guest run into
    an import crash instead of a refusal.
    """
    try:
        importlib.import_module("wasmtime")
    except ImportError as exc:
        return f"{type(exc).__name__}: {exc}"
    return None


def runtime_qualification() -> tuple[bool, str]:
    """Whether guest execution is on the audited engine, plus the reason.

    The reason is user-facing and names the fix, because this string is what an
    operator reads when the gate refuses. Never raises.
    """
    version = reported_runtime_version()
    if version is None:
        return (
            False,
            "wasmtime is not installed — the 1.2.x line needs the qualified "
            'engine: pip install "wasmtime>=49.0.3,<50" (or the release '
            "wheelhouse)",
        )
    identity = native_engine_identity()
    if identity.match is False:
        return (
            False,
            f"native engine does not match the qualified 1.2.x build: "
            f"{identity.reason}. This is not the audited runtime, whatever the "
            "installed version string says; set "
            f"{UNQUALIFIED_RUNTIME_ENV}=1 only if you knowingly run an "
            "unqualified engine",
        )
    broken = import_error()
    if broken is not None:
        return (
            False,
            f"wasmtime {version} is recorded as installed but cannot be imported "
            f"({broken}) — the engine that would run the guest is not this one",
        )
    if not runtime_line_ok(version):
        floor, ceiling = QUALIFIED_LINE
        return (
            False,
            f"wasmtime {version} is outside the controlled line — this release "
            f"is qualified against wasmtime>={'.'.join(map(str, floor))},"
            f"<{ceiling[0]} only, and the unpatched build carries the advisories "
            "the fix line closes",
        )
    suffix = "; native identity verified" if identity.match is True else ""
    return True, f"wasmtime {version} on the qualified line{suffix}"


def unqualified_runtime_allowed() -> bool:
    """True when the operator has explicitly opted into an unqualified engine."""
    return os.environ.get(UNQUALIFIED_RUNTIME_ENV, "").strip().lower() in _TRUTHY
