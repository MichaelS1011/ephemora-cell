# SPDX-License-Identifier: BUSL-1.1
# Copyright 2026 Michael Soppa

"""Is this environment allowed to run guest code as the audited runtime?

The answer comes from distribution metadata, the sha256 of the exact native
file the bindings load (on the qualified platform), the mapped image's
``__TEXT``/``__LINKEDIT`` bytes on macOS, and one import probe, so it stays
reachable in an installation where ``wasmtime`` cannot even be imported — the
case where a diagnosis still has to be possible. The gate refuses a file
mismatch and refuses a mapped image that differs from the bytes it just
hashed. Importing ``ephemora_cell`` already maps the native library, so the
mapped check is what binds the executing image to the checked file; a
swap-and-restore that fools the file hash is refused. A local actor who can
write the package can still patch the check itself. This is a detection
control, not a tamper-proof boundary.

One line, two ways to be wrong about it:

* ``49.0.0`` through ``49.0.3`` are the published builds that carry the
  advisories the 49.0.4 fix line exists to close — including the aarch64
  Cranelift ``br_table`` sandbox escape (GHSA-mghf-wjfp-p5xm). Running a guest
  on any of them is not the configuration this release was audited against.
* a build that merely shares the ``49.0.4`` prefix (``.dirty``, a foreign wheel)
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

import ctypes
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
    "QUALIFIED_ENGINE_SHA256_BY_PLATFORM",
    "QUALIFIED_LINE",
    "UNQUALIFIED_RUNTIME_ENV",
    "NativeEngineIdentity",
    "import_error",
    "native_engine_identity",
    "native_library_path",
    "qualified_engine_sha256",
    "qualified_platform",
    "reported_runtime_version",
    "runtime_line_ok",
    "runtime_qualification",
    "unqualified_runtime_allowed",
    "version_tuple",
]

#: The controlled Wasmtime line this release is qualified against: ``[49.0.4, 50.0)``.
QUALIFIED_LINE = ((49, 0, 4), (50, 0))

#: sha256 of the qualified native engine build per supported platform.
#: macOS is the existing 1.2.x reference; Linux aarch64 is the Linux C API
#: asset from the same upstream v49.0.4 release, assembled with the same
#: byte-identical Python bindings (see the private release evidence).
QUALIFIED_ENGINE_SHA256_BY_PLATFORM = {
    ("darwin", "aarch64"): (
        "247c1529445001f4b6ed1d46d4f3b4a2c67f8a0c568c9e6559500eb1a89ca30b"
    ),
    ("linux", "aarch64"): (
        "57fa323d0a5d65c936d4feb3e3245c89bedc3ce5c9510a3d87cbae273b3640ec"
    ),
}

#: Backwards-compatible name for the macOS reference build.
QUALIFIED_ENGINE_SHA256 = QUALIFIED_ENGINE_SHA256_BY_PLATFORM[("darwin", "aarch64")]

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
    #: Whether the bytes mapped into this process match the file the gate
    #: hashed. ``None`` means the check could not run (wasmtime not imported
    #: yet, or a platform without a dyld image list); it never means "fine".
    mapped_match: bool | None = None
    mapped_reason: str = ""

    def verified(self) -> bool:
        """True only when the file and the executing image were both checked."""
        return self.match is True and self.mapped_match is True


#: Mach-O load-command constants (macOS). The gate runs on every platform, but
#: only darwin has this loaded-image check.
_LC_SEGMENT_64 = 0x19
_MAPPED_SEGMENTS = ("__TEXT", "__LINKEDIT")


class _MachHeader64(ctypes.Structure):
    _fields_ = [
        ("magic", ctypes.c_uint32),
        ("cputype", ctypes.c_uint32),
        ("cpusubtype", ctypes.c_uint32),
        ("filetype", ctypes.c_uint32),
        ("ncmds", ctypes.c_uint32),
        ("sizeofcmds", ctypes.c_uint32),
        ("flags", ctypes.c_uint32),
        ("reserved", ctypes.c_uint32),
    ]


class _LoadCommand(ctypes.Structure):
    _fields_ = [("cmd", ctypes.c_uint32), ("cmdsize", ctypes.c_uint32)]


class _SegmentCommand64(ctypes.Structure):
    _fields_ = [
        ("cmd", ctypes.c_uint32),
        ("cmdsize", ctypes.c_uint32),
        ("segname", ctypes.c_char * 16),
        ("vmaddr", ctypes.c_uint64),
        ("vmsize", ctypes.c_uint64),
        ("fileoff", ctypes.c_uint64),
        ("filesize", ctypes.c_uint64),
        ("maxprot", ctypes.c_uint32),
        ("initprot", ctypes.c_uint32),
        ("nsects", ctypes.c_uint32),
        ("flags", ctypes.c_uint32),
    ]


#: One successful comparison per process is enough: a mapped image cannot be
#: replaced in place. Keyed by the file's identity so a replaced file in a new
#: process is checked again.
_MAPPED_CHECKS: dict[tuple[str, int, int, int], tuple[bool, str]] = {}


def _loaded_image_matches_gated(path: Path) -> tuple[bool | None, str]:
    """Compare the mapped ``__TEXT``/``__LINKEDIT`` bytes with the gated file.

    Importing the package already maps the native library, so a file hash taken
    afterwards cannot by itself bind the executing image: an attacker who can
    write the wheel can swap the audited file out for the loader and restore it
    before the gate hashes it. The mapped image stays the unqualified one. This
    check closes that gap by hashing the bytes dyld actually mapped.

    ``__DATA_CONST``/``__DATA`` are deliberately excluded: dyld applies pointer
    relocations there, so they differ from the file even for an honest image.
    Returns ``None`` when the platform or import state cannot answer the
    question; on darwin with wasmtime imported, any inconsistency is ``False``.
    """
    if sys.platform != "darwin":
        return None, "loaded-image check is implemented for darwin only"
    if "wasmtime" not in sys.modules:
        return None, "wasmtime is not imported yet; the image cannot be checked"
    try:
        stat = path.stat()
        key = (str(path), stat.st_ino, stat.st_size, stat.st_mtime_ns)
    except OSError as exc:
        return False, f"cannot stat gated path {path}: {exc}"
    cached = _MAPPED_CHECKS.get(key)
    if cached is not None:
        return cached
    try:
        result = _loaded_image_matches_gated_uncached(path)
    except Exception as exc:  # malformed Mach-O, dyld symbols absent, mmap fault
        result = (False, f"loaded-image inspection failed: {type(exc).__name__}: {exc}")
    # Do not cache a "not imported yet" answer: the next call can check it.
    if result[0] is not None:
        _MAPPED_CHECKS[key] = result
    return result


def _loaded_image_matches_gated_uncached(path: Path) -> tuple[bool, str]:
    dyld = ctypes.CDLL(None)
    dyld._dyld_image_count.restype = ctypes.c_uint32
    dyld._dyld_get_image_name.restype = ctypes.c_char_p
    dyld._dyld_get_image_header.restype = ctypes.c_void_p
    wanted = os.path.realpath(path)
    header_addr = None
    for index in range(dyld._dyld_image_count()):
        name = dyld._dyld_get_image_name(index)
        if name is None:
            continue
        if os.path.realpath(os.fsdecode(name)) == wanted:
            header_addr = dyld._dyld_get_image_header(index)
            break
    if not header_addr:
        return False, f"gated path {path} is not a loaded dyld image"
    header = _MachHeader64.from_address(header_addr)
    text = None
    segments: list[_SegmentCommand64] = []
    address = header_addr + ctypes.sizeof(_MachHeader64)
    for _ in range(header.ncmds):
        command = _LoadCommand.from_address(address)
        if command.cmdsize < ctypes.sizeof(_LoadCommand):
            return False, "malformed Mach-O load command"
        if command.cmd == _LC_SEGMENT_64:
            segment = _SegmentCommand64.from_address(address)
            segments.append(segment)
            if segment.segname.rstrip(b"\x00") == b"__TEXT":
                text = segment
        address += command.cmdsize
    if text is None:
        return False, "loaded image has no __TEXT segment"
    slide = header_addr - text.vmaddr
    checked: list[str] = []
    with path.open("rb") as handle:
        for segment in segments:
            name = segment.segname.rstrip(b"\x00").decode("ascii", "replace")
            if name not in _MAPPED_SEGMENTS or segment.filesize == 0:
                continue
            mapped = ctypes.string_at(slide + segment.vmaddr, segment.filesize)
            handle.seek(segment.fileoff)
            on_disk = handle.read(segment.filesize)
            if mapped != on_disk:
                return (
                    False,
                    f"mapped {name} differs from the gated file "
                    f"({len(mapped)} bytes mapped, {len(on_disk)} on disk)",
                )
            checked.append(name)
    if "__TEXT" not in checked:
        return False, "no mapped __TEXT bytes were comparable"
    return True, "mapped " + "+".join(checked) + " match the gated file"


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


def qualified_engine_sha256() -> str | None:
    """The reference native digest for this platform, or None when absent."""
    return QUALIFIED_ENGINE_SHA256_BY_PLATFORM.get(
        (_loader_platform(), _normalized_machine())
    )


def qualified_platform() -> bool:
    """True only for a platform this release carries a reference build for."""
    return qualified_engine_sha256() is not None


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
    reference = qualified_engine_sha256()
    if path is None:
        return NativeEngineIdentity(
            None,
            None,
            False if reference is not None else None,
            "cannot locate the native library the wasmtime bindings load",
        )
    try:
        digest = _sha256_file(path)
    except OSError as exc:
        return NativeEngineIdentity(
            path,
            None,
            False if reference is not None else None,
            f"cannot read {path}: {exc}",
        )
    if reference is None:
        return NativeEngineIdentity(
            path,
            digest,
            None,
            "no qualified engine build exists for this platform; "
            "only the version line is checked",
        )
    if digest == reference:
        mapped, mapped_reason = _loaded_image_matches_gated(path)
        if mapped is False:
            return NativeEngineIdentity(
                path,
                digest,
                False,
                "engine file matches the qualified digest, but the bytes "
                f"mapped into this process do not: {mapped_reason}",
                mapped,
                mapped_reason,
            )
        reason = "engine artifact matches the qualified digest " f"{reference[:12]}..."
        if mapped is True:
            reason += "; " + mapped_reason
        elif mapped_reason:
            reason += "; " + mapped_reason
        return NativeEngineIdentity(path, digest, True, reason, mapped, mapped_reason)
    return NativeEngineIdentity(
        path,
        digest,
        False,
        f"engine artifact at {path} has sha256 {digest[:12]}..., the qualified "
        f"build has {reference[:12]}...",
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
    if identity.verified():
        suffix = "; native identity verified"
    elif identity.match is True:
        suffix = "; native file identity verified, loaded image not checked"
    else:
        suffix = ""
    return True, f"wasmtime {version} on the qualified line{suffix}"


def unqualified_runtime_allowed() -> bool:
    """True when the operator has explicitly opted into an unqualified engine."""
    return os.environ.get(UNQUALIFIED_RUNTIME_ENV, "").strip().lower() in _TRUTHY
