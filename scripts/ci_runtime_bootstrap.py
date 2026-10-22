#!/usr/bin/env python3
# SPDX-License-Identifier: BUSL-1.1
# Copyright 2026 Michael Soppa
"""Build or install the one qualified Wasmtime runtime, fail-closed.

The product's security floor is the upstream 49.0.4 fix line, and PyPI carries
no 49.0.4 wheel. ``--prepare`` therefore builds the wheel from two pinned
upstream inputs with the checked-in recipe:

* the official C-API tarball ``wasmtime-v49.0.4-aarch64-macos-c-api.tar.xz``
  (sha256 ``f83147d1…5460``), and
* the official ``wasmtime`` 49.0.0 macOS arm64 bindings wheel
  (sha256 ``de98d628…ec2f``).

Both input hashes are checked before the build. The built wheel must then have
the qualified name, wheel sha256, embedded native-library sha256 and version.
``--wheel`` installs a wheel produced by that same build (the workflow artifact)
under the same checks. ``--url`` is retained only for an explicit local/release
audit of a prebuilt wheel.

All modes share the platform gate: arm64 hardware, an arm64 or universal2
interpreter, and a host of macOS 11.0 or newer. Installation is
``--no-index --no-deps`` and the loaded native library is re-hashed. A missing
or substituted input, a build failure, a wrong architecture or a foreign PyPI
wheel is a red gate; there is no fallback to an unpatched 49.0.0-49.0.3 engine.
"""

from __future__ import annotations

import argparse
import hashlib
import importlib.metadata as metadata
import platform
import re
import shutil
import subprocess
import sys
import sysconfig
import tempfile
import urllib.parse
import urllib.request
import zipfile
from pathlib import Path

VERSION = "49.0.4.post1+git.2c2970205f"
WHEEL_NAME = "wasmtime-49.0.4.post1+git.2c2970205f-py3-none-macosx_11_0_arm64.whl"
WHEEL_SHA256 = "5d1ac8807b9d99d3d6824560d729bf11f93c8b348590d7547557d2345bd0865e"
NATIVE_MEMBER = "wasmtime/darwin-aarch64/_libwasmtime.dylib"
NATIVE_SHA256 = "247c1529445001f4b6ed1d46d4f3b4a2c67f8a0c568c9e6559500eb1a89ca30b"

#: Pinned upstream inputs. Changing either URL or hash is a reviewed code change;
#: neither is read from an environment variable.
C_API_URL = (
    "https://github.com/bytecodealliance/wasmtime/releases/download/v49.0.4/"
    "wasmtime-v49.0.4-aarch64-macos-c-api.tar.xz"
)
C_API_SHA256 = "f83147d18f6089bfb0c5f01b8158f051fe98d26fb0a0e0dbb40a6b8cd8045460"
BINDINGS_URL = (
    "https://files.pythonhosted.org/packages/b7/c1/"
    "2333bb9b9364c28b4d113853d4e002e6ee3ee8d87d33b413dfdb220ce4d1/"
    "wasmtime-49.0.0-py3-none-macosx_11_0_arm64.whl"
)
BINDINGS_SHA256 = "de98d6282c61d5dd4dc1ff1b410936ceb6fff3a27439e9cab51a375b8da2ec2f"
BUILD_SCRIPT = Path(__file__).resolve().with_name("build_runtime_wheel.py")

#: A prebuilt wheel may still be supplied explicitly for a local release audit.
#: It is not the default path: the PR workflow builds from the pinned inputs.
DEFAULT_URL = (
    "https://github.com/MichaelS1011/ephemora-cell/releases/download/"
    "wasmtime-runtime-49.0.4.post1/" + WHEEL_NAME
)
#: GitHub serves release downloads from github.com and redirects to one of these
#: asset hosts. The bindings wheel comes directly from PyPI's file CDN. A mirror
#: needs a reviewed change here, not an environment value: the download URL is
#: part of the supply-chain decision.
ALLOWED_HOSTS = frozenset(
    {
        "github.com",
        "objects.githubusercontent.com",
        "release-assets.githubusercontent.com",
        "files.pythonhosted.org",
    }
)
MAX_DOWNLOAD_BYTES = 32 * 1024 * 1024
CHUNK = 1 << 20


class BootstrapError(RuntimeError):
    """A checked condition failed; the message is the GitHub error line."""


def _require_https(url: str) -> str:
    parsed = urllib.parse.urlparse(url)
    if parsed.scheme != "https":
        raise BootstrapError(f"runtime URL must be https, got {parsed.scheme!r}")
    if parsed.username or parsed.password:
        raise BootstrapError("runtime URL must not carry credentials")
    if parsed.hostname not in ALLOWED_HOSTS:
        raise BootstrapError(
            f"runtime URL host {parsed.hostname!r} is not an allowed asset host"
        )
    return url


def _sha256(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        for chunk in iter(lambda: handle.read(CHUNK), b""):
            digest.update(chunk)
    return digest.hexdigest()


def _download(url: str, destination: Path) -> None:
    request = urllib.request.Request(
        _require_https(url), headers={"User-Agent": "ephemora-cell-ci-runtime/1.2"}
    )
    with urllib.request.urlopen(request, timeout=60) as response:
        _require_https(response.geturl())
        declared = response.headers.get("Content-Length")
        if declared is not None:
            try:
                length = int(declared)
            except ValueError:
                length = None
            if length is not None and length > MAX_DOWNLOAD_BYTES:
                raise BootstrapError(
                    f"runtime download declares {length} bytes; limit is "
                    f"{MAX_DOWNLOAD_BYTES}"
                )
        seen = 0
        with destination.open("wb") as handle:
            while True:
                chunk = response.read(CHUNK)
                if not chunk:
                    break
                seen += len(chunk)
                if seen > MAX_DOWNLOAD_BYTES:
                    raise BootstrapError("runtime download exceeds the size limit")
                handle.write(chunk)
    if seen == 0:
        raise BootstrapError("runtime download was empty")


def _wheel_metadata(archive: zipfile.ZipFile) -> str:
    members = [n for n in archive.namelist() if n.endswith(".dist-info/METADATA")]
    if len(members) != 1:
        raise BootstrapError(f"wheel has {len(members)} METADATA members, expected 1")
    return archive.read(members[0]).decode("utf-8", "replace")


def _native_bytes(archive: zipfile.ZipFile) -> bytes:
    members = [n for n in archive.namelist() if n == NATIVE_MEMBER]
    if len(members) != 1:
        raise BootstrapError(
            f"wheel carries {len(members)} {NATIVE_MEMBER!r} members, expected 1"
        )
    return archive.read(NATIVE_MEMBER)


def _is_arm64_macho(data: bytes) -> bool:
    """True for a thin 64-bit little-endian Mach-O with CPU_TYPE_ARM64."""
    if len(data) < 8 or data[:4] != b"\xcf\xfa\xed\xfe":
        return False
    return int.from_bytes(data[4:8], "little") == 0x0100000C


def _verify_input(path: Path, expected_sha256: str, label: str) -> str:
    if not path.is_file():
        raise BootstrapError(f"{label} not found: {path}")
    actual = _sha256(path)
    if actual != expected_sha256:
        raise BootstrapError(f"{label} sha256 {actual} != pinned {expected_sha256}")
    return actual


def _verify_wheel(
    path: Path,
    *,
    expected_name: str = WHEEL_NAME,
    expected_sha256: str = WHEEL_SHA256,
    expected_native_sha256: str = NATIVE_SHA256,
) -> tuple[str, str]:
    if path.name != expected_name:
        raise BootstrapError(f"runtime wheel name {path.name!r} != {expected_name!r}")
    actual = _sha256(path)
    if actual != expected_sha256:
        raise BootstrapError(
            f"runtime wheel sha256 {actual} != qualified {expected_sha256}"
        )
    try:
        with zipfile.ZipFile(path) as archive:
            native_bytes = _native_bytes(archive)
            native = hashlib.sha256(native_bytes).hexdigest()
            fields: dict[str, str] = {}
            for line in _wheel_metadata(archive).splitlines():
                if not line:
                    break
                key, _, value = line.partition(": ")
                if key and value:
                    fields.setdefault(key, value)
    except zipfile.BadZipFile as exc:
        raise BootstrapError(f"runtime wheel is not a valid zip: {exc}") from exc
    if native != expected_native_sha256:
        raise BootstrapError(
            f"embedded native library sha256 {native} != qualified "
            f"{expected_native_sha256}"
        )
    if not _is_arm64_macho(native_bytes):
        raise BootstrapError("embedded native library is not a thin arm64 Mach-O")
    if fields.get("Version") != VERSION:
        raise BootstrapError(
            f"runtime wheel declares version {fields.get('Version')!r} != {VERSION!r}"
        )
    license_expression = fields.get("License-Expression") or fields.get("License", "")
    if license_expression != "Apache-2.0 WITH LLVM-exception":
        raise BootstrapError(
            "runtime wheel does not declare Apache-2.0 WITH LLVM-exception"
        )
    return actual, native


_ARM64_TAG = re.compile(r"macosx-(\d+)\.(\d+)-(arm64|universal2)")


def _platform_gate() -> str:
    machine = platform.machine()
    if machine != "arm64":
        raise BootstrapError(
            f"qualified runtime requires arm64 macOS, this interpreter reports {machine!r}"
        )
    tag = sysconfig.get_platform()
    if _ARM64_TAG.fullmatch(tag) is None:
        raise BootstrapError(
            "qualified runtime requires an arm64 or universal2 macOS interpreter, "
            f"got platform tag {tag!r}"
        )
    # A universal2 interpreter's tag carries its deployment target (10.13), not
    # the host it runs on; the wheel's macOS 11.0 floor applies to the host.
    release = platform.mac_ver()[0]
    parts = release.split(".")
    try:
        version = (int(parts[0]), int(parts[1]) if len(parts) > 1 else 0)
    except (ValueError, IndexError) as exc:
        raise BootstrapError(f"cannot read the macOS version from {release!r}") from exc
    if version < (11, 0):
        raise BootstrapError(
            f"runtime wheel is tagged macOS 11.0+, this host reports {release!r}"
        )
    return tag


def _lock_agrees() -> None:
    lock = Path(__file__).resolve().parents[1] / "requirements.lock"
    if not lock.is_file():
        return
    text = lock.read_text(encoding="utf-8")
    if VERSION not in text or WHEEL_SHA256 not in text:
        raise BootstrapError(
            f"{lock.name} does not carry the runtime version/hash this script pins"
        )


def _install(wheel: Path) -> None:
    subprocess.run(
        [
            sys.executable,
            "-m",
            "pip",
            "install",
            "--no-index",
            "--no-deps",
            "--force-reinstall",
            str(wheel),
        ],
        check=True,
    )


def _verify_installed() -> tuple[Path, str]:
    try:
        version = metadata.version("wasmtime")
    except metadata.PackageNotFoundError as exc:
        raise BootstrapError("wasmtime is not installed after the bootstrap") from exc
    if version != VERSION:
        raise BootstrapError(f"installed wasmtime {version!r} != qualified {VERSION!r}")
    try:
        import wasmtime
    except ImportError as exc:
        raise BootstrapError(f"installed wasmtime does not import: {exc}") from exc
    library = (
        Path(wasmtime.__file__).resolve().parent
        / f"{sys.platform}-aarch64"
        / "_libwasmtime.dylib"
    )
    if not library.is_file():
        raise BootstrapError(f"qualified native library not found at {library}")
    digest = _sha256(library)
    if digest != NATIVE_SHA256:
        raise BootstrapError(
            f"loaded native library sha256 {digest} != qualified {NATIVE_SHA256}"
        )
    return library, digest


def _prepare(
    out: Path, *, tarball: Path | None, bindings: Path | None
) -> tuple[Path, str, str]:
    """Build the qualified wheel from the two pinned upstream inputs."""
    if (tarball is None) != (bindings is None):
        raise BootstrapError("--tarball and --bindings must be supplied together")
    if not BUILD_SCRIPT.is_file():
        raise BootstrapError(f"build recipe not found: {BUILD_SCRIPT}")
    out = out.resolve()
    out.mkdir(parents=True, exist_ok=True)
    with tempfile.TemporaryDirectory(prefix="ephemora-runtime-build-") as directory:
        work = Path(directory)
        if tarball is None:
            tarball = work / "wasmtime-v49.0.4-aarch64-macos-c-api.tar.xz"
            bindings = work / "wasmtime-49.0.0-py3-none-macosx_11_0_arm64.whl"
            _download(C_API_URL, tarball)
            _download(BINDINGS_URL, bindings)
        _verify_input(tarball, C_API_SHA256, "C-API tarball")
        _verify_input(bindings, BINDINGS_SHA256, "bindings wheel")
        build_dir = work / "wheel"
        subprocess.run(
            [
                sys.executable,
                str(BUILD_SCRIPT),
                "--tarball",
                str(tarball),
                "--bindings",
                str(bindings),
                "--out",
                str(build_dir),
            ],
            check=True,
        )
        wheel = build_dir / WHEEL_NAME
        if not wheel.is_file():
            raise BootstrapError(f"build did not produce {WHEEL_NAME}")
        wheel_sha256, native_sha256 = _verify_wheel(wheel)
        target = out / WHEEL_NAME
        shutil.copy2(wheel, target)
        if _sha256(target) != wheel_sha256:
            raise BootstrapError("copied wheel digest changed after the build")
    return target, wheel_sha256, native_sha256


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument(
        "--prepare",
        action="store_true",
        help="build the qualified wheel from pinned upstream inputs and stop",
    )
    parser.add_argument(
        "--wheel",
        type=Path,
        help="wheel produced by --prepare; install it under the same checks",
    )
    parser.add_argument(
        "--url",
        default=None,
        help="explicit prebuilt wheel URL for a local/release audit (not the default)",
    )
    parser.add_argument(
        "--out",
        type=Path,
        default=Path("dist"),
        help="directory for --prepare (default: dist)",
    )
    parser.add_argument(
        "--tarball",
        type=Path,
        help="local official C-API tarball for an offline build audit",
    )
    parser.add_argument(
        "--bindings",
        type=Path,
        help="local official bindings wheel for an offline build audit",
    )
    args = parser.parse_args(argv)
    if args.prepare and (args.wheel is not None or args.url is not None):
        parser.error("--prepare cannot be combined with --wheel or --url")
    if args.wheel is not None and args.url is not None:
        parser.error("--wheel and --url are mutually exclusive")
    if (args.tarball is not None) != (args.bindings is not None):
        parser.error("--tarball and --bindings must be supplied together")
    try:
        tag = _platform_gate()
        _lock_agrees()
        if args.prepare:
            wheel, wheel_sha256, native_sha256 = _prepare(
                args.out, tarball=args.tarball, bindings=args.bindings
            )
            print(
                "prepared runtime: "
                f"version={VERSION} wheel={wheel} wheel_sha256={wheel_sha256} "
                f"native_sha256={native_sha256} platform={tag} "
                f"python={sys.version.split()[0]}"
            )
            return 0
        with tempfile.TemporaryDirectory(prefix="ephemora-runtime-") as directory:
            if args.wheel is not None:
                wheel = args.wheel.resolve()
                if not wheel.is_file():
                    raise BootstrapError(f"runtime wheel not found: {wheel}")
                wheel_sha256, native_sha256 = _verify_wheel(wheel)
            elif args.url is not None:
                wheel = Path(directory) / WHEEL_NAME
                _download(args.url, wheel)
                wheel_sha256, native_sha256 = _verify_wheel(wheel)
            else:
                wheel, wheel_sha256, native_sha256 = _prepare(
                    Path(directory) / "wheel",
                    tarball=args.tarball,
                    bindings=args.bindings,
                )
            _install(wheel)
        library, loaded = _verify_installed()
        print(
            "qualified runtime: "
            f"version={VERSION} wheel_sha256={wheel_sha256} "
            f"native_sha256={native_sha256} loaded_sha256={loaded} "
            f"library={library} platform={tag} python={sys.version.split()[0]}"
        )
        return 0
    except BootstrapError as exc:
        print(f"::error::runtime bootstrap: {exc}", file=sys.stderr)
        return 1
    except (OSError, subprocess.CalledProcessError) as exc:
        print(f"::error::runtime bootstrap failed: {exc}", file=sys.stderr)
        return 1


if __name__ == "__main__":
    sys.exit(main())
