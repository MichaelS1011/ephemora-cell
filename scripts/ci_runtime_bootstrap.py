#!/usr/bin/env python3
# SPDX-License-Identifier: BUSL-1.1
# Copyright 2026 Michael Soppa
"""Install the one qualified Wasmtime runtime in CI, fail-closed.

The product's security floor is the upstream 49.0.3 fix line, and the wheel that
carries it is not on PyPI. CI therefore downloads ONE versioned HTTPS artifact
and accepts it only if all of these hold:

* the URL is HTTPS (no credentials, no ``http://``, no local path);
* the wheel name, the wheel sha256 and the embedded native library sha256 are
  the qualified values below, checked *before* pip sees the file;
* the installed distribution reports the exact version and the loaded native
  library hashes to the qualified value, checked *after* installation;
* the interpreter runs natively on Apple Silicon (arm64, or a universal2 build
  whose ``platform.machine()`` is arm64) on a host of macOS 11.0 or newer, i.e.
  the only platform the wheel is tagged for. An x64/Rosetta interpreter or an
  older host is refused.

No index, no fallback, no cache: pip runs with ``--no-index --no-deps`` and the
download lives in a temporary directory. A missing release asset, a 404, a
truncated download or a substituted wheel is a red gate, never a downgrade to
the unpatched 49.0.0 line.

CI uses the default URL. ``--wheel`` exists for the local release audit and is
subject to the same name/hash/native-digest checks; it does not skip them.
"""

from __future__ import annotations

import argparse
import hashlib
import importlib.metadata as metadata
import platform
import re
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

#: Versioned release asset of this repository. The tag is dedicated to the
#: runtime; it is not a product release. The wheel sha256 above pins the bytes,
#: so the URL can move to a mirror only by editing this constant on purpose.
DEFAULT_URL = (
    "https://github.com/MichaelS1011/ephemora-cell/releases/download/"
    "wasmtime-runtime-49.0.4.post1/" + WHEEL_NAME
)
#: GitHub serves release downloads from github.com and redirects to one of these
#: asset hosts. A mirror needs a reviewed change here, not an environment value:
#: the download URL is part of the supply-chain decision.
ALLOWED_HOSTS = frozenset(
    {
        "github.com",
        "objects.githubusercontent.com",
        "release-assets.githubusercontent.com",
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


def _native_digest(archive: zipfile.ZipFile) -> str:
    members = [n for n in archive.namelist() if n == NATIVE_MEMBER]
    if len(members) != 1:
        raise BootstrapError(
            f"wheel carries {len(members)} {NATIVE_MEMBER!r} members, expected 1"
        )
    return hashlib.sha256(archive.read(NATIVE_MEMBER)).hexdigest()


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
            native = _native_digest(archive)
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


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument(
        "--url",
        default=DEFAULT_URL,
        help="versioned HTTPS wheel URL (default: the qualified release asset)",
    )
    parser.add_argument(
        "--wheel",
        type=Path,
        help="local wheel for the release audit; the same checks apply",
    )
    args = parser.parse_args(argv)
    try:
        tag = _platform_gate()
        _lock_agrees()
        with tempfile.TemporaryDirectory(prefix="ephemora-runtime-") as directory:
            if args.wheel is not None:
                wheel = args.wheel.resolve()
                if not wheel.is_file():
                    raise BootstrapError(f"runtime wheel not found: {wheel}")
            else:
                wheel = Path(directory) / WHEEL_NAME
                _download(args.url, wheel)
            wheel_sha256, native_sha256 = _verify_wheel(wheel)
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
