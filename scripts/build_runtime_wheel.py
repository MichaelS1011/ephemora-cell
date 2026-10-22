#!/usr/bin/env python3
# SPDX-License-Identifier: BUSL-1.1
# Copyright 2026 Michael Soppa
"""Assemble the qualified Wasmtime runtime wheel from pinned upstream inputs.

The native engine is NOT compiled here. It is the official C API dylib from the
Wasmtime release asset, pinned by tarball digest; the Python bindings are the
byte-identical files from the PyPI ``wasmtime`` wheel, pinned by wheel digest.
The assembly is deterministic: fixed ZIP timestamps, sorted entries, fixed
metadata. Two runs must produce the same wheel sha256.

    python scripts/build_runtime_wheel.py \
        --tarball wasmtime-v49.0.4-aarch64-macos-c-api.tar.xz \
        --bindings wasmtime-49.0.0-py3-none-macosx_11_0_arm64.whl \
        --out dist
"""

from __future__ import annotations

import argparse
import base64
import hashlib
import tarfile
import zipfile
from pathlib import Path

UPSTREAM_TAG = "v49.0.4"
UPSTREAM_COMMIT = "2c2970205fe05d6bbf15b9bff6f1e67874b2db5c"
FIX_COMMIT = "994549891c"  # "Security Fixes for release 49.0.4" (#14820)
VERSION = "49.0.4.post1+git.2c2970205f"
DIST = f"wasmtime-{VERSION}"
WHEEL_NAME = f"{DIST}-py3-none-macosx_11_0_arm64.whl"
TARBALL_SHA256 = "f83147d18f6089bfb0c5f01b8158f051fe98d26fb0a0e0dbb40a6b8cd8045460"
BINDINGS_SHA256 = "de98d6282c61d5dd4dc1ff1b410936ceb6fff3a27439e9cab51a375b8da2ec2f"
BINDINGS_DIST = "wasmtime-49.0.0.dist-info"
ZIP_EPOCH = (2026, 10, 19, 0, 0, 0)


def _sha256(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        for chunk in iter(lambda: handle.read(1 << 20), b""):
            digest.update(chunk)
    return digest.hexdigest()


def _record_hash(data: bytes) -> str:
    return base64.urlsafe_b64encode(hashlib.sha256(data).digest()).rstrip(b"=").decode()


def build(tarball: Path, bindings: Path, out: Path) -> Path:
    if _sha256(tarball) != TARBALL_SHA256:
        raise SystemExit("official C API tarball digest mismatch")
    if _sha256(bindings) != BINDINGS_SHA256:
        raise SystemExit("bindings wheel digest mismatch")

    with tarfile.open(tarball) as archive:
        member = archive.getmember(
            f"wasmtime-{UPSTREAM_TAG}-aarch64-macos-c-api/lib/libwasmtime.dylib"
        )
        dylib = archive.extractfile(member).read()

    with zipfile.ZipFile(bindings) as base:
        py_files = {
            name: base.read(name)
            for name in base.namelist()
            if name.startswith("wasmtime/") and name.endswith(".py")
        }
        license_bytes = base.read(f"{BINDINGS_DIST}/licenses/LICENSE")
        metadata = base.read(f"{BINDINGS_DIST}/METADATA").decode()
    if not py_files:
        raise SystemExit("bindings wheel carries no wasmtime/*.py")

    metadata = metadata.replace("Version: 49.0.0", f"Version: {VERSION}", 1)
    if f"Version: {VERSION}" not in metadata:
        raise SystemExit("METADATA version rewrite failed")

    wheel_text = (
        "Wheel-Version: 1.0\n"
        "Generator: ephemora-runtime-assembly (official Wasmtime 49.0.4 C API)\n"
        "Root-Is-Purelib: true\n"
        "Tag: py3-none-macosx_11_0_arm64\n"
    )
    files: dict[str, bytes] = {
        "wasmtime/darwin-aarch64/_libwasmtime.dylib": dylib,
        **py_files,
        f"{DIST}.dist-info/licenses/LICENSE": license_bytes,
        f"{DIST}.dist-info/METADATA": metadata.encode(),
        f"{DIST}.dist-info/WHEEL": bytes(wheel_text, "utf-8"),
        f"{DIST}.dist-info/top_level.txt": b"wasmtime\n",
    }
    record = [
        f"{name},sha256={_record_hash(data)},{len(data)}"
        for name, data in sorted(files.items())
    ]
    record.append(f"{DIST}.dist-info/RECORD,,")
    files[f"{DIST}.dist-info/RECORD"] = ("\n".join(record) + "\n").encode()

    out.mkdir(parents=True, exist_ok=True)
    target = out / WHEEL_NAME
    with zipfile.ZipFile(target, "w", zipfile.ZIP_DEFLATED) as wheel:
        for name in sorted(files):
            info = zipfile.ZipInfo(name, date_time=ZIP_EPOCH)
            info.compress_type = zipfile.ZIP_DEFLATED
            info.external_attr = 0o644 << 16
            wheel.writestr(info, files[name])

    print(f"wheel        {target}")
    print(f"wheel sha256 {_sha256(target)}")
    print(f"dylib sha256 {hashlib.sha256(dylib).hexdigest()}")
    print(f"version      {VERSION}")
    print(f"upstream     {UPSTREAM_TAG} {UPSTREAM_COMMIT} (fix {FIX_COMMIT})")
    return target


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--tarball", type=Path, required=True)
    parser.add_argument("--bindings", type=Path, required=True)
    parser.add_argument("--out", type=Path, default=Path("dist"))
    args = parser.parse_args()
    build(args.tarball, args.bindings, args.out)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
