#!/usr/bin/env python3
# SPDX-License-Identifier: BUSL-1.1
"""Check the CA bundles that the Python toolchain actually loads.

The eMudhra/emSign incident removed ``emSign ECC Root CA - G3`` from the
audited certifi line. A system-store update is not enough: pip and certifi
load their own bundles, and the active interpreter may also carry an
``ensurepip`` wheel with an older vendored certifi. This check is fail-closed
for the active environment and reports the system/ensurepip bundles
separately (they are not silently treated as fixed).
"""

from __future__ import annotations

import argparse
import importlib.metadata as md
import subprocess
import sys
import tempfile
import zipfile
from pathlib import Path

import certifi

MIN_PIP = (26, 2, 2)
MIN_CERTIFI = (2026, 10, 19)
REMOVED_SUBJECT = "CN=emSign ECC Root CA - G3"
SYSTEM_BUNDLES = (
    Path("/etc/ssl/cert.pem"),
    Path("/opt/homebrew/etc/openssl@3/cert.pem"),
)


def _version_tuple(text: str) -> tuple[int, ...]:
    parts: list[int] = []
    for part in text.split("."):
        digits = "".join(ch for ch in part if ch.isdigit())
        if not digits:
            break
        parts.append(int(digits))
    return tuple(parts)


def _bundle_has_removed_root(path: Path) -> bool:
    try:
        pkcs7 = subprocess.run(
            ["openssl", "crl2pkcs7", "-nocrl", "-certfile", str(path)],
            capture_output=True,
            text=True,
            check=True,
        )
        listed = subprocess.run(
            ["openssl", "pkcs7", "-print_certs", "-noout"],
            input=pkcs7.stdout,
            capture_output=True,
            text=True,
            check=True,
        )
    except (OSError, subprocess.CalledProcessError) as exc:
        raise SystemExit(f"FAIL: cannot parse CA bundle {path}: {exc}") from exc
    return REMOVED_SUBJECT in listed.stdout


def _check_bundle(label: str, path: Path, *, fatal: bool) -> bool:
    if not path.is_file():
        print(f"SKIP {label}: {path} is not present")
        return True
    present = _bundle_has_removed_root(path)
    status = "FAIL" if present and fatal else "WARN" if present else "OK"
    print(
        f"{status} {label}: {path} {'contains' if present else 'does not contain'} {REMOVED_SUBJECT}"
    )
    return not (present and fatal)


def _ensurepip_bundles() -> list[Path]:
    try:
        import ensurepip
    except ImportError:
        return []
    bundled = Path(ensurepip.__file__).with_name("_bundled")
    return sorted(bundled.glob("pip-*.whl"))


def _check_ensurepip() -> None:
    for wheel in _ensurepip_bundles():
        try:
            with zipfile.ZipFile(wheel) as archive:
                data = archive.read("pip/_vendor/certifi/cacert.pem")
        except (KeyError, OSError, zipfile.BadZipFile) as exc:
            print(f"WARN ensurepip {wheel.name}: cannot read vendored certifi: {exc}")
            continue
        with tempfile.NamedTemporaryFile(suffix=".pem") as handle:
            handle.write(data)
            handle.flush()
            if _bundle_has_removed_root(Path(handle.name)):
                print(f"WARN ensurepip {wheel.name}: contains {REMOVED_SUBJECT}")
            else:
                print(f"OK ensurepip {wheel.name}: does not contain {REMOVED_SUBJECT}")


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument(
        "--skip-system",
        action="store_true",
        help="do not report the OS trust store (the product does not use it)",
    )
    args = parser.parse_args()

    pip_version = md.version("pip")
    certifi_version = certifi.__version__
    failures: list[str] = []
    if _version_tuple(pip_version) < MIN_PIP:
        failures.append(f"pip {pip_version} < 26.2.2")
    if _version_tuple(certifi_version) < MIN_CERTIFI:
        failures.append(f"certifi {certifi_version} < 2026.10.19")

    if not _check_bundle("active certifi", Path(certifi.where()), fatal=True):
        failures.append("active certifi bundle contains the removed root")

    try:
        import pip
    except ImportError:
        print("WARN pip module is not importable; vendored bundle not checked")
    else:
        vendored = Path(pip.__file__).parent / "_vendor" / "certifi" / "cacert.pem"
        if not _check_bundle("pip vendored certifi", vendored, fatal=True):
            failures.append("pip vendored bundle contains the removed root")

    _check_ensurepip()

    if not args.skip_system:
        for bundle in SYSTEM_BUNDLES:
            _check_bundle("system CA", bundle, fatal=False)

    print(f"active environment: pip {pip_version}, certifi {certifi_version}")
    if failures:
        for failure in failures:
            print(f"FAIL {failure}")
        return 1
    print("CA store check: active environment is fixed")
    return 0


if __name__ == "__main__":
    sys.exit(main())
