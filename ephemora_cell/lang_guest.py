# SPDX-License-Identifier: BUSL-1.1
# Copyright 2026 Michael Soppa

"""Language guest resolution — no manual hunting, no hidden downloads.

The 1.2.0 language decision makes Python and JavaScript mandatory
and states that after a documented install a developer must NOT have to hunt
for guest ``.wasm`` files, and that the runtime must NOT silently download or
execute a foreign interpreter. This module is the single place that turns that
contract into code:

* a guest is provided by an **official, versioned optional language package**
  installed alongside the core (declared via the ``python`` / ``javascript``
  extras in ``pyproject.toml``), which registers an entry point in the
  ``ephemora_cell.language_guest`` group;
* resolution happens at **install time delivery**, never by a runtime fetch —
  if no guest is installed the caller gets a fail-closed ``GuestNotInstalled``
  naming the exact ``pip install`` command, and NOTHING is downloaded or run;
* a bring-your-own guest (the historical research path, e.g. the pinned
  CPython-WASI 3.10 interpreter) stays fully supported through the
  ``EPHEMORA_BYO_*`` environment pins — those are the caller explicitly
  supplying a path, not a hidden lookup;
* when the resolved guest carries a pinned digest it is verified before the
  path is handed to a sandbox, so a swapped artifact fails closed.

This module owns no execution logic and imports no language runtime; it only
locates and validates the artifact bytes that an adapter is later asked to run
under the mandatory protection profile.
"""

from __future__ import annotations

import hashlib
import os
from collections.abc import Callable
from dataclasses import dataclass
from importlib import metadata

#: Entry-point group each optional language-guest distribution registers into.
GUEST_ENTRY_POINT_GROUP = "ephemora_cell.language_guest"

#: language id -> the human command that installs its guest (never downloaded).
_INSTALL_HINTS = {
    "python": 'pip install "ephemora-cell[python]"',
    "javascript": 'pip install "ephemora-cell[javascript]"',
}

#: BYO pins kept for the historical research path (explicit caller supply).
_BYO_ENV = {
    "python": (
        "EPHEMORA_BYO_PYTHON_GUEST",
        "EPHEMORA_BYO_PYTHON_STDLIB",
        "EPHEMORA_BYO_PYTHON_SHA256",
    ),
    "javascript": ("EPHEMORA_BYO_JS_GUEST", None, "EPHEMORA_BYO_JS_SHA256"),
}


class GuestNotInstalled(FileNotFoundError):
    """No guest is available for the language through an installed package or an
    explicit BYO pin. Fail-closed: the message names the install command and no
    download is ever attempted."""


@dataclass(frozen=True)
class GuestArtifact:
    """A resolved, digest-verified guest ready for an adapter to run isolated."""

    language: str
    wasm_path: str
    stdlib_dir: str | None
    expected_sha256: str | None
    version: str
    source: str  # "package:<distribution>" or "byo:<envvar>"


def _sha256_file(path: str) -> str:
    digest = hashlib.sha256()
    with open(path, "rb") as handle:
        for chunk in iter(lambda: handle.read(1 << 20), b""):
            digest.update(chunk)
    return digest.hexdigest()


def _verify_digest(wasm_path: str, expected_sha256: str | None) -> None:
    """Check the bytes on disk against the pinned digest before any run.

    A guest installed under an expected digest but with different bytes is a
    supply-chain mismatch — refuse before the sandbox ever sees the path.
    """
    if expected_sha256 is None:
        return
    actual = _sha256_file(wasm_path)
    if actual.lower() != expected_sha256.lower():
        raise GuestNotInstalled(
            f"guest digest mismatch for {wasm_path}: pinned {expected_sha256}, "
            f"found {actual} (refusing to run; no download attempted)"
        )


def _from_byo(language: str) -> GuestArtifact | None:
    """Honour an explicit caller-supplied guest (the BYO research path)."""
    guest_var, stdlib_var, sha_var = _BYO_ENV[language]
    wasm_path = os.environ.get(guest_var)
    if not wasm_path:
        return None
    if not os.path.exists(wasm_path):
        raise GuestNotInstalled(f"{guest_var} points at a missing file: {wasm_path}")
    stdlib_dir = os.environ.get(stdlib_var) if stdlib_var else None
    expected = os.environ.get(sha_var) if sha_var else None
    _verify_digest(wasm_path, expected)
    return GuestArtifact(
        language=language,
        wasm_path=wasm_path,
        stdlib_dir=stdlib_dir,
        expected_sha256=expected,
        version="byo",
        source=f"byo:{guest_var}",
    )


def _from_package(language: str) -> GuestArtifact | None:
    """Resolve a guest registered by an installed optional language package."""
    try:
        eps = list(metadata.entry_points(group=GUEST_ENTRY_POINT_GROUP))
    except TypeError:  # pragma: no cover - pre-3.10 metadata API
        eps = list(metadata.entry_points().select(group=GUEST_ENTRY_POINT_GROUP))
    for ep in eps:
        if ep.name != language:
            continue
        factory: Callable[[], dict] = ep.load()
        info = factory()
        wasm_path = info["wasm_path"]
        if not os.path.exists(wasm_path):
            raise GuestNotInstalled(
                f"installed guest for {language!r} is missing bytes at "
                f"{wasm_path} (reinstall {_INSTALL_HINTS.get(language, language)})"
            )
        expected = info.get("expected_sha256")
        _verify_digest(wasm_path, expected)
        dist_name = info.get("distribution")
        if dist_name is None:
            owner = getattr(ep, "dist", None)
            dist_name = owner.metadata["Name"] if owner is not None else ep.value
        return GuestArtifact(
            language=language,
            wasm_path=wasm_path,
            stdlib_dir=info.get("stdlib_dir"),
            expected_sha256=expected,
            version=str(info.get("version", ep.value)),
            source=f"package:{dist_name}",
        )
    return None


def resolve_guest(language: str) -> GuestArtifact:
    """Return the installed guest for ``language`` or fail closed.

    Precedence: an explicit BYO pin (caller supplied it) then an installed
    optional language package. Never downloads and never runs a host
    interpreter; an unavailable guest is a ``GuestNotInstalled`` naming the
    single documented install command.
    """
    if language not in _INSTALL_HINTS:
        raise GuestNotInstalled(f"no guest mechanism is defined for {language!r}")
    byo = _from_byo(language)
    if byo is not None:
        return byo
    packaged = _from_package(language)
    if packaged is not None:
        return packaged
    raise GuestNotInstalled(
        f"no {language} guest is installed. Install it with the single "
        f"documented command — {_INSTALL_HINTS[language]} — and no manual "
        f"guest hunting or runtime download is required (nothing was downloaded)."
    )
