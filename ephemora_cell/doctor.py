# SPDX-License-Identifier: BUSL-1.1
# Copyright 2026 Michael Soppa

"""Local health checks for the Ephemora Cell installation.

``ephemora doctor`` answers one question: would a run on THIS machine be the
qualified 1.2.x configuration? The checks are deliberately offline — they
inspect the interpreter, the host platform, the installed package, the
Wasmtime runtime and its native engine bytes, the optional language guests,
the console entry points, and finally prove the whole chain with one tiny
end-to-end run. Nothing here downloads, installs or mutates state, and no
check ever raises: a broken installation is a ``fail`` result, not a traceback.
"""

from __future__ import annotations

import hashlib
import importlib
import importlib.metadata as metadata
import json
import os
import platform as _platform
import shutil
import sys
import tempfile
import time
from collections.abc import Callable
from dataclasses import asdict, dataclass
from pathlib import Path
from typing import Any

try:
    import wasmtime

    HAS_WASMTIME = True
except ImportError:  # pragma: no cover - wasmtime is a hard dependency
    HAS_WASMTIME = False

from . import lang_guest

# The controlled Wasmtime line lives in runtime_qualification, because the
# execution gate and this diagnosis must not be able to disagree.
from .runtime_qualification import (
    QUALIFIED_ENGINE_SHA256,
    UNQUALIFIED_RUNTIME_ENV,
    native_engine_identity,
    qualified_platform,
    reported_runtime_version,
    runtime_line_ok,
    runtime_qualification,
    unqualified_runtime_allowed,
)
from .wasi_runtime import ExecutionStatus, WASIConfig, WASISandbox

__all__ = [
    "UNQUALIFIED_RUNTIME_ENV",
    "CheckResult",
    "exit_code",
    "format_report",
    "run_checks",
    "runtime_line_ok",
    "runtime_qualification",
    "to_json",
    "unqualified_runtime_allowed",
]

_SCHEMA = "ephemora-cell/doctor/1"

#: Kept as a module-local alias for callers that imported it from doctor;
#: the single source is runtime_qualification.QUALIFIED_ENGINE_SHA256.
_QUALIFIED_ENGINE_SHA256 = QUALIFIED_ENGINE_SHA256

_STATUS_LABEL = {"ok": "PASS", "warn": "WARN", "fail": "FAIL"}

# Minimal WASI module: _start calls proc_exit(0). The memory export is not
# optional — wasmtime's WASI preview1 rejects a module without one.
_SMOKE_WAT = (
    b'(module (import "wasi_snapshot_preview1" "proc_exit" (func $e (param i32)))'
    b' (memory (export "memory") 1)'
    b' (func (export "_start") i32.const 0 call $e))'
)


@dataclass(frozen=True)
class CheckResult:
    """One doctor check outcome."""

    name: str
    status: str  # "ok" | "warn" | "fail"
    detail: str
    data: dict[str, Any]


def _sha256_file(path: Path) -> str:
    """Streamed sha256 of a file (chunked, never loads it whole)."""
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        for chunk in iter(lambda: handle.read(1 << 20), b""):
            digest.update(chunk)
    return digest.hexdigest()


def _editable_state() -> str:
    """Best-effort PEP 610 editable detection; ``"unknown"`` when not provable."""
    try:
        dist = metadata.distribution("ephemora-cell")
    except metadata.PackageNotFoundError:
        return "unknown"
    try:
        raw = dist.read_text("direct_url.json")
    except (OSError, ValueError):
        return "unknown"
    if not raw:
        return "unknown"
    try:
        info = json.loads(raw)
    except (TypeError, ValueError):
        return "unknown"
    dir_info = info.get("dir_info") if isinstance(info, dict) else None
    if isinstance(dir_info, dict) and "editable" in dir_info:
        return "editable" if dir_info["editable"] else "wheel"
    return "unknown"


def _check_python() -> CheckResult:
    info = sys.version_info
    version = f"{info.major}.{info.minor}.{info.micro}"
    ok = info >= (3, 10)
    detail = (
        f"Python {version}"
        if ok
        else f"Python {version} is too old; 1.2.x requires Python >= 3.10"
    )
    return CheckResult("python", "ok" if ok else "fail", detail, {"version": version})


def _check_platform() -> CheckResult:
    system = _platform.system()
    machine = _platform.machine()
    qualified = system == "Darwin" and machine == "arm64"
    detail = (
        f"{system}/{machine} — qualified platform"
        if qualified
        else f"{system}/{machine} — NOT QUALIFIED: 1.2.x is qualified on "
        "macOS arm64 only"
    )
    return CheckResult(
        "platform",
        "ok" if qualified else "warn",
        detail,
        {"system": system, "machine": machine},
    )


def _check_package() -> CheckResult:
    import ephemora_cell

    version = str(getattr(ephemora_cell, "__version__", "unknown"))
    pkg_file = ephemora_cell.__file__ or ""
    location = os.path.dirname(os.path.abspath(pkg_file)) if pkg_file else "unknown"
    editable = _editable_state()
    return CheckResult(
        "package",
        "ok",
        f"ephemora-cell {version} at {location} ({editable})",
        {"version": version, "location": location, "editable": editable},
    )


def _check_runtime_import() -> CheckResult:
    try:
        importlib.import_module("wasmtime")
    except ImportError as exc:
        return CheckResult(
            "runtime-import",
            "fail",
            f"wasmtime is not importable ({type(exc).__name__}: {exc}); install "
            'the qualified engine with: pip install "wasmtime>=49.0.3,<50" '
            "(or the v1.2.0 release wheelhouse)",
            {"error": f"{type(exc).__name__}: {exc}"},
        )
    try:
        version = metadata.version("wasmtime")
    except metadata.PackageNotFoundError:
        version = "unknown"
    return CheckResult(
        "runtime-import", "ok", f"wasmtime {version} imported", {"version": version}
    )


def _check_runtime_floor() -> CheckResult:
    """The EXECUTION GATE's own verdict, reported as a diagnosis.

    Deliberately the same call the sandbox consults before running a guest, so a
    report that says ``ok`` and a gate that refuses cannot coexist in one
    installation — the case this check used to produce when metadata named a
    qualified version the interpreter could not import. :mod:`runtime_qualification`
    is the one source for both sides.
    """
    qualified, why = runtime_qualification()
    version = reported_runtime_version()
    # A disabled execution gate has to be VISIBLE here: an operator who set the
    # hatch once and forgot it is running unqualified guests, and a doctor report
    # that stays silent about it reads like a clean installation.
    hatch = (
        " — NOTE: the execution gate is disabled by "
        f"{UNQUALIFIED_RUNTIME_ENV}=1, so guest code runs on this engine and is "
        "NOT covered by the release's runtime qualification"
        if unqualified_runtime_allowed()
        else ""
    )
    return CheckResult(
        "runtime-floor",
        "ok" if qualified else "fail",
        f"{why}{hatch}",
        {"version": version},
    )


def _engine_artifacts() -> list[dict[str, Any]]:
    """Native ``_libwasmtime*`` files under the package, for diagnosis.

    This is a listing, not the verdict: only the exact file the bindings load
    (``native_engine_identity``) decides ``match``. A backup copy must not be
    able to make a swapped loaded library look qualified.
    """
    if not HAS_WASMTIME:
        return []
    package_dir = Path(wasmtime.__file__).resolve().parent
    out: list[dict[str, Any]] = []
    for lib in sorted(package_dir.rglob("_libwasmtime*")):
        if lib.suffix in {".py", ".pyc"}:
            continue
        out.append(
            {
                "artifact": f"{lib.parent.name}/{lib.name}",
                "bytes": lib.stat().st_size,
                "sha256": _sha256_file(lib),
            }
        )
    return out


def _check_runtime_identity() -> CheckResult:
    identity = native_engine_identity()
    artifacts = _engine_artifacts()
    data: dict[str, Any] = {
        "artifacts": artifacts,
        "reference": _QUALIFIED_ENGINE_SHA256,
        "match": identity.match,
        "exact_artifact": str(identity.path) if identity.path else None,
        "exact_sha256": identity.sha256,
        "reason": identity.reason,
    }
    if identity.match is True:
        name = identity.path.name if identity.path else "the native engine"
        return CheckResult(
            "runtime-identity",
            "ok",
            f"{name} matches the qualified digest " f"{_QUALIFIED_ENGINE_SHA256[:12]}…",
            data,
        )
    # On the platform this release is qualified for, a missing or different
    # exact file is a FAILED claim, not a warning: the package says "audited
    # 1.2.x runtime" and the bytes say otherwise. The verdict follows the file
    # the bindings load, never "some _libwasmtime* file in the package".
    if qualified_platform() and identity.match is False:
        location = identity.path if identity.path else "the expected path"
        return CheckResult(
            "runtime-identity",
            "fail",
            f"the native engine at {location} does not match the qualified "
            f"release build {_QUALIFIED_ENGINE_SHA256[:12]}… ({identity.reason}) "
            "— this is not the audited 1.2.x runtime, whatever the installed "
            "version string says",
            data,
        )
    return CheckResult(
        "runtime-identity",
        "warn",
        f"native engine identity not matched against a qualified build "
        f"({identity.reason}); NOT QUALIFIED",
        data,
    )


def _check_language_guests() -> CheckResult:
    results: dict[str, str] = {}
    details: list[str] = []
    ok = True
    for language in ("python", "javascript"):
        try:
            guest = lang_guest.resolve_guest(language)
        except lang_guest.GuestNotInstalled as exc:
            ok = False
            results[language] = "missing"
            details.append(f"{language}: {exc}")
        except Exception as exc:  # resolution bug must not crash doctor
            ok = False
            results[language] = "error"
            details.append(f"{language}: {type(exc).__name__}: {exc}")
        else:
            results[language] = guest.wasm_path
            details.append(f"{language}: {guest.wasm_path}")
    return CheckResult(
        "language-guests",
        "ok" if ok else "warn",
        "; ".join(details),
        {"guests": results},
    )


def _script_shebang(path: str) -> str | None:
    """The interpreter a console script names on its ``#!`` line, if any."""
    try:
        with open(path, "rb") as handle:
            first = handle.readline(256)
    except OSError:
        return None
    if first.startswith(b"#"):
        return first[1:].decode("utf-8", "replace").strip()
    return None


def _shebang_names_this_interpreter(shebang: str, this_python: str) -> bool:
    """Whether a console script's ``#!`` line points at the running interpreter.

    Handles both spellings a wheel can produce: an absolute interpreter path and
    the ``#!/usr/bin/env python3`` form (matched on the interpreter's own file
    name, which is what the env shim would resolve).
    """
    parts = shebang.split()
    if not parts:
        return False
    if os.path.realpath(parts[0]) == this_python:
        return True
    return (
        os.path.basename(parts[0]) == "env"
        and len(parts) > 1
        and os.path.basename(parts[-1]) == os.path.basename(this_python)
    )


def _check_cli_entrypoints() -> CheckResult:
    """Where the console scripts of THIS installation actually live.

    ``PATH`` answers "can this shell type ``ephemora``"; the directory beside the
    running interpreter answers "is the release installed at all". A wheel
    installed into a virtual environment whose ``bin`` is not exported is a
    WORKING installation, so the second search decides the verdict and the first
    only shapes the advice — a WARN that fires on a good install teaches an
    operator to ignore the WARN that would catch a broken one.

    A PATH hit only counts when it belongs to this interpreter. The Homebrew
    ``ephemora-cell`` of an older release otherwise satisfied the check while the
    environment under test carried a different version, which would have made
    "entrypoints ok" a statement about some other installation.
    """
    script_dir = os.path.dirname(os.path.abspath(sys.executable))
    this_python = os.path.realpath(sys.executable)
    found: dict[str, str | None] = {}
    off_path: list[str] = []
    nowhere: list[str] = []
    foreign: list[str] = []
    for name in ("ephemora-cell", "ephemora"):
        beside = os.path.join(script_dir, name)
        on_path = shutil.which(name)
        if os.path.exists(beside):
            found[name] = beside
            if not on_path:
                off_path.append(name)
        elif on_path:
            shebang = _script_shebang(on_path) or ""
            if _shebang_names_this_interpreter(shebang, this_python):
                found[name] = on_path
            else:
                # The bare name resolves, but to somebody else's installation:
                # this environment still has no such entry point, and reporting
                # "ok" would describe an installation that is not the one running.
                found[name] = None
                nowhere.append(name)
                foreign.append(f"{name}={on_path} (shebang: {shebang or 'none'})")
        else:
            found[name] = None
            nowhere.append(name)
    detail = "; ".join(f"{name}={path}" for name, path in found.items() if path)
    if foreign:
        detail += (
            ("; " if detail else "")
            + "ignored PATH hits from another installation: "
            + ", ".join(foreign)
        )
    if off_path:
        detail += (
            " — not on PATH: "
            + ", ".join(off_path)
            + " (activate this environment or invoke the full path)"
        )
    if nowhere:
        return CheckResult(
            "cli-entrypoints",
            "warn",
            "found nowhere for this interpreter — neither beside "
            + script_dir
            + " nor on PATH as this environment's own script: "
            + ", ".join(nowhere)
            + (("; " + detail) if detail else ""),
            {"paths": found},
        )
    return CheckResult("cli-entrypoints", "ok", detail, {"paths": found})


def _check_smoke_run() -> CheckResult:
    if not HAS_WASMTIME:
        return CheckResult(
            "smoke-run",
            "fail",
            "wasmtime is not importable; the sandbox chain cannot be exercised",
            {},
        )
    wasm_path: str | None = None
    try:
        wasm_bytes = wasmtime.wat2wasm(_SMOKE_WAT)
        fd, wasm_path = tempfile.mkstemp(suffix=".wasm", prefix="ephemora_doctor_")
        with os.fdopen(fd, "wb") as handle:
            handle.write(wasm_bytes)
        started = time.monotonic()
        result = WASISandbox(config=WASIConfig(timeout_seconds=10)).run(wasm_path)
        elapsed_ms = (time.monotonic() - started) * 1000
        ok = result.status == ExecutionStatus.SUCCESS
        return CheckResult(
            "smoke-run",
            "ok" if ok else "fail",
            f"end-to-end run {result.status.value} in {elapsed_ms:.1f} ms "
            f"(mode={result.execution_mode})"
            + ("" if ok else f": {result.stderr.strip()[:200]}"),
            {
                "status": result.status.value,
                "elapsed_ms": round(elapsed_ms, 3),
                "execution_mode": result.execution_mode,
            },
        )
    except Exception as exc:
        return CheckResult(
            "smoke-run",
            "fail",
            f"smoke run could not complete: {type(exc).__name__}: {exc}",
            {},
        )
    finally:
        if wasm_path is not None:
            try:
                os.unlink(wasm_path)
            except OSError:
                pass


def _guard(name: str, fn: Callable[[], CheckResult]) -> CheckResult:
    try:
        return fn()
    except Exception as exc:
        return CheckResult(
            name, "fail", f"check crashed: {type(exc).__name__}: {exc}", {}
        )


_CHECKS: tuple[tuple[str, Callable[[], CheckResult]], ...] = (
    ("python", _check_python),
    ("platform", _check_platform),
    ("package", _check_package),
    ("runtime-import", _check_runtime_import),
    ("runtime-floor", _check_runtime_floor),
    ("runtime-identity", _check_runtime_identity),
    ("language-guests", _check_language_guests),
    ("cli-entrypoints", _check_cli_entrypoints),
    ("smoke-run", _check_smoke_run),
)


def run_checks() -> list[CheckResult]:
    """Run all checks in order; never raises (a crash becomes a ``fail``)."""
    return [_guard(name, fn) for name, fn in _CHECKS]


def exit_code(checks: list[CheckResult]) -> int:
    """0 when no check failed, else 1."""
    return 1 if any(c.status == "fail" for c in checks) else 0


def to_json(checks: list[CheckResult]) -> dict[str, Any]:
    """Machine payload for ``--json``."""
    summary = {"ok": 0, "warn": 0, "fail": 0}
    for check in checks:
        if check.status in summary:
            summary[check.status] += 1
    return {
        "schema": _SCHEMA,
        "ok": summary["fail"] == 0,
        "summary": summary,
        "checks": [asdict(c) for c in checks],
    }


def format_report(checks: list[CheckResult]) -> str:
    """Human report: 'PASS/WARN/FAIL  name — detail' plus a summary line."""
    lines = [
        f"{_STATUS_LABEL.get(c.status, c.status.upper()):<4}  {c.name} — {c.detail}"
        for c in checks
    ]
    summary = to_json(checks)["summary"]
    lines.append(
        f"summary: {summary['ok']} ok, {summary['warn']} warn, {summary['fail']} fail"
    )
    return "\n".join(lines)
