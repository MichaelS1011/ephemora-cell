#!/usr/bin/env python3
"""Watch the three external gates ADR-009 sets for the language roadmap.

Gate 1 — engine upgrade window: Python wheels on PyPI for the wasmtime
patch releases covering the 2026 advisory batch (GHSA-m63x-6p34-q65x,
GHSA-vqjp-4c8c-hfgg / CVE-2026-47261, GHSA-j2g9-4prp-pf6h,
GHSA-c9gc-w9vx-w86p, GHSA-jqpg-j7w6-42pr). The 48.0.3 / 49.0.1 targets
cover the full batch; 47.0.4 covers the 47.x-line subset (per-advisory
mapping in SECURITY.md).

Gate 2 — wasmtime-py 0.3 component surface: the Python bindings expose
`Linker.add_wasip3` (today only `add_wasip2`/`add_wasi_http` exist —
asserted in tests/test_surface_audit.py). The bindings track the wasmtime
C API, so this checks the installed package (offline) and the
bytecodealliance/wasmtime-py main branch (online) for `add_wasip3`.

Gate 3 — GC-heap limiter binding: a `ResourceLimiter`-style GC-heap hook
in wasmtime-py (SECURITY.md LTS gate for the Tier-3 language tier; today
only linear memory is bounded via `Store.set_limits`). Checked in the
installed package and in the wasmtime-py main branch.

Run (manually or from CI; supersedes ad-hoc PyPI checks for gate 1 —
scripts/check_wasmtime_patch.py stays for the M2 go/no-go):

    python scripts/watch_upstream.py [--json]

Exit codes: 0 = all three gates open, 1 = at least one gate still closed,
2 = a gate could not be determined (network failure). Stdlib only.
"""

from __future__ import annotations

import argparse
import importlib
import inspect
import json
import sys
import urllib.error
import urllib.request

WASMTIME_PATCH_TARGETS = ("48.0.3", "49.0.1", "47.0.4")
REQUIRED_WHEEL_MARKERS = ("macosx", "manylinux")  # Cell ships macOS + Linux

WASMTIME_PY_RAW = "https://raw.githubusercontent.com/bytecodealliance/wasmtime-py/main"
LINKER_PATH = "wasmtime/component/_linker.py"
STORE_PATH = "wasmtime/_store.py"
BINDINGS_PATH = "wasmtime/_bindings.py"

GATE_OPEN = "OPEN"
GATE_CLOSED = "CLOSED"
GATE_UNKNOWN = "UNKNOWN"


class GateError(RuntimeError):
    """A gate could not be determined (network/parse failure)."""


def fetch_url(url: str, timeout: int = 15) -> str | None:
    """GET a URL, return the body as text; None on HTTP 404."""
    try:
        with urllib.request.urlopen(url, timeout=timeout) as resp:
            return resp.read().decode("utf-8", errors="replace")
    except urllib.error.HTTPError as e:
        if e.code == 404:
            return None
        raise GateError(f"HTTP {e.code} für {url}") from e
    except (urllib.error.URLError, TimeoutError, OSError) as e:
        raise GateError(f"Netzwerkfehler für {url}: {e}") from e


def wheels_ok(filenames: list[str]) -> bool:
    """True if the release has wheels for every platform Cell ships."""
    joined = " ".join(filenames)
    return all(marker in joined for marker in REQUIRED_WHEEL_MARKERS)


def source_exposes_p3(source: str) -> bool:
    """True if a wasmtime-py Linker source defines add_wasip3."""
    return "def add_wasip3" in source


def source_exposes_gc_limiter(source: str) -> bool:
    """True if a wasmtime-py source exposes a GC-heap ResourceLimiter hook."""
    return "ResourceLimiter" in source or "resource_limiter" in source


def _fetch_json_release(version: str) -> dict | None:
    url = f"https://pypi.org/pypi/wasmtime/{version}/json"
    try:
        with urllib.request.urlopen(url, timeout=15) as resp:
            return json.load(resp)
    except urllib.error.HTTPError as e:
        if e.code == 404:
            return None
        raise GateError(f"HTTP {e.code} für {url}") from e
    except (urllib.error.URLError, TimeoutError, OSError) as e:
        raise GateError(f"Netzwerkfehler für {url}: {e}") from e


def gate_engine_upgrade() -> tuple[str, str]:
    """Gate 1: patched wasmtime wheels on PyPI (evidence: target list)."""
    lines: list[str] = []
    for version in WASMTIME_PATCH_TARGETS:
        data = _fetch_json_release(version)
        if data is None:
            lines.append(f"    {version}: (noch nicht auf PyPI)")
            continue
        wheel_files = [
            f["filename"]
            for f in data.get("urls", [])
            if f["filename"].endswith(".whl")
        ]
        joined = " ".join(wheel_files)
        missing = [m for m in REQUIRED_WHEEL_MARKERS if m not in joined]
        note = "OK" if not missing else f"Plattformen fehlen: {missing}"
        lines.append(f"    {version}: {len(wheel_files)} Wheels ({note})")
    for version in WASMTIME_PATCH_TARGETS[:2]:  # fully patched: 48.0.3, 49.0.1
        data = _fetch_json_release(version)
        if data is None:
            continue
        wheel_files = [
            f["filename"]
            for f in data.get("urls", [])
            if f["filename"].endswith(".whl")
        ]
        if wheels_ok(wheel_files):
            return (
                GATE_OPEN,
                f"wasmtime {version} auf PyPI verfügbar (M2-Upgradepfad offen)\n"
                + "\n".join(lines),
            )
    return GATE_CLOSED, "kein vollständig gepatchtes Ziel auf PyPI\n" + "\n".join(lines)


def _installed_linker_source() -> str | None:
    try:
        linker_cls = importlib.import_module("wasmtime.component").Linker
        return inspect.getsource(linker_cls)
    except Exception:
        return None


def _installed_store_source() -> str | None:
    try:
        store_mod = importlib.import_module("wasmtime._store")
        return inspect.getsource(store_mod)
    except Exception:
        return None


def gate_wasip3_surface() -> tuple[str, str]:
    """Gate 2: add_wasip3 in the installed bindings or on wasmtime-py main."""
    installed = _installed_linker_source()
    if installed is not None and source_exposes_p3(installed):
        return GATE_OPEN, "installierte wasmtime-py exponiert Linker.add_wasip3"
    try:
        upstream = fetch_url(f"{WASMTIME_PY_RAW}/{LINKER_PATH}")
    except GateError as e:
        return GATE_UNKNOWN, f"installed: kein p3; upstream-Check fehlgeschlagen ({e})"
    if upstream is None:
        return (
            GATE_UNKNOWN,
            f"installed: kein p3; {LINKER_PATH} auf main nicht gefunden",
        )
    if source_exposes_p3(upstream):
        return (
            GATE_OPEN,
            "wasmtime-py main exponiert add_wasip3 (Upgrade der Bindings öffnet den Gate)",
        )
    return GATE_CLOSED, "weder installiert noch auf main: nur add_wasip2/add_wasi_http"


def gate_gc_limiter() -> tuple[str, str]:
    """Gate 3: GC-heap ResourceLimiter hook in the installed bindings or on main."""
    installed = _installed_store_source()
    if installed is not None and source_exposes_gc_limiter(installed):
        return (
            GATE_OPEN,
            "installierte wasmtime-py exponiert einen GC-Heap-Limiter-Hook",
        )
    sources: list[str] = []
    try:
        for path in (STORE_PATH, BINDINGS_PATH):
            body = fetch_url(f"{WASMTIME_PY_RAW}/{path}")
            if body is not None:
                sources.append(body)
    except GateError as e:
        return (
            GATE_UNKNOWN,
            f"installed: kein Limiter; upstream-Check fehlgeschlagen ({e})",
        )
    if not sources:
        return (
            GATE_UNKNOWN,
            "installed: kein Limiter; upstream-Sourcen nicht erreichbar",
        )
    if any(source_exposes_gc_limiter(src) for src in sources):
        return (
            GATE_OPEN,
            "wasmtime-py main exponiert einen ResourceLimiter/GC-Heap-Hook (Bindings-Upgrade öffnet den Gate)",
        )
    return (
        GATE_CLOSED,
        "weder installiert noch auf main: nur Store.set_limits (linear memory)",
    )


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    parser.add_argument("--json", action="store_true", help="maschinenlesbare Ausgabe")
    args = parser.parse_args()

    gates = [
        ("engine_upgrade_wheels", gate_engine_upgrade),
        ("wasip3_surface", gate_wasip3_surface),
        ("gc_heap_limiter", gate_gc_limiter),
    ]
    results: list[dict[str, str]] = []
    for name, fn in gates:
        try:
            status, evidence = fn()
        except GateError as e:
            status, evidence = GATE_UNKNOWN, str(e)
        results.append({"gate": name, "status": status, "evidence": evidence})

    if args.json:
        print(json.dumps({"gates": results}, ensure_ascii=False, indent=2))
    else:
        print("ADR-009-Gates (externe Abhängigkeiten der Sprach-Roadmap):\n")
        for entry in results:
            print(f"  [{entry['status']}] {entry['gate']}")
            for line in entry["evidence"].splitlines():
                print(f"      {line}")
            print()

    statuses = {entry["status"] for entry in results}
    if GATE_UNKNOWN in statuses:
        print("Ergebnis: unbestimmbar (Netzwerk) — später erneut prüfen.")
        return 2
    if statuses == {GATE_OPEN}:
        print(
            "Ergebnis: alle drei Gates offen — M2/WASI-0.3/GC-Folgearbeit kann starten."
        )
        return 0
    print("Ergebnis: noch wartend — gehärtete Interim-Posture bleibt aktiv.")
    return 1


if __name__ == "__main__":
    sys.exit(main())
