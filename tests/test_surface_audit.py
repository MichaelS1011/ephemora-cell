"""Surface & backend audit — structural facts the security posture relies on.

These tests pin down binding-level facts that several documentation claims
rest on, so a wasmtime upgrade that silently changes them fails loudly:

- the component linker exposes only the WASIp2 worlds (+ wasi-http) — the
  WASIp3 streams surface of GHSA-x84v-gj2h-g759 is unreachable;
- execution always runs on a native (Cranelift) backend — no interpreted
  fallback (Pulley) is in play, so warm-latency claims stay single-backend;
- Winch is not selectable via ``Config.strategy`` (documented "never Winch");
- the pinned wasmtime carries the April 2026 advisory fixes (>= 43.0.1,
  CVE-2026-34971 class).
"""

from __future__ import annotations

import os
import sys
from importlib.metadata import version as _pkg_version

import pytest

sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))

import wasmtime


def test_component_linker_offers_no_wasip3_world():
    """GHSA-x84v-gj2h-g759 (WASIp3 streams): the affected surface is only
    reachable through a WASIp3 world. The binding exposes exactly two world
    loaders — wasip2 (which Cell links) and wasi-http — so the streams
    surface cannot be reached from Cell regardless of engine defaults."""
    from wasmtime import component as _component

    linker = _component.Linker(wasmtime.Engine())
    world_methods = sorted(m for m in dir(linker) if m.startswith("add_"))
    assert world_methods == ["add_wasi_http", "add_wasip2"], world_methods


def test_engine_runs_native_not_interpreted():
    """Warm-latency numbers are Cranelift numbers: the engine must never be
    the Pulley interpreter. If a future binding ever routes to Pulley, this
    test trips and the performance docs need per-backend re-qualification."""
    assert wasmtime.Engine().is_pulley() is False


def test_winch_backend_not_selectable():
    """Documented policy: never Winch. The Python binding's strategy knob
    only accepts auto/cranelift, so Winch cannot be reached accidentally."""
    config = wasmtime.Config()
    with pytest.raises(wasmtime.WasmtimeError, match="unknown strategy"):
        config.strategy = "winch"


def test_wasmtime_version_floor_covers_april_2026_advisories():
    """CVE-2026-34971 / RUSTSEC-2026-0096 (aarch64 Cranelift heap escape)
    is fixed in 36.0.7 / 42.0.2 / 43.0.1+ — the pinned engine must never
    drop below the oldest fix line (SECURITY.md, engine advisories)."""
    raw = _pkg_version("wasmtime")
    parts = []
    for chunk in raw.split(".")[:3]:
        digits = "".join(ch for ch in chunk if ch.isdigit())
        parts.append(int(digits or 0))
    assert tuple(parts) >= (43, 0, 1), f"wasmtime {raw} below the advisory floor"
