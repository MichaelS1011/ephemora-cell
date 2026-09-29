"""Surface & backend audit — structural facts the security posture relies on.

These tests pin down binding-level facts that several documentation claims
rest on, so a wasmtime upgrade that silently changes them fails loudly:

- the component linker exposes only the WASIp2 worlds (+ wasi-http) — the
  WASIp3 streams surface of GHSA-x84v-gj2h-g759 is unreachable;
- Cell's guest-facing linker registers wasip2 ONLY — wasi-http is never
  linked for guests (GHSA-c9gc-w9vx-w86p posture; existence of the
  ``add_wasi_http`` method on the binding's Linker class is not use);
- a component importing ``wasi:http`` cannot instantiate against Cell
  (behavioral, fail-closed);
- execution always runs on a native (Cranelift) backend — no interpreted
  fallback (Pulley) is in play, so warm-latency claims stay single-backend;
- Winch is not selectable via ``Config.strategy`` (documented "never Winch");
- the pinned wasmtime carries the April 2026 advisory fixes (>= 43.0.1,
  CVE-2026-34971 class).
"""

from __future__ import annotations

import ast
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


def _called_attribute_names(source: str) -> set[str]:
    """Method names invoked anywhere in a module's source (AST-walk)."""
    tree = ast.parse(source)
    return {
        node.func.attr
        for node in ast.walk(tree)
        if isinstance(node, ast.Call) and isinstance(node.func, ast.Attribute)
    }


def test_guest_facing_linker_never_registers_wasi_http():
    """GHSA-c9gc-w9vx-w86p (wasmtime-wasi-http outgoing-body host memory
    exhaustion): exploitation requires a guest that can invoke WASIp2
    outgoing-HTTP APIs. Cell's ONLY guest-facing linker construction site
    registers wasip2 and never wasi-http, so a guest world importing
    ``wasi:http`` cannot instantiate (behavioral pin in the next test).
    Structural: an upgrade that starts linking wasi-http for guests must
    fail loudly here — the method's existence on the binding's Linker
    class (previous test) is existence, not use."""
    path = os.path.join(
        os.path.dirname(__file__), "..", "ephemora_cell", "wasi_02.py"
    )
    with open(path, encoding="utf-8") as f:
        source = f.read()
    called = _called_attribute_names(source)
    assert "add_wasip2" in called, "component linker must register wasip2"
    assert "add_wasi_http" not in called, (
        "guest-facing linker must never register wasi-http (GHSA-c9gc-w9vx-w86p)"
    )


def test_component_with_wasi_http_import_fails_closed(tmp_path):
    """GHSA-c9gc-w9vx-w86p, behavioral: a component importing
    ``wasi:http/outgoing-handler`` must fail at instantiate time against
    Cell's linker (the wasi-http world is not registered for guests), so
    the advisory's precondition — a guest creating outgoing-request /
    outgoing-response resources — has no reachable entry point. Egress is
    host-mediated regardless (egress_sidecar.py: the guest has no
    sockets)."""
    from ephemora_cell import ExecutionStatus, WASIConfig
    from ephemora_cell.wasi_02 import ComponentSandbox

    wat = """
    (component
      (import "wasi:http/outgoing-handler@0.2.0"
        (instance $http
          (export "handle" (func (param "request" u32) (result u32)))
        )
      )
    )
    """
    path = tmp_path / "http_import.component.wasm"
    path.write_bytes(wasmtime.wat2wasm(wat))
    sandbox = ComponentSandbox(config=WASIConfig(max_fuel=1_000_000))
    try:
        result = sandbox.run(str(path))
    finally:
        sandbox.cleanup()
    assert result.status == ExecutionStatus.ERROR, result.stderr
    assert "wasi:http" in (result.stderr or ""), result.stderr


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
