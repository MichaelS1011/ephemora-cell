"""GHSA-32h6-97mm-8q3c — reachability tripwire for the async-lifted callback path.

GHSA-32h6-97mm-8q3c is identical to RUSTSEC-2026-0327 and is a **native stack
buffer overflow** (the async-lifted callback result count is unvalidated) — a
memory-safety defect, not an availability-only panic. It is **unresolved** at the
pinned 49.0.0 (IN BAND, fix 49.0.2, no wheel on PyPI); public 1.2.0 is on HOLD.

The advisory needs an *async-lifted* component export whose callback is invoked
through the engine's async runtime. Ephemora Cell never builds such a store: the
product engine turns stack switching off, and the shipped wasmtime-py binding has
no async call surface at all.

What this file pins is the *configuration edge*, deliberately NOT a claim that
"no Python method exists, therefore safe" (the directive forbids that reasoning):
the native artifact itself still exports the C-API async surface, and the lab
measurement in ``benchmarks/results/2026-10-13/async_component_validation_ghsa_32h6.json``
shows the synchronous call path aborting inside the engine instead of running the
callback trampoline. That abort is a **different code path than the
unvalidated-result-count overflow** — it is NOT proof the overflow is unreachable,
so the memory-safety risk stays open (SECURITY.md). These tests fail loudly if a
future upgrade moves that boundary.

The negative validation runs against the vulnerable component shapes live in the
isolated lab harness, not here: a native abort inside the test process would
take pytest down with it, and publishing exploit-shaped fixtures is not wanted.
"""

from __future__ import annotations

import os
import subprocess
import sys

import pytest

sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))

import wasmtime

from ephemora_cell._engine_config import build_engine_config

_ADVISORY = "GHSA-32h6-97mm-8q3c"


class _SpyConfig(wasmtime.Config):
    """Records the async/stack posture the product actually sets."""

    instances: list[_SpyConfig] = []  # noqa: RUF012 (shared test register)

    def __init__(self) -> None:
        self.tracked: dict[str, object] = {}
        super().__init__()
        type(self).instances.append(self)

    def __setattr__(self, name: str, value: object) -> None:
        if name == "tracked":
            object.__setattr__(self, name, value)
        else:
            if name in {"wasm_stack_switching", "wasm_threads", "wasm_gc"}:
                self.tracked[name] = value
            object.__setattr__(self, name, value)


def test_product_engine_config_disables_stack_switching(monkeypatch) -> None:
    """The product config must explicitly turn stack switching off.

    Native async component calls ride on stack switching; ``False`` is the knob
    that keeps the async-lifted trampoline out of the built engine.
    """
    import ephemora_cell._engine_config as ec

    _SpyConfig.instances = []
    monkeypatch.setattr(ec.wasmtime, "Config", _SpyConfig)
    build_engine_config(max_fuel=1_000, memory64=False)
    assert _SpyConfig.instances, "build_engine_config did not construct a Config"
    tracked = _SpyConfig.instances[-1].tracked
    assert (
        tracked.get("wasm_stack_switching") is False
    ), f"stack switching not explicitly disabled ({_ADVISORY}): {tracked}"


def test_stack_switching_cannot_be_silently_enabled() -> None:
    """Behavioural: an engine with stack switching ON does not come up.

    Run in a child process because the binding answers a rejected engine
    configuration with a native abort — that abort IS the result. A future
    binding that accepted the flag would flip this test red, which is exactly
    the drift that would re-open the async path.
    """
    child = (
        "import wasmtime\n"
        "c = wasmtime.Config()\n"
        "c.wasm_stack_switching = True\n"
        "e = wasmtime.Engine(c)\n"
        "print('ENGINE_BUILT')\n"
    )
    proc = subprocess.run(
        [sys.executable, "-c", child], capture_output=True, text=True, timeout=120
    )
    assert (
        "ENGINE_BUILT" not in proc.stdout
    ), f"stack switching became enableable — re-check {_ADVISORY} reachability"
    assert (
        proc.returncode != 0
    ), "engine construction with stack switching ON must not succeed cleanly"


def test_binding_exposes_no_async_component_call_surface() -> None:
    """Tripwire, not the safety argument.

    If a future wasmtime-py grows async entry points, the product could reach
    the async-lifted callback path without any code change here — so this must
    fail visibly rather than quietly. The positive evidence for the current
    release is the measured validation/abort behaviour, recorded in the gate
    evidence file.
    """
    import wasmtime.component as component_mod

    for module in (wasmtime, component_mod):
        names = [n for n in dir(module) if "async" in n.lower()]
        assert not names, f"{module.__name__} grew an async surface: {names}"
    for cls in (wasmtime.Store, component_mod.Func, component_mod.Linker):
        names = [n for n in dir(cls) if "async" in n.lower()]
        assert not names, f"{cls.__name__} grew an async surface: {names}"


def test_sync_component_path_still_works(hello_component_wasm) -> None:
    """The edge under test must not be protected by breaking WASIp2 itself."""
    engine = wasmtime.Engine(build_engine_config(max_fuel=5_000_000, memory64=False))
    comp = wasmtime.component.Component(engine, hello_component_wasm.read_bytes())
    store = wasmtime.Store(engine)
    store.set_fuel(5_000_000)
    # Same store posture the product component path applies (wasi_02.py) — the
    # hardened config turns epoch interruption on, so a store without a
    # deadline traps immediately.
    store.set_epoch_deadline(1)
    linker = wasmtime.component.Linker(engine)
    linker.add_wasip2()
    instance = linker.instantiate(store, comp)
    assert instance is not None


@pytest.fixture
def hello_component_wasm(tmp_path):
    """The shipped WASIp2 component fixture, copied into the test sandbox."""
    src = os.path.join(os.path.dirname(__file__), "fixtures", "hello02.wasm")
    dst = tmp_path / "hello02.wasm"
    dst.write_bytes(open(src, "rb").read())
    return dst
