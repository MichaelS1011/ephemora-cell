"""
Threads baseline tests (shared-everything-threads roadmap).

Phase 0 guard: every engine Ephemora Cell constructs must set
``wasm_threads = False`` (parser-level rejection of shared memories) and
``wasm_multi_memory = False``; ``wasm_memory64`` mirrors the per-config
opt-in. Verified on all three construction sites:

  1. ``WASISandbox`` inline engine (use_engine_pool=False)
  2. ``EnginePool._new_entry`` (default pooled path)
  3. ``ComponentSandbox`` (WASI 0.2 components)

Important wasmtime 47 facts verified empirically:
- ``wasm_threads`` defaults to **True** in wasmtime 47 — a shared-memory
  module *compiles* on a blank ``Config()``. Our explicit ``False`` is what
  makes the parser reject it.
- Independently, ``Config.shared_memory`` defaults to **False**, so even a
  threads-enabled engine refuses to *instantiate* shared memories unless
  that flag is set too — a second, host-side barrier Ephemora Cell relies on.
- So "compiles iff wasm_threads=True" is only true for the min/max form;
  the real defense is our flag + wasmtime's ``shared_memory`` default.

Mirrors the behavioral technique of tests/test_security.py
(TestSecurityBoundary.test_wasm_threads_disabled) and adds structural
inspection of the created engine config via a recording ``Config`` spy, plus a
positive control proving the parser accepts shared-memory modules once
``wasm_threads`` is enabled (so rejection in our sandbox is caused by our
freeze).

See docs/threads_roadmap.md for the full threat model and phased roadmap.
"""

from __future__ import annotations

import os
import sys
from pathlib import Path

import pytest
import wasmtime

sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))

from ephemora_cell import (
    EnginePool,
    ExecutionStatus,
    WASIConfig,
    WASISandbox,
)

# Shared memory WITHOUT a max size would fail to compile even with threads
# enabled; the (1 2) min/max form is accepted by the parser once
# wasm_threads is enabled (and even on a blank wasmtime 47 config, where
# threads defaults to True — instantiation is then blocked by wasmtime's
# shared_memory=False default, see module docstring).
SHARED_MEM_WAT = b"""
(module
  (memory (export "memory") 1 2 shared)
  (func (export "_start"))
)
"""

TRIVIAL_WAT = b"""
(module
  (memory (export "memory") 1)
  (func (export "_start"))
)
"""

# Flags every engine must freeze, and the opt-in that mirrors the config.
_FROZEN_FLAGS = ("wasm_threads", "wasm_multi_memory")
_OPTIN_FLAGS = ("wasm_memory64",)


class _SpyConfig(wasmtime.Config):
    """wasmtime.Config that records which frozen flags were set on it."""

    instances: list[_SpyConfig] = []  # noqa: RUF012 (shared test register)

    def __init__(self) -> None:
        self.tracked: dict[str, bool] = {}
        super().__init__()
        type(self).instances.append(self)

    def __setattr__(self, name: str, value: bool) -> None:
        if name == "tracked":
            object.__setattr__(self, name, value)
        else:
            if name in _FROZEN_FLAGS or name in _OPTIN_FLAGS:
                self.tracked[name] = value
            object.__setattr__(self, name, value)


@pytest.fixture
def shared_mem_wasm(tmp_path) -> Path:
    path = tmp_path / "shared_mem.wasm"
    path.write_bytes(wasmtime.wat2wasm(SHARED_MEM_WAT))
    return path


@pytest.fixture
def trivial_wasm(tmp_path) -> Path:
    path = tmp_path / "trivial.wasm"
    path.write_bytes(wasmtime.wat2wasm(TRIVIAL_WAT))
    return path


def _patch_config(monkeypatch, module_name: str) -> type[_SpyConfig]:
    """Swap module.wasmtime.Config for _SpyConfig; return the spy class."""
    import importlib

    module = importlib.import_module(module_name)
    _SpyConfig.instances = []
    monkeypatch.setattr(module.wasmtime, "Config", _SpyConfig)
    return _SpyConfig


class TestSharedMemoryRejected:
    """Behavioral: a shared-memory module must never instantiate."""

    def test_rejected_via_pooled_engine(self, shared_mem_wasm):
        """Default path (EnginePool._new_entry) rejects shared memory."""
        sandbox = WASISandbox(config=WASIConfig())
        result = sandbox.run(str(shared_mem_wasm), use_engine_pool=True)
        assert (
            result.status == ExecutionStatus.ERROR
        ), f"Shared memory WASM not blocked via pooled engine: {result.status}"

    def test_rejected_via_inline_engine(self, shared_mem_wasm):
        """Non-pooled path (wasi_runtime inline config) rejects shared memory."""
        sandbox = WASISandbox(config=WASIConfig())
        result = sandbox.run(str(shared_mem_wasm), use_engine_pool=False)
        assert (
            result.status == ExecutionStatus.ERROR
        ), f"Shared memory WASM not blocked via inline engine: {result.status}"

    def test_max_threads_optin_is_inert_in_phase0(self, shared_mem_wasm):
        """Phase 0: WASIConfig.max_threads>1 must NOT enable threads yet."""
        sandbox = WASISandbox(config=WASIConfig(max_threads=4))
        result = sandbox.run(str(shared_mem_wasm))
        assert (
            result.status == ExecutionStatus.ERROR
        ), f"max_threads>1 unexpectedly enabled shared memory: {result.status}"

    def test_positive_control_threads_on_compiles(self, shared_mem_wasm):
        """Control: with wasm_threads=True the parser accepts the module —
        proving rejection in our sandbox comes from the freeze. (On a blank
        wasmtime 47 config the module also compiles, because threads defaults
        to True there; instantiation is the second barrier — see docstring.)"""
        engine_config = wasmtime.Config()
        engine_config.wasm_threads = True
        engine = wasmtime.Engine(engine_config)
        module = wasmtime.Module(engine, shared_mem_wasm.read_bytes())
        assert module is not None

    def test_blank_wasmtime_engine_compiles_but_does_not_instantiate(
        self, shared_mem_wasm
    ):
        """Empirical proof of the wasmtime 47 defaults: a blank engine
        compiles the shared-memory module (threads defaults on), but
        instantiation is refused via Config.shared_memory=False."""
        engine = wasmtime.Engine()
        module = wasmtime.Module(engine, shared_mem_wasm.read_bytes())
        store = wasmtime.Store(engine)
        try:
            wasmtime.Instance(store, module, [])
        except Exception as ex:
            assert "shared memory support is disabled" in str(ex)
        else:
            raise AssertionError("shared memory instantiated without a flag")


class TestEngineConfigFreeze:
    """Structural: every construction site freezes threads/multi-memory and
    mirrors the memory64 opt-in."""

    def _assert_site(self, spy_config, config: WASIConfig):
        assert spy_config.instances, "no Config was constructed"
        for cfg in spy_config.instances:
            assert cfg.tracked.get("wasm_threads") is False
            assert cfg.tracked.get("wasm_multi_memory") is False
            assert cfg.tracked.get("wasm_memory64") is config.memory64

    def test_wasi_sandbox_inline_engine_frozen(self, monkeypatch, trivial_wasm):
        """WASISandbox non-pooled engine freezes threads + mirrors memory64."""
        spy_config = _patch_config(monkeypatch, "ephemora_cell.wasi_runtime")
        sandbox = WASISandbox(config=WASIConfig())
        result = sandbox.run(str(trivial_wasm), use_engine_pool=False)
        assert result.status == ExecutionStatus.SUCCESS
        self._assert_site(spy_config, WASIConfig())

    def test_wasi_sandbox_inline_engine_memory64_optin(self, monkeypatch, trivial_wasm):
        spy_config = _patch_config(monkeypatch, "ephemora_cell.wasi_runtime")
        sandbox = WASISandbox(config=WASIConfig(memory64=True))
        result = sandbox.run(str(trivial_wasm), use_engine_pool=False)
        assert result.status == ExecutionStatus.SUCCESS
        self._assert_site(spy_config, WASIConfig(memory64=True))

    def test_engine_pool_engine_frozen(self, monkeypatch):
        """EnginePool._new_entry freezes threads + mirrors memory64."""
        spy_config = _patch_config(monkeypatch, "ephemora_cell.engine_pool")
        pool = EnginePool()
        pool.engine_for(WASIConfig())
        self._assert_site(spy_config, WASIConfig())

    def test_engine_pool_engine_memory64_optin(self, monkeypatch):
        spy_config = _patch_config(monkeypatch, "ephemora_cell.engine_pool")
        pool = EnginePool()
        pool.engine_for(WASIConfig(memory64=True))
        self._assert_site(spy_config, WASIConfig(memory64=True))

    def test_component_sandbox_engine_frozen(self, monkeypatch, tmp_path):
        """ComponentSandbox engine freezes threads + mirrors memory64.

        The engine is constructed before component validation, so forcing the
        component-binary check to pass and feeding a core module is enough to
        observe the constructed config (run() then fails on parse, which is
        fine — we only assert the engine flags here).
        """
        from ephemora_cell import wasi_02

        spy_config = _patch_config(monkeypatch, "ephemora_cell.wasi_02")
        wasm_bytes = wasmtime.wat2wasm(TRIVIAL_WAT)
        path = tmp_path / "not_a_component.wasm"
        path.write_bytes(wasm_bytes)
        monkeypatch.setattr(wasi_02, "is_component_binary", lambda _: True)
        sandbox = wasi_02.ComponentSandbox(config=WASIConfig())
        result = sandbox.run(str(path))
        assert result.status == ExecutionStatus.ERROR  # not a real component
        self._assert_site(spy_config, WASIConfig())

    def test_component_sandbox_engine_memory64_optin(self, monkeypatch, tmp_path):
        from ephemora_cell import wasi_02

        spy_config = _patch_config(monkeypatch, "ephemora_cell.wasi_02")
        wasm_bytes = wasmtime.wat2wasm(TRIVIAL_WAT)
        path = tmp_path / "not_a_component.wasm"
        path.write_bytes(wasm_bytes)
        monkeypatch.setattr(wasi_02, "is_component_binary", lambda _: True)
        sandbox = wasi_02.ComponentSandbox(config=WASIConfig(memory64=True))
        result = sandbox.run(str(path))
        assert result.status == ExecutionStatus.ERROR  # not a real component
        self._assert_site(spy_config, WASIConfig(memory64=True))
