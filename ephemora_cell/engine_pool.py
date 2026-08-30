# Ephemora Cell — Engine and module pooling
# SPDX-License-Identifier: Apache-2.0
"""
Engine and module pooling for wasmtime.

``EnginePool`` reuses wasmtime ``Engine`` objects across sandbox runs,
keyed by an LRU fingerprint of the engine-relevant WASIConfig fields, and
caches compiled ``Module`` objects per engine. Module access is serialized
per engine entry with a lock because wasmtime ``Module`` instances are not
thread-safe.

Root integration into ``wasi_runtime.WASISandbox.run()``: keep a module-level
``pool = EnginePool()`` and replace the per-run engine construction with
``engine = pool.engine_for(self._config)`` and replace
``Module.from_file(engine, wasm_path)`` with ``pool.cached_module(engine,
wasm_path)``; cached modules must only be instantiated while holding the
pool's per-engine lock (or by taking the lock around linker.instantiate),
since wasmtime Module objects are not thread-safe and the pool serializes
cache access per engine entry. Everything Store-scoped stays per-run as
today (``Store(engine)``, ``store.set_limits``, ``store.set_fuel``,
``store.set_epoch_deadline``, ``store.set_wasi``). For subprocess isolation,
route the whole call through ``process_executor.run_isolated`` instead,
which has its own engine/module lifecycle inside the worker process.
"""

from __future__ import annotations

import hashlib
import json
import threading
from collections import OrderedDict
from contextlib import contextmanager
from pathlib import Path

try:
    import wasmtime
    from wasmtime import Engine, Module

    HAS_WASMTIME = True
except ImportError:
    HAS_WASMTIME = False

from .wasi_runtime import WASIConfig

__all__ = ["EnginePool", "config_fingerprint"]


_EPOCH_TICK_SECONDS = 0.05


def config_fingerprint(config: WASIConfig) -> str:
    """Deterministic sha256 fingerprint of engine-relevant config fields.

    Covers wasm feature selection (max_threads, memory64), fuel metering
    (max_fuel) and memory limits (max_memory_mb). ``timeout_seconds`` is
    deliberately NOT part of the fingerprint: the timeout is enforced
    per-run via the store's epoch deadline, not by the engine — including
    it would split one engine pool into per-timeout shards. allow_dirs/
    allow_env are WASI-level and do not affect the Engine.
    """
    key = (
        config.max_memory_mb,
        config.max_fuel,
        config.max_threads,
        config.memory64,
    )
    return hashlib.sha256(json.dumps(key, sort_keys=True).encode()).hexdigest()


class _EngineEntry:
    """One pooled engine with its serialized module cache.

    The ticker thread advances the engine's epoch every
    ``_EPOCH_TICK_SECONDS`` so per-run ``store.set_epoch_deadline`` values
    fire without each run managing its own timer (S3: prevents epoch
    crossfire between concurrent runs sharing one engine). ``refcount``
    tracks live runs; an entry with refcount > 0 is never evicted.
    """

    def __init__(self, engine: Engine) -> None:
        self.engine = engine
        self.lock = threading.Lock()
        self.modules: OrderedDict[tuple, Module] = OrderedDict()
        self.refcount = 0
        self._stop = threading.Event()
        self._ticker: threading.Thread | None = None

    def start_ticker(self) -> None:
        if self._ticker is not None:
            return
        engine = self.engine
        stop = self._stop

        def _tick() -> None:
            while not stop.wait(_EPOCH_TICK_SECONDS):
                engine.increment_epoch()

        self._ticker = threading.Thread(
            target=_tick, daemon=True, name="ephemora-epoch-ticker"
        )
        self._ticker.start()

    def stop_ticker(self) -> None:
        self._stop.set()
        if self._ticker is not None:
            self._ticker.join(timeout=2.0)
            self._ticker = None


class EnginePool:
    """LRU pool of wasmtime engines and per-engine module caches.

    Args:
        max_engines: Maximum number of Engine instances held (LRU).
        max_modules_per_engine: Maximum cached Module instances per engine.

    Thread safety: engine_for and cached_module are safe for concurrent
    use; module cache access is serialized per engine entry.
    """

    # Epoch ticker granularity (seconds) — also exported for callers that
    # compute per-store deadlines.
    TICK_SECONDS = _EPOCH_TICK_SECONDS

    def __init__(self, max_engines: int = 4, max_modules_per_engine: int = 32) -> None:
        if not HAS_WASMTIME:
            raise RuntimeError(
                "wasmtime is not installed. Install with: pip install wasmtime"
            )
        if max_engines < 1:
            raise ValueError("max_engines must be >= 1")
        self._max_engines = max_engines
        self._max_modules_per_engine = max_modules_per_engine
        self._entries: OrderedDict[str, _EngineEntry] = OrderedDict()
        self._by_engine_id: dict[int, _EngineEntry] = {}
        self._lock = threading.Lock()

    def _new_entry(self, config: WASIConfig) -> _EngineEntry:
        engine_config = wasmtime.Config()
        if config.max_fuel is not None:
            engine_config.consume_fuel = True
        engine_config.epoch_interruption = True
        engine_config.wasm_threads = False
        engine_config.wasm_memory64 = config.memory64
        engine_config.wasm_multi_memory = False
        return _EngineEntry(Engine(engine_config))

    def engine_for(self, config: WASIConfig) -> Engine:
        """Return the pooled Engine for a config (LRU by fingerprint).

        The same config fingerprint yields the same Engine; distinct
        fingerprints yield distinct Engines up to max_engines, evicting
        the least recently used entry otherwise. Entries with a live run
        (acquired via :meth:`acquire`) are never evicted.
        """
        fingerprint = config_fingerprint(config)
        with self._lock:
            entry = self._entries.pop(fingerprint, None)
            if entry is None:
                entry = self._new_entry(config)
                entry.start_ticker()
                self._evict_locked()
                self._by_engine_id[id(entry.engine)] = entry
            self._entries[fingerprint] = entry
            return entry.engine

    def _evict_locked(self) -> None:
        """Evict LRU entries beyond max_engines, skipping live ones."""
        while len(self._entries) >= self._max_engines:
            for _fingerprint, candidate in self._entries.items():
                if candidate.refcount == 0:
                    break
            else:
                return  # all entries are live — keep them all
            del self._entries[_fingerprint]
            self._by_engine_id.pop(id(candidate.engine), None)
            candidate.stop_ticker()

    @contextmanager
    def lease(self, config: WASIConfig):
        """Acquire the pooled engine for one run with a refcount lease.

        Convenience wrapper around engine_for/retain/release. Yields
        (engine, deadline_ticks) where deadline_ticks is the per-store
        epoch deadline matching the config's timeout at the shared ticker
        granularity (TICK_SECONDS).
        """
        engine = self.engine_for(config)
        self.retain(engine)
        try:
            yield engine, self.epoch_deadline(config)
        finally:
            self.release(engine)

    @staticmethod
    def epoch_deadline(config: WASIConfig) -> int:
        """Per-store epoch deadline for ``config.timeout_seconds`` at the
        shared ticker granularity. Minimum 1 tick."""
        import math

        seconds = getattr(config, "timeout_seconds", 0) or 0
        return max(1, math.ceil(seconds / _EPOCH_TICK_SECONDS))

    def retain(self, engine: Engine) -> None:
        """Mark ``engine`` as in live use: it is never evicted and its
        ticker keeps running until :meth:`release`."""
        entry = self._entry_for(engine)
        with self._lock:
            entry.refcount += 1

    def release(self, engine: Engine) -> None:
        """End a live-use lease taken with :meth:`retain`."""
        entry = self._entry_for(engine)
        with self._lock:
            entry.refcount = max(0, entry.refcount - 1)

    def _entry_for(self, engine: Engine) -> _EngineEntry:
        with self._lock:
            entry = self._by_engine_id.get(id(engine))
        if entry is None or entry.engine is not engine:
            raise ValueError("engine is not managed by this EnginePool")
        return entry

    def cached_module(self, engine: Engine, wasm_path: str) -> Module:
        """Return a cached compiled Module for (engine, wasm_path).

        Cache key is (resolved path, mtime, size); file changes invalidate
        the entry. Access is serialized per engine with the entry lock.
        """
        entry = self._entry_for(engine)
        resolved = Path(wasm_path).resolve()
        stat = resolved.stat()
        key = (str(resolved), stat.st_mtime_ns, stat.st_size)
        with entry.lock:
            module = entry.modules.pop(key, None)
            if module is None:
                module = Module.from_file(entry.engine, str(resolved))
                entry.modules[key] = module
                while len(entry.modules) > self._max_modules_per_engine:
                    entry.modules.popitem(last=False)
            else:
                entry.modules[key] = module
            return module

    @contextmanager
    def locked(self, engine: Engine):
        """Hold the per-engine lock for the duration of the block.

        Use around ``linker.instantiate`` when reusing a cached Module so a
        wasmtime Module instance is never touched from two threads.
        """
        entry = self._entry_for(engine)
        with entry.lock:
            yield entry.engine

    def close(self) -> None:
        """Drop all pooled engines and module caches, stopping tickers."""
        with self._lock:
            for entry in self._entries.values():
                entry.stop_ticker()
            self._entries.clear()
            self._by_engine_id.clear()

    def __len__(self) -> int:
        with self._lock:
            return len(self._entries)
