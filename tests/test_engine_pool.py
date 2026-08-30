"""Tests for engine_pool — engine/module pooling."""

from __future__ import annotations

import os
import sys
import time
from concurrent.futures import ThreadPoolExecutor

import pytest
import wasmtime

sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))

from ephemora_cell import EnginePool, WASIConfig, config_fingerprint

SIMPLE_WAT = b"""
(module
  (memory (export "memory") 1)
  (func (export "run") (result i32) i32.const 42)
)
"""


@pytest.fixture
def wasm_file(tmp_path):
    path = tmp_path / "module.wasm"
    path.write_bytes(wasmtime.wat2wasm(SIMPLE_WAT))
    return path


def _configs() -> list[WASIConfig]:
    return [
        WASIConfig(max_memory_mb=64, max_fuel=1_000_000, timeout_seconds=5),
        WASIConfig(max_memory_mb=128, max_fuel=1_000_000, timeout_seconds=5),
        WASIConfig(max_memory_mb=64, max_fuel=2_000_000, timeout_seconds=5),
    ]


class TestFingerprint:
    def test_same_config_same_fingerprint(self):
        a, b = WASIConfig(), WASIConfig()
        assert config_fingerprint(a) == config_fingerprint(b)

    def test_different_config_different_fingerprint(self):
        a = config_fingerprint(WASIConfig(max_memory_mb=64))
        b = config_fingerprint(WASIConfig(max_memory_mb=128))
        assert a != b

    def test_memory64_changes_fingerprint(self):
        a = config_fingerprint(WASIConfig())
        b = config_fingerprint(WASIConfig(memory64=True))
        assert a != b

    def test_engine_pool_respects_memory64(self):
        pool = EnginePool(max_engines=4)
        e_off = pool.engine_for(WASIConfig())
        e_on = pool.engine_for(WASIConfig(memory64=True))
        assert e_off is not e_on

    def test_allow_dirs_do_not_change_fingerprint(self):
        a = config_fingerprint(WASIConfig(allow_dirs=("/tmp",)))
        b = config_fingerprint(WASIConfig())
        assert a == b


class TestEnginePool:
    def test_engine_for_same_fingerprint_reuses_engine(self):
        pool = EnginePool(max_engines=4)
        engine1 = pool.engine_for(WASIConfig())
        engine2 = pool.engine_for(WASIConfig())
        assert engine1 is engine2

    def test_engine_for_different_fingerprint_distinct_engine(self):
        pool = EnginePool(max_engines=4)
        engine1 = pool.engine_for(WASIConfig(max_memory_mb=64))
        engine2 = pool.engine_for(WASIConfig(max_memory_mb=128))
        assert engine1 is not engine2

    def test_lru_eviction(self):
        pool = EnginePool(max_engines=2)
        cfgs = _configs()
        e0 = pool.engine_for(cfgs[0])
        e1 = pool.engine_for(cfgs[1])
        e2 = pool.engine_for(cfgs[2])  # evicts e0 (oldest)
        assert pool.engine_for(cfgs[1]) is e1
        assert pool.engine_for(cfgs[2]) is e2
        assert pool.engine_for(cfgs[0]) is not e0

    def test_close_drops_all_engines(self):
        pool = EnginePool(max_engines=4)
        engine = pool.engine_for(WASIConfig())
        pool.close()
        assert len(pool) == 0
        with pytest.raises(ValueError):
            pool.cached_module(engine, "/tmp/x.wasm")

    def test_max_engines_must_be_positive(self):
        with pytest.raises(ValueError):
            EnginePool(max_engines=0)


class TestModuleCache:
    def test_cached_module_reused(self, wasm_file):
        pool = EnginePool()
        engine = pool.engine_for(WASIConfig())
        module1 = pool.cached_module(engine, str(wasm_file))
        module2 = pool.cached_module(engine, str(wasm_file))
        assert module1 is module2

    def test_cached_module_different_per_engine(self, wasm_file):
        pool = EnginePool()
        engine_a = pool.engine_for(WASIConfig(max_memory_mb=64))
        engine_b = pool.engine_for(WASIConfig(max_memory_mb=128))
        assert pool.cached_module(engine_a, str(wasm_file)) is not pool.cached_module(
            engine_b, str(wasm_file)
        )

    def test_cached_module_invalidated_on_file_change(self, tmp_path):
        wasm_file = tmp_path / "module.wasm"
        wasm_file.write_bytes(wasmtime.wat2wasm(SIMPLE_WAT))
        pool = EnginePool()
        engine = pool.engine_for(WASIConfig())
        module1 = pool.cached_module(engine, str(wasm_file))
        time.sleep(0.01)
        wasm_file.write_bytes(wasmtime.wat2wasm(b'(module (func (export "f")))'))
        os.utime(wasm_file, None)
        module2 = pool.cached_module(engine, str(wasm_file))
        assert module1 is not module2

    def test_cached_module_unknown_engine_raises(self, wasm_file):
        pool = EnginePool()
        foreign = pool.engine_for(WASIConfig(max_memory_mb=32))
        pool.close()
        with pytest.raises(ValueError):
            pool.cached_module(foreign, str(wasm_file))

    def test_invalid_wasm_raises(self, tmp_path):
        bad = tmp_path / "bad.wasm"
        bad.write_bytes(b"\0\x61\x73\x6d\x01\0\0\0\xff\xff\xff\xff")
        pool = EnginePool()
        engine = pool.engine_for(WASIConfig())
        with pytest.raises(wasmtime.WasmtimeError):
            pool.cached_module(engine, str(bad))


class TestPoolConcurrency:
    def test_parallel_usage_does_not_crash(self, wasm_file):
        pool = EnginePool(max_engines=4)
        cfgs = _configs() * 3

        def worker(i):
            cfg = cfgs[i % len(cfgs)]
            engine = pool.engine_for(cfg)
            return pool.cached_module(engine, str(wasm_file))

        with ThreadPoolExecutor(max_workers=8) as pool_exec:
            modules = list(pool_exec.map(worker, range(200)))
        assert all(m is not None for m in modules)

    def test_parallel_same_key_returns_same_module(self, wasm_file):
        pool = EnginePool(max_engines=1)
        engine = pool.engine_for(WASIConfig())

        def worker(_):
            return pool.cached_module(engine, str(wasm_file))

        with ThreadPoolExecutor(max_workers=8) as pool_exec:
            modules = list(pool_exec.map(worker, range(64)))
        assert all(m is modules[0] for m in modules)


class TestS3TimeoutLease:
    """S3: timeout_seconds is not part of the fingerprint; pooled runs get
    a per-store epoch deadline driven by a shared ticker; a live run is
    never evicted."""

    def test_timeout_not_in_fingerprint(self):
        a = config_fingerprint(WASIConfig(timeout_seconds=5))
        b = config_fingerprint(WASIConfig(timeout_seconds=600))
        assert a == b

    def test_shared_engine_runs_concurrently_no_false_timeout(self, tmp_path):
        """Two concurrent runs on ONE shared engine: the timeout of run A
        must not trip run B (epoch crossfire regression)."""
        import threading

        wat = b"""
        (module
          (import "wasi_snapshot_preview1" "proc_exit" (func $exit (param i32)))
          (memory (export "memory") 1)
          (func (export "_start")
            i32.const 0
            call $exit
          )
        )
        """
        wasm_path = tmp_path / "ok.wasm"
        wasm_path.write_bytes(wasmtime.wat2wasm(wat))

        from ephemora_cell import WASISandbox

        slow_cfg = WASIConfig(max_fuel=1_000_000, timeout_seconds=30)
        fast_cfg = WASIConfig(max_fuel=1_000_000, timeout_seconds=1)
        slow = WASISandbox(config=slow_cfg)
        fast = WASISandbox(config=fast_cfg)

        slow_result: dict = {}

        def _slow_run():
            res = slow.run(str(wasm_path), use_engine_pool=True)
            slow_result["status"] = res.status

        t = threading.Thread(target=_slow_run, daemon=True)
        t.start()
        time.sleep(0.2)  # ensure the slow run is mid-flight
        fast_result = fast.run(str(wasm_path), use_engine_pool=True)
        t.join(timeout=30)

        assert fast_result.status.value == "success"
        assert slow_result.get("status") is not None
        # The 1s timeout of the fast run must not have killed the slow run:
        assert slow_result["status"].value == "success"

    def test_pool_timeout_still_enforced(self, tmp_path):
        """A looping guest under a pooled engine still hits its deadline."""
        wat = b"""
        (module
          (import "wasi_snapshot_preview1" "proc_exit" (func $exit (param i32)))
          (memory (export "memory") 1)
          (func (export "_start") (loop $l br $l))
        )
        """
        wasm_path = tmp_path / "loop.wasm"
        wasm_path.write_bytes(wasmtime.wat2wasm(wat))

        from ephemora_cell import WASISandbox

        sandbox = WASISandbox(config=WASIConfig(max_fuel=None, timeout_seconds=1))
        t0 = time.monotonic()
        result = sandbox.run(str(wasm_path), use_engine_pool=True)
        wall = time.monotonic() - t0
        assert result.status.value == "timeout"
        assert wall < 10

    def test_live_engine_not_evicted(self):
        from ephemora_cell import WASISandbox  # noqa: F401

        pool = EnginePool(max_engines=1)
        e1 = pool.engine_for(WASIConfig(max_memory_mb=64))
        pool.retain(e1)
        # A different config would evict e1 — but it is retained:
        e2 = pool.engine_for(WASIConfig(max_memory_mb=128))
        assert e2 is not e1
        assert len(pool) == 2  # over max_engines: retained entry survives
        assert pool.engine_for(WASIConfig(max_memory_mb=64)) is e1
        pool.release(e1)
        # Now eviction may proceed:
        pool.engine_for(WASIConfig(max_memory_mb=32))
        assert len(pool) <= 2


class TestLeaseApi:
    def test_lease_yields_engine_and_deadline(self):
        pool = EnginePool()
        with pool.lease(WASIConfig(timeout_seconds=7)) as (engine, deadline):
            assert deadline == 140  # 7s / 0.05s tick
            # engine is functional inside the lease
            assert pool.engine_for(WASIConfig(timeout_seconds=7)) is engine
        # lease released — entry can be evicted again (no crash)

    def test_epoch_deadline_minimum_one_tick(self):
        assert EnginePool.epoch_deadline(WASIConfig(timeout_seconds=0.01)) == 1
