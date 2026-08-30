"""ADR-003: the `analytical` profile — memory64 beyond 4 GiB.

Definition tests + a live regression that grows a 64-bit-memory guest
past the 32-bit 4 GiB boundary under the profile's cap (measured first
in benchmarks/analytical_breakpoint/), and engine-pool separation.
"""

from __future__ import annotations

import os
import sys

import wasmtime

sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))

from ephemora_cell import (
    EnginePool,
    ExecutionStatus,
    WASISandbox,
    config_fingerprint,
    get_profile,
)
from ephemora_cell.profiles import list_profiles

# 64-bit memory guest growing page-by-page to TARGET pages (64 KiB each),
# touching every 4096th page. Same shape as the breakpoint measurement.
GROW64_WAT = """
(module
  (memory (export "memory") i64 1)
  (func (export "_start") (local $pages i64) (local $r i64) (local $t i64)
    (local.set $t {target})
    (block $done
      (loop $l
        local.get $pages
        local.get $t
        i64.ge_u
        br_if $done
        i64.const 1
        memory.grow
        local.set $r
        local.get $r
        i64.const 0xFFFFFFFFFFFFFFFF
        i64.eq
        if
          unreachable
        end
        local.get $pages
        i64.const 4096
        i64.rem_u
        i64.const 0
        i64.eq
        if
          local.get $pages
          i64.const 16
          i64.shl
          i32.const 42
          i32.store
        end
        local.get $pages
        i64.const 1
        i64.add
        local.set $pages
        br $l
      )
    )
  )
)
"""

BOUNDARY_PAGES = 65_792  # 4 GiB + 2 MB


class TestAnalyticalProfileDefinition:
    def test_registered(self):
        assert "analytical" in list_profiles()
        profile = get_profile("analytical")
        assert profile.memory64 is True
        assert profile.max_memory_mb == 4608
        assert profile.max_fuel == 50_000_000
        assert profile.timeout_seconds == 120
        assert profile.max_threads == 1  # threads stay OFF (ADR-003)
        assert profile.io_cpu_seconds == 10.0
        assert profile.allow_dirs == ()  # no ambient grants
        assert profile.allow_env == ()

    def test_default_profile_unchanged(self):
        profile = get_profile("default")
        assert profile.memory64 is False
        assert profile.max_memory_mb == 128

    def test_engine_pool_separates_analytical(self):
        pool = EnginePool()
        default_engine = pool.engine_for(get_profile("default"))
        analytical_engine = pool.engine_for(get_profile("analytical"))
        assert analytical_engine is not default_engine
        assert config_fingerprint(get_profile("analytical")) != config_fingerprint(
            get_profile("default")
        )


class TestAnalyticalProfileRun:
    def test_growth_past_4gib_boundary(self, tmp_path):
        """Live regression: >4 GiB linear memory under the profile cap."""
        profile = get_profile("analytical")
        sandbox = WASISandbox(config=profile)
        wat = GROW64_WAT.format(target=f"i64.const {BOUNDARY_PAGES}")
        wasm_path = tmp_path / "grow64.wasm"
        wasm_path.write_bytes(wasmtime.wat2wasm(wat))
        try:
            result = sandbox.run(str(wasm_path))
        finally:
            sandbox.cleanup()
        assert result.status == ExecutionStatus.SUCCESS, result.stderr[:200]

    def test_over_cap_refused(self, tmp_path):
        """Over the profile cap the growth is refused, not crashed."""
        profile = get_profile("analytical")
        sandbox = WASISandbox(config=profile)
        # 4608 MB cap = 73_728 pages; ask for +512 pages
        wat = GROW64_WAT.format(target="i64.const 74_240")
        wasm_path = tmp_path / "grow64_over.wasm"
        wasm_path.write_bytes(wasmtime.wat2wasm(wat))
        try:
            result = sandbox.run(str(wasm_path))
        finally:
            sandbox.cleanup()
        # unreachable on refusal -> trap; contained as ERROR, not host damage
        assert result.status == ExecutionStatus.ERROR
        assert (
            "memory" in result.stderr.lower() or "unreachable" in result.stderr.lower()
        )


class TestAnalyticalProfileCLI:
    """Regression (2026-08-29 docs audit): the CLI must honor the profile's
    own memory64. The old _resolve_config clobbered it with the --memory64
    flag default (store_true -> False), so `--profile analytical` silently
    ran with memory64 off while the security baseline reported the profile's
    memory cap correctly — the exact class of gap behavioral tests exist to catch."""

    @staticmethod
    def _args(**kw):
        from argparse import Namespace

        defaults = dict(
            profile="analytical",
            memory64=False,
            memory_mb=None,
            fuel=None,
            timeout=None,
            allow_dirs=None,
            allow_env=None,
        )
        defaults.update(kw)
        return Namespace(**defaults)

    def test_profile_memory64_survives_cli_resolution(self):
        from ephemora_cell.cli import _resolve_config

        config = _resolve_config(self._args())
        assert config.memory64 is True
        assert config.max_memory_mb == 4608
        assert config.max_fuel == 50_000_000
        assert config.timeout_seconds == 120

    def test_memory64_flag_enables_without_profile(self):
        from ephemora_cell.cli import _resolve_config

        config = _resolve_config(self._args(profile=None, memory64=True))
        assert config.memory64 is True
        assert config.max_memory_mb == 128

    def test_default_profile_stays_memory32(self):
        from ephemora_cell.cli import _resolve_config

        config = _resolve_config(self._args(profile=None))
        assert config.memory64 is False
        assert config.max_memory_mb == 128
