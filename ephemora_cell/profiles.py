# SPDX-License-Identifier: BUSL-1.1
# Copyright 2026 Michael Soppa

"""Sandbox Profiles — preconfigured WASIConfig presets."""

from __future__ import annotations

from ephemora_cell.wasi_runtime import WASIConfig

# Plugin profile — minimal permissions for plugin execution
PLUGIN = WASIConfig(
    max_memory_mb=64,
    max_fuel=500_000,
    timeout_seconds=10,
    allow_dirs=(),
    allow_env=(),
)

# LLM profile — moderate limits for AI agent tool execution
# NOTE: /tmp is NOT preopened — its realpath (/private/tmp on macOS) is in the
# forbidden canonical allowlist.
LLM = WASIConfig(
    max_memory_mb=128,
    max_fuel=2_000_000,
    timeout_seconds=30,
    allow_dirs=(),
    allow_env=(),
)

# Edge profile — minimal resources for edge/edge-compute workloads
EDGE = WASIConfig(
    max_memory_mb=32,
    max_fuel=200_000,
    timeout_seconds=5,
    allow_dirs=(),
    allow_env=(),
)

# Default profile — balanced defaults
DEFAULT = WASIConfig(
    max_memory_mb=128,
    max_fuel=1_000_000,
    timeout_seconds=30,
    allow_dirs=(),
    allow_env=(),
)

# Analytical profile — data-analysis workloads beyond the 128 MB wall
# (ADR-003): memory64 memories, 4.5 GiB linear memory, larger compute
# and host-I/O budgets. Threads stay OFF (threads_roadmap Phase 1);
# over-cap growth is refused byte-exactly and in milliseconds (measured,
# benchmarks/analytical_breakpoint/). Opt-in — default behavior unchanged.
ANALYTICAL = WASIConfig(
    max_memory_mb=4608,
    max_fuel=50_000_000,
    timeout_seconds=120,
    memory64=True,
    io_cpu_seconds=10.0,
    allow_dirs=(),
    allow_env=(),
)

# Interpreter profile — for running a BYO interpreter *as the guest*
# (ADR-009 Tier 2: CPython-WASI, StarlingMonkey/QuickJS, ruby.wasm …).
# An interpreter module is ~10-150 MB, boots a runtime before user code
# runs, and burns fuel for the interpreter itself, so every budget the
# default profile calibrates for a compiled module is too small here:
# 32 MiB module cap, 128 MB memory, 1 M fuel, 30 s. It raises five values and
# NOTHING else: no sync exception, no filesystem grant, no env, no claim that
# Cell speaks a language. The sync posture in particular stays closed —
# CPython-WASI imports fd_datasync during startup but never calls it, which is
# measured, so the profile needs no opt-in
# (benchmarks/interpreter_guest/probe_datasync.py). The interpreter binary
# itself stays the caller's.
#
# io_cpu_seconds is the one raise that is not a guest-budget: on the isolation
# path the worker pays for compiling a 22 MB guest before it can run it, and
# the measured cost of one interpreter run is 5.40 s of worker CPU — the
# default 2.0 s wall kills the run before CPython starts. 30 s bounds that
# host work while leaving room for a larger BYO binary; it is attested.
#
# Budgets are set from a pinned wasi-python 3.10 guest
# (benchmarks/results/2026-10-02/interpreter_guest.json): boot 71.6 M fuel
# once its stdlib is primed, 357 M on a freshly extracted tree, json round-trip
# 128 M, sum(range(200000)) 194 M; 128 MB is the lowest memory cap it boots
# under. max_fuel = 1 G leaves ~5x the largest measured boot and roughly a
# few seconds of interpreter CPU; it is the constraint that binds first, by
# design — fuel stops exactly on the budget, the 120 s wall-clock does not.
INTERPRETER = WASIConfig(
    max_memory_mb=1024,
    max_fuel=1_000_000_000,
    timeout_seconds=120,
    max_wasm_bytes=512 * 1024 * 1024,
    io_cpu_seconds=30.0,
    allow_dirs=(),
    allow_env=(),
)

PROFILES: dict[str, WASIConfig] = {
    "plugin": PLUGIN,
    "llm": LLM,
    "edge": EDGE,
    "default": DEFAULT,
    "analytical": ANALYTICAL,
    "interpreter": INTERPRETER,
}


def get(profile: str) -> WASIConfig:
    """Return a WASIConfig for a named profile."""
    if profile not in PROFILES:
        raise ValueError(
            f"Unknown profile: {profile!r} (available: {list(PROFILES.keys())})"
        )
    return PROFILES[profile]


def list_profiles() -> list[str]:
    """Return available profile names."""
    return list(PROFILES.keys())
