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

PROFILES: dict[str, WASIConfig] = {
    "plugin": PLUGIN,
    "llm": LLM,
    "edge": EDGE,
    "default": DEFAULT,
    "analytical": ANALYTICAL,
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
