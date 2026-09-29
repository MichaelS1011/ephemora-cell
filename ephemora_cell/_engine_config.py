# Ephemora Cell — hardened wasmtime engine config builder (private module)
# SPDX-License-Identifier: BUSL-1.1
# Copyright 2026 Ephemora AG (in formation), Zug, Switzerland
"""ONE builder for the hardened wasmtime engine ``Config``.

The proposal-policy freeze below previously existed as THREE
hand-synchronized copies (``wasi_runtime`` inline engine,
``engine_pool._new_entry``, ``wasi_02`` component engine) — the CHANGELOG
1.0.4.2 hardening (GHSA-m63x-6p34-q65x) had to edit every site in
lockstep. This module is now the single site; the flag set AND the flag
order are identical for every engine Ephemora Cell constructs.

Kept honest by tests/test_threads_baseline.py (the ``_SpyConfig`` recording
``Config`` subclass inspects every constructed engine config) and
tests/test_proposal_policy.py (compile-probe matrix against this posture).

NOTE for the wasmtime M2 engine upgrade: flipping a proposal default now
happens HERE — one site instead of three.
"""

from __future__ import annotations

try:
    import wasmtime

    HAS_WASMTIME = True
except ImportError:  # pragma: no cover - wasmtime is a hard dependency
    HAS_WASMTIME = False


def build_engine_config(*, max_fuel: int | None, memory64: bool) -> wasmtime.Config:
    """Build the hardened wasmtime engine ``Config`` (proposal policy).

    Args:
        max_fuel: ``None`` disables fuel metering (``consume_fuel`` stays
            off, trusted-workload mode). Any budget enables it.
        memory64: Mirrors the per-config ``WASIConfig.memory64`` opt-in
            (Wasm 3.0 memory64); off by default for a deterministic
            security baseline.

    Callers wrap the returned config in ``Engine(...)`` themselves (the
    pool, the inline preview1 path and the component path each own their
    engine lifecycle). Construction resolves ``wasmtime.Config`` at call
    time, so the recording spy in tests/test_threads_baseline.py keeps
    intercepting every engine Ephemora Cell builds.
    """
    engine_config = wasmtime.Config()
    if max_fuel is not None:
        engine_config.consume_fuel = True
    engine_config.epoch_interruption = True
    # P1 #11: Disable threads (single-thread only for security)
    engine_config.wasm_threads = False
    # P1/K2: Freeze the baseline — multi-memory stays off; memory64
    # is a per-config opt-in (WASIConfig.memory64).
    engine_config.wasm_memory64 = memory64
    engine_config.wasm_multi_memory = False
    # GHSA-m63x-6p34-q65x: call_ref (function-references) and
    # try_table (exceptions) can discard callee fuel — deterministic
    # fuel accounting requires these proposals off. GC and tail-calls
    # are not needed by any Cell workload; enforced like threads.
    engine_config.wasm_function_references = False
    engine_config.wasm_exceptions = False
    engine_config.wasm_gc = False
    engine_config.wasm_tail_call = False
    # WASI 0.3 (2026-06-11) positions native async on component
    # stack-switching primitives — not needed by the shipped
    # wasip2 surface, gate-off until the 0.3 story is qualified
    # (SECURITY_ADVISORY_PLAN: WASIp3 streams, GHSA-x84v-gj2h-g759).
    engine_config.wasm_stack_switching = False
    # NOTE: no explicit memory_guard_size — an explicit 4 GiB
    # guard broke run_isolated in constrained Linux VMs
    # (mmap ENOMEM on the combined reservation+guard); the
    # pooling allocator (CVE-2026-34988 class) is unreachable
    # via the Python binding and the residue test guards the
    # behavior instead.
    return engine_config
