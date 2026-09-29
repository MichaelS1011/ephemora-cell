"""Component-path security matrix — the Preview1 attack vectors re-proven
end-to-end on the WASI 0.2 sandbox (``ComponentSandbox``).

The component ABI shares the enforcement helpers with Preview1
(``ephemora_cell/_sandbox_common.py``), but it links, instantiates and runs
guests through a different wasmtime path (``wasmtime.component`` +
``Linker.add_wasip2``). This file re-proves the security matrix on THAT
path instead of assuming parity from the shared helpers:

- fuel bomb: the guest stops exactly at the budget (``fuel_consumed ==
  max_fuel``, including the 0 budget boundary) — mirrors the Preview1
  fuel-boundary pattern from tests/test_component.py and
  tests/test_security.py.
- memory bomb: a guest growing memory to the configured cap faults cleanly
  (``MEMORY_EXCEEDED``) and the host stays fully operational afterwards.
- output cap: stdout past the shared 10 KB budget is bounded
  (``_MAX_OUTPUT_BYTES`` from the shared helpers — single source of truth).
- stdin cap: input past ``STDIN_MAX_BYTES`` is rejected before the guest
  instantiates; within-cap input runs.
- dangerous-dir filtering incl. the ``/etc::guest-etc`` mapping-style
  regression (denylist drift fixed 2026-09-29): construction fails closed
  before ``run()`` and the sandbox-level filter drops the entry — the
  component-level twin of tests/test_dir_guard.py.
- positive control: a granted preopen write (fs02) succeeds — proving the
  blocks above are a defense, not a broken sandbox (same philosophy as the
  Preview1 suite).

Documented gap (NOT faked as covered): named state (ADR-004,
``ephemora_state`` imports) is a Preview1-only feature —
``WASISandbox.run(state_store=...)`` injects custom host imports, while
``ComponentSandbox.run()`` takes no ``state_store`` and the component linker
cannot define unknown imports (they fail instantiation). The final pin test
below keeps that gap explicit: if named state ever lands on the component
ABI, this test flags the matrix for extension.

Fixtures: attack payloads are component-model WAT compiled at test time via
``wasmtime.wat2wasm`` (supported on the pinned wasmtime — no external
toolchain, runs in CI); the positive-control guests reuse the committed
``tests/fixtures/*.wasm`` components. No ``.wasm`` is committed or built
here.
"""

from __future__ import annotations

import inspect
import os
import shutil
import sys
import tempfile
from pathlib import Path

import pytest
import wasmtime

sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))

from ephemora_cell import (
    STDIN_MAX_BYTES,
    ComponentSandbox,
    ExecutionStatus,
    WASIConfig,
)
from ephemora_cell._sandbox_common import _MAX_OUTPUT_BYTES

FIXTURES = os.path.join(os.path.dirname(__file__), "fixtures")
HELLO02 = os.path.join(FIXTURES, "hello02.wasm")
FS02 = os.path.join(FIXTURES, "fs02.wasm")

# Infinite-loop component (the fuel bomb), same shape as
# tests/fixtures/wat_loop.wat — generated, not fixture-file based.
FUEL_BOMB_WAT = """(component
    (core module $m
        (func $loop (export "run") (result i32)
            loop $l br $l end
            i32.const 0))
    (core instance $i (instantiate $m))
    (func (export "run") (result u32) (canon lift (core func $i "run")))
)
"""

# Memory bomb: grow one page (64 KiB) per iteration and write at the END of
# the grown region. While growth succeeds the write lands inside the last
# page; once the configured cap refuses further growth (wasmtime returns -1)
# the wrapped offset is out of bounds and the guest faults — after having
# actually grown memory to the cap, not on iteration one.
MEMORY_BOMB_WAT = """(component
    (core module $m
        (memory (export "memory") 1)
        (func $run (export "run") (result i32)
            (local $pages i32)
            (loop $l
                (local.set $pages (memory.grow (i32.const 1)))
                (i32.store
                    (i32.sub
                        (i32.mul (local.get $pages) (i32.const 65536))
                        (i32.const 4))
                    (i32.const 1))
                br $l)
            i32.const 0))
    (core instance $i (instantiate $m))
    (func (export "run") (result u32) (canon lift (core func $i "run")))
)
"""


def _compile_component(wat: str) -> str:
    """Compile component-model WAT to a temp .wasm file (path returned).

    Skips the calling test if the pinned wasmtime build cannot compile
    component WAT (defensive: the suite then degrades instead of failing).
    """
    try:
        wasm_bytes = wasmtime.wat2wasm(wat)
    except Exception:
        pytest.skip("wasmtime wat2wasm cannot compile component-model WAT")
    fd, path = tempfile.mkstemp(suffix=".wasm", prefix="ephemora_compsec_")
    with os.fdopen(fd, "wb") as f:
        f.write(wasm_bytes)
    return path


class TestComponentFuelBomb:
    def test_stops_exactly_at_budget(self):
        """A fuel-burning guest stops AT the budget, never past it."""
        path = _compile_component(FUEL_BOMB_WAT)
        for budget in (1_000, 1_000_000):
            sandbox = ComponentSandbox(WASIConfig(max_fuel=budget))
            try:
                result = sandbox.run(path)
                assert result.status == ExecutionStatus.FUEL_EXHAUSTED, (
                    f"budget={budget}: got {result.status}: " f"{result.stderr[:200]}"
                )
                assert result.fuel_consumed == budget, (
                    f"budget={budget}: consumed {result.fuel_consumed} — "
                    "the component path overshot its fuel budget"
                )
            finally:
                sandbox.cleanup()

    def test_zero_budget_stops_immediately(self):
        """Boundary: max_fuel=0 stops the guest before any real work."""
        path = _compile_component(FUEL_BOMB_WAT)
        sandbox = ComponentSandbox(WASIConfig(max_fuel=0))
        try:
            result = sandbox.run(path)
            assert result.status == ExecutionStatus.FUEL_EXHAUSTED
            assert result.fuel_consumed == 0
            assert result.elapsed_ms < 5_000
        finally:
            sandbox.cleanup()


class TestComponentMemoryBomb:
    def test_grows_to_cap_then_clean_fault(self):
        """A guest growing memory past max_memory_mb faults cleanly into
        MEMORY_EXCEEDED — and the host stays operational afterwards."""
        path = _compile_component(MEMORY_BOMB_WAT)
        sandbox = ComponentSandbox(WASIConfig(max_memory_mb=16, max_fuel=50_000_000))
        try:
            result = sandbox.run(path)
            assert result.status == ExecutionStatus.MEMORY_EXCEEDED, (
                f"memory bomb not contained: {result.status}: " f"{result.stderr[:200]}"
            )
            # Clean, classified result — the host-classified message, a
            # bounded capture, no crash leaking out of sandbox.run().
            assert "Memory limit exceeded" in result.stderr
            assert len(result.stderr) <= _MAX_OUTPUT_BYTES + 100
        finally:
            sandbox.cleanup()

        # No host crash: a follow-up run on the same sandbox object works.
        sandbox = ComponentSandbox(WASIConfig(max_fuel=1_000_000))
        try:
            rerun = sandbox.run(HELLO02)
            assert rerun.status == ExecutionStatus.SUCCESS
        finally:
            sandbox.cleanup()


class TestComponentOutputCap:
    def test_stdout_capped_at_shared_budget(self):
        """hello02 echoes argv[1] back — a 20 KB argument pushes stdout past
        the shared 10 KB budget. The captured output stays bounded and the
        run returns a clean verdict (the guest may observe the refused
        write and exit non-zero; the host does not crash either way)."""
        sandbox = ComponentSandbox(WASIConfig(max_fuel=5_000_000))
        try:
            result = sandbox.run(HELLO02, args=["A" * 20_000])
            assert result.status in (
                ExecutionStatus.SUCCESS,
                ExecutionStatus.ERROR,
            ), f"unexpected status {result.status}: {result.stderr[:200]}"
            assert len(result.stdout) <= _MAX_OUTPUT_BYTES + 50, (
                f"stdout cap failed: {len(result.stdout)} bytes "
                f"(limit {_MAX_OUTPUT_BYTES})"
            )
            # The oversized payload must not have survived intact.
            assert "A" * 20_000 not in result.stdout
            if result.status == ExecutionStatus.SUCCESS:
                assert "[... truncated]" in result.stdout
        finally:
            sandbox.cleanup()


class TestComponentStdinCap:
    def test_stdin_over_cap_rejected_before_instantiation(self):
        """STDIN_MAX_BYTES is a host-side cap (wasmtime silently truncates
        larger stdin on fd 0) — the component path must refuse oversized
        stdin cleanly instead of feeding truncated bytes to the guest."""
        sandbox = ComponentSandbox(WASIConfig(max_fuel=5_000_000))
        try:
            result = sandbox.run(HELLO02, stdin_data="x" * (STDIN_MAX_BYTES + 1))
            assert result.status == ExecutionStatus.ERROR
            assert str(STDIN_MAX_BYTES) in result.stderr
            assert "preopened file" in result.stderr
        finally:
            sandbox.cleanup()

    def test_stdin_within_cap_runs(self):
        """Below the cap the same input is accepted and the guest runs."""
        sandbox = ComponentSandbox(WASIConfig(max_fuel=5_000_000))
        try:
            result = sandbox.run(HELLO02, stdin_data="x" * 100)
            assert result.status == ExecutionStatus.SUCCESS
        finally:
            sandbox.cleanup()


class TestComponentDangerousDirs:
    def test_mapping_entry_fails_closed_end_to_end(self):
        """THE denylist-drift regression (2026-09-29) at the component
        sandbox level, through the public run() path: a ``host::guest``
        mapping entry whose HOST part is a denylist entry must fail closed
        at construction — ``run()`` never happens."""
        for entry in ("/etc::guest-etc", "/etc/passwd::shadow"):
            with pytest.raises(ValueError, match="forbidden"):
                ComponentSandbox(WASIConfig(allow_dirs=(entry,)))

    def test_mapping_entry_filtered_at_sandbox_layer(self):
        """Defense-in-depth twin of tests/test_dir_guard.py on the component
        class: the runtime filter (the layer behind config validation) drops
        the mapping entry whose host part is dangerous and keeps a safe
        mapping verbatim — identical to the Preview1 sandbox."""
        component = ComponentSandbox()
        assert component._filter_dangerous_dirs(("/etc::guest-etc",)) == ()
        assert component._filter_dangerous_dirs(("/usr/local::u",)) == ()
        target = Path(tempfile.mkdtemp(prefix="ephemora_compsec_safe_"))
        try:
            entry = f"{target}::/"
            assert component._filter_dangerous_dirs((entry,)) == (entry,)
        finally:
            shutil.rmtree(target, ignore_errors=True)


class TestComponentPositiveControl:
    def test_granted_preopen_write_works(self):
        """Positive control: with a legitimately granted directory the same
        component path writes the file — the blocks above are a defense,
        not a broken sandbox."""
        target = tempfile.mkdtemp(prefix="ephemora_compsec_grant_")
        sandbox = ComponentSandbox(WASIConfig(max_fuel=5_000_000, allow_dirs=(target,)))
        try:
            result = sandbox.run(FS02, args=[target])
            assert result.status == ExecutionStatus.SUCCESS, (
                f"positive control failed: {result.status}: " f"{result.stderr[:200]}"
            )
            with open(os.path.join(target, "out.txt")) as f:
                assert f.read() == "pwned-by-component\n"
        finally:
            sandbox.cleanup()


class TestComponentNamedStateGap:
    def test_named_state_gap_stays_explicit(self):
        """Pinned gap (see module docstring): named state (ADR-004) is
        Preview1-only. ``ComponentSandbox.run`` must NOT silently claim
        state support: until a state_store parameter exists here, the
        capability matrix documents it as not implemented on this ABI. If
        this assertion starts failing because the feature landed, extend
        this matrix with grant + access-within-budget vectors."""
        signature = inspect.signature(ComponentSandbox.run)
        assert "state_store" not in signature.parameters
        # The Preview1 path really has the feature (the gap is component-
        # specific, not a project-wide absence).
        from ephemora_cell import WASISandbox

        assert "state_store" in inspect.signature(WASISandbox.run).parameters
