# ADR-004: Named State Across Isolated Runs — StateStore as an Explicit Capability

- **Status:** Accepted
- **Date:** 2026-08-29
- **Context:** Overhead measurement (`benchmarks/state_overhead/`)
- **Predecessor:** ADR-002 (I/O Budget — provides the generic host-import mechanism)

## Context (measured)

Two isolated runs currently share nothing — the only in-sandbox channel is a
persistent preopen directory. Measurement over 100 consecutive runs
(warm cache, macOS M5):

| Mode | ms/run | Delta |
|---|---:|---:|
| Stateless (trivial) | 0.65 | — |
| FS state: 32-B record append + full-file read-back | 0.95 | **+0.30** |
| FS state at 1 MiB state.bin | 0.87 | +0.22 |

**Finding:** the price of FS state is small (~0.3 ms/run) — the real problem is
**semantic**: no namespace, no caps (only the S4/ADR-002 bounds), manual cleanup,
session-leakage risk (two sessions on the same directory), and state bytes run quietly
into the I/O budget. A stateless agent workflow (incremental aggregation,
multi-call analyses) needs explicit, bounded, automatically cleaned-up state objects.

## Decision

**Variant (a): `StateStore` as an opt-in WASI host import** — not (b) an MCP server layer.

1. `ephemora_cell.state.StateStore`: a host-side key/value store, session-scoped
   (lifetime = object), caps enforced by the host (`max_value_bytes` 256 KiB,
   `max_total_bytes` 1 MiB, `max_entries` 64). Nothing is persisted to disk.
2. **The handover is the capability:** `sandbox.run(..., state_store=store)`. Without
   the handover the imports do not exist (fail-closed, test-confirmed: instantiation
   fails without the grant). The guest imports `ephemora_state.get/set/del`;
   a cap violation → WASI errno to the guest (1 = cap, 3 = not-found, 4 = buffer too
   small with the required length written), no Python raise in the guest path.
3. **Auditability:** `ExecutionResult.state_bytes` attests the state footprint
   per run.
4. **Scope:** in-process path (v1). Subprocess runs cannot share host-side state
   (process boundary) — the imports are not defined there; documented.
   Variants (persistent sandbox-dir preopen) rejected: no caps per session,
   leakage between sessions, manual cleanup — exactly the problems of the primitive.
5. **MCP layer (b) as an add-on, not a replacement:** an MCP server can hold the same
   StateStore per session and serve tools across multiple calls; the
   Cell primitive stays independent of the host framework (same logic as
   ADR-001's interface commitment).

## Consequences

- Gate demo: 3 isolated runs with counter hand-off are green
  (`tests/test_state.py::test_gate_demo_counter_across_three_runs`).
- Reference: WASP (arXiv 2607.25493) normalizes explicit, configurable
  state handling for serverless isolates — Cell follows the same principle at
  WASM scale: state is a limited artifact, not an accident.
- Risk: low — the feature is dead without explicit handover; caps and
  session isolation are test-confirmed (leakage test).
