# ADR-015: Central Enforcement Gate — Untrusted/Unknown WASI 0.2 Components Run Isolated, Never in-Process

- **Status:** Accepted
- **Date:** 2026-10-11
- **Refines:** ADR-014 (effective-enforcement attestation), ADR-012 (tenant attribution)
- **CTO decision:** WP-L4-1 — Option A + B released (Option C rejected)

## Context

A runtime resource wall (fuel, epoch, memory cap) bounds a guest's compute;
a **process wall** bounds what a guest can do *to the host*. Ephemora-cell had
both, but only the operator could choose between them per call
(`use_subprocess`). For WASI 0.2 **components** that choice was load-bearing in
a way it was not for Preview1:

- **GHSA-j2g9 (measured, R-03).** A `component` guest calling
  `fd_filestat_set_times(u64::MAX)` hits a datetime overflow that raises
  `SIGABRT` **in the host process** on the in-process path (returncode `-6`,
  host dies). The identical guest under the subprocess worker only kills the
  worker: the parent survives, the run returns `ERROR` with
  `worker_crashed=true`. Fuel/wall/memory do not bite on this host-side call —
  **process isolation is the only wall that contains it.**
- **The gap.** The MCP dispatch path (`CellToolEngine.execute`) hardcoded
  `use_subprocess=False, abi="auto"`, so an untrusted component reached the host
  process by default. Trust was implicit: absent a classification, a run was
  treated as safe enough to keep in-process.

ADR-014 already made the *evidence* honest (`execution_mode`, `abi`,
`sync_blockade_enforced` are attested). The remaining question was an
*enforcement* one: which runs are **required** to be isolated, and where is that
decided so no entry point can bypass it.

## Decision

**Isolation is mandatory for components the host has not explicitly authorised,
enforced at a single choke-point, with trust controlled only by the host.**

### Option A — the Central Enforcement Gate

The gate lives in `WASISandbox.run()` — the one facade every path flows through
(CLI, MCP, `run_wasm`, direct SDK calls). It fires **before** any guest
execution and after ABI resolution, so `abi="auto"` cannot dodge it:

1. `trust ∈ {trusted, untrusted, unknown}` is validated; an unknown value is
   refused (`ValueError`), never defaulted to trusted.
2. A missing/unspecified classification is **`unknown`**, which the gate treats
   exactly like `untrusted` (fail-closed).
3. The mandate is a single-source predicate, `isolation_required_for(trust, abi)
   = (abi == component and trust != trusted)`, shared by the gate and the record
   layer so policy and evidence cannot drift.
4. When isolation is required the gate raises `use_subprocess` to `True`; it
   **never lowers it**. If the worker is genuinely unavailable, the run is
   **refused** (`ERROR`), not silently downgraded to in-process — **no silent
   fallback**.

Preview1 runs are never a mandate class (measured unaffected by GHSA-j2g9), so
the large in-process Preview1 workload is untouched. `run()`'s default
`abi="preview1"` keeps that surface stable.

### Option B — MCP trust posture

`CellToolEngine` gains a host-declared allowlist, `trusted_tools`. A tool's
trust is `trusted` **iff the host names it**; otherwise it is `unknown`. Trust is
never read from a tool's own bytes or its sidecar — a guest cannot elevate
itself. An empty set (the default) is the strict posture: no tool is trusted.

Where an untrusted/unknown **component** also carries a host-sidecar **egress**
surface, `execute()` **refuses the run** rather than drop the capability silently
or downgrade to in-process. Full egress-across-isolation parity is deferred to a
separate work package (CTO §2), so the honest interim behaviour is an explicit
refusal.

### Authority, binding, and path separation (CTO §2 conditions)

A reachable `trust="trusted"` argument is not, by itself, authorisation. The
following make the authority host-originated and the exception auditable:

- **Authority originates only at the host.** `trusted_tools` is a construction
  argument of `CellToolEngine` (set in the server/operator process). It is never
  read from request `params` (which become guest stdin only), from a `ToolSpec`
  field (there is no trust field), or from a manifest key. A guest, agent, or
  MCP request has no channel to mint `trusted`.
- **Trust binds to the executed bytes.** In signed/governed mode the engine
  passes `expected_sha256=spec.wasm_sha256`, the register-time digest, on every
  call; the digest is checked against the bytes actually read before compiling
  (no re-read gap). A module swapped under a still-`trusted` name therefore
  **fails closed** ("module hash mismatch") rather than silently inheriting the
  in-process classification.
- **The exception is auditable.** The signed record carries the real
  `execution_mode`, so a host-authorised in-process run reads `in_process` —
  visible to a verifier as "no OS wall", never hidden behind an isolated label.
  The boundary of that evidence: `execution_mode` proves **which path executed
  the guest**, and nothing more. It is **not** a standalone cryptographic proof
  that a `trusted` exception was authorised — the authorisation lives in the
  operator's host configuration (`trusted_tools`), not in the receipt. A
  verifier reading `in_process` on a component run sees an unprotected path
  happened; attributing it to a legitimate trusted decision requires the
  host-side config as a separate source of truth.
- **Public/guaranteed vs internal/primitive are separated.** The mandate is
  enforced at `WASISandbox.run` and every path routed through it (`run_wasm`,
  `run_isolated`, MCP `execute`). `ComponentSandbox` is the low-level engine
  primitive the gate and worker themselves call; it is documented as NOT a
  guaranteed path. Mislabelling a component as `preview1` cannot smuggle it
  in-process either: preview1 routing does not hand the file to the component
  engine, so it fails to link rather than run.

## Consequences

- Positive: GHSA-j2g9's host-abort class can no longer reach the host through
  any default path — an untrusted component either runs in the worker or the run
  is refused. Legitimate in-process component workloads survive only behind an
  explicit, host-owned `trusted` authorisation (an auditable decision, not a
  default).
- Positive: one predicate (`isolation_required_for`) drives both enforcement and
  attestation, so a signed record's `execution_mode` reflects what the gate
  actually mandated.
- **Accepted cost (measured, reproducible):** forcing a component through the
  worker adds ~66 ms per run (4.3–5.7×) —
  `benchmarks/isolation_overhead_probe.py`. This is the price of the containment
  boundary, weighed against a host process a guest can abort.
- **Kept honest (NOT faked as covered):** process isolation is *not* full OS
  sandboxing — no seccomp/pledge filter is claimed; and isolation does not
  retro-fit the component sync blockade, so `component →
  sync_blockade_enforced=false` still holds (ADR-014). **No false guarantees.**
- Deferred: sidecar egress across the isolation boundary is a separate WP; until
  it lands, an untrusted component with an egress surface is refused, never run
  with a silently missing capability.
