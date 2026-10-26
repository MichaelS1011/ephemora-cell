# ADR-015: Central Enforcement Gate — Untrusted/Unknown WASI 0.2 Components Run Isolated, Never in-Process

- **Status:** Accepted — **amended 2026-10-14 for 1.2.0** (governance
  decision 2026-10-14, the isolation mandate: it is extended from components-only to **both ABIs**;
  see “Amendment — 1.2.0” below, which supersedes the Preview1 carve-out in the
  original text)
- **Date:** 2026-10-11 (amended 2026-10-14)
- **Refines:** ADR-014 (effective-enforcement attestation), ADR-012 (tenant attribution)
- **Decision:** enforced isolation for untrusted/unknown components plus a
  host-owned trust exception (a blanket subprocess flip was rejected)

## Context

A runtime resource wall (fuel, epoch, memory cap) bounds a guest's compute;
a **process wall** bounds what a guest can do *to the host*. Ephemora-cell had
both, but only the operator could choose between them per call
(`use_subprocess`). For WASI 0.2 **components** that choice was load-bearing in
a way it was not for Preview1:

- **GHSA-j2g9 (measured).** A `component` guest calling
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
separate follow-up effort, so the honest interim behaviour is an explicit
refusal.

### Authority, binding, and path separation (sign-off conditions)

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
  in-process classification. Name-level identity is protected too: a governed
  tool request that collides with an already-registered name — trusted or not —
  is **rejected** (`server._evaluate_tool_request`), and dynamic loads require
  signed-tools mode outright, so a trusted name cannot be re-registered over
  different bytes. Distinction to keep honest: the **authorisation of a module
  state** is the manifest signature over its digest (given at signing time by
  the key holder), the **per-call binding** is the `expected_sha256` re-check.
  In unsigned/legacy registry mode there is no digest to bind — a `trusted`
  name there is pure disk-truth (filesystem write = host privilege, and tool
  requests are refused in this mode); pair any `trusted_tools` entry with
  signed-tools mode — that combination is the only one where the exception is
  both host-authorised and byte-bound.
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

## Protected Component profile (opt-in `protected_component=True`)

Beyond the default mandate above, callers can ask for a **narrower, explicitly
activated contract**: `WASISandbox.run(..., protected_component=True)`. This is
a distinct API contract, not a stricter default — the parameter is optional and
defaults to `False`, so every existing call keeps its current behaviour.

**The one explicitly qualified entry point.** The protected profile is defined
only for `WASISandbox.run(protected_component=True)`. Nothing else inherits the
label automatically, and each of these stays exactly as documented above unless
the caller routes through `run(..., protected_component=True)`:

- a normal `WASISandbox.run()` without the flag — the default mandate, not the
  protected profile;
- `run_wasm()` — not automatically protected;
- `run_isolated()` / the subprocess path — isolation without the component-only,
  format-verified admission the protected profile adds;
- the CLI `--isolated` flag — process isolation, not the protected guarantee;
- MCP `CellToolEngine(trusted_tools=())` — the strict trust posture, not the
  protected profile;
- direct `ComponentSandbox` primitives — explicitly **outside** the protected
  profile (low-level engine, never a guaranteed path).

Wiring any further public entry point (CLI/MCP/wrappers) to the protected
profile is a separate decision, evaluated on its own.

**What the protected profile adds over the default mandate** — every invariant
is decided **before the guest starts** (fail-closed, no side effect):

1. **Finite, bounded budgets are mandatory — and strictly validated.** The
   profile qualifies a run as resource-BOUNDED short-lived foreign execution, so
   every limit that makes it bounded must be an explicitly valid, finite,
   positive value: `max_fuel`, `max_memory_mb`, `max_wasm_bytes`,
   `io_budget_bytes` and `disk_quota_bytes` must be real positive `int`s (a
   `bool`, or a float/string, is refused — a mis-set flag is not a bound), and
   the time limits `timeout_seconds`/`io_cpu_seconds` must be finite positive
   numbers (`NaN` and both infinities refused). Nothing at or below zero, and
   nothing above the signed 64-bit range, is admitted: an over-large value would
   overflow the u64/int conversions downstream into a smaller or nonsensical
   bound, so it is refused rather than mis-enforced. A disabled (`None`/zero)
   mandatory limit is refused from the config alone, before any file is touched.
   `max_gc_heap_mb` is deliberately **not** gated: it is recorded, not enforced,
   in the current binding, so refusing on it would assert a bound that does not
   exist. This rule lives only in the protected profile — `WASIConfig` semantics
   for every other caller are unchanged (the general constructor keeps its own,
   looser validation).
2. **Actual format, verified from a bounded read.** The module is read under a
   bounded read — never more than `max_wasm_bytes` plus one overflow byte into
   the parent — so an oversized input is refused on its declared size before its
   bytes ever enter the parent process, and a file that grows between the size
   check and the read is caught by that single overflow byte. The bytes read
   carry component magic. An `abi="component"` argument is a routing hint, not
   proof — a preview1/core module named `abi="component"` or `abi="auto"` is
   refused, and an explicit `abi="preview1"` request is refused outright (the
   profile routes components only). File/read errors become controlled
   refusals; a non-regular path (for example a directory) is refused.
3. **Foreign-code trust only.** `trust` must be `unknown` or `untrusted`;
   `trusted` is refused (the profile never takes the host-authorised in-process
   fast path), and an invalid posture is refused rather than defaulted.
4. **Module identity bound to the load, verified end to end.** The digest of the
   inspected bytes is threaded as the per-call module binding, so the worker
   re-checks the bytes it actually loads. This is verified across a real
   parent/worker run: a module swapped after admission — including through a
   symlink or path repoint — is refused by the worker before the guest starts,
   and a caller-supplied digest that contradicts the inspected bytes is refused.
   No second identity architecture is introduced; the existing per-call digest
   binding is the mechanism.
5. **Mandatory isolation, no fallback.** With a proven component and a foreign
   posture the central gate forces the disposable worker and refuses (never
   downgrades) when it is unavailable; a worker failure is a fail-closed error
   with no in-process retry.

**Scope of the guarantee, fixed in writing.** A refusal is an `ERROR` carrying
the prefix `refused: protected component profile`, distinguishable from a guest
trap. It resolves **no ABI** (`abi=None`): nothing ran, so a refusal is never
attested as a component or preview1 execution under some process mode — it
claims no executed process mode and produces no successful attestation. This
holds for **every** protected refusal, not only the admission guard: the
sync-blockade requirement a component can never honour, the isolation mandate
when no worker is available, and a tenant admission denial all resolve no ABI.
The opposite case is reported truthfully instead: a worker that genuinely
started and then failed keeps `execution_mode=subprocess`, because that mode
did take effect. A successful protected run signs a record whose
`execution_mode` is `subprocess` and whose `abi` is `component`, verifiable with
the existing signer-agnostic verifier. Existing resource budgets stay in force.
Unsupported network egress is handled only where a real mechanism exists: the
runtime sandbox exposes no guest socket surface on these paths, and the MCP tool
layer owns the component+egress refusal — the profile makes no network-isolation
claim beyond that. The protected profile still makes **no claim of full
operating-system isolation**: an external Linux isolation layer remains an
operator precondition for the eventual deployment profile, and the component
sync blockade is still absent (`sync_blockade_enforced=false`) as attested by
ADR-014.

## Amendment — 1.2.0 (governance decision, the isolation mandate): extended to BOTH ABIs

**What changed.** The original gate (above) mandated isolation for
`abi == component and trust != trusted` and explicitly carved out Preview1
(“Preview1 runs are never a mandate class … the large in-process Preview1
workload is untouched”). The 1.2.0 decision rejects that carve-out: `untrusted`
**and** `unknown` require the protected worker for **both** ABIs, independent of
Preview1-vs-Component. The single-source predicate becomes
`isolation_required_for(trust, abi) = (trust != trusted)`; `unknown` stays
fail-closed and equals `untrusted`. Only an explicitly host-authorised `trusted`
run keeps the in-process path.

**Why.** The Preview1 exemption was justified only by GHSA-j2g9 (a
component-only datetime-overflow abort). The 1.2.0 posture does not rest
isolation on one advisory’s ABI shape: process isolation is the wall against the
whole class of host-side effects a runtime resource wall cannot bound (native
abort, the GHSA-32h6 async-lifted-component host effects (open memory-safety
risk, see below), future
Preview1-reachable classes). A per-advisory ABI carve-out would silently
re-expose the host whenever a new Preview1-reachable class lands.

**Enforcement is unchanged in kind:** decided at the same `WASISandbox.run()`
choke point before dispatch, raised to `use_subprocess` and **never lowered**;
if the worker is unavailable the run is **refused** (`ERROR`), never downgraded
in-process; a worker crash (including a native abort) is a fail-closed `ERROR`
with no in-process retry (pinned by
`tests/test_isolation_gate.py::test_forced_run_never_falls_back_to_in_process_on_worker_crash`).
Python, JavaScript, the direct WASM API, the CLI (`--trust`, default `unknown`)
and MCP all flow through this one decision.

**Breaking change + migration.** The `run()` default posture is `unknown`, so a
call that previously ran a Preview1 module in-process now spawns the worker.
Operators/tests that intend the in-process path must now **declare it**:
`sandbox.run(path, trust="trusted")`. This is the sanctioned host-authorisation
exception, never guest/manifest/MCP-derivable (decision 2 forbids silent
trust-elevation and forbids a performance-driven auto-upgrade). ADR-004
`state_store` grants remain in-process-only, so a state-backed run must declare
`trusted` (the gate refuses `state_store` + mandated isolation instead of
dropping the capability silently).

**Performance re-measurement (isolation mandate, item 10).** The prior “~66 ms per
forced component run” cost (below) no longer bounds the change: the default
Preview1 workload now pays the worker-spawn cost too. The broad
default-posture test-suite re-validation is **DONE** on the macOS dev box: the
full suite passes 1148 / 7 skipped / 0 failed after the isolation-mandate test adaption
(the in-process-subject tests declare the sanctioned `trusted` posture, the
timeout test asserts the security invariant across postures — no blanket
isolation flip), and the isolation-gate recursion that produced the 759-incident
worker fan-out is fixed (worker reaping + concurrency cap + payload deadline),
with **0 lingering `process_worker` processes** after a 24-burst and after the
full run (see commits 87a9b06, 4a1f0b5, dc04038). Re-measuring the worker-per-run
tax across the full workload matrix is still **gated on a healthy CI/pilot host**:
spot measurements taken while unrelated foreign processes held the box at load
average ~199–224 confirmed the posture split (trusted → `in_process`, unknown →
`subprocess`) but their wall-clock overhead is **host-contention contaminated and
NOT AUTHORITATIVE**; a clean matrix re-measure is tracked as **OFFEN**, not asserted.

**Async advisory note.** See [SECURITY.md](../../SECURITY.md) —
GHSA-32h6-97mm-8q3c (identical to RUSTSEC-2026-0327, a **native stack buffer
overflow**, not a host panic): the overflow is an **open, unresolved
memory-safety risk** at the 49.0.0 pin; the worker boundary is containment, not
closure, and the observed `unreachable!()` abort is a different code path that
does **not** prove the overflow unreachable. Public 1.2.0 is on HOLD.

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
