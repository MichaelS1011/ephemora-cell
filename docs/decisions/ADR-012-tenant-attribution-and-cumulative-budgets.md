# ADR-012: Tenant Attribution and Cumulative Budgets — Refuse Before the Run

- **Status:** Accepted
- **Date:** 2026-10-04
- **Predecessors:** ADR-002 (per-run I/O and CPU walls), ADR-004 (a passed
  capability IS the grant), ADR-008 (record split, frozen `to_dict()` schema),
  ADR-011 (hash chain across runs, single writer)
- **Basis:** Code inspection of `ephemora_cell/wasi_runtime.py` and
  `ephemora_cell/execution_report.py` on 2026-10-04, plus a market comparison
  against [`astrid-runtime/astrid`](https://github.com/astrid-runtime/astrid)
  (retrieved 2026-10-03), which keeps a per-principal fuel ledger whose own
  source comment scopes it to telemetry rather than enforcement.

## Context (verified, not assumed)

1. **Every wall in the Cell is per-run.** `WASIConfig` bounds one execution:
   `max_fuel`, `timeout_seconds`, `max_memory_mb`, `io_budget_bytes`,
   `io_cpu_seconds`, `disk_quota_bytes`, `max_wasm_bytes`. A guest that stays
   inside them and is simply called again pays nothing for the previous run:
   nothing in the config, the records or the engine expresses "across runs".
   A run counter and a cumulative fuel total therefore cannot be derived from
   any existing object — they need state the host owns.
2. **The record schema is frozen** (ADR-008: "`to_dict()` of plain reports is
   frozen (compat-pinned in tests); `back_link` is additive"). Adding
   `tenant` next to `status` would break every machine reader. The one place
   that is explicitly a free dict of posture and is already carried by BOTH
   records is `security_baseline`.
3. **Two runs of one module can finish in an order no clock can recover.**
   Subprocess runs start and complete independently, so timestamps cannot rank
   them — ADR-011 already resolved this by making arrival order the chain
   order under one writer lock. Cumulative accounting has the identical
   problem: two threads that each read "there is room" spend the same budget
   twice unless the read-that-decides and the write share one critical
   section.
4. **The market difference is enforcement, not bookkeeping.** A per-principal
   ledger that only reports consumption does not stop the next call. This ADR
   deliberately does not claim that recording is rare; it claims that a
   refusal issued *before* the module is compiled is the useful property.

## Decision

**`ephemora_cell/tenant.py`: `TenantId`, `Charge`, `CumulativeBudget`,
`TenantUsage`, `Admission`, `TenantStore` — and admission inside
`WASISandbox.run`.**

1. **A tenant is a billing and aggregation identity, not an isolation
   boundary.** `TenantId` (`tenant.py:57`) is an operator-chosen label,
   validated on construction (1..128 chars, `[A-Za-z0-9._:-]`, no padding, no
   leading dot). It is never read out of a guest-visible channel (argv, stdin,
   state keys, MCP `params`) and never carried as an env *value* — env values
   are excluded from `policy_fingerprint` by design, so an account key living
   there would be invisible to attestation. `SECURITY.md` and
   `docs/threat-model.md` keep their "single-tenant by design" statement: this
   adds attribution, it does not silently overturn it.
2. **Three dimensions, all integers the host already measures:** `fuel`,
   `output_bytes`, `wall_ms`. `Charge` (`tenant.py:94`) refuses negatives,
   floats, booleans and anything above the RFC 8785 safe-integer ceiling —
   sums across runs must not depend on float shortest-round-trip forms, and a
   number a verifier cannot read back identically is refused at the door
   rather than written.
3. **One window exists: all time.** `CumulativeBudget`
   (`tenant.py:139`) raises on `window="day"` instead of pretending. A rolling
   window needs a clock-trust decision (whose time, what skew, what happens
   after a restart) that has not been made; see Consequences.
4. **One writer, one critical section.** `TenantStore` builds on the same
   `AppendLog` (`ephemora_cell/_appendlog.py`) as the ledger: exclusive
   `flock`, `O_APPEND`, one `os.write`, `fsync` before the lock is released.
   `decide_and_append()` hands the caller the current tail and the writer's
   decision together, which is the only shape in which "read the balance,
   then decide" is safe.
5. **Reserve on admission, bill the actual, release on crash**
   (`tenant.py:272`/`:358`/`:401`). The reservation is NOT caller-supplied: it
   is `WASISandbox.reservation()`, read off the config — `max_fuel`, plus
   `2 * _MAX_OUTPUT_BYTES + io_budget_bytes` bytes (captured stdout and stderr
   plus the sandbox scratch wall), plus `timeout_seconds * 1000`. A caller
   therefore cannot bill a rival tenant a full budget by reserving loudly. A
   knob set to `None` (unbounded by design) contributes 0 rather than an
   invented number, which is exactly why admission also compares what previous
   runs *actually* consumed.
6. **Caps are inclusive: a cap of N admits exactly N runs.** The comparison is
   the account INCLUDING this run (`settled + open reservations + this
   reservation`, `runs + inflight + 1`), so the Nth run fits and the N+1st is
   refused. Pinned under contention: 20 threads against `max_runs=7` yield 7
   admissions and no more.
7. **Refusal happens before anything starts.** Admission is in `run()`
   (`wasi_runtime.py:439`), above the subprocess, component and preview1
   dispatches; `_execute()` (`:602`) is the private, unbilled body. A refused
   run compiles nothing, spawns nothing and opens the module file nowhere —
   `run()` returns `ExecutionResult(status=ERROR)` whose stderr names the cap
   (`tenant budget exhausted: runs`). This is the only place all three paths
   converge, so it is the only place the check has to live.
8. **No new top-level schema keys.** Attribution rides inside
   `security_baseline.tenant` and `security_baseline.tenant_budget_ref`
   (`execution_report.py:72`, written by `apply_config` at `:169` and
   `PreExecutionRecord.build`), and `policy_fingerprint` (`:375`) folds both
   into the digest — but the keys are present ONLY when a tenant was
   attached, so a record of an unaccounted run keeps the exact bytes it had
   before this existed. That is tested, not argued.
9. **Two flags carry the truth a total cannot:** `violation` (the run hit one
   of its own walls: timeout, fuel, memory, I/O budget) and `unknown` (no fuel
   figure, i.e. the worker died before reporting one). An unknown run is
   billed in wall time and counted separately — never as free fuel.
10. **The raw APIs stay raw.** `run_wasm`, `ComponentSandbox.run` and
    `run_isolated` do not take a tenant: `run_wasm`'s docstring names
    `WASISandbox.run` as the entry that bills. Using the guts directly is
    documented, not silently unbilled.

## Consequences

**Gained**

- A cumulative cap that can refuse a run before it costs anything, on the same
  three units the sandbox already measures.
- Per-account totals that are *derived* by replaying the file, not stored
  alongside it — and a line-level check that proves a booked charge was
  edited or lines reordered.
- Receipts that name the account and the cap they were admitted under, which
  no per-run config digest can express.
- Two processes pointed at one book share one book, because every decision is
  taken under the writer lock.

**Accepted costs and limits (stated, not hidden)**

- **Overshoot is bounded by (concurrent runs × per-run walls).** A run already
  executing is never stopped by this module — only by its own ADR-002 walls.
  Refusal is pre-run; there is no mid-run kill here.
- **A budget smaller than one run's own wall refuses everything.** The
  reservation IS that wall, so `max_total_fuel=1000` with `max_fuel=10_000`
  never admits a run. That is arithmetic, not a bug to paper over; sizing
  budgets against the per-run ceilings is the operator's decision and is
  pinned by test.
- **The book proves editing and reordering, not truncation or appended
  history.** Each line carries the state as it must be AFTER it took effect,
  so a forged middle is visible; a file cut short, or extra honest-looking
  lines appended by someone with write access, is not — the same blindness
  ADR-011 accepts, and the same cure (an externally anchored head) applies.
- **Single host, advisory `flock`.** NFS semantics vary; multi-host accounting
  needs a different store.
- **A crashed caller leaves its reservation standing** until `expire()` is
  called or the 900 s TTL passes. Until then the account sees that capacity as
  in use, which is the safe direction and is also a slow self-DoS if a caller
  crashes repeatedly.
- **No rolling windows, no per-tool budgets, no rate limiting.** Those need
  time semantics this module deliberately does not guess.
- **The MCP server does not bill yet.** `ephemora_cell_mcp/engine.py:187` calls
  `WASISandbox.run` without a tenant, and that is the deliberate part: which
  account a tool call belongs to — the tool, the session, the API key — is a
  policy decision of the operator, and inventing a default would attribute runs
  to an account nobody chose. The attachment point is the same report builder
  that already puts the run's receipt into MCP `_meta.execution`, so an
  embedding that passes a tenant gets the account attested there; the
  `run --tenant` CLI path is tested end to end in the meantime.
- **The tenant label appears in signed evidence.** It is an operator-chosen
  account key, so it must not be a personal-data string.
- **Guests are unaffected:** nothing a guest can observe changes when a
  tenant is attached. That is the point, and it is why `tenant` never reaches
  the worker payload (`tests/test_tenant_budgets.py::TestRunEnforcement::test_the_worker_never_sees_the_tenant`).

## Evidence

- `ephemora_cell/tenant.py`, `ephemora_cell/_appendlog.py` (shared writer),
  `WASISandbox.run`/`_execute`/`reservation`, and the optional attestation
  kwargs in `execution_report.py`.
- `tests/test_tenant_budgets.py` — 49 tests, including
  `test_reservation_is_the_configs_own_wall`,
  `test_parallel_admissions_cannot_oversell_a_run_cap`,
  `test_every_dispatch_is_billed_exactly_once` (preview1, subprocess,
  component, auto-unpooled),
  `test_refusal_starts_nothing`,
  `test_a_run_that_never_returns_gives_its_reservation_back`,
  `test_the_worker_never_sees_the_tenant`,
  `test_edited_totals_do_not_silently_pass`, and
  `test_a_budget_smaller_than_one_runs_wall_refuses_everything`.
- `tests/test_records_envelope.py` — records without a tenant are
  byte-identical, and with one the fingerprint and the baseline both move.
- `ephemora-cell run --tenant ID --tenant-book PATH [--tenant-max-runs N
  --tenant-max-fuel N]` — two invocations against one book accumulate, and
  the second is refused once its cap is spent.
- Market basis: astrid's `fuel_ledger.rs` (per-principal, telemetry-scoped)
  and its signed audit chain — see `docs/comparison-mcp-servers.md`,
  retrieved 2026-10-03.
