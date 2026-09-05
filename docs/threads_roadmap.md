# Shared-Everything Threads — Roadmap & Security Model

Status: **Phase 0 (threads disabled by default — shipped since 1.0.0)**
Document owner: Release & Quality Engineering
Last updated: 2026-08-13 (wasmtime 47.0.1, Wasm 3.0)

This document is the decision record for Ephemora Cell's threading posture. It
describes how threads are disabled today, audits the Python-side concurrency
posture of the runtime, defines what enabling shared-everything threads
(Wasm threads + shared memory + WASI threads) would require, and lays out a
phased roadmap with security gates. It grounds itself in the WASM/WASI research
file (`wasm-recherche-2026.md` — external research file, August 2026 state; not
part of this repo) and the
resource-isolation analysis in [arXiv 2509.11242](https://arxiv.org/abs/2509.11242).

---

## 1. Current state: threads are disabled everywhere

### 1.1 The three engine construction sites

Every wasmtime engine Ephemora Cell ever creates is built with the same frozen
feature baseline. There is exactly one engine per construction site, and all
three set the flags in the same way:

| # | Construction site | File | Location |
|---|-------------------|------|----------|
| 1 | `WASISandbox.run()` inline engine (non-pooled path) | `ephemora_cell/wasi_runtime.py` | `engine_config.wasm_threads = False` (also `wasm_multi_memory = False`; `wasm_memory64 = config.memory64`) |
| 2 | `EnginePool._new_entry()` pooled engine (default `use_engine_pool=True` path) | `ephemora_cell/engine_pool.py` | `engine_config.wasm_threads = False` (multi-memory frozen, memory64 from config) |
| 3 | `ComponentSandbox.run()` engine (WASI 0.2 components) | `ephemora_cell/wasi_02.py` | `engine_config.wasm_threads = False` (multi-memory frozen, memory64 from config) |

In all three sites the sequence is identical: `consume_fuel = True` when
`max_fuel` is set, `epoch_interruption = True`, then the feature policy
(`wasm_threads = False`, `wasm_multi_memory = False`; memory64 mirrors the
per-config opt-in).

Note: the *engine* has no memory-limit knob that works — `Config.memory_max_bytes`
is a no-op in wasmtime-py 47. The real memory limit is
`Store.set_limits(memory_size=...)`, which is applied per-store at
`wasi_runtime.py` and `wasi_02.py`. See §4.4 for why this matters for shared
memories.

### 1.2 The test asserting single-thread enforcement

`tests/test_security.py` (`TestSecurityBoundary.test_wasm_threads_disabled`)
compiles a core module with a shared memory (`(memory (export "memory") 1
shared)`) and asserts that running it through `WASISandbox` returns
`ExecutionStatus.ERROR` — a shared-memory module must never instantiate. The
security-baseline fingerprint in `execution_report.py` additionally freezes
`threads_enabled: False` into every `ExecutionReport`, and that flag is asserted
in `tests/test_security.py` and carried through the process-isolation report
(`process_executor.py`/`process_worker.py`).

`tests/test_threads_baseline.py` (added with this document) extends coverage to
**all three** construction sites: the pooled engine, the inline Preview1 engine,
and the component engine, plus a positive control proving that the rejection is
caused by `wasm_threads=False` and not by the module itself.

### 1.3 Why threads are disabled (the security rationale)

1. **Attack surface.** Shared memory + atomics are the one Wasm feature that
   introduces *cross-instance* state. A malicious module can use a shared memory
   as a covert channel (see §5.1) and can busy-wait on atomics in a way that
   fuel metering does not directly bound (§5.2).
2. **Multi-tenant contamination.** Ephemora Cell documents itself as
   single-tenant in-process (§7 of this doc). Enabling threads while
   multi-instance modules can share memory would create implicit coupling
   between instances in the same process — contradicting the isolation model in
   `README.md`.
3. **No WASI threads host support.** WASI-level thread spawning is not
   standardized as of 2026: the original `wasi-threads` proposal was **withdrawn
   in August 2023** (issue #48) in favor of the shared-everything-threads (SET)
   proposal, which is still a draft and **unimplemented in wasmtime 47**
   (tracking issue #9466). WASI 0.3.0 ships without threading. Until a stable
   host API exists, "threads on" only enables *core* shared memory — the least
   useful, highest-risk slice.
4. **Engine-documented resource-limit gaps.** wasmtime's own stability docs mark
   the core threads proposal as "Finished: 🚧" with two known issues: shared
   memories are **not well integrated with resource-limiting features in
   `Store`**, and shared memories are **not supported in the pooling allocator**.
   Both are exactly the primitives Ephemora Cell's memory/fuel accounting relies
   on — the engine vendor itself documents the boundary Phase 0 protects.
5. **Epoch/fuel semantics with threads are unresolved** (§5.3, §5.4). The
   runtime's guarantees (fuel, timeout, memory cap) are defined for single-thread
   guests; enabling threads without re-deriving those guarantees would silently
   weaken them.

**Decision: threads remain disabled by default (Phase 0).** Enabling is an
explicit, config-gated, security-reviewed opt-in (Phase 1) — never a default.

---

## 2. Python-side thread-safety audit (current concurrency posture)

Audience note: this section is about the *host* Python runtime, not about
Wasm guest threads. It answers "what can application threads do concurrently
today?"

### 2.1 What is safe for concurrent use today

| Component | Posture | Detail |
|-----------|---------|--------|
| `WASISandbox.run()` | **Per-instance state only** | All state (`_sandbox_dir`, `_host_dir`) is instance-scoped and per-run. Two sandboxes can run concurrently on two Python threads with no shared mutable state — this is the documented "one thread per instance" model (`CHANGELOG.md` 1.0.0). |
| `Store` (wasmtime) | **Per-run, never shared** | A new `Store(engine)` per `run()`; `set_limits`/`set_fuel`/`set_epoch_deadline`/`set_wasi` are all store-scoped and never cross threads. |
| `EnginePool.engine_for()` | **Safe** | `_lock` serializes LRU bookkeeping; fingerprint lookup is atomic under the lock. |
| `EnginePool.cached_module()` | **Safe** | Cache access is serialized per engine entry with `entry.lock`. |
| `linker.instantiate` on pooled modules | **Safe** | Must be wrapped in `pool.locked(engine)` — done at `wasi_runtime.py:399-401` because wasmtime `Module` instances are **not** thread-safe. This is the single most important discipline for pool users. |
| `process_executor.run_isolated()` | **Safe** | Each call spawns its own worker process; JSON is exchanged over the worker's pipes. No cross-call host state. |
| `run_wasm()` convenience wrapper | **Safe** | Pure composition of the above; sandbox is local to the call. |
| `Engine.increment_epoch()` | **Engine-level, shared** | See §2.2. |

### 2.2 What is NOT safe for concurrent use today (or is subtle)

- **`engine.increment_epoch()` is engine-global and racy by design.** The epoch
  timer thread (`wasi_runtime.py:414-422`, `wasi_02.py:212-219`) fires on the
  timeout deadline and increments the *engine's* epoch. With the inline (non-
  pooled) path each run owns its engine, so the timer only affects its own run.
  **But** with the engine pool, the engine is *shared*: a late-firing timer from
  run A can increment the epoch while run B (same engine, different store) is
  mid-execution. Today this is benign — every run sets `set_epoch_deadline(1)`
  and each run's deadline is evaluated per-store — but it means the timer is
  **not** a per-run isolation primitive when engines are pooled. Concurrent runs
  on the same pooled engine must never assume their timeout trap is triggered
  *only* by their own timer.
- **Two concurrent `run()` calls must not share one `WASISandbox` instance.**
  `_sandbox_dir`/`_host_dir` are overwritten per run; `cleanup()` deletes
  whatever the fields currently point at. Concurrent `run()` + `cleanup()` on
  the same sandbox object is a use-after-free class bug (host-side). One thread
  per instance — or one sandbox per run.
- **Module cache + instantiation.** Sharing a wasmtime `Module` across threads
  is unsupported; the pool serializes it (see §2.1). A caller bypassing the pool
  (inline engine path) has no such hazard because modules are per-run.
- **Epoch timer threads are daemon threads that outlive the call.** The timer
  is only joined via `timeout_event.set()` in `finally`. On the pooled path a
  timer that fired late touches a shared engine after the run returned. This is
  safe (engine is pooled and never dropped while referenced) but it means engine
  teardown (pool `close()`) must not race active timers — pool `close()` is
  intended for single-threaded shutdown.
- **Process isolation does not protect the host's own process.** `run_isolated`
  moves the *guest* into a disposable worker (RLIMIT_NOFILE=256,
  RLIMIT_AS = max(guest memory + 64 MiB, 8 GiB) — the 8 GiB floor matches
  wasmtime's 4 GiB-per-memory virtual reservation, see §3.4 —
  RLIMIT_RSS = memory + 64 MiB, 32 MiB module cap, hard timeout = guest
  timeout + 5 s), but the *caller* can still hammer the parent with many
  concurrent workers. Worker spawn cost is the only natural throttle.

### 2.3 Summary statement

> Safe for concurrent use: any number of `WASISandbox`/`ComponentSandbox`
> instances on separate threads, pooled engine lookup/caching, subprocess
> execution. Not safe: sharing one sandbox instance across threads, sharing a
> wasmtime `Module` outside `pool.locked()`, or relying on a pooled engine's
> epoch timer as a per-run isolation boundary.

This posture is unchanged by Phase 0 and is a prerequisite input to Phase 1's
review checklist.

---

## 3. What enabling shared-everything threads would require

Shared-everything threads = the threads proposal set: shared memories +
atomics + (eventually) WASI threads (thread spawn). None of it exists in the
codebase today; every engine has `wasm_threads = False`.

### 3.1 Core engine changes (single site of truth)

Today the feature freeze is copy-pasted at three sites. Enabling threads must
first **unify** the freeze into one shared builder (e.g. a module-level
`_build_engine_config(config, threads: bool)`), or the three sites will drift.
The switch itself is one line per site: `engine_config.wasm_threads = True`
when an opt-in is granted (Phase 1) or unconditionally (Phase 2). `wasmtime
47.0.1` supports `wasm_threads` (shared memory + atomics; default engine is Wasm
3.0 with GC/exceptions — `wasm-recherche-2026.md` §1).

### 3.2 Shared-memory semantics that interact with existing limits

- **`memory.grow` on shared memories.** Growing a shared memory is an
  *aggregate* operation — one agent grows memory visible to every other agent
  sharing the same memory. `Store.set_limits(memory_size=...)` binds the store's
  memories; it is not documented as binding the *shared* aggregate across
  stores. All memory-accounting claims ("max 128MB default") must be re-derived
  for shared memories before threads can be on by default.
- **memory64 × shared-memory interaction.** Wasm 3.0 brings memory64
  (`wasm-recherche-2026.md` §1). A 64-bit shared memory would make
  "shared aggregate size" accounting even looser; memory64 is a per-config
  opt-in since 2.1.0 but **64-bit shared memory** (shared-everything threads)
  stays out of scope — see §6, Q5 (resolved).
- **Atomics and fuel.** `memory.atomic.*` instructions are metered like any
  other instruction, but see §5.2 for why this is not a DoS defense on its own.
- **`wait`/`notify` host limits.** Shared memories have a max waiters count and
  `notify` semantics; wasmtime's defaults are not a security boundary. A guest
  can legally park threads on a shared memory — and if the guest is single
  "thread" in Ephemora Cell's model, a self-parked `wait` becomes a hang that
  only the epoch interrupt resolves (and only if the waiting instruction yields
  to epoch checks — see §5.3).

### 3.3 WASI threads for components (wasmtime 47 status)

**Empirically verified (wasmtime 47.0.1):** `wasm_threads` defaults to
**True** — a blank engine *compiles* a shared-memory module
`(memory 1 2 shared)`. Ephemora Cell's explicit `wasm_threads = False` is
therefore what rejects shared memories at parse time. As a second,
independent barrier, wasmtime's separate `Config.shared_memory` defaults to
**False**: even with `wasm_threads = True`, instantiation of a shared memory
fails with "shared memory support is disabled for this engine" unless
`shared_memory = True` is also set. Any future threads opt-in (Phase 1+) must
set *both* flags; Ephemora Cell sets neither (`shared_memory` stays at its
default), so both barriers are currently host-side defaults or explicit.

`wasm_threads=True` on the engine enables the *core* threads proposal (shared
memories + atomics + wait/notify — this part is Phase 4 / finalized and
implemented server-side in wasmtime, *not* browser-only). It does **not**
provide the WASI threads *host API* (spawn): `wasi-threads` was withdrawn in
August 2023, and the successor shared-everything-threads proposal is a draft
that wasmtime 47 has **not implemented** (tracking issue #9466). For components
there is no stable `wasi:threads` world in wasmtime 47. Practical consequences
for Ephemora Cell:

- Preview1 path: modules compiled with `wasm32-wasi-threads` (the old,
  preview-only threads) will not run — Ephemora Cell's `WASISandbox` provides
  no threads host functions. No regression; status quo.
- Component path (`ComponentSandbox`, WASI 0.2): no threads imports exist to
  link; enabling the engine flag only allows *shared-memory* core modules.
- A real spawn-capable configuration requires the shared-everything-threads
  proposal to reach the Component Model — aligned with Component Model 1.0
  (target late 2026 / early 2027, `wasm-recherche-2026.md` §3).

### 3.4 Interaction with the process-isolation layer

`process_worker.py` applies OS rlimits (NOFILE, AS/RSS) before the sandbox runs.
Shared memory is host-backed mmap; a multi-gigabyte shared memory reservation
counts against RLIMIT_AS on Linux (best effort on macOS, where RLIMIT_AS cannot
be lowered). RLIMIT_AS is set to `max(guest memory + 64 MiB, 8 GiB)` — the
8 GiB floor exists because wasmtime reserves 4 GiB of virtual address space per
32-bit linear memory (plus JIT code space), and a tighter cap broke
instantiation on Linux with "mmap failed / Cannot allocate memory" (reproduced
and fixed 2026-08, CI #7). So the AS limit is a **runaway-allocation backstop,
not a tight per-memory cap**; the physical cap is `Store.set_limits` plus
RLIMIT_RSS (best effort; historically unenforced on Linux). For shared-memory
guest code this keeps the honest promise "bounded by the process" rather than
by store-level accounting, matching option C in §4.4.

---

## 4. Security model for enabled threads

### 4.1 Cross-instance shared memory: covert channel / attack surface

The fundamental property change: with threads enabled, **memory is no longer
private to an instance**. If a host ever multi-tenant runs two untrusted
modules in one process (the current docs explicitly say it does not — §2.3),
shared memory becomes:

- a **covert channel** between tenants (timing + data signals through shared
  pages), and
- a **confused-deputy** vector: one guest can `memory.grow` a shared memory and
  force *another* guest's store accounting out of sync (arXiv 2509.11242's
  resource-isolation analysis: the paper catalogs exactly this class — limits
  attached to the wrong granularity).

Mitigation stance for Phase 1: shared memory is only meaningful across
instances if two modules coordinate. Ephemora Cell instantiates one module per
store per run; cross-instance sharing requires *named exports of memories*
between components, which Ephemora Cell never wires. The Phase 1 review
checklist must assert that no linking path can pass a memory handle between
instances.

### 4.2 Spin-lock DoS — does fuel metering cover atomics?

**Partially, and not by default.** Atomic instructions consume fuel per
execution, so an infinite `atomic.rmw` loop is bounded like any other CPU loop.
But the classic spin-lock DoS is *waiting*: a thread that parks on
`memory.atomic.wait` consumes **no** instructions (and no fuel) while blocked.
With one OS-thread-per-guest and no WASI spawn, a single `wait` on a never-
notified address is an instant hang — caught only by the wall-clock timeout,
*if* the epoch interrupt fires while the guest is in a wait (see §5.3).
Conclusion: **fuel metering is not a sufficient DoS defense for threads; the
epoch timeout remains the primary backstop, and its semantics for waiting
guests are an open question (Q2).**

### 4.3 Epoch interruption in multithreaded guests

Today `store.set_epoch_deadline(1)` + a host timer + `engine.increment_epoch()`
traps the *single* running guest. With a multithreaded guest, wasmtime's epoch
check is per-thread-point: threads parked in `atomic.wait` may or may not
observe the epoch bump promptly (wait returns on spurious wakeup/notify —
wasmtime semantics). Two risks:

1. **Late trap:** a guest that swallows the trap in one thread while another
   keeps computing can exceed `timeout_seconds` from the *host's* perspective —
   the wall-clock guarantee weakens from "hard" to "best effort". The process
   isolation layer (worker hard timeout) is the only absolute guarantee, which
   pushes Phase 2 toward *requiring* process isolation when threads are on.
2. **Timer/engine coupling (from §2.2):** with pooled engines, one timer bumps a
   shared engine epoch; a multithreaded guest is more likely to notice *and
   mishandle* an unexpected interrupt (e.g. trap in a random thread → torn
   guest state → host-side exceptions in guest-wasm imports).

### 4.4 Memory accounting for shared memories

The real memory limit (`Store.set_limits(memory_size=...)`) is applied per
store. A shared memory's *minimum* is committed on first touch per participating
store and its *maximum* can be reserved once. wasmtime's stability docs confirm
the gap explicitly: **shared memories are "not well integrated with
resource-limiting features in `Store`"** and unsupported in the pooling
allocator — i.e. the engine itself does not promise that
`Store.set_limits(memory_size=...)` accounts shared-memory aggregates. Options
for accounting:

- **A:** count `max` of every shared memory against the store limit (strict,
  breaks legitimate large shared buffers).
- **B:** count current aggregate (pages actually grown) across stores — needs
  host-side bookkeeping that wasmtime-py does not expose today.
- **C:** treat shared memories as outside the store limit and rely on process
  isolation (RLIMIT_AS) as the cap — pragmatic, keeps the promise "bounded by
  the process", but changes the documented meaning of `max_memory_mb`.

Roadmap position: **C for Phase 1 (with mandatory process isolation), B as a
Phase 2 engineering task** (track per-engine shared-memory aggregates; expose
them in the `ExecutionReport.security_baseline`).

### 4.5 Additional attack surface introduced

- **`memory.atomic.wait`-based resource exhaustion** (§4.2).
- **Shared-memory data races** are a *correctness* concern, but in a sandbox the
  security question is whether a host-side panic class opens (wasmtime 47
  hardening — see `wasm-recherche-2026.md` §6 for the CVE cadence around
  Cranelift/GC; any threads work must re-run the CVE review gate).
- **Guest-to-guest interference** if Ephemora ever grows multi-module
  composition.

---

## 5. Roadmap

### Phase 0 — Keep disabled (DEFAULT, current)

**What:** `wasm_threads = False` everywhere; shared-memory modules rejected
(asserted in `tests/test_security.py` and `tests/test_threads_baseline.py`);
`threads_enabled: False` frozen in the security baseline of every report.

**Trigger criteria to LEAVE Phase 0:** none. Phase 0 is the default and the
security posture this project ships on.

**Acceptance criteria:**
- The three engine construction sites and the baseline tests above remain in
  sync (a drift in one site is caught by `tests/test_threads_baseline.py`).
- No public API accepts a "threads" knob that is silently ignored.

**Open questions:** none for Phase 0; all Q1–Q5 below are Phase 1/2 inputs.

### Phase 1 — Per-config opt-in (`max_threads > 1`) with security review

**What:** an explicit opt-in flag (the field `WASIConfig.max_threads` already
exists and is fingerprint-relevant in `EnginePool.config_fingerprint`; today
any value > 1 is silently ignored because the engine freeze wins). Phase 1
makes `max_threads > 1` actually set `wasm_threads = True` at all three
construction sites, under mandatory constraints:

- **Mandatory security review checklist (each item must be signed off):**
  1. `wasm_memory64` keeps its per-config opt-in semantics — default stays
     `False`; **64-bit shared memory** (memory64 × threads) stays out of
     scope (Q5, resolved in 2.1.0).
  2. `wasm_multi_memory` stays `False`.
  3. Process isolation is *required* for any run with threads on
     (`use_subprocess=True` enforced or warned) — RLIMIT_AS/RSS become the
     shared-memory hard cap (§3.4).
  4. No path can link a memory export between two module instances (§4.1).
  5. `max_threads` is capped (e.g. ≤ 4) and appears in the
     `security_baseline` fingerprint instead of the frozen `False`.
  6. Documentation updated: timeout is best-effort for waiting guests (§4.3).
- **Trigger criteria to START:** a customer/toolchain need for shared-memory
  guest code (e.g. a `wasm32-wasip2` component using shared memory) with a
  written acceptance that single-thread defaults remain intact.
- **Acceptance criteria:** opt-in is per-config, default unchanged
  (`max_threads = 1` ⇒ `wasm_threads = False`); review checklist is a checked
  CI job or at minimum a reviewed doc with sign-off; new tests assert that
  shared-memory modules run *only* with the opt-in and fail otherwise; report
  fingerprint reflects the opt-in.
- **Open questions:** Q1, Q2, Q4.

### Phase 2 — Full support with shared-memory accounting

**What:** threads become a first-class, accountable feature:

- Per-engine shared-memory aggregate tracking (§4.4, option B) surfaced in
  `ExecutionReport`; `max_memory_mb` semantics re-derived for shared memories.
- WASI threads (spawn) support when the shared-everything-threads proposal
  lands in wasmtime and Component Model 1.0 (late 2026 / early 2027,
  `wasm-recherche-2026.md` §3) — this is a *dependency*, not a commitment.
- Epoch-interrupt semantics for multithreaded guests verified (or the timeout
  contract explicitly re-scoped to "process-level only" for threaded runs).
- Fuel-vs-wait analysis: document whether `atomic.wait` can be bounded by fuel
  at all (it cannot, per §4.2 — so the wall-clock/epoch contract must carry the
  guarantee).
- **Trigger criteria to START:** Phase 1 has shipped ≥ 2 real adopters with
  feedback; shared-everything-threads is stable upstream; Component Model 1.0
  final.
- **Acceptance criteria:** memory accounting is testable and unit-tested
  (shared aggregate ≤ documented cap); threaded guests are interrupted by
  epoch/timeout with a worst-case latency bound; `tests/test_threads_baseline.py`
  gains positive-path thread tests; full CVE review of wasmtime's threads
  implementation (research file §6: review the Cranelift/GC advisory cadence
  before enabling in production).
- **Open questions:** Q3.

### Cross-phase decision table

| Question | Phase 0 | Phase 1 | Phase 2 |
|----------|---------|---------|---------|
| Ephemora Cell default `wasm_threads` (engine default is *True*, §3.3) | False | False | False (opt-in stays) |
| Opt-in via `max_threads>1` | — | Yes (≤4, reviewed) | Yes (capped, accounted) |
| Shared-memory accounting | — | Process rlimits only | Store/engine-level aggregate |
| WASI threads (spawn) | No | No | Yes (when upstream stable) |
| Timeout contract | Hard (single thread) | Best-effort for waiters, hard via process | Bounded-latency interrupt |

---

## 6. WebAssembly 3.0 posture (verification, 2026-08)

Precise status of the Wasm 3.0 release as it relates to Ephemora Cell,
verified against webassembly.org, the W3C track, the spec repo, and wasmtime
47.0.1's own proposal matrix.

### 6.1 What "Wasm 3.0" officially is

- Wasm 3.0 was **released 2025-09-17** by the WebAssembly W3C Community Group
  as the new "live" standard (webassembly.org news post by Andreas Rossberg).
  It is a rolling spec (spec repo releases 2026-07-10 / 2026-07-28 are later
  editions) — there is **no W3C "Recommendation" status** for 3.0; the W3C
  Working Group track continues to maintain the core spec as a Candidate
  Recommendation living standard. Claims of "finalized June 2026" come from
  third-party blogs (e.g. byteiota), not from webassembly.org or the W3C.
- The official 3.0 additions (webassembly.org release note): **memory64
  (64-bit address space), multiple memories, WasmGC, typed function
  references (`call_ref`), tail calls, relaxed SIMD, the deterministic
  execution profile, and custom annotation syntax** (text format) — exception
  handling, extended constant expressions and branch hinting are also part of
  the 3.0 spec. 128-bit fixed-width SIMD itself was already a Wasm 2.0
  feature (2022); the "nine production features" lists floating around vary by
  source and are not authoritative. The user-facing short list "WasmGC,
  Memory64, EH, Tail Calls, SIMD, Multiple Memories, Typed Function References,
  Relaxed SIMD" is 7/8 accurate as *3.0* features (SIMD = 2.0) and omits
  extended const / branch hinting.

### 6.2 Feature status inside Ephemora Cell (wasmtime 47.0.1)

| Wasm feature | Engine default in 47 | Ephemora Cell | Verifiable at |
|--------------|----------------------|---------------|---------------|
| WasmGC (`wasm_gc`) | enabled | **enabled** | `gc_poc` benchmarks (3.93 ms / 10.6× vs arithmetic) |
| Exceptions (`wasm_exceptions`) | enabled | **enabled** | engine defaults untouched |
| Tail calls (`wasm_tail_call`) | enabled | **enabled** | engine defaults untouched |
| SIMD (`wasm_simd`) | enabled | **enabled** | Wasm 2.0 feature, engine default |
| Relaxed SIMD | enabled | **enabled** | engine default |
| Typed function refs (`wasm_function_references`) | enabled | **enabled** | engine default |
| Extended const | always on | **enabled** | no flag exists in wasmtime-py 47 |
| Branch hinting | disabled (pre-fuzz) | disabled | wasmtime default |
| Memory64 (`wasm_memory64`) | enabled | **off by default, per-config opt-in** (`WASIConfig.memory64` / `--memory64`) | all 3 construction sites + worker passthrough + fingerprint |
| Multiple memories (`wasm_multi_memory`) | enabled | **frozen OFF** (policy) | all 3 construction sites |
| Threads / shared memory (`wasm_threads`) | enabled (Tier 2, gaps) | **frozen OFF** (policy) | all 3 construction sites |

The freeze on multi-memory and threads is policy, not engine limitation:
wasmtime 47 fully supports memory64 and multi-memory (Tier 1). Ephemora Cell
keeps multi-memory and threads off for a deterministic,
attack-surface-minimized baseline, and exposes memory64 as an explicit
per-config opt-in (see §6.3).

### 6.3 Memory64 and the `llm` profile — what is actually true

Memory64 (64-bit address space, up to 16 EiB *theoretically*) is often called
the most relevant Wasm 3.0 feature. For Ephemora Cell the honest analysis is:

- The **llm profile caps memory at `max_memory_mb=128`** (`profiles.py`), far
  below the 4 GiB i32 wall. The address width is **not** the binding constraint
  for LLM workloads today — the cap, the absence of GPU access (no
  standardized GPU proposal; `wasi-nn` remains a proposal), and the 30 s
  timeout are.
- **Local LLM inference inside the sandbox is therefore not a Memory64 story.**
  Even with memory64 enabled, the 128 MB cap would still block model hosting;
  and no accelerator path exists in WASI. Ephemora Cell's llm profile remains
  aimed at *tool-call execution*, not model hosting.
- Memory64 **would** matter if Cell ever hosted >4 GiB single-memory data
  workloads (large embedding stores, in-memory knowledge bases). That is why
  memory64 is a **per-config opt-in since 2.1.0** (`WASIConfig.memory64=True`,
  `run_wasm(memory64=True)` or CLI `--memory64`), defaulting to `False`:
  `Store.set_limits(memory_size=...)` still binds committed size, the in-process
  worker keeps its `RLIMIT_AS` floor at 8 GiB (wasmtime reserves 4 GiB per
  32-bit memory; 64-bit reservations grow on demand — verified up to a 32 TiB
  declared max under the 8 GiB floor on Linux), and the engine-pool fingerprint
  splits engines by `memory64` so frozen and opted-in configs never share an
  engine. Multi-memory and threads remain frozen regardless (§6.1).

---

## 7. Open design questions

- **Q1 (gating):** Is there a concrete near-term use case for shared-memory
  guests at all? If not, Phase 1 has no trigger and the flag stays inert —
  which the team accepts as the default posture.
- **Q2 (timeout contract):** May the wall-clock timeout contract be weakened to
  "best effort inside the process, hard via worker kill" for threaded runs?
  (The only honest option given §4.2/§4.3.)
- **Q3 (accounting):** For Phase 2, is per-store `max` accounting (option A)
  or aggregate tracking (option B) the product's memory promise? A changes
  `max_memory_mb` semantics for all users; B adds host-side tracking cost.
- **Q4 (opt-in surface):** Should `max_threads` remain a raw int, or should
  the public API expose a two-value enum (`SINGLE` / `SHARED_MEMORY_LEGACY`)
  to make the "no spawn yet" limitation impossible to misunderstand?
- **Q5 (memory64):** *Resolved in 2.1.0* — memory64 is a per-config opt-in
  (`WASIConfig.memory64` / `--memory64`, default off). Open: should a
  profile (e.g. a future `embedding` profile) default it to on?

---

## 8. References

- `wasm-recherche-2026.md` — WASI/WASM state of the art (August 2026): Wasm 3.0
  (memory64, GC, exceptions), WASI 0.3 (ratified 2026-06-11), Component Model
  1.0 target, wasmtime 47 defaults, wasmtime CVE cadence.
- [arXiv 2509.11242](https://arxiv.org/abs/2509.11242) — WASM resource
  isolation gaps; the cross-instance/limit-granularity attack classes map
  directly to §4.1–§4.4.
- `tests/test_security.py` — `TestSecurityBoundary.test_wasm_threads_disabled`
  and the `security_baseline` fingerprint tests.
- `tests/test_threads_baseline.py` — the three-site threads baseline.
- `CHANGELOG.md` 1.0.0 — "Single-thread enforcement (`wasm_threads = False`)".
- webassembly.org — *Wasm 3.0 Completed* (2025-09-17, release of the 3.0 live
  standard), spec releases 2026-07-10 / 2026-07-28 (rolling).
- wasmtime 47 — *Wasm Proposals* stability matrix (threads = Tier 2
  "Finished: 🚧": shared memories not integrated with `Store` resource limits,
  unsupported in the pooling allocator; shared-everything-threads listed under
  unimplemented proposals, tracking issue #9466).
- WebAssembly/wasi-threads — proposal withdrawn Aug 2023 (issue #48) in favor
  of shared-everything-threads; retained only as a legacy preview1 API.
- wasmtime-py 47 config surface (verified): `wasm_memory64`, `wasm_multi_memory`,
  `wasm_threads`, `wasm_gc`, `wasm_exceptions`, `wasm_tail_call`,
  `wasm_function_references`, `wasm_relaxed_simd` all settable; extended-const
  has no flag (always on).
