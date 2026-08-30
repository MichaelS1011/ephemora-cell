# ADR-002: I/O Budget as a First-Class Limit + Egress Model

- **Status:** Accepted
- **Date:** 2026-08-28
- **Context:** Fuel bypass inventory (`benchmarks/io_dos/README.md`) and
  attack measurement (`benchmarks/io_dos/attack_results_2026-08-28.json`)
- **Predecessor:** ADR-001 (Compute Scope)

## Context (measured)

Fuel measures guest compute time, not host work (measured): `fd_write` to a preopen file
costs 7.3 fuel at 5.79 µs of host time (~790 µs of host work per 1000 fuel); `fd_filestat_get`
costs 3 fuel at 9.7 µs — **at zero bytes**. Under `max_fuel=None` (trusted configuration)
syscalls are completely unmetered: 172k–233k syscalls/s per run (measured), stopped only by the
10-s timeout, repeatable at will. Existing walls do not cover the gap:

| Defense | Covers | Does NOT cover |
|---|---|---|
| Output sink (10 KB, ENOSPC) | stdout/stderr bytes | Preopen writes, syscall count |
| S4 disk quota (RLIMIT_FSIZE) | bytes PER FILE | aggregate across files, metadata churn |
| Fuel | guest compute | host work per syscall (structural) |
| Epoch timeout | run duration | work per run; runs repeatable without limit |
| RLIMIT_NOFILE (worker only) | concurrent FDs | churn (open/close series) |

## Decision (a) — I/O Budget

Two new `WASIConfig` fields, default-ON (overridable like all limits):

1. **`io_cpu_seconds: float | None` (default 2.0)** — the *primary* wall. Enforcement:
   a worker polling thread (100 ms) reads `resource.getrusage(RUSAGE_SELF)`
   (utime+stime); on exceedance → `engine.increment_epoch()` → the run ends with
   ERROR "I/O budget exceeded (io_cpu_seconds=…)". Rationale: ANY unmetered
   host work — file writes (write() to the page cache = sys-CPU), stat floods,
   open churn — shows up as CPU time of the worker process. One knob covers all
   of the measured bypass classes, portable (POSIX rusage), without wasmtime internals.
   Calibration: 2.0 s ≈ 2× the measured full-load work of a 10-s write flood
   per second (~1 s CPU/s) — legitimate workloads (500 MB batch write ≈ 0.5 s
   CPU) stay comfortably below it.
2. **`io_budget_bytes: int | None` (default 64 MiB)** — a *more precise* bytes wall for
   the guest scratch directory (`/sandbox`). Enforcement: the worker polling thread
   sums file sizes under `sandbox_dir`; on exceedance → epoch kill.
   Overshoot through the 100-ms polling is measurably bounded (≤ ~150 KB at
   maximum rate), conservatively compensated in the default.

**Naming:** the draft called it `io_max_syscalls`; implemented as `io_cpu_seconds`.
Rationale: true syscall counting cannot be portably realized in the worker
(no /proc on macOS, dtrace/LD_PRELOAD require root, linker wrapping would replace
the WASI semantics instead of supplementing them). `io_cpu_seconds` bounds the same threat
(host work per run) more measurably and without a KiB-accuracy fiction; the syscall rate
itself remains visible as a metric in the ExecutionReport (see below).

**Scope boundaries (documented, S4 precedent):** enforcement only in the
subprocess path (`run_isolated`/worker). In-process runs are trusted by design
(there, rusage would measure the host process itself — the wrong signal);
`io_budget_bytes` v1 covers `/sandbox` exactly, preopen trees are covered by the
CPU budget (their write() cost is CPU) — a du delta over preopen trees is noted
as a v2 option (cost: a full tree scan per poll).

**Auditability:** the worker reports `io_cpu_used_seconds` and `io_bytes_written`
(sandbox_dir) in the report; a budget breach is reported as its own error text (not a generic
ERROR). The status enum remains unchanged (no new ExecutionStatus).

## Decision (b) — Egress Model (WASI 0.2/0.3 Sockets)

**Host-mediated proxy model with an allowlist — as a roadmap, not as today's code.**

1. Cell stays at "no socket imports" (verified by `verify_8_vectors.py`,
   vectors 1–3). WASI 0.3 sockets (released 2026-06-11) are NOT exposed,
   as long as wasmtime-py does not bind them stably — no feature requirement
   on an ongoing wasmtime release train (risk of "WASI 0.3 pull").
2. The secure egress path for agents is the **host-sidecar pattern**: the guest writes
   a request artifact into `/sandbox`, the host validates/allowlists, calls the API
   and writes the response back. Isolation stays intact (the guest has no
   socket), and every call is auditable in the ExecutionReport. Specification and
   reference implementation: `docs/egress_patterns.md` — this ADR
   is the authoritative decision, the patterns documentation the user-facing view (no duplicate documentation).
3. A profile tier with free egress (option b of the draft) is **rejected**:
   it breaks the isolation promise ("deny-all by default") for a
   convenience gain that the sidecar pattern delivers without loss of isolation.
   Can be re-evaluated in a later ADR for the explicitly untrusted reverse
   direction (egress INTO the sandbox).

## Consequences

- Two knobs, one enforcement path (worker poller, modeled on the S4 mechanics) — no
  new isolation principle, no wasmtime forks.
- Reference: Resource Isolation Attacks (arXiv 2509.11242) classifies exactly this
  "host-side resource exhaustion via cheap guest operations"; the budget
  moves the boundary from "fuel ≈ guest compute" to "fuel + CPU/bytes ≈ host work".
- Risk: the CPU budget can break legitimate CPU-heavy (but trusted) workloads →
  `None` remains as a documented capability (like `max_fuel=None`).
- Backward compatibility: new fields with defaults = a behavior change for
  existing configs that previously ran `max_fuel=None` floods without limits — that is
  the intended fix, called out explicitly in the CHANGELOG.
