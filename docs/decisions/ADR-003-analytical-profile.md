# ADR-003: Analytical Profile — memory64 beyond the 4-GiB Boundary, Threads Stay Out

- **Status:** Accepted
- **Date:** 2026-08-29
- **Context:** Breakpoint measurement (`benchmarks/analytical_breakpoint/`)
- **Predecessors:** ADR-001 (Compute Scope), ADR-002 (I/O Budget)

## Context (measured)

Agent workloads for data analysis (dataframes, large arrays) run into the
128 MB default limit. The measurement captures the properties of the wall:

- **Breakpoint is byte-exact:** `Store.set_limits` cuts off at cap − 0 bytes;
  over-requests fail in a controlled manner within ~2 ms (no trap chaos, no
  host damage) — identical at 32/64/128/256 MiB.
- **memory64 works under limits:** a 64-bit-memory guest grows under
  a 4.5-GiB cap to 4.112 GB (708 ms) — beyond the 32-bit 4-GiB boundary —
  and is rejected byte-exactly above the cap (21.6 ms).

## Decision

New profile `analytical` alongside `plugin/llm/edge/default` (opt-in, default
behavior unchanged):

| Field | default | analytical | Rationale |
|---|---|---|---|
| `memory64` | False | **True** | 64-bit memories are a prerequisite for >4 GiB (measurement part B) |
| `max_memory_mb` | 128 | **4608** | 4.5 GiB virtual, sparsely touched; measured as safe under limits |
| `max_fuel` | 1 000 000 | **50 000 000** | data processing needs compute reserve; still hard-limited |
| `timeout_seconds` | 30 | **120** | larger workloads; the epoch wall remains |
| `io_cpu_seconds` | 2.0 | **10.0** | more host I/O for read/write batches, still bounded (ADR-002) |
| `max_threads` | 1 | **1** | **deliberately unchanged** — threads stay OFF |
| `allow_dirs` / `allow_env` | empty | **empty** | capabilities stay explicit; the profile grants nothing ambient |

**Threads stay OFF** — enabling threads follows exclusively
threads_roadmap phase 1 (its own security review and trigger). This profile extends
the memory space, not the concurrency domain: fuel + epoch wall +
worker isolation cover memory64 guests with the same model as
32-bit guests.

**Isolation under the profile (still valid unchanged):** no sockets, no
ambient FS access, S4 disk quota + ADR-002 I/O budgets active, the engine-pool
fingerprint separates `analytical` engines automatically (max_memory_mb + memory64
in the fingerprint), over-cap behavior is controlled (measurement part A).

## Consequences

- Dataframe/array workloads >128 MB run without configuration magic:
  `WASISandbox(config=get_profile("analytical"))` or `--profile analytical`.
- Risk: 50 M fuel and 4.5 GiB are more generous — but every channel stays
  budgeted (fuel, CPU wall, bytes, timeout), and the profile is explicitly
  opt-in. Trusted runs still need `None` knobs.
- Reversible: removing the profile = deleting the entry; the engine fingerprint
  isolates side effects on other profiles.
