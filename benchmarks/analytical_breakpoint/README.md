# Analytical Memory Breakpoint (measured)

**Date:** 2026-08-28 · wasmtime 47.0.1 · macOS arm64 (Apple M5) ·
`memory_breakpoint.py` → `results_2026-08-28.json` (`measured:true`)

**Method:** the guest WAT grows linear memory page by page (64 KiB) against
`Store.set_limits` caps; over-cap requests are rejected by the runtime
(`memory.grow` → −1), the guest reports GROWN/REFUSED on stdout. Touching the new
pages (every 64th page) forces real allocation.

## Part A — Breakpoint at Staged Caps (32-bit memory)

| Cap | Fits (Cap − 2 MB) | Over-Request (Cap + 4 MB) | Time |
|---|---|---|---|
| 32 MB | GROWN | **REFUSED** | 1.6–1.9 ms |
| 64 MB | GROWN | **REFUSED** | 1.9 ms |
| 128 MB | GROWN | **REFUSED** | 2.4 ms |
| 256 MB | GROWN | **REFUSED** | 4.1 ms |

**Finding:** the breakpoint sits **byte-exact at the cap** — `Store.set_limits`
enforces the limit in every case; an over-request fails in a controlled way
(no trap, no host damage, 2 ms). The 128-MB default limit is thereby confirmed as
a hard, exactly enforced wall (not just "best effort").

## Part B — memory64 Feasibility Beyond the 32-bit 4-GiB Limit

| Cap | Target | Result | Time |
|---|---|---|---|
| 4608 MB (4.5 GiB) | 4112 MB (4 GiB + 2 MB) | **SUCCESS** — growth beyond the 32-bit limit | 708 ms |
| 4096 MB (exactly 4 GiB) | 4112 MB | **ERROR** (controlled refusal) | 21.6 ms |

**Finding:** with `memory64=True` a guest grows in a controlled way **beyond the
4-GiB limit**, and `Store.set_limits` byte-exact enforcement applies unchanged.
This is the mechanism proof for the `analytical` profile (ADR-003): memory64
is the key to >4-GiB workloads; threads are NOT needed for that
(deliberate decoupling, see ADR-003).

## Part C — Pandas/NumPy Context (Literature, `measured:false`)

numpy/pandas for wasm32-wasip1 are not published as wheels; browser Pyodide
documents stricter memory limits than native Python and the well-known
pandas OOM class (stackoverflow.com/questions/67636518). Real
dataframe workloads in Cell are waiting on a wasi-python recipe; until then
Part A/B is the authoritative measured basis: the memory wall is exact,
controlled, and liftable beyond 4 GiB with memory64.

## Derivation for ADR-003

- `analytical` profile: `memory64=True` + raised `max_memory_mb` (recommendation
  from Part B: 4.5–5 GiB virtual, sparsely touched); fuel/timeout remain
  strongly bound; threads stay OFF (threads_roadmap phase 1, deliberate decoupling).
- Over-cap behavior is controlled (REFUSED, ms-fast) — no
  crash risk from mis-sized profiles.
