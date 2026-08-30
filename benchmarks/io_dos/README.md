# Fuel-Bypass Inventory: WASI Preview 1 Syscalls

**Measured:** 2026-08-28 · wasmtime 47.0.1 · macOS arm64 (in-process path) ·
`fuel_per_syscall.py` → `results_2026-08-28.json` (`measured:true`, `source:"measurement"`)

**Method:** counted loop that invokes a WASI syscall N times (`max_fuel` set);
`fuel/iter = fuel_consumed / N`; net cost per syscall = variant − baseline loop
(loop + counter, 8.33 fuel/iter). `host_us/call` is the measured host wall-clock per
call (proxy for pure host work; actual scheduler degradation is measured by `attack_host_impact.py`).

## Inventory (measured)

| Syscall | Net Fuel/Call | Host µs/Call | Host Work | Fuel-Bypass Risk |
|---|---:|---:|---|---|
| `clock_time_get` | 4.0 | 0.06 | trivial (clock read) | low |
| `random_get` | 3.0 | 0.13 | trivial (entropy) | low |
| `sched_yield` | 2.3 | 0.14 | trivial | low |
| `environ_sizes_get` | 3.0 | 0.04 | trivial | low |
| `fd_prestat_get` | 3.0 | 0.06 | trivial | low |
| `fd_fdstat_get` | 3.0 | 0.10 | trivial | low |
| `fd_filestat_get` | 3.0 | 9.69 | **real (stat on host FS)** | **medium** — no I/O bytes, but host-FS access per call |
| `fd_write` → stdout (10KB sink capped) | 5.5 | 2.15 | low (budget check + append up to cap) | low — ENOSPC cap kicks in |
| `fd_write` → **preopen file** | 7.3 | **5.79** | **real (file growth on host FS)** | **high** — core finding |
| `fd_read` → preopen file | 7.3 | **5.30** | **real (host-FS read I/O)** | **high** |
| `fd_seek` | 6.0 | 0.11 | trivial (in-memory offset) | low |
| `path_open` + `fd_close` | 29.1 | **14.59** | **real (create + open + close)** | **high** — most expensive single syscall, but still cheap in fuel |

Baseline loop (counter without syscall): 8.33 fuel/iter — reference point: pure
compute consumes the same amount of fuel at ~0 host cost.

## Core Finding (Bypass Factor)

Fuel measures **guest compute time**, not **host work**. A real file write costs
only **7.3 fuel** at **5.79 µs** of host work → **~790 µs of host work per 1000 fuel**.
Pure compute: ~0 µs per 1000 fuel. Consequences at defaults:

- `max_fuel = 1_000_000` (default) allows **~137k real file writes** (≈ 0.79 s of
  host I/O work per run) or **~34k path_open+close cycles** (≈ 0.50 s) — per run,
  repeatable arbitrarily often across runs.
- `max_fuel = None` (trusted workloads) → **completely unmetered**: unlimited host I/O
  up to `disk_quota_bytes` (per-file only, S4) or RLIMIT_NOFILE (subprocess path only).
- In-process path (`use_subprocess=False`): no RLIMIT_NOFILE → fd exhaustion in the
  host process is theoretically possible (fd_filestat_get/path_open abuse).

The 10-KB output budget sink covers **stdout/stderr** — **not** write volume
into preopens (only the S4 per-file quota applies there) and **not** syscall count.

## Derivation (ADR-002)

The I/O budget must cover two dimensions that fuel structurally cannot see:

1. **`io_budget_bytes`** — guest write volume into preopens + `/sandbox` per run
   (stdout/stderr are already covered by the 10-KB output budget).
2. **Host CPU wall** — syscall floods without byte volume (`fd_filestat_get` stat-flood,
   `path_open` churn) consume host CPU time instead of bytes.

Implemented in ADR-002: `io_budget_bytes = 64 MiB`, `io_cpu_seconds = 2.0 s`
(the draft called the second lever `io_max_syscalls`; a CPU wall via
rusage is more portable than a syscall count).
`None` = unlimited for trusted (documented capability, like `max_fuel=None`).

---

# Attack Measurement: High-Frequency Small I/O Against the Host

**Measured:** 2026-08-28 · macOS arm64 (Apple M5, APFS) · `attack_host_impact.py` →
`attack_results_2026-08-28.json` (`measured:true`).

**Method:** canary process (appends to an *unrelated* file + 10-ms sleep loop) measures
scheduler jitter and write latency: baseline (5 s) vs. attack window (12 s, attack starts
1 s after canary start). Attacks run over the worker path (`run_isolated`,
`max_fuel=None` = trusted configuration), stopped only by the 10-s epoch timeout.

## Results

| Phase | Syscall Rate | Bytes | Jitter (×Baseline) | Write Latency (×Baseline) |
|---|---:|---:|---:|---:|
| Baseline (no attack) | — | — | 2.07 ms mean | reference |
| Write-Flood (1 run) | **172,560 writes/s** | 15.2 MB / 10 s | 1.18× | 0.21× |
| Open-Churn (1 run) | ~68k opens/s* | 0 | 1.19× | 0.19× |
| Stat-Flood (1 run) | unthrottled, 3 fuel/call | 0 | 1.19× | 0.17× |
| Write-Flood ×4 parallel | **233,325 writes/s** | 20.3 MB / 11 s | 1.02× | 0.26× |

\* derived from the inventory measurement (14.59 µs/open); zero bytes.

## Interpretation (honest)

1. **On Mac M5/APFS the per-run degradation is moderate** (jitter 1.02–1.19×, p95
   unchanged). APFS + page cache + 10 cores absorb 8-byte appends; the
   canary's write latency even drops (cache warming). **A single run does not
   bring this host to its knees.**
2. **The syscall rate itself is unthrottled:** 172k–233k syscalls/s per run; with
   `max_fuel=None` limited only by the 10-s timeout — and runs are **repeatable
   without limit**. The timeout covers duration, not the work per run.
3. **Stat-flood and open-churn generate ZERO bytes** — no byte-based limit
   (output budget, disk quota) ever kicks in; only fuel exhaustion or the timeout stops them.
   `fd_filestat_get` costs 3 fuel at 9.7 µs of real host-FS access — the
   most efficient bypass in the inventory.
4. **Finding under parallel load:** the 4× phase additionally showed path_open misbehavior
   (errno 2 races on the shared target directory) — instability under load is itself
   a symptom of the unthrottled rates.

**Derivation:** The threat is not the single run on fast hardware, but
unthrottled syscall rates on weaker targets (edge, shared host I/O, Linux with
a slower FS — measurement pending there) and unlimited repetition. The budget
(`io_budget_bytes` + `io_cpu_seconds`) limits the work PER RUN independently of
fuel configuration — exactly the gap that neither the output sink, nor the quota, nor the timeout
covers. Linux degradation measurement as a follow-up (same harness, Docker/CI environment).

---

# Follow-up Measurement — Budgets Active (2026-08-28)

Same harness, same attacks — now with ADR-002 defaults
(`io_cpu_seconds=2.0`, `io_budget_bytes=64MiB`, `max_fuel=None` as in the attack measurement):

| Phase | Before (unthrottled) | After (budget active) |
|---|---|---|
| Write-Flood 1× | 10.99 s, 15.2 MB | **ERROR after 2.07 s, 2.8 MB** (CPU 2.02 s) |
| Open-Churn | 10.97 s | **ERROR after 2.07 s** (CPU 2.00 s) |
| Stat-Flood | 10.99 s | **ERROR after 1.96 s** (CPU 1.97 s) |
| Write-Flood ×4 parallel | 10.85 s, 20.3 MB | **all 4 workers ERROR after 2.06 s**, 3.7 MB |

The attack breaks against the budget, not against the host: the syscall work per run is limited to
~2 s of host CPU (or 64 MB of sandbox bytes), and jitter degradation drops from
1.18× to 1.01–1.05×. Every budget breach is auditable in the report
(`io_cpu_used_seconds`, `io_bytes_written`, `io_budget_exceeded`).

Limitation of the proof: measured on macOS M5/APFS; Linux degradation in CI
noted as a follow-up.
