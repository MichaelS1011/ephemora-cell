# Performance — Detail (reproducible)

**Current 2026-09-14 — Mac M5, wasmtime 47.0.1, `examples/hello.wasm`, n=1000 after 50 warmup (`pool_vs_budget.py`)**

| Scenario | Wall median | Wall p95 | Wall min | Guest median |
|----------|-----------|----------|----------|--------------|
| Pooled (`io_budget_bytes=None`) | 0.514 ms | 0.891 ms | 0.438 ms | 0.174 ms |
| Default (per-run engine, 64 MiB I/O budget) | 0.941 ms | 1.153 ms | 0.809 ms | 0.606 ms |

Raw: `benchmarks/results/2026-09-14/pool_vs_budget.json` (`measured:true`)

**Cold/warm + overhead 2026-09-14 — `pov_benchmark.py`, HELLO_WAT (max_fuel=100k), n=300 each, first run discarded**

| Mode | Guest median | Guest p95 | Wall median | Wall p95 |
|------|-------------|-----------|-------------|----------|
| Cold (fresh sandbox per run) | 0.590 ms | 0.957 ms | 0.994 ms | 1.447 ms |
| Warm (cached engine) | 0.550 ms | 0.791 ms | 0.926 ms | 1.313 ms |

Sandbox overhead (warm wall median − guest median): **0.376 ms** — fuel metering, epoch deadline, preopen grant, output capture.
Raw: `benchmarks/results/2026-09-14/pov_benchmark.json` (`cold_start_raw`/`warm_start_raw` arrays included)

## Fuel boundary 2026-09-14 (`fuel_boundary.py`, macOS arm64)

CPU: **13.0 fuel/iteration, R² = 1.000** (7 successful points, 100–1M iterations);
exhaustion boundary at default 1M fuel: 76,923 CPU iterations / 49,181 fd_writes
(1.50 MB). I/O: 226.4 fuel per 32-byte fd_write, R² = 1.000. Fuel counts are
deterministic per module+platform but NOT comparable across platforms/wasmtime
builds. Raw: `benchmarks/results/2026-09-14/fuel_boundary.json`.

**2026-08-25 — Mac M5, wasmtime 47.0.1, HELLO_WAT, WASIConfig(max_fuel=100k)**

## Tail N=1000
| Mode | Median | P95 | P99 | P999 | Mean | StdDev |
|------|--------|-----|-----|------|------|--------|
| Cell warm (pooled) | 0.117ms | 0.138ms | 0.151ms | 0.19ms | 0.120ms | 0.010ms |
| Cell cold | 0.121ms | 0.143ms | 0.171ms | 1.49ms | 0.125ms | 0.045ms |
Raw: `benchmarks/results/2026-08-25/09_tail_*.json` (1000 raw_ms)

## Two platforms 2026-08-06 (300 runs)
| Platform | Median | P95 | P99 | Mean | StdDev | 95% CI |
|----------|--------|-----|-----|------|--------|--------|
| Mac M5 | 0.55ms | 0.83ms | 0.98ms | 0.57ms | 0.28ms | ±0.03ms |
| DGX Spark GB10 | 7.70ms | 12.5ms | 13.3ms | 8.26ms | 3.10ms | ±0.35ms |

## vs Docker (2026-09-14, live, `measured:true`)

Mac M5, Docker daemon 28.5.1, `docker run --rm` cold start with minimal payload
(warmup run excluded, n=100 per image via `--docker-runs 100`). Reproducible:
`python benchmarks/competitive_benchmark.py`. Raw:
`benchmarks/results/2026-09-14/competitive_benchmark.json`
(`docker_measured:true`).

| Runtime | Mean | P95 | vs Cell cold (0.485 ms) |
|---------|------|-----|-------------------------|
| Docker python:3.12-slim | 185.89 ms | 215.50 ms | **383× slower** |
| Docker node:24-alpine | 176.84 ms | 207.90 ms | **365× slower** |
| Ephemora Cell cold | 0.485 ms | 0.670 ms | baseline |
| Ephemora Cell warm | 0.432 ms | 0.704 ms | 430× faster than Docker python |

**Reading every multiplier on this page** (all three vs-Docker sections): a
container-cold-start vs. invoked-WASM comparison for this benchmark workload on this
machine (Docker on macOS runs in a VM) — not a general claim that WASM is always
faster than Docker. For Wasm-based container *runtimes* — a different integration
path — an academic measurement reports ~51 % slower startup vs. Docker (Liu et al.,
ACM TOSEM 34(6), 2025, [doi:10.1145/3712197](https://dl.acm.org/doi/10.1145/3712197)).

## vs Docker (2026-08-30, live, `measured:true` — historical reference)

Mac M5, Docker 28.5.1, `docker run --rm` cold start with minimal payload
(warmup pull excluded, n=7 per image). Reproducible:
`python benchmarks/competitive_benchmark.py`. Raw:
`benchmarks/results/2026-08-30/competitive_benchmark.json`
(`docker_measured:true`).

| Runtime | Mean | P95 | vs Cell cold (0.400 ms) |
|---------|------|-----|-------------------------|
| Docker python:3.12-slim | 170.63 ms | 179.50 ms | **427× slower** |
| Docker node:24-alpine | 167.75 ms | 179.99 ms | **419× slower** |
| Ephemora Cell cold | 0.400 ms | 0.572 ms | baseline |
| Ephemora Cell warm | 0.376 ms | 0.494 ms | 454× faster than Docker python |

## vs Docker (2026-08-06, same Mac — historical reference)

> **Historical:** the 2026-08-06 figures below predate the live-measurement
> workflow (no raw JSON was committed for that run). They are kept for
> continuity; the reproducible reference is the live 2026-09-14 table above.

| Runtime | Mean | Median | vs Cell |
|---------|------|--------|---------|
| Docker python:3.12-slim | 126ms | 122ms | 191x slower |
| Docker node:24-alpine | 122ms | 118ms | 185x slower |
| Cell cold | 0.66ms | 0.55ms | baseline |
| Cell warm | 0.55ms | 0.52ms | — |

## Overhead fair (same HELLO_WAT, 2026-08-25, n=300)
Cell warm 0.25ms vs pure WASI 0.027ms = **825%** — 0.22ms for fuel, timeout, preopen, output cap. `10_overhead_fair.json`

## Fuel vs epoch vs wall-clock (2026-09-18, mechanism benchmark)

The three ways to stop a run, measured on three axes. Repro:
`python benchmarks/fuel_epoch_wall.py` — evidence
`benchmarks/results/2026-09-18/07_fuel_epoch_wall.json` (`measured:true`;
macOS arm64, wasmtime 47.0.1 pinned — relative taxes are per-platform and a
DIFFERENT measurement from the 0.376 ms per-call overhead above; never mixed).

| Axis | Fuel | Epoch | Wall-clock (subprocess) |
|---|---|---|---|
| Mechanism tax (10M-iter mixed loop, n=30, raw wasmtime) | **+35.2%** | **+1.4%** | n/a — kills the process |
| Stop point deterministic? | **yes** — `fuel_consumed` identical across 5 runs (1,000,000/1,000,000) | no — ms-scale jitter | no |
| Overshoot at T=0.1 s (n=20, median / p95 / max) | n/a — instruction-exact stop at the budget | pooled: 10.0 / 10.1 / 10.5 ms · per-run: **5.3 / 6.3 / 6.4 ms** | 53.9 / 59.0 / 59.2 ms (spawn + teardown dominate) |
| What it bounds | guest CPU share | wall time | process lifetime — the only layer whose blast radius also survives an engine bug (see [SECURITY.md](../SECURITY.md), engine advisories) |

Reading: fuel buys a deterministic, budget-exact stop point at a real tax;
epoch is essentially free but time-based (the per-run timer variant is
measurably tighter than the pooled 50 ms ticks); the subprocess wall is the
coarsest stop. Cited anchor for the fuel tax — 28–40% (wasmtime#4109) — is
corroborated by our own 35.2%: measured, not assumed.

## Fuel is per-platform — never compare fuel across hosts (2026-09-24)

Fuel counts are deterministic **per platform** (`fuel_spread: 0` on every
host measured), but the counts themselves are platform-bound. Same modules,
same wasmtime 47.0.1, macOS arm64 vs DGX Spark GB10 (aarch64-Linux),
2026-09-24 Vollabnahme run:

| Module | macOS arm64 | DGX GB10 aarch64 |
|---|---|---|
| `examples/hello.wasm` | 16 397 | 12 |
| bundled `echo` tool (via MCP) | 20 564 | 3 727 |
| `determinism_probe` workload | 20 891 (spread 0) | 4 506 (spread 0) |

Repro: `python benchmarks/determinism_probe.py` on each host. Practical
consequence for integrators: a fuel budget tuned on one machine does not
transfer 1:1 to another — pin budgets per deployment platform (or budget in
wall-clock/epoch terms and treat fuel as the platform-local deterministic
stop). Never present cross-platform fuel numbers in the same column as a
billing or quota claim.

## Engine backend & execution mode (2026-09-25)

Every number on this page is a **Cranelift** number. The Python binding
pins the backend: `Config.strategy` accepts only `auto`/`cranelift` (Winch
is not selectable, and Cell's documented policy is "never Winch"), and a
surface-audit test asserts `Engine.is_pulley() is False` on every test run
— an interpreted fallback cannot silently enter the shipped posture.
Consequence of the Lumos study (arXiv
[2510.05118](https://arxiv.org/abs/2510.05118), preprint — `measured:false`
for Cell, literature): interpreted Wasm runs up to **55× slower warm** and
carries up to **10× I/O-serialization overhead**, while AOT Wasm images are
up to **30× smaller** with **16 % faster cold starts** vs. containers. If a
future binding ever makes an interpreted backend reachable, warm-start
numbers must be re-published **per backend and per platform** before any
single "~0.5 ms" claim survives; the `is_pulley()` test is wired to catch
that moment.

## Third-party positioning: Wasm vs. microVMs (2026-09-25)

Independent corroboration of the hybrid positioning — arXiv
[2509.09400](https://arxiv.org/abs/2509.09400) (VHPC'25, `measured:false`
for Cell, literature): WebAssembly wins cold starts for lightweight
functions, while Firecracker-class microVMs win on I/O-heavy and complex
workloads. That is exactly Cell's split: sub-millisecond budgeted execution
for short CPU-heavy snippets (`run_wasm`, MCP tools), and the OS-level
process wall via `run_isolated()`/`--isolated` for anything I/O-heavy or
long-running — with Firecracker comparisons kept at `measured:false` until
live KVM evidence lands (see the competitive-benchmark history).

## Linux-native Docker row (CI evidence job)

The macOS Docker numbers above run inside the Docker Desktop VM (caveat
stated inline). A weekly non-blocking CI job measures the same comparison on
an ubuntu runner, where Docker is native: `.github/workflows/benchmark-linux.yml`
(Mondays 06:00 UTC + manual dispatch; evidence as run artifact + step summary —
main stays bot-commit-free). The canonical table gains Linux rows once the job
has run; until then no Linux number is claimed here.

## Agentic 2026-08-25 (n=500 pooled, fresh)
| Scenario | Median | P95 | P99 | Mean |
|----------|--------|-----|-----|------|
| Code Review | 0.24ms | 0.29ms | 0.31ms | 0.28ms |
| Data Transform | 0.24ms | 0.27ms | 0.29ms | 0.24ms |
| Plugin Chain | 0.26ms | 0.28ms | 0.31ms | 0.28ms |
Docker null (daemon off) — 143–154x from 2026-08-06 remain historical context; the reproducible docker reference is the live 2026-08-30 table above. Raw: `06_agentic_fresh_2026-08-25.json`

## Original Agentic 2026-08-06
| Scenario | Naive | Pooled | Docker | Speedup |
|----------|-------|--------|--------|---------|
| Code Review | 0.84ms | 0.81ms | 119.9ms | 143x |
| Data Transform | 0.82ms | 0.81ms | 121.5ms | 148x |
| Plugin Chain | 0.79ms | 0.76ms | 121.7ms | 154x |

## Tail & Cost
p99 0.15ms p999 0.19ms warm (raw: `09_tail_*.json`) — an SLA of <0.2 ms at p99.9 is sustainable.
Cost density (engine ~14 MB warm + <1 MB per guest vs ~50 MB per Docker container,
throughput in the 10M calls/h/core class, savings 100–350x) comes from a local
cost-density run whose raw log is not committed (`07_cost_density.log`, gitignored) —
treat it as an order-of-magnitude indicator, not committed evidence.
