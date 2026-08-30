# Performance — Detail (reproducible)

**Current 2026-08-25 — Mac M5, wasmtime 47.0.1, HELLO_WAT, WASIConfig(max_fuel=100k)**

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

## vs Docker (2026-08-30, live, `measured:true`)

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
> continuity; the reproducible reference is the live 2026-08-30 table above.

| Runtime | Mean | Median | vs Cell |
|---------|------|--------|---------|
| Docker python:3.12-slim | 126ms | 122ms | 191x slower |
| Docker node:24-alpine | 122ms | 118ms | 185x slower |
| Cell cold | 0.66ms | 0.55ms | baseline |
| Cell warm | 0.55ms | 0.52ms | — |

## Overhead fair (same HELLO_WAT, 2026-08-25, n=300)
Cell warm 0.25ms vs pure WASI 0.027ms = **825%** — 0.22ms for fuel, timeout, preopen, output cap. `10_overhead_fair.json`

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
p99 0.15ms p999 0.19ms warm — SLA <0.2ms p99.9 sustainable. Engine 14MB warm + <1MB/guest vs Docker 50MB/container, throughput 10M/h/core, savings 100–350x — `07_cost_density.log`
