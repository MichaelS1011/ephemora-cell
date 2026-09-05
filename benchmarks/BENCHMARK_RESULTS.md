# Agentic Workflow Benchmark Results

| Generated: 2026-08-06 (historical baseline — pre-rework) | Machine: Mac M5 | N=50 calls × 10 repeats | NOT re-runnable from this repo, see Limitations |
|---|---|---|

> **Provenance:** every figure below comes from the 2026-08-06 run, before
> the benchmark rework (wasmtime pinning, live Docker measurement, honest
> Docker payloads). The raw JSONs of that run are **not retained in this
> repository** — the tracked files `results/agentic_workflow.json` and
> `results/2026-08-25/06_agentic_fresh_2026-08-25.json` are the 2026-08-25
> re-runs of the CELL/naive columns only (no Docker, `docker: null`), and
> their naive numbers (0.31/0.31/0.37 ms) intentionally differ from the
> historical 2026-08-06 figures below. Treat this page as a historical
> baseline, not as reproducible evidence; the reproducible Docker reference
> is the live 2026-08-30 cold-start comparison in
> [`docs/performance.md`](../docs/performance.md).

## Speedup (Naive vs Docker) — historical 2026-08-06 figures

| Scenario | Ephemora Cell Naive | Docker | Speedup | Cost/1K (est.) |
|----------|----------------|--------|---------|---------|
| code_review | 0.84ms/call | 119.89ms | **143x** | $0.0007 vs $0.10 |
| data_transform | 0.82ms/call | 121.51ms | **148x** | $0.0007 vs $0.10 |
| plugin_chain | 0.79ms/call | 121.69ms | **154x** | $0.0007 vs $0.10 |

**Average speedup: 148x | Cost savings: 147x**

## Security Injection (all scenarios)

| Scenario | Injections | Blocked | Block Rate | Interrupted |
|----------|-----------|---------|------------|-------------|
| code_review | 50 | 50 | 100% | 0 |
| data_transform | 50 | 50 | 100% | 0 |
| plugin_chain | 50 | 50 | 100% | 0 |

## Concurrency (5 agents × 50 calls × 3 repeats)

| Scenario | Concurrent Throughput | Mean/call |
|----------|----------------------|-----------|
| code_review | 11,526 calls/s | 2.05ms |
| data_transform | 13,339 calls/s | 2.30ms |
| plugin_chain | 10,421 calls/s | 2.14ms |

## Statistical Significance (Welch's t-test, raw samples)

| Scenario | t-statistic | p-value | Cohen's d | df |
|----------|-------------|---------|-----------|-----|
| code_review | -458.01 | <0.000001 | -64.77 | 106.2 |
| data_transform | -377.01 | <0.000001 | -53.32 | 102.3 |
| plugin_chain | -568.65 | <0.000001 | -80.42 | 111.0 |

**All three scenarios show extremely significant differences**
(Cohen's d > 0.8 = "large"; here d > 50 = massive).

## Known Limitations

- Results generated 2026-08-06 predate the benchmark rework (wasmtime pinning,
  live Docker measurement, honest Docker payloads); figures may not reproduce
  with current tooling, and the raw per-run JSONs of that date are not
  retained in this repository.
- The per-agent breakdowns file referenced by earlier revisions
  (`agentic-full-results.json`) is not retained; the tracked raw data for the
  cell-side re-runs is `results/agentic_workflow.json` and
  `results/2026-08-25/06_agentic_fresh_2026-08-25.json`.
- Docker baselines measure container cold-start + minimal Python work, not
  computational parity with the WASM guest workloads (scenario `.wasm` modules
  are not shipped in this repository).
- Speedup ratios include Docker image startup overhead, which favours
  in-process runtimes; treat them as order-of-magnitude indicators.
- Ephemora Cell figures are single-tenant, single-thread; no multi-tenant
  isolation or thread scaling was measured.
- I/O-DoS boundary is measured, not mitigated (see SECURITY.md).
- `run_docker()` in `agentic_workflow.py` previously executed `print('OK')`;
  it now runs scenario-derived Python transform logic and reports are labelled
  accordingly.
- The DGX Spark scale/cross-platform artifacts
  (`results/scale_dgx_*.json`, `results/cross-platform-results.json`) are
  hardware-specific to that machine and were not re-run elsewhere; treat them
  as single-machine evidence.
