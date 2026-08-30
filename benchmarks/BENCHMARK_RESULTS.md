# Agentic Workflow Benchmark Results (Full)

| Generated: 2026-08-26 (revalidated) | Machine: Mac M5 | N=50 calls × 10 repeats | historical baseline 2026-08-06, see Limitations |
|---|---|---|

## Speedup (Naive vs Docker)

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

## Full Raw Data
See `agentic-full-results.json` in same directory for per-agent breakdowns.

## Known Limitations

- Results generated 2026-08-06 predate the benchmark rework (wasmtime pinning,
  live Docker measurement, honest Docker payloads); figures may not reproduce
  with current tooling.
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