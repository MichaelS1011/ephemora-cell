# Benchmark Methodology

All benchmarks in this directory are reproducible. Each script documents its
hardware assumptions, statistical method, and exact invocation.

## Hardware

| Platform | CPU | RAM | Docker | OS |
|----------|-----|-----|--------|-----|
| Mac M5 | Apple M5 (10-core) | 32 GB | Docker Desktop 29.1 | macOS 26.5.1 |
| DGX Spark GB10 | Grace 20-core ARM | 128 GB (121 GiB measured) | Docker Engine 29.1 | Ubuntu (Linux) |

**Unless noted otherwise, results are from the Mac M5 platform.** DGX hardware as
measured and recorded in `results/cross-platform-results.json` (20 cores / 121 GiB).

## Benchmarks

| Script | Purpose | Calls | Repeats | Output |
|--------|---------|-------|---------|--------|
| `pov_benchmark.py` | Cold/Warm start (isolated) | 1 | 300 | Mean, P95, P99, CI |
| `competitive_benchmark.py` | Ephemora Cell vs Docker (cold start) | 1 | 100 | Speedup ratio |
| `security_comparison.py` | 8 attack vectors (Docker vs Ephemora Cell) | 8 | 1 | Allow/Block |
| `fuel_boundary.py` | Fuel consumption characterization | 1 | 50 | R², slope |
| `verify_8_vectors.py` | Reproduce 8-vector security claims | 8 | 1 | Pass/Fail |
| `agentic_workflow.py` | 50 tool-calls in agent loop | 50 | 10–30 | Latency, cost, security |
| `fuzz_smoke.py` | Random WASM module smoke fuzzing | 1 | 100 | Crash/hang report |

## Statistical Method

### Agentic Workflow (`agentic_workflow.py`)

- **Samples:** n=500 per Ephemora Cell mode (50 calls × 10 repeats), n=100 for Docker
- **Metric:** Per-call latency in milliseconds (mean ± stdev, P95, P99)
- **CI:** 95% confidence interval = mean ± 1.96 × (stdev / √n)
- **t-test:** Welch's t-test (independent samples, unequal variance)
- **Effect size:** Cohen's d (pooled standard deviation)
- **Implementation:** Custom `t_test_independent()` with log-gamma approximation
  for the incomplete beta function (no scipy dependency)

### Microbenchmarks (`pov_benchmark.py`)

- **Warm-up:** First run is discarded as warm-up (the code performs one
  unmeasured run before the timing loop); subsequent 300 runs are averaged
- **Metrics:** Mean, Median, P95, P99, StdDev, 95% CI
- **Raw data:** Per-run latencies are exported as `cold_start_raw` /
  `warm_start_raw` arrays in the JSON output
- **Platform:** Reported separately for Mac M5 and DGX GB10

## Cost Model

All cost figures assume an **AWS f4dn.2xlarge** instance at **$3.06/hr**:

- `cost_per_1k` = ($3.06 / calls_per_hour) × 1,000
- `cost_per_1m` = ($3.06 / calls_per_hour) × 1,000,000

This is a rough proxy; actual costs depend on instance type, region, and
reserved pricing.

## Reproduction

```bash
# Install dependencies
pip install -e ".[dev]"

# Full agentic workflow benchmark (all scenarios, with security + concurrency + stats)
python benchmarks/agentic_workflow.py --scenario all --n 50 --repeats 10 --inject --n-agents 5 --stats

# Docker comparison (requires Docker)
python benchmarks/agentic_workflow.py --scenario all

# Quick run (no Docker, no injection)
python benchmarks/agentic_workflow.py --no-docker --n 20 --repeats 5

# JSON output (for automated reporting)
python benchmarks/agentic_workflow.py --json > results.json
```

## Known Limitations

1. **Docker baseline is Python transform logic**, not the WASM workloads —
   the scenario `.wasm` modules are not shipped with the repository, so
   `run_docker()` executes representative Python-side work derived from the
   module name (see `_docker_transform_payload`). This measures container
   startup + Python logic, not computational parity.
2. **`competitive_benchmark.py` Docker numbers are measured live** on the host
   (`docker run --rm`); first run per image pulls the image, then 7 runs are
   timed. If Docker is unavailable a local `python3 -c pass` baseline is used
   and the table is marked "measured without docker".
3. **I/O-DoS boundary** is measured, not eliminated — ~1.18 MB theoretical
   before fuel exhaustion at default 1M fuel (27 fuel per 32 B write;
   the pre-fix "~2.1 MB / ~0 fuel per call" figure was a measurement
   artifact, see `benchmarks/fuel_boundary.py`). Mitigated since:
   guest output is capped at 10 KB (ENOSPC), sandbox-dir writes are
   walled by `io_budget_bytes` (default 64 MiB, both paths), and host
   CPU spend is walled by `io_cpu_seconds` (subprocess path; ADR-002).
4. **Concurrency benchmark** uses Python ThreadPoolExecutor (GIL-limited).
   Real-world throughput with native threads or multiprocessing may differ.
5. **No LLM latency included** — the benchmark measures sandbox overhead only,
   not total agent loop latency (which includes model inference).
6. **Fuzz smoke** (`fuzz_smoke.py`) generates random but valid WAT modules;
   it is a smoke test for crashes/hangs, not a coverage-guided fuzzer.