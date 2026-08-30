# Limits enforcement (Engine + MCP channel)

> Measured 2026-08-20 · macOS 26.5.1 arm64 · wasmtime 47.0.1 · ephemora-cell 2.1.1

Proves the Cell enforces its three resource limits **deterministically**,
both through the Engine (`WASISandbox`) and through the MCP channel
(`ephemora-cell-mcp` tools/call + `_meta.execution`). 3 runs each.

## Guests (`guests/`, Rust → `wasm32-wasip1`)

| Guest | Attacks | Expected limit |
|---|---|---|
| `memhog` | `memory.grow` in +512-page steps until failure | `max_memory_mb` |
| `hugeout` | writes 128 B lines forever | 10 KB stdout byte-budget (ENOSPC) |
| `busy` | infinite `acc += 1` loop | `max_fuel` |

Build: `cargo build --release --target wasm32-wasip1` (in `guests/`).

## Results (median of 3, all 3 identical)

### Engine

| Guest | Status | Determinism | Evidence |
|---|---|---|---|
| `memhog` | success | fuel 19420 ×3 (spread 0) | `MEMORY_LIMIT_REACHED at 1537 pages (96 MB)` — the guest observes the ceiling; runtime caps at `max_memory_mb` |
| `hugeout` | error | stdout_len 9216 ×3 | write fails after the budget (ENOSPC); capture stays **9216 B < 10 KB**; guest exits non-zero (its own post-error write also fails) |
| `busy` | **fuel_exhausted** | stdout `iter 65536/131072` ×3 | runaway loop stopped by fuel metering at `max_fuel` |

### MCP channel (same guests as registered tools)

| Guest | `_meta.execution` | Determinism |
|---|---|---|
| `memhog` | status `success`, fuel 19420, wasmtime 47.0.1 | ×3 identical |
| `hugeout` | status `error` | ×3 identical |
| `busy` | status `fuel_exhausted` | ×3 identical |

The MCP channel propagates the ExecutionReport unchanged — the resource
boundary is enforced **inside the Cell**, not in the adapter.

## Known caveats (honest)

- **`fuel_consumed` is `None` on `fuel_exhausted`** (preview1 trap path does
  not read back fuel; known limitation, documented in the acceptance findings). Fuel IS
  reported on success runs.
- The output-budget threshold observed on this run is 9216 B (capture side);
  the acceptance range (`>=9000 && <=10100`) covers it.
- First run per process pays WASM compilation (~11 ms); subsequent runs are
  sub-millisecond (0.35–0.87 ms) — compilation cost, not enforcement cost.

## Reproduce

```
.venv/bin/python benchmarks/pocs/limits_poc/run_limits_poc.py
# -> benchmarks/pocs/limits_poc/results.json
```