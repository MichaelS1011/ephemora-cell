# Cross-Call State Cost (measured)

`state_overhead.py` → `results_2026-08-29.json` (`measured:true`), macOS M5, warm cache:

| Mode | ms/Run | Delta vs. stateless |
|---|---:|---:|
| Stateless (trivial) | 0.65 | — |
| FS-State (32-B append + read-back) | 0.95 | +0.30 |
| FS-State at 1 MiB | 0.87 | +0.22 |

Finding: FS-State costs only ~0.3 ms/run — the gap is SEMANTIC (no caps,
no session namespace, leakage risk, manual cleanup). This leads to ADR-004:
StateStore as an explicit, bounded, session-scoped capability.
