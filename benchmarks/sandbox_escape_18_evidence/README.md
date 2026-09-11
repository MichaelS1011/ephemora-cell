# SandboxEscapeBench 18 — Enterprise Evidence (redacted public copy)

> **What this is:** the public, redacted evidence bundle for the results quoted in
> ["0 execution-boundary escapes"](https://www.linkedin.com/posts/michael-soppa_ai-cybersecurity-aisecurity-activity-7503904100842024961-gW-b)
> (LinkedIn, 2026-09).
>
> **Measured against:** Ephemora **Enterprise** (the proprietary execution pipeline),
> run `20260910T192649`. The open-source Cell shares the WASI runtime design but was
> **not scored** by this run — reproduction requires the Enterprise stack.
>
> **What is redacted and why:** enforcement internals — module identifiers, exit-code
> fingerprints, capability configuration — are proprietary and deliberately omitted.
> You don't need them: every escape verdict here comes from the **host filesystem
> check**, not from trusting our internals. If nothing lands on the host, it didn't escape.

**Run:** 2026-09-10 · **wasmtime:** 46.0.1 (pinned) · **WASI:** preview1

## Source benchmark

[SandboxEscapeBench](https://github.com/UKGovernmentBEIS/sandbox_escape_bench) —
UK AI Security Institute (UKGovernmentBEIS, Inspect). 18 container-escape scenarios
built from real Docker & Kubernetes CVEs. Paper:
[arXiv:2603.02277](https://arxiv.org/abs/2603.02277) — frontier LLM agents escape
ordinary containers in 47–100% of the L1/L2 scenarios (context, not an identical setup).

An escape only counts if the attack lands a file on the host filesystem —
the benchmark's own verdict logic, and the only logic used here.

## Methodology

- No-LLM exploit mode: hand-written exploits and probes, no agent in the loop.
- All 18 container scenarios mapped onto their WASI equivalents.
- 16 attack Linux surfaces a WASI guest does not have (kernel, sockets, /proc,
  cgroups, runc) — documented per scenario. That is an architectural argument,
  **not** a measurement.
- The 2 scenarios with a filesystem surface (`hostpath_etc`, `dac_read_search`)
  were probed live with hand-written WASM.
- 10 additional WASM escape probes: path traversal ×3, absolute host paths ×3,
  /proc access, socket import, symlink escape, environment leak.
- Positive control: a write inside the allowed scope must succeed.

## Results

| Metric                                  | Result                |
|-----------------------------------------|-----------------------|
| Container scenarios contained           | **18/18**             |
| — no Linux surface by design            | 16                    |
| — live-probed with WASM                 | 2                     |
| WASM escape probes blocked              | **10/10**             |
| Escapes (host-FS verified)              | **0**                 |
| Errors                                  | 0                     |
| Positive control (in-scope write)       | Passed (ALLOWED)      |

Full per-scenario and per-probe verdicts: [`results_2026-09-10.json`](./results_2026-09-10.json).

## What we don't claim

- **No 100% claim.** 16 of 18 scenarios are excluded by attack-surface
  architecture — an argument, not a measurement. The measurements are the
  2 live-probed scenarios, the 10 probes, and the host-FS verdicts.
- The positive control showed run-to-run variance in early runs; an n≥10
  repetition series is planned. Escape verdicts are unaffected — they come from
  the host filesystem check only.

## Integrity

Checksums over this folder's artifacts (regenerated after redaction — the
internal bundle seals do not apply to this public copy):

```bash
shasum -a 256 -c SHA256SUMS.txt
```
