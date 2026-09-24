# Threat Model

Consolidated threat model for Ephemora Cell. This page frames *who the
adversary is and where the trust boundaries run*; the concrete control
matrix lives in [SECURITY.md](../SECURITY.md) and the measured attack-surface
evaluation in [security_posture.md](security_posture.md). Numbers are
referenced there, not duplicated here.

## What is being protected

1. **The host process and its filesystem** — credentials, source, neighboring
   data. The guest must not read, write or execute anything outside its
   granted preopens.
2. **Host resources** — CPU, memory, disk, file descriptors, scheduler
   latency. A hostile guest must not degrade the host even when it cannot
   escape (DoS is a security boundary, not just a performance issue).
3. **Output integrity of the evidence chain** — `security_baseline`, I/O
   counters and the RFC 8785-canonicalized, sign-ready execution records must reflect what actually
   ran (a falsified baseline would poison every downstream audit).
4. **The supply chain** — the `wasmtime` runtime is the trusted computing
   base; CVE posture is handled by pip-audit + SBOM in CI, not by the sandbox.

## Adversary model

The adversary is **the guest**: untrusted, possibly malicious code —
LLM-generated tool output, a user-uploaded plugin, a compromised
dependency in an agent skill chain (see the supply-chain poisoning
reference in [security_posture.md](security_posture.md#related-research)).
The guest is assumed to:

- know the sandbox design and actively probe it (TOCTOU on preopen grants,
  symlink tricks, iovec layout games),
- try to burn host resources rather than escape (write floods, stat churn,
  fuel-cheap host syscalls),
- produce output designed to deceive the consuming agent or operator.

**Trusted by definition:** the host process that embeds Cell, the operator
running it, and the allowlisted egress policy an operator configures.
Cell does not defend the guest *from* the host, and it does not evaluate
whether guest code is *good* — only contained.

## Trust boundaries

| Boundary | What crosses it | Enforcement |
|---|---|---|
| Guest → WASI Preview1 surface | syscalls only (`fd_*`, `path_open`, `clock`, `random`, `environ`) | capability-based: preopened dirs only, dangerous dirs denied, `fd_psync`/`fd_sync` rejected at instantiate |
| Guest → host compute | fuel, memory pages, wall clock | fuel metering, `Store.set_limits`, epoch interruption — enforced on **both** execution paths |
| Sandbox dir → host disk | guest-written bytes | `io_budget_bytes` wall (both paths); `disk_quota_bytes` (RLIMIT_FSIZE) and `io_cpu_seconds` rusage watchdog on the **subprocess path only** — see the [execution-path matrix](../SECURITY.md#execution-paths--which-control-runs-where) |
| Worker → OS (subprocess path) | process creation itself | RLIMIT_NOFILE/AS/RSS, 32 MB module cap, hard kill on timeout |
| Sandbox → network | nothing, by default | WASI Preview1: no socket APIs; the WASI 0.2 world links `wasi:sockets` but connect is denied at call time (measured, CVE-replay component evidence 2026-09-18); the [egress sidecar](egress_patterns.md) is the audited, allowlist-mediated alternative |

## Resource exhaustion via WASI calls (host-side)

A host call is **fuel-cheap but host-expensive**: fuel meters guest compute,
not the work a syscall triggers on the host. That gap is a threat class of
its own — the WASM-container resource-isolation study (arXiv
[2509.11242](https://arxiv.org/abs/2509.11242)) documents how malicious
guests exhaust host resources through legitimate WASI interfaces rather
than escaping, and real wasmtime advisories keep landing in exactly this
class (e.g. the `fd_renumber` host-fd leak,
[GHSA-3p27-qvp9-27qf](https://github.com/bytecodealliance/wasmtime/security/advisories/GHSA-3p27-qvp9-27qf)
/ CVE-2026-54786: every call silently kept a host descriptor alive until
the Store died — a looping guest exhausts host fds without ever misbehaving
in guest-visible terms. The pinned 47.0.1 line is **not** in that advisory's
affected list; it is cited here as the class exemplar, not a Cell incident).

Cell's answer is a **budget ladder** — every measured WASI call is walled by
at least one enforced budget, and the expensive ones by several:

| WASI call (measured) | Net Fuel/Call | Host µs/Call | Walls that bound it |
|---|---:|---:|---|
| `clock_time_get` | 4.0 | 0.06 | fuel · epoch wall-clock |
| `random_get` | 3.0 | 0.13 | fuel · epoch |
| `sched_yield` | 2.3 | 0.14 | fuel · epoch |
| `environ_sizes_get` | 3.0 | 0.04 | fuel |
| `fd_prestat_get` | 3.0 | 0.06 | fuel |
| `fd_fdstat_get` | 3.0 | 0.10 | fuel |
| `fd_filestat_get` | 3.0 | 9.69 | fuel · `io_cpu_seconds` (subprocess) |
| `fd_write` → stdout | 5.5 | 2.15 | fuel · 10 KB output cap (ENOSPC) · `io_budget_bytes` |
| `fd_write` → preopen | 7.3 | 5.79 | fuel · `io_budget_bytes` · `disk_quota_bytes` (subprocess) · `io_cpu_seconds` (subprocess) |
| `fd_read` → preopen | 7.3 | 5.30 | fuel · `io_cpu_seconds` (subprocess) — reads carry no byte-wall by design; the byte budget walls writes |
| `fd_seek` | 6.0 | 0.11 | fuel |
| `path_open` + `fd_close` | 29.1 | 14.59 | fuel · preopen capability + TOCTOU revalidation · `disk_quota_bytes` (subprocess) |

Fuel numbers are the committed measurement
(`benchmarks/io_dos/results_2026-08-28.json`, `measured:true`, wasmtime
47.0.1, macOS arm64 — per-platform, like all fuel); the class core finding:
a real file write costs ~7.3 fuel at ~5.8 µs of host work — **~790 µs of
host work per 1000 fuel**, which is why fuel alone is not an I/O wall and
[ADR-002](decisions/ADR-002-io-budget-egress.md) adds the byte/CPU walls.
Scheduler-degradation evidence (guest attack vs. host canary):
`benchmarks/io_dos/attack_results_2026-08-28.json`. The walls' placement
per execution path is in the [SECURITY.md
matrix](../SECURITY.md#execution-paths--which-control-runs-where).

## Residual risks (documented, accepted)

- **Host-side I/O costs minimal fuel** — bounded by the output cap and I/O
  budgets, not eliminated; measured boundary in
  [security_posture.md](security_posture.md#fuel-metering-boundary-characterized)
  and mapped call-by-call in the section above.
- **WasmGC heap is not byte-bounded** in wasmtime-py 47 — fuel is the
  effective bound; `max_gc_heap_mb` is declared/recorded, not enforced.
- **In-process defaults are documented-trusted** for the controls that would
  cap your own process (I/O CPU wall, disk quota) — subprocess path enforces
  them; the matrix states which control runs where.
- **Single-tenant by design** — no isolation between concurrent modules in
  one process beyond per-run budgets.
- **Supply-chain trust in wasmtime** — mitigated by CI (pip-audit, SBOM),
  never by the sandbox itself.

Threads (shared memory + atomics) are treated as an attack surface and
frozen off by default (shipped that way since 1.0.0); enabling them is a
future, separately security-reviewed opt-in decision with its own
concurrency threat analysis.

## How this model is verified

- 8/8 attack-vector suite, live: [`benchmarks/verify_8_vectors.py`](../benchmarks/verify_8_vectors.py)
- 11 exploitation strategies from arXiv 2509.11242, evaluated:
  [security_posture.md](security_posture.md#arxiv-250911242--tested-attack-surface)
- Security regression suite (`tests/test_security.py` et al.) on every push,
  plus the I/O-DoS attack harness in [`benchmarks/io_dos/`](../benchmarks/io_dos/)

To report a violation of this model: [SECURITY.md](../SECURITY.md) —
never a public issue.
