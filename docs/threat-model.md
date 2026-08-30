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
   counters and RFC 8785 signed execution records must reflect what actually
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
| Sandbox → network | nothing, by default | no socket APIs in WASI Preview1 / 0.2; the [egress sidecar](egress_patterns.md) is the audited, allowlist-mediated alternative |

## Residual risks (documented, accepted)

- **Host-side I/O costs minimal fuel** — bounded by the output cap and I/O
  budgets, not eliminated; measured boundary in
  [security_posture.md](security_posture.md#fuel-metering-boundary-characterized).
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
frozen off; the full concurrency threat analysis is
[threads_roadmap.md](threads_roadmap.md).

## How this model is verified

- 8/8 attack-vector suite, live: [`benchmarks/verify_8_vectors.py`](../benchmarks/verify_8_vectors.py)
- 11 exploitation strategies from arXiv 2509.11242, evaluated:
  [security_posture.md](security_posture.md#arxiv-250911242--tested-attack-surface)
- Security regression suite (`tests/test_security.py` et al.) on every push,
  plus the I/O-DoS attack harness in [`benchmarks/io_dos/`](../benchmarks/io_dos/)

To report a violation of this model: [SECURITY.md](../SECURITY.md) —
never a public issue.
