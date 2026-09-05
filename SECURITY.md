# Security Policy

## Supported Versions

| Version | Supported          |
| ------- | ------------------ |
| 1.0.x   | ✅ Yes             |

Earlier internal milestones (pre-public, 2026-08) are not published and
not supported — upgrade to the current release.

## Reporting a Vulnerability

We take security vulnerabilities seriously. If you discover a security issue in Ephemora Cell, please report it responsibly.

**Do NOT open a public GitHub issue.**

### How to Report

**Report via:** LinkedIn DM to Michael Soppa — https://www.linkedin.com/in/michael-soppa

Please include:
- A clear description of the vulnerability
- Steps to reproduce the issue
- Potential impact assessment
- Any suggested mitigation (if applicable)

### What to Expect

- **Acknowledgment:** Within 48 hours
- **Initial Assessment:** Within 5 business days
- **Resolution Timeline:** Depends on severity (Critical: 7 days, High: 14 days, Medium: 30 days)
- **Credit:** We acknowledge responsible disclosers in our security advisories (unless you prefer anonymity)

### Scope

**In Scope:**
- WASM escape vulnerabilities (guest-to-host breakout)
- Preopen directory bypass (`/dev`, `/proc`, `/sys` access)
- Memory limit bypass
- Fuel metering bypass leading to DoS
- Network access through WASI Preview1 sandbox
- Path traversal attacks via preopened directories

**Out of Scope:**
- I/O rate limiting (I/O system calls bypass fuel metering) — known limitation, documented
- CPU-DoS within fuel budget — by design (guest must compute)
- Social engineering / phishing
- Missing features (e.g., no memory zeroing, no network proxying)

### Known Limitations

Ephemora Cell is an isolated WASM sandbox, not a full security enforcement platform. Documented limitations include:

- **I/O costs minimal fuel:** `fd_write` calls run on the host and consume ~27 fuel/write
  on the stdout path (~1.18MB theoretical before exhaustion at default 1M fuel); preopen
  *file* writes measure ~7.3 fuel/write (`benchmarks/io_dos/`) — in both cases the shared
  10 KB output byte-budget (ENOSPC) caps captured output far earlier
- **GC heap not byte-bounded:** `Store.set_limits` limits linear memory only. `WASIConfig.max_gc_heap_mb` is recorded in the security baseline (observability); wasmtime-py 47 has no GC-heap limiter binding, so fuel remains the effective GC memory bound (see `benchmarks/pocs/README.md`)
- **No memory zeroing:** WASM memory is reclaimed by the Python GC, not cryptographically wiped
- **Single-tenant:** No multi-tenant isolation between concurrent modules in the same process
- **Default execution is in-process:** `run()`/`run_wasm()` execute the guest inside the calling process — fuel, memory cap, timeout, 10 KB output cap and the `io_budget_bytes` wall are enforced there; the OS-level walls (RLIMIT_NOFILE/AS/RSS, per-file `disk_quota_bytes`, `io_cpu_seconds` rusage watchdog, 32 MB module cap, hard process kill) exist only on the subprocess path (`run_isolated()` / `use_subprocess=True`). For untrusted guests, use the subprocess path.
- **No network, no process spawning:** WASI Preview1 + WASI 0.2 component execution expose no socket or process APIs (by design)
- **Disk quota is per-file:** `disk_quota_bytes` (default 256 MiB) is enforced via RLIMIT_FSIZE in the subprocess isolation path — a kernel per-file cap, not a per-run aggregate; in-process runs document it as a granted capability
- **Grant-time preopen revalidation closes TOCTOU at grant time:** entries are re-realpath'd immediately before `preopen_dir`; a swap in the milliseconds between config validation and grant is skipped with a warning, but a swap DURING a run (while the guest holds the fd) is outside the sandbox's control

### Execution paths — which control runs where

Cell has two isolation paths, and the difference is material. The default
executes the guest **inside your process**; the subprocess path
(`run_isolated()` / `use_subprocess=True`) adds OS-level walls around a
disposable worker. For untrusted guests, use the subprocess path.

```python
from ephemora_cell import run_isolated, WASIConfig

result = run_isolated("guest.wasm", WASIConfig(max_fuel=1_000_000))
# run_isolated returns a DICT (not an ExecutionResult object) with the same
# fields plus worker-bootstrap timing:
result["status"]        # ExecutionStatus.SUCCESS / TIMEOUT / ...
result["exit_code"]; result["stdout"]; result["stderr"]
result["fuel_consumed"]; result["io_cpu_used_seconds"]; result["io_budget_exceeded"]
result["security_baseline"]   # attested limits, incl. wasmtime_version
```

| Control | In-process (default) | Subprocess (`run_isolated()`) |
|---|---|---|
| Fuel metering (guest CPU) | ✅ | ✅ |
| Memory cap (`Store.set_limits`) | ✅ | ✅ |
| Wall-clock timeout (epoch) | ✅ | ✅ + hard process kill |
| 10 KB output cap | ✅ | ✅ |
| I/O byte wall (`io_budget_bytes`, sandbox dir) | ✅ watcher + epoch interrupt | ✅ |
| I/O CPU wall (`io_cpu_seconds`) | ❌ documented-trusted * | ✅ worker rusage watchdog |
| Disk quota (`disk_quota_bytes`) | ❌ trusted capability * | ✅ RLIMIT_FSIZE (per file) |
| RLIMIT_NOFILE / AS / RSS, 32 MB module cap | ❌ | ✅ |
| Preopen deny + grant-time TOCTOU revalidation | ✅ | ✅ |

\* In-process runs execute inside your own process — a kernel-level cap
there would cap your application itself, so these knobs are honored as
declared capabilities, not enforced walls (guest code is still fuel-,
memory-, timeout- and byte-wall-bounded in-process).

Backed by tests: `tests/test_run_io_budgets.py` (byte wall on both paths,
CPU wall on the worker path), `tests/test_disk_quota.py` (RLIMIT_FSIZE),
`tests/test_process_executor.py` (rlimits, timeout kill, module cap),
`tests/test_effective_preopens.py` (preopens).

For production and regulated deployments, the Ephemora enterprise edition builds on Cell's isolation.

## Security Design

Threat model (adversary model, trust boundaries, residual risks):
[docs/threat-model.md](docs/threat-model.md).

Ephemora Cell relies on:
- **WASM Memory Safety:** Bounds-checked memory access (no buffer overflows)
- **WASI Preview1 / WASI 0.2:** Capability-based filesystem access (only preopened directories; the effective per-ABI grant is attested in the execution report's `security_baseline.preopens`)
- **Resource Limits:** Fuel metering (CPU), memory caps (128MB default), wall-clock timeout (30s default)
- **Import Blocking:** `fd_psync`/`fd_sync` imports rejected at the WASI layer

### Threading

Shared-everything threads (shared memory + atomics + WASI threads) are **disabled
by default and treated as an attack surface**, not a feature:

- `wasm_threads = False` and `wasm_multi_memory = False` are enforced on every
  engine at all three construction sites: `WASISandbox` (pooled and inline),
  `EnginePool._new_entry`, and `ComponentSandbox`. This is asserted
  behaviorally in `tests/test_security.py` and structurally in
  `tests/test_threads_baseline.py`.
- **memory64 is a per-config opt-in** (`WASIConfig.memory64` / `--memory64`,
  default `False`): opted-in engines enable `wasm_memory64`, get their own
  engine-pool fingerprint entry, and remain bound by `Store.set_limits`
  (`memory_size=`) on committed bytes. Multi-memory and threads stay frozen
  even when memory64 is on.
- A guest module with a shared memory is rejected **at parse/compile time**:
  `wasm_threads = False` makes the wasmtime 47 parser refuse `shared`
  memories immediately. (Verified: threads defaults to *True* in wasmtime 47
  — without our flag the module compiles; instantiation would then still be
  blocked by wasmtime's separate `Config.shared_memory = False` default, a
  second host-side barrier.) `max_threads` > 1 in `WASIConfig` is currently
  inert; enabling it is gated behind the security-reviewed phases in
  [docs/threads_roadmap.md](docs/threads_roadmap.md).
- If threads are ever enabled (opt-in only), shared memories are a covert
  channel and cross-instance memory state; fuel metering does not bound
  `memory.atomic.wait` spin/blocking, so the wall-clock timeout (epoch
  interruption) and process-level rlimits are the binding DoS backstops.
- This freeze is not an engine limitation: wasmtime 47 supports shared memory +
  atomics server-side (the core threads proposal is Phase 4), but its own
  stability docs mark it "Finished: 🚧" — **shared memories are not well
  integrated with `Store` resource limits and unsupported in the pooling
  allocator**, the exact primitives Cell's memory/fuel accounting relies on.
  WASI-level thread *spawning* is not standardized in 2026 at all
  (`wasi-threads` withdrawn Aug 2023; shared-everything-threads unimplemented
  in wasmtime 47; not part of WASI 0.3).

The full threat model, concurrency audit, Wasm 3.0 feature posture, and phased
roadmap (Phase 0 = disabled default, Phase 1 = reviewed opt-in, Phase 2 = full
accounting) live in [docs/threads_roadmap.md](docs/threads_roadmap.md).

## Dependency & Upgrade Policy

**Runtime dependency:** `wasmtime` is the only runtime dependency. It is declared
as a range in `pyproject.toml` (`>=36.0.12,<48`) and pinned to the exact tested
revision in `requirements.txt` (`wasmtime==47.0.1`).

**Upgrade windows:**
- Security/CVE fixes: within **14 days** of upstream release
- Feature/minor releases: within **30 days**
- Major releases: within **90 days** after regression validation against the full
  test suite and benchmarks

**CVE scanning in CI:**
- `pip-audit -r requirements.txt` runs on every push/PR and weekly (Monday 03:00 UTC)
- Any known vulnerability fails the CI job (blocking merge)
- CycloneDX SBOM (`sbom.json`) is generated and uploaded as a CI artifact per run

**LTS review:**
- The `wasmtime` release train is reviewed quarterly against the sandbox
  requirements (fuel metering, epoch interruption, WASI Preview1)
- Next scheduled LTS review: **Q3/2027**

**Process:** Bumping the pinned `requirements.txt` revision requires a passing
`pytest` run plus a clean `pip-audit` before merge.