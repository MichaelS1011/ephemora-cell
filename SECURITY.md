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

**Preferred: GitHub Private Vulnerability Reporting** — open the
[Security tab](https://github.com/MichaelS1011/ephemora-cell/security/advisories/new)
and file a private report. It stays confidential (visible only to the
maintainers), supports the coordinated patch/disclose workflow, and credit
is handled inside the advisory.

**Secondary channel:** LinkedIn DM to Michael Soppa — https://www.linkedin.com/in/michael-soppa
(only if GitHub is not an option for you).

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
  10 KB output byte-budget (ENOSPC) caps captured output far earlier. NOTE (2026-09-12):
  fuel is **not cross-platform deterministic** — wasmtime charges different per-instruction
  costs per backend/arch (e.g. one `fd_write` hello measured ~16.4k units on macOS arm64
  vs ~12 total on Linux x86_64). Fuel budgets are enforced correctly everywhere; they are
  only comparable within one platform.
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

### Proposal policy — set, not inherited (2026-09-25)

wasmtime 47 ships several proposals **enabled by engine default** (Wasm GC,
exceptions, function-references — per the Bytecode Alliance's July 2026
default-on rollout). That default-on set is exactly where the 2025/26
divergence incidents cluster: fuel accounting dropped across
`call_ref`/`try_table` calls (GHSA-m63x-6p34-q65x), the Cranelift aarch64
heap escape (CVE-2026-34971), and the vm2 escape riding WebAssembly
`try_table`/JSTag handling (CVE-2026-26956, secondary sources). Cell's rule:

**Every proposal the shipped WASI surface does not need is enforced `False`
in the engine config at all construction sites** (`wasi_runtime`,
`engine_pool`, `wasi_02`, conformance harness) — compile-probe-tested per
release (`tests/test_proposal_policy.py`), attested in `security_baseline`
(`*_enabled` keys), and structurally guarded against silent default drift
(`tests/test_threads_baseline.py` SpyConfig assertions).

| Proposal | Posture | Rationale |
|---|---|---|
| `wasm_threads` | **off, frozen** | shared memories = covert channel + unsupported with `Store` limits (below) |
| `wasm_multi_memory` | **off, frozen** | no Cell workload needs it; baseline freeze (P1/K2) |
| `wasm_function_references` | **off, enforced** | `call_ref` drops callee fuel (GHSA-m63x-6p34-q65x) |
| `wasm_exceptions` | **off, enforced** | `try_table` catch drops fuel (same advisory); vm2-class escape surface |
| `wasm_gc` | **off, enforced** | not needed; GC heap not byte-bounded in the binding |
| `wasm_tail_call` | **off, enforced** | not needed by any Cell workload |
| `wasm_stack_switching` | **off, enforced** | WASI 0.3 native-async base — gate-off until the 0.3 surface is qualified (see [docs/recipes.md](docs/recipes.md#wasi-02-components)) |
| `wasm_memory64` | **opt-in** | per-config (`WASIConfig.memory64`), own pool fingerprint, `Store` limits still bind |
| `wasm_component_model` | **on** | required by the WASI 0.2 component path |
| SIMD / bulk-memory / multi-value / sign-extension / reference-types | **on** | spec-core; the wasip1/wasip2 surfaces and ordinary toolchain output build on them — compile-probe-tested as accepted |

Not exposed by the Python binding (documented posture, unreachable either
way): the **pooling allocator** (`allocation_strategy` has no binding — the
CVE-2026-34988 cache-pressure-residue class cannot be reached from Cell).
An explicit 4 GiB `memory_guard_size` was tried and **reverted**: it broke
`run_isolated` in constrained Linux VMs (mmap ENOMEM on the combined
reservation+guard, caught end-to-end by the arm64 container gate).
`tests/test_memory_hygiene.py` proves sequential instances observe only
zeroed memory and remains the standing guard. Also unreachable:
**Spectre mitigations** (engine default, no binding toggle —
always on), and **Pulley/Winch backends** (`Config.strategy` accepts only
auto/cranelift; "never Winch" by policy; `Engine.is_pulley()` asserted
`False` in `tests/test_surface_audit.py`).

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
  inert; enabling it is gated behind a future, security-reviewed opt-in
  phase with thread-aware fuel and wall-clock accounting.
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

The thread posture is phased: Phase 0 (shipped) = disabled by default;
any opt-in phase requires its own security review covering the
concurrency threat model, the Wasm 3.0 feature posture and thread-aware
fuel/wall accounting before it can ship.

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
- **GC-heap gate trigger:** when a wasmtime-py release exposes a GC-heap
  limiter (`ResourceLimiter`) or a `wasm_gc` engine flag in the Python
  bindings, add the corresponding enforcement for `max_gc_heap_mb`
  (recorded only today — see Known Limitations) to that upgrade's
  validation checklist

**Engine advisories (wasmtime):** the engine itself is part of the threat surface.
The April 2026 Bytecode Alliance advisory batch (2026-04-09; 12 advisories, two
critical sandbox escapes, both aarch64-specific: RUSTSEC-2026-0096 / CVE-2026-34971,
a Cranelift miscompiled guest heap access enabling host memory access, and
RUSTSEC-2026-0095, a Winch-backend memory access — fixed in 36.0.7 / 42.0.2 / 43.0.1
/ 24.0.7; the pinned 47.0.1 contains the fixes) demonstrated that engine 0-days are
a real in-process risk. Cell's answer is layered: security claims are bound to the
tested engine version (`requirements.txt` pin, `wasmtime_version` attested in every
execution record), CI watches RUSTSEC/bytecodealliance alongside pip-audit, and
`run_isolated()` is the mitigation layer for untrusted guests (disposable worker
process, hard kill). Confirmation artifacts (2026-09-25): a version-floor
test pins the engine at `>= 43.0.1` so the "contains the fixes" claim
cannot silently regress; the memory64 opt-in and the unselectable Winch
backend are asserted alongside (proposal-policy table above).
- **GHSA-x84v-gj2h-g759** (WASIp3 streams, CVSS 6.9 — added 2026-09-25):
  guest-controlled-size host heap allocation when writing to WASIp3
  streams; affects wasmtime 46.0.0–46.0.2 and 47.0.0–47.0.3, patched in
  47.0.4 (Python wheel pending on PyPI — tracked by
  `scripts/check_wasmtime_patch.py`). **Cell's exposure: the surface is
  structurally unreachable** — WASIp3 worlds cannot be linked through the
  Python binding (component linker exposes only `add_wasip2`/
  `add_wasi_http`, asserted in `tests/test_surface_audit.py`), and the
  async base is gated off (`wasm_stack_switching=False`). The full fix
  lands with the M2 engine upgrade; the WASI 0.3 position stays gate-off
  until that line ships and the 0.3 surface gets its own budget
  qualification ([docs/recipes.md](docs/recipes.md#wasi-02-components)).

**September 2026 advisories — exposure statement (2026-09-24):** two wasmtime
advisories affect the pinned 47.0.1 line:

- **GHSA-m63x-6p34-q65x** (fuel amplification via `call_ref`/`try_table`,
  CVSS 5.7): with fuel metering on (Cell always enables it), a guest using
  these opcodes can run exponentially longer than its budget on wasmtime
  47.0.x. **Cell's exposure:** real — the proposals ride engine defaults and
  every Cell run meters fuel. **Mitigation shipped in v1.0.4.2:** the engine
  config enforces `wasm_function_references=False` and `wasm_exceptions=False`
  (plus `wasm_gc=False`, `wasm_tail_call=False`) at every Config construction
  site, so guest modules using the affected opcodes fail to compile
  (fail-closed; empirically verified) and the posture is attested in
  `security_baseline` (`function_references_enabled`, `exceptions_enabled`,
  `gc_enabled`, `tail_calls_enabled`). Guests that legitimately need
  exceptions/GC cannot run until the engine upgrade — this is the documented
  trade-off for keeping "deterministic fuel accounting" honest. Full fix:
  upgrade to wasmtime 48.0.3/49.0.1 (Python wheels pending on PyPI — tracked
  by `scripts/check_wasmtime_patch.py`), then re-qualify fuel determinism.
- **GHSA-vqjp-4c8c-hfgg** (CVE-2026-47261, CVSS 7.5, wasmtime-wasi filesystem
  escape via trailing-slash/symlink paths in `path_open`): **Cell's exposure:**
  every Preview1 run grants the `/sandbox` scratch preopen by design, so the
  affected code path is reachable even in the default posture; operator-granted
  `allow_dirs` widen the reachable scope. No config-level workaround exists
  upstream. Tracked as the engine-upgrade gate (47.0.4+ or 48.0.3+ once wheels
  publish); the preopen test matrix will gain trailing-slash/hardlink/rename/
  TRUNCATE vectors with positive controls as part of that upgrade
  (SECURITY_ADVISORY_PLAN_2026-09-24.md, milestones M2–M4).

**Engine-upgrade gate:** any wasmtime bump re-runs the security evidence suite —
`benchmarks/verify_8_vectors.py`, `benchmarks/mcp_cve_replay.py`, and the wasi
conformance job — before security claims are re-attested. CI watch *detects* new
advisories; this gate prevents claims from silently carrying across an engine
version with changed enforcement behavior.

**Process:** Bumping the pinned `requirements.txt` revision requires a passing
`pytest` run plus a clean `pip-audit` before merge.