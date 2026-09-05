# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/).

## [Unreleased]

### Fixed (15-user field study findings, 2026-09-05)

- **Fuel classification (code):** an out-of-fuel trap firing inside a host
  function or during `linker.instantiate` surfaced as generic ERROR;
  it now classifies as `FUEL_EXHAUSTED` (regression test added).
- **`run_isolated()` return contract** documented (dict with
  `status`/`exit_code`/`stdout`/`stderr`/`fuel_consumed`/`security_baseline`/
  io counters) with a usage example in SECURITY.md; README links to it.
- **macOS `allow_dirs` trap** documented: `/tmp`/`/var` are symlinks into
  blocked `/private` — the rejection is the symlink-escape defense working;
  use a real directory (recipes.md).
- **`build` README line** aligned with builder reality: a cargo project
  context is required for Rust; bare files get guidance.
- **Zig build failures** now hint at version skew (CI verifies with zig
  0.13.0; newer zig can fail differently) before pointing at the raw error.
- **`--tools-dir` semantics** documented: it replaces the bundled
  `clock`/`echo` set entirely.

### Fixed (repository-wide audit, 2026-09-05)

- **Privacy:** redacted the local home-directory prefix from captured stdout
  in `benchmarks/pocs/componentize_poc/results.json` and rewrote the
  cross-platform results note that named a user path.
- **English-only surface:** translated the remaining German text in
  `tests/test_security.py` (incl. assert messages), the result artifacts
  `13_sandbox_escape_18.json` / `cross-platform-results.json` /
  `scale-results.json`, and the scripts `setup_firecracker.sh`,
  `sandbox_escape_18.py`, `security_comparison.py`, `pov_benchmark.py`.
- **Package license:** `ephemora_cell/LICENSE` contained a stray 9-line
  source-header fragment instead of a license; replaced with the canonical
  Apache-2.0 text (identical to the root `LICENSE`).
- **Claim precision:** "signed execution records" softened to
  "sign-ready" (RFC 8785 JCS canonicalization + `sign()`/`verify()`
  primitives ship; records are not signed by default) across README,
  threat-model, enterprise page and MCP docs.
- **Evidence alignment:** `benchmarks/BENCHMARK_RESULTS.md` relabelled as the
  historical 2026-08-06 baseline (raw JSONs not retained; tracked agentic
  JSONs are the 2026-08-25 cell-side re-runs) and the dead
  `agentic-full-results.json` pointer removed; `build_friction` re-measured
  (0.4 s warm, new committed evidence `results_2026-09-05.json`; earlier
  snapshots explained); io_dos pre-fix attack figures labelled as
  single-run historical context with untracked raws; DGX hardware figures
  aligned with the recorded measurement (20 cores / 121 GiB); GC-PoC and
  componentize figures aligned with their tracked JSONs; cost-density
  figures marked as uncommitted order-of-magnitude.
- **Drift & hygiene:** whitepaper test count 379 → 386 (PDF re-rendered);
  stale "347 tests" and unevidenced "17/17 acceptance scenarios" removed;
  MCP protocol table de-pinned from a hardcoded version; broken README
  anchor and dead artifact references (`cross-platform-m11.json`,
  `scale-d14.json`, `scale_probe.py`) fixed; the empty `11_pip_freeze.txt`
  artifact and the byte-identical `competitive-firecracker-macos.json`
  duplicate removed; internal milestone/CI-run references in test
  docstrings replaced with descriptive text; `test_wvm_wasm_runtime.py`
  renamed to `test_wasm_runtime.py`; personal Ollama model list de-personalized;
  wrong AutoGen install hint corrected.

## [1.0.1] - 2026-09-05

Release metadata and MCP surface hardening. Repo-committed code is
unchanged in behavior except where listed; PyPI publish pending token
rotation (the 1.0.0 PyPI metadata publicly exposes a personal email that
the repository itself no longer carries — this upload replaces it).

### Added

- **Bundled `clock` MCP tool** — second tool alongside `echo`, sourced in
  `tools_src/clock` (dependency-free Rust, `wasm32-wasip1`): returns current
  UTC time (ISO-8601 + Unix ms) from the WASI real-time clock only — no
  filesystem, no network, no environment. Gives agent clients an immediately
  useful capability the model itself lacks (current time), with every call
  fuel-metered and reported via `_meta.execution`.
- **Native `get-policy` meta tool** — read-only: reports the effective
  sandbox policy per tool or for the whole registry (fuel budget, memory
  limit, threads, preopens as configured, network policy, wasmtime
  version), derived from the same `_config_for()` path execution uses, so
  reported policy and enforced policy cannot drift. Capability changes
  remain host decisions (ADR-006); policy reads are tools, policy writes
  are not.
- **`code --add-mcp` one-liner** for GitHub Copilot in VS Code (README +
  docs/mcp.md VS Code section); bundled-tools line updated to `clock + echo`.
- **Wassette row** in the MCP comparison latency table (qualitative, sourced,
  not measured): same Wasmtime engine family, per-component permission grants,
  OCI component distribution — with the Cell differentiators stated
  (per-call fuel metering, execution witness, CI-verified SDK interop).
- **ADR-006** (governed dynamic tool loading: request-file +
  verify-before-register; no agent-callable permission grants) and
  **ADR-007** (browser interaction is out of scope by design; mediated
  capability via host sidecar) recorded as decision documents.
- **Daily metrics snapshot workflow** (`metrics.yml` +
  `scripts/metrics_snapshot.py`): PyPI downloads (pypistats, one call/day
  per etiquette), GitHub stars/forks/traffic appended as JSONL to the
  `metrics` branch. Public distribution channels only — no in-package
  telemetry; Cell never phones home.
- **MCP SDK interop CI gate** (`mcp-sdk-interop` job): the shipped stdio
  server is verified in CI against the official MCP Python SDK 2.0 —
  initialize, `tools/list`, and a real `tools/call` with execution
  `_meta` (`integration/test_mcp_sdk_client.py`, new `integration` extra).

### Changed

- **Release metadata**: version 1.0.0 → 1.0.1 (`ephemora_cell`,
  `ephemora_cell_mcp` — the MCP server version now shares the package
  version via `ephemora_cell_mcp/_version.py`), classifier
  "Development Status :: 4 - Beta" → "5 - Production/Stable", README
  status badge → stable, plus PyPI downloads and stars badges. The git
  identity for project commits is now the GitHub noreply address.

### Test coverage

- Statement coverage 74% → 85% measured over `ephemora_cell` +
  `ephemora_cell_mcp` (`--cov-fail-under` gate 70 → 80; 84.55% measured):
  new in-process characterization tests for `cli.py` (17% → 86%) and
  `process_worker.py` (30% → 81%) — payload validation at the worker
  trust boundary, run/inspect/build/benchmark command paths, previously
  only exercised via subprocesses invisible to coverage. Coverage now
  counts the shipped `ephemora_cell_mcp` package, which was previously
  measured at 0% despite being installed and documented.

## [1.0.0] - 2026-08-30

**First public release** — first version published to PyPI. Internally
developed across August 2026 (internal milestones 1.0.0 → 2.2.0, referenced
in some docs); public versioning starts at 1.0.0.

### I/O-DoS hardening

**Fixed (security)**

- **Fuel meters guest compute, not host work — unmetered host I/O
  closed (High, CWE-770 / CWE-400):** measured inventory
  (`benchmarks/io_dos/`): a real file write costs 7.3 fuel at 5.8 µs
  host time; a stat costs 3 fuel at 9.7 µs; with `max_fuel=None` a
  guest sustained 172k–233k host syscalls/s per run, repeatable
  without bound, and zero-byte attacks (stat/open churn) defeat every
  byte-based wall. Two new first-class `WASIConfig` budgets enforce
  per-run limits (ADR-002):
  - **`io_cpu_seconds`** (default 2.0): worker-side rusage watchdog —
    bounds ALL guest-induced host work (writes, stat/open churn),
    interrupts the guest via epoch; breaks attacks at the budget, not
    at the host (re-run of the attack harness: 10–11 s floods now end
    at ~2 s, canary jitter degradation 1.18× → 1.05×).
  - **`io_budget_bytes`** (default 64 MiB): aggregate byte wall for the
    guest sandbox dir, enforced in BOTH paths by a watcher; breach ends
    the run with a dedicated "I/O budget exceeded" error.
- Both knobs accept `None` (documented trusted capability, like
  `max_fuel=None`); in-process runs remain documented-trusted for the
  CPU wall (rusage would measure the host process).
- Auditability: reports now carry `io_cpu_used_seconds`,
  `io_bytes_written`, `io_budget_exceeded`.

**Changed**

- WASI 0.2 components honor the CPU wall (same epoch-interrupt
  mechanism); budget-guarded runs use a per-run engine (deadline=1
  semantics — `set_epoch_deadline` from a watcher thread does not
  affect a running guest; verified experimentally).
- **Egress decision (ADR-002):** host-mediated proxy model with
  allowlist; WASI 0.3 sockets not exposed until stable in wasmtime-py;
  free-egress profile tier rejected (breaks deny-by-default). User-
  facing pattern: host-sidecar (`docs/egress_patterns.md`).

### Build pipeline

**Added**

- **`ephemora-cell build <source>` (ADR-005):** one-command WASM builds —
  recipe detection per file suffix with real toolchain builds for Rust
  (`cargo build --target wasm32-wasip1`, manifest searched upward like
  cargo) and Go (`GOOS=wasip1 GOARCH=wasm`), and fail-closed actionable
  guidance for C (WASI-SDK required — Apple clang has no wasm32 target,
  measured) and Python (no AOT-to-WASM exists; wasi-python interpreter
  guidance). Failed builds map verbatim toolchain errors to hints from
  the measured friction matrix (`benchmarks/build_friction/`: missing
  toolchains, missing rust target, missing wasi-sysroot, wrong
  GOOS/GOARCH). Registry deferred (YAGNI) with rationale in the ADR.
- Measured: Rust hello-world → .wasm in 2.9 s and executed in the cell;
  Go recipe exercised in CI (new `build-recipes` job installing Go +
  the rust WASM target).

### Named state

**Added**

- **Named state across isolated runs (ADR-004):** `ephemora_cell.state.StateStore`
  — a host-side, session-scoped, bounded key/value store. Passing it into
  `WASISandbox.run(..., state_store=store)` IS the capability grant: the guest
  imports `ephemora_state.get/set/del` (fail-closed — without the grant the
  imports do not exist). Caps are host-enforced (256 KiB per value, 1 MiB
  total, 64 entries; breach returns a WASI-style errno to the guest, including
  required-length reporting for undersized read buffers). The run result
  attests the footprint via `state_bytes`. Nothing persists to disk; two
  stores never share keys (leakage test included).
- Measured basis (`benchmarks/state_overhead/`): filesystem state costs only
  ~0.3 ms/run — the gap is semantics (no caps, no session namespace), which
  the StateStore closes.
- Demo: three consecutive isolated runs passing a counter through
  the state imports (get → +1 → set) — green.

### Analytical profile

**Added**

- **`analytical` profile (ADR-003, opt-in):** for data-analysis workloads
  beyond the 128 MB wall — 64-bit memories (`memory64=True`), 4.5 GiB
  linear memory, 50 M fuel, 120 s timeout, 10 s host-I/O CPU budget.
  Threads deliberately remain off (threads_roadmap Phase 1); no ambient
  FS/env grants; all isolation budgets (disk quota, I/O
  walls) stay active. Engine-pool fingerprint separates analytical
  engines automatically.
- Measured basis (`benchmarks/analytical_breakpoint/`): the memory wall
  is enforced byte-exactly at the cap (over-cap growth refused in ~2 ms
  across 32–256 MiB caps), and a 64-bit-memory guest grew past the
  32-bit 4 GiB boundary under the 4.5 GiB cap (708 ms) — the mechanism
  proof behind the profile. numpy/pandas wheels for wasm32-wasip1 are
  unpublished; dataframe workloads wait for a wasi-python recipe
  (documented as literature, `measured:false`).

### Egress patterns

**Added**

- **Egress pattern documentation** (`docs/egress_patterns.md`): catalog of
  six community workarounds for "sandboxed tool calls an API" with
  isolation/audit/budget assessments (filesystem tunneling, stdio RPC,
  sidecar proxies, runtime forks, config softening, host-agent abuse),
  plus the full specification of the recommended **P1 host-sidecar
  pattern** and the WASI 0.3 outlook (P2). Decision basis: ADR-002.
- **Host-sidecar egress mediator** (`ephemora_cell.egress_sidecar`,
  dependency-free): guest writes `sidecar.request.json` into its
  sandbox dir; the host validates it against an `EgressPolicy`
  (scheme+host+path-prefix allowlist, method allowlist, header
  allowlist, response size cap, timeout) — fail-closed, request
  artifacts are untrusted input, credentials stay host-side — executes
  the call and returns a machine-readable response doc plus an audit
  entry for the execution report. End-to-end test: a real preview1 WASM
  guest produces the artifact in `/sandbox`, the host mediates against
  a local API (loopback); policy/parse/allowlist denial paths covered.

### Release preparation

**Changed**

- **SECURITY.md** brought up to date: supported-version table reflects
  2.2.x; documents the per-file semantics of the new disk quota, the
  grant-time TOCTOU revalidation (and its boundary), and WASI 0.2
  component execution in scope/design sections.
- **SUPPORT.md** added (channels, report checklist, supported platforms,
  release cadence).

**Verified (release readiness — publishing is a maintainer decision)**

- `python -m build` produces sdist + wheel; `twine check` passes for both.
- Wheel contains the MCP `echo.wasm` tool fixture and package metadata.

**Decisions**

- **ADR-001 (docs/decisions/):** Compute (NN/GPU inference) is out of Cell scope —
  Cell commits only to the generic opt-in host-import mechanism (emerging via the
  I/O-budget and State work). Cell compute claims are limited to existing measured
  CPU benchmarks.

### CI

**Fixed**

- **Coverage measured nothing** — `pyproject.toml` pytest addopts pointed
  at the misspelled `--cov=ephemera_cell`; every "70 % coverage" claim ran
  on an empty measurement. Corrected to `ephemora_cell` and the CI
  coverage job now passes `--cov=ephemora_cell` explicitly with a hard
  `--cov-fail-under=70` gate (current coverage: 74 %).
- **Integration tests could not fail CI** — both integration steps ran
  with `continue-on-error: true`; regressions were silently green.
  Removed.
- **Benchmark used an unpinned wasmtime** — `pip install wasmtime` made
  Firecracker-benchmark results non-comparable across runs; pinned to the
  tested 47.0.1. The benchmark workflow also now only triggers on `main`.

**Added**

- pip dependency caching in all CI jobs.
- SBOM is generated from the installed environment metadata
  (`cyclonedx-py environment`), reflecting the true dependency tree
  including the package itself, instead of parsing `requirements.txt`.

### MCP server hardening

**Fixed (security)**

- **One bad call could kill the server** — an unhandled exception inside a
  request handler propagated out of the stdio loop and terminated the
  process. Handlers are now wrapped: unexpected failures answer JSON-RPC
  `-32603` and the loop continues; `BrokenPipeError` on send shuts down
  cleanly when the client disconnects.
- **JSON-RPC request validation** — `jsonrpc` must be `"2.0"` and `id`
  must be string/number/null; violations answer `-32600` (structurally
  invalid) instead of being lumped in with `-32700` (unparseable JSON),
  which is now correctly reserved for malformed JSON.
- **Sidecar could widen permissions** — a sidecar `allow_dirs` entry
  REPLACED the profile's grants; it is now intersected with the profile,
  so a sidecar can narrow but never widen filesystem access. Non-empty
  grants are logged for auditability.
- **Advertised tool name could differ from callable name** — a sidecar
  `name` was advertised via `tools/list` while `tools/call` resolved by
  file stem. The stem is now the enforced identity; mismatching sidecar
  names are overridden with a warning, and duplicate tool definitions
  raise at scan time.
- **Transport line limit** — lines beyond 10 MB are rejected with a
  JSON-RPC error instead of being read into memory unbounded.
- **`protocolVersion` negotiation** — `initialize` echoes a supported
  client-requested version and falls back to the server's own.

**Added**

- Fuzz gate: 100 random/malformed JSON-RPC lines per run must all be
  answered specification-conform, with the server serving valid requests
  afterwards (regression test `test_fuzz_100_malformed_lines_survive`).

### Correctness

**Fixed**

- **WASI 0.2 epoch traps were misclassified as ERROR** — the component
  sandbox only recognized `"interrupt"` as a timeout message; wasmtime
  reports `"epoch deadline reached"`. Epoch traps now classify as
  TIMEOUT (mirroring the preview1 sandbox).
- **`ComponentSandbox.run` UnboundLocalError on early failure** — the
  `except (Trap, WasmtimeError)` handler referenced `store` and
  `timeout_event` before assignment when a component failed to parse;
  both are now pre-bound and the epoch timer is stopped on exit.
- **`fuel_utilization` semantics** — division by a zero budget no longer
  raises (0/0 → 0.0, >0/0 → 1.0), a genuine 0.0 utilization is no longer
  falsified to `None` in `to_dict`, and utilization is clamped to 1.0.
- **Sandbox dir leaks on repeated `run()`** — calling `run()` twice on
  one sandbox instance leaked one sandbox/host dir pair per call; the
  previous run's dirs are now removed before creating new ones (skipped
  when the module lives inside them).
- **`run_wasm` returned a deleted `sandbox_dir` path** — the result now
  reports `sandbox_dir=None` after the internal cleanup.
- **Output budget is byte-based everywhere** — the in-memory truncation
  counted characters while the fd_write sink counted UTF-8 bytes; both
  now enforce the same 10 KB byte budget, and the redundant double
  truncation (`_limit_output(_read_capped_output(...))`) was removed.
- **`exceptions.py` deleted** — the seven exception classes were exported
  but never raised anywhere (including a `TimeoutError` that shadowed the
  builtin); failures are reported via `ExecutionResult.status`.
- Lint: `ruff check` is now clean (0 errors) across package, MCP package,
  and tests.

### Security hardening

**Fixed (security)**

- **Guest run payload leaked via worker argv (High, CWE-200):**
  `run_isolated` passed the full WASIConfig — including `allow_env` secret
  values, guest argv, and stdin data — as `--config <json>` on the worker
  command line, readable by any local user via `ps`/`/proc/<pid>/cmdline`
  for the whole run duration. The payload now travels as JSON over the
  worker's stdin pipe (`--payload-stdin`); argv carries only non-sensitive
  parameters (wasm path, size cap, ABI). Regression tests assert argv
  cleanliness and run a live `ps` poll with a positive control.
- **Engine-pool epoch crossfire / false timeouts (High, CWE-362):**
  `config_fingerprint` included `timeout_seconds`, sharding the pool per
  timeout value, and each run incremented the shared engine's epoch on its
  own timer — a slow run's timer fired the epoch deadline of every
  concurrent run sharing that engine, producing spurious TIMEOUT results.
  The pool now runs one daemon ticker per engine (50 ms tick); each store
  sets its own epoch deadline from its config timeout; the fingerprint no
  longer includes `timeout_seconds`; a refcount lease keeps live engines
  from LRU eviction mid-run. Regression test: concurrent fast+slow runs on
  a shared engine both succeed.
- **TOCTOU — preopen path swap between validation and grant (High,
  CWE-367):** `allow_dirs` entries were realpath-validated at config time
  only; a path swapped to a symlink into a forbidden location before the
  preopen grant was still mounted. Each entry is now re-resolved
  immediately before `preopen_dir` and skipped with a warning on mismatch.
- **Security baseline attested configured, not effective, preopens
  (Medium, CWE-757):** `security_baseline.preopens` listed the configured
  `allow_dirs` plus an unconditional `/sandbox`, even for entries filtered
  out, never-existent, or for component runs (which get no `/sandbox`).
  `ExecutionResult` now carries `effective_preopens` (post-filter, per
  ABI); `apply_config(config, effective_preopens=...)` attests exactly
  what was granted; config-only baselines no longer claim grants.

**Added**

- **Disk quota for guest file writes (Medium, CWE-400):** new
  `WASIConfig.disk_quota_bytes` (default 256 MiB, `None` = unlimited) is
  enforced in the subprocess isolation path via `RLIMIT_FSIZE` with
  `SIGXFSZ` ignored — an over-quota guest write fails with EFBIG (WASI
  errno 22) instead of filling host disk. Kernel semantics make the cap
  per-file; documented as such. Regression test: guest write flood capped
  exactly at the quota with EFBIG, positive control writes through.
- Worker is launched via a direct `-c` import instead of `python -m`
  (runpy module resolution is unreliable for editable installs on some
  hosts); `effective_preopens` is part of the worker report contract.

### Benchmarks

- **Docker comparison re-measured live (2026-08-30, Mac M5, Docker 28.5.1):**
  `docker run --rm python:3.12-slim` 170.6 ms / node:24-alpine 167.8 ms vs
  Cell 0.400 ms cold / 0.376 ms warm = **427×/454×** (n=7 per image, warmup
  pull excluded). Evidence committed:
  `benchmarks/results/2026-08-30/competitive_benchmark.json`
  (`docker_measured:true`); README and `docs/performance.md` now quote the
  reproducible live number — the 191× figure stays labeled as the 2026-08-06
  historical reference.

- **Enterprise page (IP-neutral):** new `docs/enterprise.md` — when Cell is
  enough, the operational questions an enterprise conversation answers, and
  contact channels (LinkedIn for enterprise inquiries, GitHub for OSS).
  Linked from the README "Relationship to Ephemora" paragraph. No feature
  claims, no SLAs, no roadmap details. GitHub Discussions enabled (was
  promised in SUPPORT.md but disabled).

### Documentation

- **Visual assets:** adaptive hero diagram (`assets/hero-light/dark.svg`,
  GitHub light/dark via `<picture>`, regenerated deterministically by
  `assets/make_hero.py`) and a terminal demo GIF (`assets/demo.gif`, 40 KB,
  generated by `assets/make_gif.py` from verbatim real-run outputs —
  install, first run, `--json` report, attack module blocked).
- **Threat model published (`docs/threat-model.md`):** consolidated
  adversary model (the guest is the adversary), protected assets, trust
  boundaries with their enforcement points, and documented residual risks —
  referencing the control matrix and measured evaluations instead of
  duplicating numbers. Linked from README and SECURITY.md.
- **`--version` flag for the CLI** (`ephemora-cell --version`), matching
  the MCP server and the `__version__` attribute SUPPORT.md documents.
- **Architecture diagram modernized:** ASCII box art in the README replaced
  with a native Mermaid flowchart (GitHub renders it inline; syntax
  validated with mermaid-cli) — same content parity (enforcement knobs,
  WASI Preview1 syscall surface, blocked-by-design list), diffable and
  mobile-readable.
- **First-run UX fixes from a fresh-clone user test:** CLI stderr now
  always ends with a newline (host diagnostics like "WASM module not
  found" and fuel traps no longer glue onto the shell prompt — stdout
  stays verbatim for programmatic use); successful `build` prints a
  copy-paste `run it: ephemora-cell run …` hint next to the output path;
  the stale `build` help/error texts now list all five real recipes
  (.rs/.go/.c/.ts/.zig, guidance: .py). Regression tests added.
- **CONTRIBUTING:** documented the `benchmarks/results/<date>/`
  convention — commit dated evidence dirs that back a claim, delete
  throwaway runs (no blanket gitignore, evidence culture preserved).
- **README restructured for GitHub-first reading** (~35 KB / 623 lines →
  ~15 KB / 241 lines): short hero + Quick Start, 8 feature bullets,
  single performance and security tables; detail moved instead of
  deleted — execution-path control matrix → SECURITY.md, arXiv
  2509.11242 evaluation + fuel boundary + related research →
  `docs/security_posture.md`, FastAPI + serverless/air-gapped/component
  recipes → `docs/recipes.md`, interpreter guidance + Preview1
  limitations → `docs/languages.md`. Marketing duplication (Why Now /
  Why Enterprises Switch) removed; measured facts retained in
  Performance/Security.
- **Docker 191× figure caveated** in `docs/performance.md`: historical
  2026-08-06 measurement, no committed `docker_measured: true` JSON —
  treated as order-of-magnitude indicator, not a verified claim
  (`benchmarks/competitive_benchmark.py` measures Docker live per run).

### Earlier internal development (2026-08-04 → 2026-08-26)

Pre-public milestones (internal labels 1.0.0 → 2.2.0) established the
sandbox core, WASI 0.2 component support, execution records (RFC 8785),
the MCP server, the control matrix (in-process vs subprocess), profiles,
named state and the first security hardening passes. Their detailed
entries live in the pre-public development history and are summarized in
[README.md](README.md) and [SECURITY.md](SECURITY.md).
