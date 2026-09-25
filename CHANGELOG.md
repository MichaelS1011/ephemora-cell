# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/).

## [Unreleased]

### Security

- **Atomic publication + per-call module binding (load-path TOCTOU
  closed):** all producers (governed-load install, `sign_tool`, rust
  builder) publish files via temp + fsync + `os.replace` — a
  partially-written module is never visible under its final name, and
  the governed install publishes exactly the bytes it verified. The
  registry load-guard registers only settled, magic-prefixed modules
  within the size cap; in signed-tools mode every execution is bound to
  the register-time digest (`WASISandbox.run(expected_sha256=...)`,
  preview1/component/subprocess alike) — a swapped on-disk file fails
  closed instead of executing. The engine-pool module cache is keyed by
  content hash (no stat-then-open race, no stale-serve for mtime-preserving
  swaps). ADR-006 amendment documents the full model.
- **Explicit proposal policy (set, not inherited):** the engine now also
  enforces `wasm_stack_switching=False` (WASI 0.3 native-async base —
  gate-off until the 0.3 surface is qualified; WASIp3 streams of
  GHSA-x84v-gj2h-g759 are structurally unreachable: the Python binding
  cannot link a WASIp3 world, asserted in `tests/test_surface_audit.py`).
  The full proposal posture is documented in SECURITY.md and locked by a
  compile-probe matrix (`tests/test_proposal_policy.py`) plus SpyConfig
  assertions at every engine construction site — a wasmtime upgrade that
  silently flips a proposal default now fails tests instead of production.
- **CVE-2026-34988 class guard:** the pooling allocator is not exposed by
  the Python binding (the cache-pressure-residue class is unreachable).
  An explicit 4 GiB `memory_guard_size` was evaluated and **reverted** —
  it broke `run_isolated` in constrained Linux VMs (mmap ENOMEM on
  reservation+guard; caught by the arm64 container gate).
  `tests/test_memory_hygiene.py` proves sequential instances observe only
  zeroed memory (secret-writer → residue-reader, same sandbox and pooled
  engine) and is the standing guard.
- **CVE-2026-34971 confirmation artifacts:** a version-floor test pins
  wasmtime `>= 43.0.1` (April 2026 advisory fixes), the Winch backend is
  asserted unselectable ("never Winch"), and `Engine.is_pulley()` is
  asserted `False` — no interpreted fallback in the shipped posture.

### Added

- **ADR-008 record split + open-standard envelopes:** `PreExecutionRecord`
  signs what a run *will* do before it runs (module digest, policy
  fingerprint with allow_env names only, input digest); the receipt's
  optional `back_link` binds it to exactly that attestation
  (`verify_chain()`, fail-closed). DSSE v1 envelopes (PAE-signed,
  in-toto/TUF-interoperable) and detached JWS (RFC 7797) wrap the same
  RFC 8785 JCS payload bytes; a transparency-log inclusion proof is a
  signature-covered payload field — no network client, no dependency.
  Plain report schemas are unchanged (compat-pinned).
- docs/threat-model.md: dedicated resource-exhaustion section with a
  per-WASI-call budget matrix (12 measured Preview1 syscalls mapped to
  fuel / I/O byte wall / disk quota / io-CPU watchdog / output cap),
  framing the arXiv 2509.11242 findings and the fd_renumber leak class
  (GHSA-3p27-qvp9-27qf — 47.x not affected, cited as class exemplar).
- docs/performance.md: backend-transparency section (every published
  number is Cranelift; Lumos literature numbers marked `measured:false`)
  and third-party positioning vs. Firecracker-class microVMs (arXiv
  2509.09400, VHPC'25).
- README "What is enforced": the structural default-off defense narrative
  (2025/26 divergence pattern: fuel gap, Cranelift batch, vm2 try_table
  escape); docs/recipes.md carries the explicit WASI 0.3 gate-off stance.

## [1.0.4.2] - 2026-09-24

### Security

- **Fuel-determinism hardening for GHSA-m63x-6p34-q65x** (wasmtime fuel
  amplification via `call_ref`/`try_table`, CVSS 5.7): the Cell engine now
  enforces `wasm_function_references=False`, `wasm_exceptions=False`,
  `wasm_gc=False` and `wasm_tail_call=False` at every Config construction
  site (`wasi_runtime`, `engine_pool`, `wasi_02`, conformance harness) —
  guest modules using the affected opcodes fail to compile (fail-closed,
  empirically verified on the pinned wasmtime 47.0.1). Breaking for guests
  that legitimately need exceptions/GC; the upgrade path to wasmtime
  48.0.3/49.0.1 (where the engine fix lands) is tracked by
  `scripts/check_wasmtime_patch.py` and re-opens those proposals for
  re-evaluation.
- **`security_baseline` attests the enforced posture**: new keys
  `function_references_enabled`, `exceptions_enabled`, `gc_enabled`,
  `tail_calls_enabled` (all `false`) — a signed record cannot claim
  features the engine would reject. Exposure statement for both September
  2026 advisories (incl. CVE-2026-47261, filesystem escape) in SECURITY.md.
- `scripts/check_wasmtime_patch.py` added: watches PyPI for the pending
  patch wheels (48.0.3/49.0.1/47.0.4; all absent as of this release) and
  signals when the full engine upgrade (security plan milestone M2) opens.

### Fixed

- **Signed-tools mode now enforces the module binding at load** (ADR-006
  register-time re-hash). `ToolRegistry._build_spec` previously verified
  only the manifest signature; a `.wasm` swapped after signing — even a
  fully valid different module (MCPoison class) — was registered and
  executed. Sidecars without `wasm_sha256` are now rejected in
  `--require-signed-tools` mode as well (same rule the governed-load path
  always applied). Found in the 2026-09-24 full-functional audit; verified
  fixed on macOS arm64 and DGX Spark aarch64.
- **MCP stdio transport no longer drops the message after an oversized
  line.** The old drain loop read the line FOLLOWING an oversized one
  (text-stream `readline()` had already consumed the whole oversized line)
  and re-parsed the transport's own error string as input, so a client got
  a generic `-32600 invalid request` instead of the transport-limit error
  and silently lost a request. The limit reply is now sent immediately and
  reading continues at the next message boundary.
- `ephemora-cell run --stdin <path>` with an unreadable file prints a clean
  one-line error (exit 1) instead of a `FileNotFoundError` traceback.
- `_HybridExecutionResult` (the unified `run_isolated()` return) now
  supports `dict(result)`, `len(result)` and `**result` unpacking via
  `keys()`/`__iter__`/`__len__` — dict-style access no longer crashes on
  the sequence protocol.

### Added

- Governed loading works on the shipped stdio server: with
  `--tool-requests-dir` configured, the serve loop evaluates dropped
  requests before each incoming message (install +
  `notifications/tools/list_changed` + request consumed). Rejections are
  reported on stderr ("never silent", ADR-006) and the request stays on
  disk. Previously only embedding hosts could call
  `Server.process_tool_requests()`.
- Container hygiene: `.dockerignore` keeps dev environments, git history
  and local caches (`.conformance_cache` alone is ~537 MB) out of the
  image — image size 1.45 GB → 271 MB — and the `Dockerfile` runs as a
  non-root user (`uid=1000 cell`).

### Changed

- CI installs `pytest<9` in every job (matching the `pyproject.toml`
  dev-extra pin and its Python 3.11 rationale) instead of unversioned
  `pytest`, which drifted to pytest 9.
- `pytest` collects only `tests/` (`testpaths` no longer lists
  `benchmarks/`, which holds evidence scripts, not pytest tests).
- `docs/performance.md` documents that fuel counts are per-platform with
  measured cross-platform examples (hello.wasm: 16 397 on macOS arm64 vs.
  12 on DGX GB10; spread 0 per platform).

## [1.0.4.1] - 2026-09-23

### Fixed

- MCP `server/discover` now reports the same registry freshness as
  `tools/list` via a shared `Server._registry_ttl_ms`. Previously
  `server/discover` hard-coded the 1 h static TTL while advertising
  `listChanged`; a host that cached that discover result for the advertised
  hour would ignore `notifications/tools/list_changed` for a full hour after a
  governed install (`--tool-requests-dir`, ADR-006) and keep issuing stale
  tool schemas against the live server — schema drift with no invalidation
  path. Under governed loading both endpoints now drop to 60 s together.
  Stdio in-place updates remain drift-free by construction (process lifetime =
  connection lifetime, a restart forces a fresh `tools/list`); `docs/mcp.md`
  adds an "Updating a running server (schema drift)" section naming `ttlMs` as
  a client hint and the three cases honestly. Guarded by
  `tests/test_mcp_2026_07_28.py::test_discover_ttl_tracks_governed_registry`.

## [1.0.4] - 2026-09-21

### Fixed

- `get-policy` now attests the filesystem surface a run will ACTUALLY
  grant, closing the last policy/enforcement drift: the security
  baseline previously reported only the profile's configured
  `allow_dirs` (empty for the default profile), while every core-module
  (Preview1) execution additionally preopens the ephemeral sandbox dir
  as `/sandbox` — a caller diffing `get-policy` against an execution
  record's `effective_preopens` saw two different filesystem stories.
  `policy_for` now derives the preopen set from the same truth as the
  run witness (configured grants + `/sandbox`; WASI 0.2 components
  excluded, matching the component path, via `is_component_binary`).
  A new `sandbox_lifecycle` field attests the execution topology
  (`fresh-per-call` default vs. `pooled` fast path), so "fresh sandbox
  per call" is a reported fact, not an inference from latency. Guarded
  by `tests/test_policy_agreement.py`: the reported preopen set must
  equal the executed run's `effective_preopens`.
- Version is now single-sourced and CI-guarded: the released 1.0.3
  wheel carried a `serverInfo`/`get-policy` version of 1.0.1 while
  `--version` said 1.0.3 — three signals for one install.
  `tests/test_policy_agreement.py` asserts `pyproject.toml` and the
  runtime `__version__` never diverge again.

### Added

- Second-platform evidence for the boundary and startup claims: the
  same-attack matrix (stock Docker 8/8 ALLOWED, hardened Docker 2/8
  blocked with all 8 pre-declared expectations matched, Cell 8/8 BLOCKED)
  and the cold/warm-start contrast (stock `python:3.12-slim` 311.8 ms /
  `node:24-alpine` 313.2 ms mean per 100 docker runs vs. Cell cold
  0.745 ms / warm 0.727 ms, pure wasmtime floor 0.006 ms) were measured
  on a DGX Spark GB10 (aarch64 Linux, idle host, load 0.73) and committed
  under `benchmarks/results/2026-09-20/*-dgx-aarch64.json` following the
  CoreMark platform-suffix convention. The macOS arm64 results are
  unchanged and remain on file (2026-09-14 / 2026-09-18): Docker is
  ~68% slower on the GB10 while Cell stays sub-millisecond on both
  platforms, so the advantage claim now carries stamped numbers on two
  architectures instead of a single-host figure.

- `benchmarks/competitive_benchmark.py` now derives its platform label
  from the actual host (`platform.system()`/`platform.machine()`,
  same as `coremark_wasi.py`) unless `BENCH_LABEL` pins one — the
  previous hardcoded default ("macOS-M5") could stamp a foreign platform
  onto evidence measured elsewhere.

- MCP `2026-07-28` stateless revision support in `ephemora-cell-mcp`
  (dual-era, per the specification's "Versioning and Compatibility"):
  the new mandatory `server/discover` method reports supported versions,
  capabilities and identity; requests carrying
  `_meta["io.modelcontextprotocol/protocolVersion": "2026-07-28"]` are
  served statelessly — no initialize handshake, `resultType: "complete"`
  envelope, per-response `_meta["io.modelcontextprotocol/serverInfo"]`,
  and CacheableResult fields (`ttlMs`/`cacheScope`) on `tools/list`.
  Unsupported per-request versions are rejected with
  `UnsupportedProtocolVersion` (`-32022`) naming the supported list;
  modern requests missing the required `clientCapabilities` get
  `-32602`. The `initialize` handshake keeps negotiating the legacy
  revisions only (2025-06-18 / 2025-03-26 / 2024-11-05) with unchanged
  response shapes, and this server issues no server-initiated requests
  (sampling/elicitation/roots are deprecated in 2026-07-28), so MRTR
  interim results cannot occur. Covered by
  `tests/test_mcp_2026_07_28.py`; the official-SDK interop job proves
  both eras against the reference implementation: the existing
  handshake-path test and a new stateless round-trip where MCP SDK 2.1.1
  probes `server/discover`, adopts the modern per-request stamp without
  ever sending `initialize`, and completes stateless `tools/list` +
  `tools/call` with the 2026-07-28 envelope (`resultType`, serverInfo)
  and the execution `_meta` intact
  (`integration/test_mcp_sdk_client.py`).

- Test-bench CI job (`test-bench` in ci.yml): the documented
  eight-attack-vector suite (`benchmarks/verify_8_vectors.py`, 8/8
  boundary gate) and the auto-grader verdict contract
  (`examples/auto_grader.py --strict`, new flag — exact expected
  pass/compute-budget/memory-budget mapping, exit 1 on drift) now run on
  every push and pull request on the pinned wasmtime baseline, so the
  README's 8/8 claim is continuously re-proven instead of asserted once.

- Deterministic conformance CI despite a documented engine flake:
  `conformance/adapters/cell_retry_wrapper.py` wraps the Cell CLI in the
  weekly WASI conformance job and reruns a test once when its process
  dies with SIGABRT (exit -6) — the rare wasmtime engine abort observed
  on shared ubuntu runners on varying filesystem tests (see
  `conformance/README.md`). Every other exit code passes through
  untouched; a second abort still fails. Each retry is recorded in
  `results/engine_abort_retries.jsonl` and echoed into the run's
  summary JSON under `engine_abort_retries`, so committed evidence shows
  exactly which runs needed a retry.

- EEMBC CoreMark benchmark (`benchmarks/coremark_wasi.py`, evidence
  `benchmarks/results/2026-09-19/09_coremark_wasi_*.json`): CoreMark 1.01
  built to wasm32-wasi (wasm3/wasm-coremark build.sh, wasi-sdk-34, CoreMark
  pinned at eembc/coremark `1f483d5b`) run interleaved under three
  configurations — bare wasmtime, the Cell sandbox, and the Cell sandbox
  with fuel metering on. Measured on macOS arm64 and DGX Spark GB10
  (aarch64): the sandbox reduces the CoreMark score by **8.1-10.0%**, fuel
  metering by a further **12.5-14.6%** — on the industry-standard CPU
  workload, self-validated per run, interleaved against thermal drift.
  External engine control columns (same binary, interleaved, versioned
  in the evidence): wasmer 7.4.2 scored +9.98%/+15.57% vs bare wasmtime,
  wasm3 0.9.0 (interpreter) −88.24%/−89.92% on DGX/macOS — engine choice
  spans a ~12× range; the Cell layer sits close to the bare engine.
  Binary committed under `benchmarks/workloads/coremark.wasm`.

- gVisor (runsc) boundary column — measured in CI: new job
  `gvisor-boundary` (ubuntu runner, pinned gVisor release 20260914.0 via
  apt, `runsc install` runtime registration, smoke container, probe run
  twice for determinism) executes the same eight attack intents with
  `--runtime runsc`. Expectation matrix pre-declared: 8/8 ALLOWED — gVisor
  protects the host from the container; the guest sees a Linux ABI, so
  guest primitives stay available. Positive control fails the run before
  any evidence is written. Evidence lands as run artifact; README/docs
  gain the column after the first measured run (nothing unmeasured
  claimed). Locally reproducible for anyone with runsc installed:
  `python benchmarks/gvisor_docker_probe.py`.

- Official WebAssembly core spec conformance
  (`conformance/run_core_spec.py` + weekly CI job `core-spec.yml`): the
  consolidated [WebAssembly/testsuite](https://github.com/WebAssembly/testsuite)
  (W3C Wasm 3.0 era, pinned `b464a4cd100d`, 257 files / ~36k commands)
  executed via `wast2json` against the exact engine configuration Cell
  ships, with per-file subprocess isolation and epoch-bounded commands.
  First run: **31,931 pass** — 3,282 documented deviations/limitations
  (memory64/multi-memory by design, v128 blocked by the wasmtime-py 47
  binding, relaxed-simd native upstream aborts), 684 text-format skips,
  46 binding-level NaN-bit remainder listed verbatim in the evidence
  (`conformance/results/core_spec_2026-09-19.json`). Cell now reports
  conformance against both official suites (WASI + core).

- README "vs Microsoft Wassette" positioning box: same Wasmtime engine
  family, OCI pull model moves the trust decision to install time; Cell adds
  what a caller can verify per call. Neutral framing, date-stamped pointer
  to the comparison doc.
- Weekly Linux-native Docker benchmark job
  (`.github/workflows/benchmark-linux.yml`, ubuntu runner — Docker without
  the Desktop VM; Mondays 06:00 UTC + dispatch, non-blocking, evidence as
  artifact + step summary; main stays bot-commit-free). Gives the canonical
  performance tables a measured Linux row once it has run.

- Smithery deployment manifest (`smithery.yaml`): stdio start command via
  `uvx --from ephemora-cell ephemora-cell-mcp`, optional `toolsDir` config;
  governance note included (governed loading, ADR-006).
- Daily metrics snapshots now carry conversion-context fields — `git_head_sha`
  + commit subject, latest release tag, latest PyPI version — so demand spikes
  in the public JSONL history can be attributed to the change/release that
  shipped the day before, without archaeology. Null-tolerant like every
  other source; live-tested.

### Changed

- README frames the existing CLI as the local devtools loop for agent
  tools: a new section after Quick Start walks the edit → `build` →
  `run --json` → `inspect`/`benchmark` cycle, shows failures arriving as
  graded statuses (`fuel_exhausted`, `memory_exceeded`) with receipts
  instead of a crashed terminal, and points at the auto-grader and the
  CI test-bench job as consumers of the same statuses. Documentation
  only — no code or claims beyond the already-published measurements.

- Claim wording aligned with the facts-only posture across README and the
  comparison doc: statements now describe what Cell does and what the
  measurements show (e.g. "What every Cell tool call carries", measured
  install footprints, per-response fields recorded for every candidate) —
  without comparative superlatives; quality judgments are left to the
  reader, who can reproduce every number.
- PyPI metadata: Documentation and Changelog URLs added to `[project.urls]`
  (previously only Homepage + Issues); keywords extended to match the GitHub
  topics (wasmtime, code-execution, capability-based-security, untrusted-code,
  mcp-server). Takes effect with the next upload.

- Fuel vs epoch vs wall-clock mechanism benchmark
  (`benchmarks/fuel_epoch_wall.py`, evidence
  `benchmarks/results/2026-09-18/07_fuel_epoch_wall.json`): the three ways to
  stop a WASM run, measured on overhead (10M-iter mixed loop, raw wasmtime,
  n=30: epoch +1.4%, fuel +35.2% — corroborating the cited 28–40% anchor),
  precision (overshoot at T=0.1 s, n=20: per-run epoch 5.3 ms median,
  pooled 10.0 ms, subprocess kill 53.9 ms incl. spawn/teardown) and
  determinism (fuel stop-point identical across runs; time-based stops
  jitter). Platform-bound numbers, claim-separated from the 0.376 ms
  per-call overhead. Documented in docs/performance.md.

- Per-call evidence + attack-surface audits (comparison doc §4.1/§4.2,
  measured 2026-09-18): the same call to every locally measurable candidate —
  ephemora-cell-mcp returns text content plus a full `_meta.execution`
  receipt (fuel, memory, output bytes, security baseline; sign-ready), the
  pinned reference server returns content only, docker/subprocess return
  stdout + exit code. Install footprints measured fresh: ephemora-cell = 2
  distributions (package + wasmtime), 36.2 MB; server-filesystem@2025.3.28 =
  52 package dirs / 22.2 MB node_modules (corrects the earlier "118" figure,
  which counted an unpinned install). Evidence:
  `benchmarks/results/2026-09-18/05_per_call_evidence.json` +
  `06_attack_surface_audit.json`; repro scripts
  `benchmarks/per_call_evidence.py` + `benchmarks/attack_surface_audit.py`.

- SandboxEscapeBench-18 harness rebuilt as an honest structural comparison
  (supersedes the 2026-08-25 run, which counted a trivially succeeding
  proc_exit module as "BLOCKED by design"): 8 of the 18 externally defined
  container/K8s escape scenarios are now execution-tested against the live
  boundary (preopen traversal toward /etc, sock_accept capability call,
  shared-memory engine rejection, live import-surface scan) and denied; the
  other 10 are labeled NOT-EXPRESSIBLE (no WASI counterpart exists) instead
  of a padded "blocked" count. Granted-preopen positive control, MIT
  attribution header (UK AISI + Oxford, arXiv 2603.02277), dated evidence
  output, `measured:true`. README now leads with an evidence ladder, the
  scenario provenance note, and a "what we do not compare" scope statement.
- WASI 0.2 component branch for the MCP CVE replay: the same attack intents
  (CVE-2025-53109/53110 symlink + traversal, CVE-2025-54136 governed-load
  tamper) are replayed against the ComponentSandbox boundary with prebuilt
  component probes (`benchmarks/component_probes/`, sources + rebuild.sh
  committed; CI does not rebuild). Verdicts (2026-09-18, deterministic across
  3 runs, `abi: "component"`): symlink escape blocked (EPERM), traversal
  blocked (no preopen base), governed-load tamper fails closed — and the
  audit-required **network intent is measured**: the WASI 0.2 world links
  `wasi:sockets` (unlike Preview1), a TCP connect is refused at call time
  while the granted-read control passes in the same run.
  Evidence: `benchmarks/results/2026-09-18/mcp_cve_replay_component.json`.

- Hardened-container baseline for the 8-vector security matrix: the same eight
  attack intents against `python:3.12-slim` with a declared flag set
  (`--network none --read-only --cap-drop=ALL --security-opt no-new-privileges
  --pids-limit 64 --user 65534:65534`) — measured 2026-09-18: 6/8 still allowed,
  both blocks are `--read-only` EROFS effects, not a guest-facing boundary.
  New probe `benchmarks/hardened_docker_probe.py` with pre-declared expectation
  matrix (deviations documented, never silently edited), positive control and a
  digest-pinned arm64 image (evidence: `benchmarks/results/2026-09-18/`).

### Changed

- MCP CVE replay: the component governed-load run uses its own registry state
  directory (the Preview1 class-3 run registers "widget" first; a shared
  state dir made the full-run component branch fail closed on a name
  collision — found by the first full-run after the component branch landed);
  internal plan-item reference removed from the harness header.
- Network claim corrected where it overclaimed ("no socket APIs in WASI" was
  Preview1-true but 0.2-false): README and threat model now state — Preview1:
  no socket APIs; WASI 0.2: linked, denied at call time (measured).
  `wasi_02` docstring corrected likewise (unknown imports fail at instantiate
  time; they are not defined as traps).
- Performance surfaces harmonized on the current measurement (2026-09-14, n=100
  per image, arm64): whitepaper and LinkedIn one-pager now carry 383× (was
  427× from the n=7 2026-08-30 run) with a fixed scope caveat and a citation
  of the differing academic measurement for Wasm-based container runtimes
  (Liu et al., ACM TOSEM 34(6), 2025). `docs/performance.md` states the caveat
  for every multiplier on the page. PDFs rebuilt and text-verified.
- README: the standard path shown for untrusted code is now the isolated one —
  Quick Start runs `--isolated` (in-process stays for modules you build and
  trust), and "no opt-in security" is restated precisely: enforced limits are
  never opt-in; the only choice is the process boundary. The fuel-bomb receipt
  demo runs isolated as well; CLI `--json` output is schema-identical between
  paths (verified against a fresh PyPI install).
- README security table compares stock Docker, hardened Docker and Cell with
  per-row boundary-layer attribution (Layer 1 WASI surface · Layer 2 sandbox
  policy · Layer 3 process wall) and an intent-equivalence table mapping every
  `python3 -c` probe body to its WASM guest equivalent.
- `assets/demo_attack_probe.py` writes dated evidence with image digest and
  architecture (no more hardcoded result directory).
- SECURITY.md: engine-advisory paragraph (April 2026 wasmtime advisories —
  12 advisories, two critical sandbox escapes, both aarch64-specific, fixed
  before the pinned 47.0.1) and an engine-upgrade gate: any wasmtime bump
  re-runs the security evidence suite before claims are re-attested.

## [1.0.3] - 2026-09-17

### Fixed

- Black formatting for `ephemora_cell/__init__.py` hybrid wrapper (long line split).

## [1.0.2] - 2026-09-17

### Added

- MCP Registry publication as `io.github.MichaelS1011/ephemora-cell-mcp` (`server.json`, PyPI `mcp-name` in README). Published to `registry.modelcontextprotocol.io` (1.0.2 active).
- GitHub Topics expanded 11 -> 17 (`wasmtime`, `wasi-preview1`, `wasm-sandbox`, `mcp-server`, `capability-based-security`, `code-execution`).

### Fixed

- Repeated `--allow-env` / `--allow-dirs` CLI flags no longer overwrite each
  other (argparse accumulation bug; found by the first external
  wasi-testsuite conformance run, fixed with regression tests).
- `allow_dirs` entries now support wasmtime-style `host::guest` preopen
  naming so wasi-libc-built binaries resolve relative paths against `/`;
  host-side validation and TOCTOU revalidation are unchanged.
- CLI `--no-memory64` to override `analytical` profile (`memory64=True`).
- `allow_dirs` non-existent paths now warn (`RuntimeWarning`) instead of silent skip.
- `_HybridExecutionResult` unifies `run_isolated` return type (`result.status` + `result["status"]`).
- Builder unified Rust default output to `project/<crate>.wasm` like Go/C/Zig.
- WASI preview-1 conformance harness against the official, pinned
  wasi-testsuite (`conformance/`, 72 pass / 1 documented xfail / 0 fail)
  with a weekly non-blocking CI job.
- Order-of-magnitude benchmark guard in CI (latency thresholds + fuel
  invariance within a run).

## [1.0.1] - 2026-09-11

Release metadata and MCP surface hardening. Repo-committed code is
unchanged in behavior except where listed; published to PyPI on
2026-09-11 (the 1.0.0 PyPI metadata publicly exposes a personal email
that the repository itself no longer carries — this upload replaces it).

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
