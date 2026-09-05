# ephemora-cell-mcp vs. the MCP server market

> As of: 2026-08-20 · Methodology: local measurements on this machine (Section 2)
> + cited external sources (Section 3). "Verified. Not claimed." — every number
> comes from a real run or a source URL.

## 1. Key takeaway

`ephemora-cell-mcp` is the only **dependency-free, locally sandboxed**
MCP server in this comparison: tools run as WASM modules inside a
Wasmtime sandbox (no host FS, no env, no network, fuel metering,
10 KB output cap) instead of in-process with full user privileges — and that at
competitive latency (0.89 ms tool call on a persistent channel; see §2) and a
small footprint (52 MB RSS, 1 runtime dependency).

The price of isolation is measurable: an *unsecured* in-process tool is
~13× faster (0.07 ms) — but it reads `/etc/passwd`, sees the
environment, and can do anything the host user may do.

## 2. Local benchmarks (2026-08-20, macOS 26.5.1, Apple arm64)

Node v22.23.1 · Python 3.14.3 · ephemora-cell-mcp 0.1.0 (Cell 2.1.1, wasmtime 47.0.1).
3 runs per candidate, median. Method: NDJSON over stdin, `time.perf_counter`,
peak RSS via `ru_maxrss`; SDK values via the official MCP Python SDK 2.0.
**Provenance:** the whole table is a dated, one-time snapshot from 2026-08-20
taken with the method above. No single generator script reproduces it end to end
and it is not tagged `measured: true`; treat every figure as reported, not
re-runnable. Determinism, fuel, and SDK interop (see directly below) are the parts
with checked-in, re-runnable evidence. Values may shift on other machines/builds.

| Candidate | Start to initialize (ms) | tools/call (ms, raw) | Peak RSS (MB) | Install (MB) | Runtime deps | Isolation |
|---|---|---|---|---|---|---|
| **ephemora-cell-mcp** | **45.9** | **0.89**⁴ | **52.3** | 23.95¹ | **1** (wasmtime) | **WASM sandbox (deny-by-default)** |
| naive MCP tool (Python stdlib) | 12.3 | 0.07 | 14.9 | 0.004 | 0 | **none** (full host rights)² |
| `@modelcontextprotocol/server-filesystem` | 70.2 | 0.32 | 75.5 | 30.32 | 118 (npm) | **none** (directory allowlist only) |
| Docker wrapper (external evidence) | — | +490 ms per call³ | — | — | Docker | Container (breakout-capable, see below) |
| Microsoft Wassette | —⁵ | —⁵ | —⁵ | —⁵ | —⁵ | Wasmtime WASI-0.2 component sandbox + per-component permission grants (network/storage/env), OCI component distribution⁵ |

¹ Of that, 23.0 MB is the wasmtime runtime, 0.7 MB package code. ² Demonstrated:
reads `/etc/passwd`, dumps env, knows cwd — a compromised or
hallucinated tool call leaks the machine. ³ https://github.com/enkryptai/secure-mcp-gateway/blob/main/docs/sandbox_walkthrough.md
(Docker +490 ms on a 530 ms baseline; authors: "~1 second overhead per call").
⁴ Warm persistent-channel steady-state: a single initialized channel reused
across calls. Each fresh `tools/call` in a new process pays WASM instantiation
(first call ≈10 ms, see determinism note below); the shipped stdio server
builds a fresh sandbox per call by default (ADR-002 io-budget ⇒ per-run engine).
⁵ Not measured here (single binary, install script — no matched method run as
of this snapshot); qualitative facts from [microsoft/wassette](https://github.com/microsoft/wassette)
(retrieved 2026-09-05): same Wasmtime engine family, MIT, components pulled as
OCI artifacts from registries (e.g. `oci://ghcr.io/microsoft/time-server-js`),
per-component permission grants; README self-labels the project "Early
Development — not production ready". Differences that matter for agents:
Cell meters every call (fuel) and attaches an execution witness to each
response (`_meta.execution`, determinism and CI-verified SDK interop above),
while Wassette's OCI pull model moves the trust decision to install time.

**Determinism (echo tool, 5 calls):** fuel_consumed = 21562 constant
(spread 0); elapsed_ms 0.43 ms median (only the first call in a fresh
process pays WASM instantiation, 10.23 ms). Deterministic
fuel metering = reproducible accounting ("Verified. Not claimed.").

**Interop note:** the naive tool breaks against the official MCP SDK 2.0
(`tools/list` returns `input_schema` instead of `inputSchema` → pydantic
ValidationError) — SDK conformance is not a given, not even
for hand-written servers. `ephemora-cell-mcp` is verified in CI against the
official MCP Python SDK 2.0 over stdio — initialize, `tools/list`, and a real
`tools/call` with execution `_meta` (`integration/test_mcp_sdk_client.py`,
job `mcp-sdk-interop`).

## 3. Market snapshot (evidenced, sources in the appendix)

| Candidate | Isolation | Technology | License/OSS | Known incidents |
|---|---|---|---|---|
| Official servers (filesystem/fetch/git) | in-process, full rights | Node/Python | MIT, OSS | CVE-2025-53109 + CVE-2025-53110 (filesystem, symlink/prefix bypass, HIGH); CVE-2025-68143/44/45 (git → RCE chain via smudge/clean filters); fetch SSRF unpatched in PyPI (2026-06) |
| Playwright MCP | in-process + browser subprocess | Node | MIT, OSS | SSRF/cloud metadata (Issue #1626) |
| Microsoft Wassette | **WASM** (Wasmtime, deny-by-default) | Rust, OCI components | MIT, OSS | none found; README: "Early Development — not production ready" |
| mcp.run / Extism | WASM (host grants, fuel) | Extism | BSD-3 (framework); platform commercial | no registry incident found; no signature verification in base Extism |
| E2B | Cloud microVM (Firecracker) | Go/Rust | Apache-2.0, self-hostable | no incidents; startup degradation ~100 ms→~1 s at 100 concurrent |
| Docker/Codex sandbox | Container/namespace | Docker, bubblewrap, seccomp | OSS (Codex) | escape class evidenced (SandboxEscapeBench, arXiv 2603.02277) |
| npx/uvx category ("installation = execution") | in-process, unpinned | npm/PyPI | n/a | postmark-mcp (typosquat), SANDWORM_MODE (worm), Shai-Hulud/"V.A.P.E." (first registry incident), Smithery breach (3,000 servers), CVE-2026-45781 (registry fails-open on 429) |

## 4. Positioning of ephemora-cell-mcp

**What it brings (only what is evidenced):**

1. **Isolation is the default architecture, not a feature flag.** The guest never
   sees host FS/env/network — this is not configurable but rather the
   sandbox intervention. (Benchmark agent: the naive counter-probe reads `/etc/passwd`.)
2. **Smallest attack surface in the market comparison:** 1 runtime dep (wasmtime),
   ~24 MB installed, no Node and no npm transitive tree (server-filesystem:
   118 packages), no npx execution of unpinned code.
3. **Per-call proof instead of trust:** every call carries `_meta.execution`
   (fuel_consumed, elapsed_ms, wasmtime_version) — deterministic
   fuel metering (spread 0). No other candidate in the comparison provides a
   measurable per-call attestation.
4. **Local and offline:** no cloud round trip, no registry requirement, no
   microVM latency (E2B: network round trip + ~100 ms–1 s startup), no
   container latency (Docker wrapper: +490 ms).
5. **A Wassette parallel, with a production-ready core:** the same
   WASM deny-by-default philosophy (Wasmtime), but Cell ships 386 CI-enforced
   tests with security gates (pip-audit, SBOM, bandit) and an active release
   line; Wassette itself declares itself "not production ready".

**Honest limitations (not hidden):**

- **No network in the sandbox guest** — tools like `fetch` (HTTP) deliberately
  do not exist. Web research tools require a host-side gateway with an
  allowlist (as with mcp.run `allowed_hosts`).
- **~13× slower than an unsecured in-process tool** (0.89 ms vs.
  0.07 ms) — that is the measurable price of isolation. The 0.89 ms figure is
  the **warm persistent channel** (§2); the shipped stdio server builds a fresh
  sandbox per `tools/call`, so its steady-state is higher (~12 ms/call measured,
  Apple arm64) — the io-budget/epoch-deadline of ADR-002 requires a per-run
  engine and bypasses the pool. Sub-millisecond holds only for pooled warm runs
  (`io_budget_bytes=None`, see `benchmarks/pool_vs_budget.py`).
- **1 runtime dep** (wasmtime) instead of 0 — won back by the sandbox.
- **SDK 2.0 interop** for server-compatible field names is tested
  (echo tool via the SDK), not for arbitrary third-party clients.

## 5. Live verification (2026-08-20): CVEs, limits, cross-arch

### 5.1 CVE-2025-53109 / CVE-2025-53110 — PoC reproduced + counter-probe

On the DGX Spark (Ubuntu/Grace arm64, Node v18) against
`@modelcontextprotocol/server-filesystem` **v2025.3.28** (vulnerable
per the advisory), with the same attacks against `ephemora-cell-mcp` (same
machine, same files):

| Read attempt | server-filesystem v2025.3.28 | ephemora-cell-mcp |
|---|---|---|
| `/allowed/ok.txt` (control) | ✅ `SAFE` | ✅ `SAFE` |
| `/allowed-secret/leak.txt` (prefix collision, CVE-2025-53110) | ❌ **leaked** `SECRET-VIA-PREFIX` | ✅ blocked (`no pre-opened fd`) |
| `/allowed/link_to_etc` → `/etc/passwd` (symlink, CVE-2025-53109) | ❌ **leaked** `root:x:0:0:...` | ✅ blocked (`os error 63`) |
| `/etc/passwd` (direct, no allowlist) | ❌ leaked | ✅ blocked (`no pre-opened fd`) |

**Assessment:** The Node server has to rebuild its FS boundary in process code
(allowlist + realpath checks) — and it is exactly this layer that had
two HIGH CVEs (CWE-59, CWE-22). The 2025.7.1 fix checks realpaths — but
the boundary remains app logic. Cell needs **no** path validation:
the guest simply has no file descriptor outside the preopens, and
wasmtime refuses the symlink escape at the engine level
(`Operation not permitted (os error 63)`). A side finding: on macOS,
the Node server's realpath check fails for `/var`/`/tmp` symlinks
(even valid reads are blocked) — the allowlist logic is
OS-sensitive. Reproduction: PoC scripts in the repo, log in the ADRs.

### 5.2 Limits enforcement (engine + MCP channel)

`benchmarks/pocs/limits_poc/` — three Rust guests (`memhog`, `hugeout`,
`busy`), 3 runs each, deterministic:

| Limit | Guest | Result (3× identical) |
|---|---|---|
| Memory (`max_memory_mb`) | `memhog` | `MEMORY_LIMIT_REACHED at 1537 pages (96 MB)`, fuel 19420 (spread 0) |
| Output budget (10 KB) | `hugeout` | Capture 9216 B < 10 KB (ENOSPC), status error |
| Fuel (`max_fuel`) | `busy` | `fuel_exhausted`, loop stopped |

The same guests as MCP tools → `_meta.execution` reflects identical
statuses (success/error/fuel_exhausted, wasmtime 47.0.1) — the limit is enforced in
the Cell, not in the adapter. To be honest: `fuel_consumed` is
`None` on `fuel_exhausted` (known limitation, Preview1 trap path).

### 5.3 Determinism cross-arch (macOS vs. DGX/Grace)

Same probe `benchmarks/determinism_probe.py`, same tool file
`echo.wasm`, same wasmtime **47.0.1** (pip-pinned):

| Machine | Arch | fuel_consumed (median, 2 runs) | Spread | elapsed median |
|---|---|---|---|---|
| macOS 26.5.1 | arm64 (M5) | **20891** | **0** | 0.39 ms |
| DGX Spark (Ubuntu 24.04) | arm64 (Grace) | **4506** | **0** | 1.70 ms |

**Honest finding:** fuel is **deterministic per platform**
(spread 0 across runs and process restarts), but **not platform-**
**identical** — the same execution burns 4.6× more fuel on macOS than
on the Grace SoC. Consequence for the "Verified. Not claimed." attestation:
`_meta.execution.fuel_consumed` is a **platform-bound** quantity
(engine baseline = deterministic, but not transferable between
machines). Cost statements must reference the same platform;
cross-platform cost comparisons need a calibration per
platform (fuel baseline, as measured above). Open: an x86_64 Linux measurement
(CI runner) as a third reference.

### 5.4 Official MCP Inspector (conformance, macOS)

The **official** reference client of the spec organization
(`@modelcontextprotocol/inspector`, modelcontextprotocol.io/docs/tools/inspector)
was run against `ephemora-cell-mcp` (CLI mode, Node 22.23.1):

| Check | Result |
|---|---|
| `initialize` | ✅ `serverInfo: ephemora-cell-mcp 0.1.0`, `protocolVersion: 2025-06-18`, `capabilities.tools.listChanged` |
| `tools/list` | ✅ exactly 1 tool `echo` with `inputSchema` (JSON schema) |
| `tools/call echo` | ✅ `_meta.execution` complete (status success, fuel 21751, wasmtime 47.0.1, security_baseline) |
| unknown tool | ✅ JSON-RPC `-32602` ("unknown tool: nonexistent") — raw stdio proof |

**Note:** The Inspector displays the error code of an unknown tool as a
string (`tool_not_found`); the server's raw stdio response returns
JSON-RPC `-32602` correctly per the spec (2025-06-18, Error Handling). Documented
as "Verified. Not claimed."

### 5.5 Cross-platform suite + scale (DGX Spark)

**Test suite + build harness on DGX (Grace arm64):** 271 passed / 1 skipped
(macOS-only `-/private` symlink test, correctly not applicable on Linux) in
27.8 s; macOS: 272/272 — state of the joint run at that date; the suite
comprises 386 tests today. Containment mock run `docker_socket`:
control group (Docker only) block_rate **0.0** (ESCAPE), experimental
(Docker+Ephemora) block_rate **1.0** (BLOCKED) — Ephemora contribution +1.0.
Artifacts: `benchmarks/results/cross-platform-results.json`.

**Scale — 1000 parallel sandboxes on DGX (20 cores):**

| N | Wall time | Throughput | P50 | P95 | P99 | Errors |
|---|---|---|---|---|---|---|
| 100 | 0.98 s | 101.8 exec/s | 14.2 ms | 271 ms | 335 ms | 0 |
| 500 | 0.99 s | 503.1 exec/s | 7.4 ms | 47 ms | 278 ms | 0 |
| 1000 | 1.18 s | **845 exec/s** | 7.4 ms | 23 ms | 242 ms | 0 |

1700 calls, 0 errors, fuel deterministic per platform (2401–2560, spread only
from varying input lengths). P99 = multiprocessing spawn overhead of the
isolated mode; the persistent MCP channel reaches 0.89 ms/call (§2).
Artifacts: `benchmarks/results/scale-results.json`, `scale_dgx_{100,500,1000}.json`.

## 6. Research landscape (short form)

- **MCP-SandboxScan** (arXiv 2601.01241): execute untrusted MCP tools in a
  WASM/WASI sandbox and link external inputs with LLM sinks —
  static scanners miss runtime exfiltration. → Architecture confirmation
  for the Cell approach.
- **SandboxEscapeBench** (UK AISI + Oxford, ICML 2026, arXiv 2603.02277):
  frontier models reliably escape container sandboxes under realistic
  misconfigurations. → Argument against "Docker is enough".
- **AgentDojo** (ETH, arXiv 2406.13352): prompt injection cannot be solved
  by sandboxing — the sandbox is a necessary, not a sufficient condition.
- **"Breaking the Protocol"** (arXiv 2601.17549): MCP amplifies attack success
  by 23–41%; ATTESTMCP lowers ASR 52.8%→12.4% at 8.3 ms overhead.
  → per-call attestation is the market trend (Cell provides `_meta.execution`).

## 7. Sources

- Benchmarks: raw data under `benchmarks/results/`,
  integration tests: `integration/test_mcp_sdk_client.py`
- Cross-platform + scale: `benchmarks/results/cross-platform-results.json`,
  `benchmarks/results/scale-results.json`, `benchmarks/results/scale_dgx_*.json`
- MCP Inspector (official): https://modelcontextprotocol.io/docs/2026-07-28/tools/inspector ·
  https://github.com/modelcontextprotocol/inspector
- CVE-2025-53109: https://github.com/advisories/GHSA-q66q-fx2p-7w4m ·
  CVE-2025-53110: https://github.com/advisories/GHSA-hc55-p739-j48w
- Git server flaws: https://github.com/advisories/GHSA-j22h-9j4x-23w5,
  https://www.theregister.com/2026/01/20/anthropic_prompt_injection_flaws/
- Fetch SSRF: https://seclists.org/fulldisclosure/2026/May/22,
  https://github.com/modelcontextprotocol/servers/issues/4143
- SDK DNS rebinding: https://github.com/advisories/GHSA-w48q-cv73-mx4w,
  https://nvd.nist.gov/vuln/detail/CVE-2025-66416
- Playwright SSRF: https://github.com/microsoft/playwright-mcp/issues/1626
- Wassette: https://github.com/microsoft/wassette
- mcp.run: https://github.com/extism/extism · https://github.com/dylibso/mcp.run-servlets
- E2B: https://github.com/e2b-dev/e2b · https://e2b.dev/pricing ·
  https://github.com/e2b-dev/infra/issues/3012
- Docker MCP overhead: https://github.com/enkryptai/secure-mcp-gateway/blob/main/docs/sandbox_walkthrough.md
- Supply chain: https://snyk.io/blog/malicious-mcp-server-on-npm-postmark-mcp-harvests-emails/,
  https://www.heise.de/en/news/Supply-chain-worm-with-its-own-MCP-server-spreads-via-GitHub-11190731.html,
  https://www.ox.security/blog/shai-hulud-outbreak-debrief-the-worm-evolves-into-mcp/,
  https://blog.gitguardian.com/breaking-mcp-server-hosting/,
  https://github.com/modelcontextprotocol/registry/security/advisories/GHSA-2v5f-5r6w-p67r,
  https://securelist.com/model-context-protocol-for-ai-integration-abused-in-supply-chain-attacks/117473/
- SandboxEscapeBench: https://arxiv.org/abs/2603.02277 ·
  MCP-SandboxScan: https://arxiv.org/abs/2601.01241 ·
  AgentDojo: https://arxiv.org/abs/2406.13352 ·
  Breaking the Protocol: https://arxiv.org/abs/2601.17549

**Deliberately NOT used** (not verifiable, despite search results):
CVE-2025-52185, GHSA-2wqr-h6r2-7m7g, GHSA-5226-3rvg-hp4x,
GHSA-8qf9-62x2-82pp, CVE-2026-4270, "StargateVoyager" (CVE-2025-4237 is
a PCMan FTP bug, no MCP relation).
