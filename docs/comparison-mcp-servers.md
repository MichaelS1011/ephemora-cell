# ephemora-cell-mcp vs. the MCP server market

> As of: 2026-08-20 (benchmark snapshot §2) · refreshed 2026-09-18:
> headline latency from the 2026-09-14 measured run (§2a), MCP CVE replay
> evidence added (§5.1), Wassette status re-verified against its README ·
> re-counted against primary sources 2026-10-03: mcp.run/turboMCP, E2B,
> Wassette, the MCP spec + registry posture and a new head-to-head section on
> `astrid-runtime/astrid` (§4.3); §4.1's framing corrected the same day.
> **The §2 table remains a dated 2026-08-20 snapshot — it was not re-run on
> 2026-10-03**, and its measured values are unchanged; only the Wassette
> footnote carries the new date.
> Methodology: local measurements on this machine (Section 2)
> + cited external sources (Section 3), each external status re-checked at the
> date stated next to it. "Verified. Not claimed." — every number
> comes from a real run or a source URL.

## 1. Key takeaway

`ephemora-cell-mcp` runs tools as **WASM modules inside a Wasmtime
sandbox** (no host FS, no env, no network, fuel metering, 10 KB output
cap) instead of in-process with full user privileges — at
**~0.5 ms pooled warm execution / ~12 ms per stdio
`tools/call`** (2026-09-14, `measured:true`,
[`benchmarks/results/2026-09-14/`](../benchmarks/results/2026-09-14/); the
one-time 2026-08-20 snapshot in §2 measured 0.89 ms on a persistent channel)
with a small footprint (52 MB RSS, 1 runtime dependency).

Against the market's real incidents this is now measured, not argued: the
[MCP CVE replay harness](../benchmarks/mcp_cve_replay.py) (2026-09-17) replays
CVE-2025-53109/53110 ("EscapeRoute") and the CVE-2025-54136 class against the
pinned vulnerable reference server and this sandbox — reference leaks, Cell
blocks at the engine level, manifest swap fails closed (§5.1).

The price of isolation is measurable: an *unsecured* in-process tool is
~13× faster (0.07 ms) — but it reads `/etc/passwd`, sees the
environment, and can do anything the host user may do.

Positioning against the closest comparable sandbox, `astrid-runtime/astrid`
(counted 2026-10-03), is laid out axis by axis in §4.3. On evidence the field has
narrowed: astrid keeps a signed, hash-chained audit history, and the unreleased
1.1 line now matches that axis with `LedgerEntry` (ADR-011) — a default-off,
host-side chain — plus tenant-level cumulative budgets (ADR-012) and enforced,
revocable egress grants (ADR-013). Cell still keeps two axes astrid does not:
WASI Preview1 guests and a per-call cost receipt returned to the caller.

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
| `@modelcontextprotocol/server-filesystem` | 70.2 | 0.32 | 75.5 | 30.32 | 52 package dirs measured 2026-09-18 (pinned v2025.3.28; earlier "118" counted an unpinned install) | **none** (directory allowlist only) |
| Docker wrapper (external evidence) | — | +490 ms per call³ | — | — | Docker | Container (breakout-capable, see below) |
| Microsoft Wassette | —⁵ | —⁵ | —⁵ | —⁵ | —⁵ | Wasmtime WASI-0.2 component sandbox + per-component permission grants (network/storage/env), OCI component distribution; no metering and no resource limits as of v0.8.0 (limits listed as future work, 2026-10-03)⁵ |

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
(re-verified 2026-10-03, first retrieved 2026-09-05): v0.8.0 published
2026-09-29, 956 stars, MIT, Rust on Wasmtime components / WASI 0.2 (wasip2),
deny-by-default, components pulled as OCI artifacts from registries (e.g.
`oci://ghcr.io/microsoft/time-server-js`). Differences that matter for agents:
Cell meters every call (fuel) and attaches an execution witness to each
response (`_meta.execution`, determinism and CI-verified SDK interop above),
while Wassette's OCI pull model moves the trust decision to install time.
Status 2026-10-03: `docs/concepts.md` lists "Resource Limits (Future)" —
maximum memory allocation, CPU time limits and maximum execution time are
planned for future versions, so as of this date Wassette has **no metering and
no per-call evidence**. Its README banner still reads, verbatim, "Early
Development: This repository is not production ready yet.", while `docs/faq.md`
says elsewhere that the project is "actively developed and used by Microsoft" —
a contradiction inside the project's own documentation, noted as such.

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
| Official servers (filesystem/fetch/git) | in-process, full rights | Node/Python — `modelcontextprotocol/servers` is still active (90 978 stars, release 2026.8.31, re-verified 2026-10-03); filesystem/git/fetch live in `src/` and are **not** archived (`servers-archived` is) | MIT, OSS | CVE-2025-53109 + CVE-2025-53110 (filesystem, symlink/prefix bypass, HIGH); CVE-2025-68143/44/45 (git → RCE chain via smudge/clean filters); CVE-2026-27735 / GHSA-vjqx-cfc4-9h6v (git, medium, "Path traversal in git_add", affects mcp-server-git < 2026.1.14, patched in 2026.1.14); fetch SSRF unpatched in PyPI (2026-06) |
| Playwright MCP | in-process + browser subprocess | Node | MIT, OSS | SSRF/cloud metadata (Issue #1626) |
| Microsoft Wassette | **WASM** (Wasmtime components / WASI 0.2 wasip2, deny-by-default) | Rust, OCI components, v0.8.0 published 2026-09-29, 956 stars | MIT, OSS | no incidents found; README banner "Early Development: This repository is not production ready yet." vs. `docs/faq.md` "actively developed and used by Microsoft" (re-verified 2026-10-03) — the project contradicts itself; no metering, no per-call evidence: `docs/concepts.md` lists memory/CPU/execution limits as "Resource Limits (Future)" |
| astrid-runtime/astrid | **WASM** (Wasmtime capsules, components only: "with no syscalls, no file descriptors, and no host memory"; every side effect is a capability-checked host call over a WIT-typed ABI) | Rust, 10 279 stars, 889 PRs, repo created 2026-02-15, release v2026.9.4 (2026-09-20), last push 2026-10-03 | Dual **MIT OR Apache-2.0** ("at your option"), copyright "Joshua J. Bouw and Unicity Labs" | none found (checked 2026-10-03); ships a signed, hash-chained per-principal audit chain — the evidence axis that §4.1 used to ignore, see §4.3 |
| mcp.run → turboMCP / Extism | WASM (host grants, fuel) | Extism runtime 5 784 stars, maintained, v1.30.0 (2026-06-04), "Upgrade to Wasmtime 48 (LTS)" committed 2026-09-02; `https://mcp.run` answers HTTP/2 301 with `location: https://turbomcp.ai/` (checked with `curl -sIL` 2026-10-03); `registry.mcp.run` and `docs.mcp.run` no longer resolve; `dylibso/mcp.run-servlets` is archived (last push 2025-11-20) | BSD-3-Clause (framework); platform commercial — turbomcp.ai positions itself as a "self-hosted MCP gateway and management platform" (trusted registry, DLP, kill-switch) | no registry incident found; no signature verification in base Extism — the manifest carries an optional sha256 hash field and a memory limit in pages, but no cryptographic signature |
| E2B | Cloud microVM (Firecracker) | Go/Rust; SDK release e2b@2.52.0 (2026-10-01); `e2b-dev/mcp-server` **archived 2026-04-16** with banner "Deprecated: This project is no longer actively maintained." | Apache-2.0, self-hostable | no incidents found; billing per second: $0.000014 / vCPU-s and $0.0000045 / GiB-s, $0 monthly plan fee; docs give runtime ceilings only ("up to 24 hours (Pro) or 1 hour (Base)") and no start latency — the ~1 s figure at 100 concurrent sandboxes is a **community measurement** (e2b-dev/infra#3012, 2026-06-15, row ``100 \| 1063.110 ms \| 46.270 ms``), not a vendor number |
| Cloudflare Code Mode | "Dynamic Worker isolate — a lightweight V8 sandbox": "no file system, no environment variables … external fetches disabled by default" | JavaScript executed as code, **not** WASM, no fuel concept; repo `cloudflare/code-mode` returns 404 (2026-10-03) | platform commercial; no license verified (repo probe 404) | none found; documentation (2026-06-24) labels the feature "experimental and may introduce breaking changes" |
| Datadog code execution (MCP server) | "a Datadog-managed sandbox" | "lets your AI agent write and run JavaScript against Datadog APIs in a single MCP tool call" (`docs.datadoghq.com/mcp_server/code_execution`, 2026-10-03); repo `DataDog/mcp-code-mode` returns 404 | Commercial SaaS | none found |
| Modal | gVisor, optional own VM | Vendor claims "Sub-second scheduling" and "tested Sandbox creation throughput up to 1,000 Sandboxes per second"; billing per second; no own MCP server verified (2026-10-03) | Commercial | none found |
| Runloop / Vercel Sandbox | VM devboxes / Firecracker microVM per sandbox | Runloop: "startup to running your first command takes a few seconds"; Vercel Sandbox docs (2026-09-22): "Sandboxes start in milliseconds" | Commercial | none found |
| Daytona | Cloud dev environment | Repo `daytonaio/daytona` **archived 2026-10-03**; last release v0.190.0 (2026-06-23); the documentation still claims "spinning up in under 90ms from code to execution" and does not mention the archiving | AGPL-3.0 | none found; status mismatch between repo and docs noted |
| Docker/Codex sandbox | Container/namespace | Docker MCP Gateway "runs MCP servers in isolated Docker containers with restricted privileges, network access, and resource usage"; "MCP Gateway as part of Docker AI Governance is an invite-only feature" (docs.docker.com, 2026-10-03). bubblewrap and seccomp on the Codex path | OSS (Codex); Docker licensing per edition | escape class evidenced (SandboxEscapeBench, arXiv 2603.02277 — see §6 for the measured rates); +490 ms per call is a third-party measurement (§2 note 3) |
| MCP protocol + registry (2026-07-28 era) | n/a — protocol layer, no execution | Current specification is 2026-07-28. Security best practices tell clients to "Execute MCP server commands in a sandboxed environment with minimal default privileges", while the spec itself states "While MCP itself cannot enforce these security principles at the protocol level". Registry repo active (push 2026-09-30, release v1.8.1 2026-08-06): ownership markers only, **no signature verification**. `schema.json` (155 `$defs`) defines **no attestation or signature field and no CPU/memory budget declaration**; `_meta` on results is self-reported, "not verified by the protocol", and callers "SHOULD NOT rely on them for security decisions" (all 2026-10-03) | OSS (specific license terms not re-verified 2026-10-03) | CVE-2026-45781 / GHSA-2v5f-5r6w-p67r ("MCP Registry: OCI validator skips ownership check on upstream rate limits", Low 3.5) — **patched in 1.7.9 (2026-05-12)**, not open; four further May-2026 advisories patched (CVE-2026-44430 SSRF, CVE-2026-44429 stored XSS, CVE-2026-44427 open redirect, CVE-2026-44428 OIDC replay) |
| npx/uvx category ("installation = execution") | in-process, unpinned | npm/PyPI | n/a | postmark-mcp (typosquat), SANDWORM_MODE (worm), Shai-Hulud/"V.A.P.E." (first registry incident), Smithery breach (3,000 servers); registry CVE-2026-45781 patched (row above) |

**What changed since 2026-09-18 (primary sources opened 2026-10-03):**

- **mcp.run is no longer reachable as a product surface.** `https://mcp.run`
  returns HTTP/2 301 with `location: https://turbomcp.ai/`; `registry.mcp.run`
  and `docs.mcp.run` do not resolve. The servlets repo is archived (last push
  2025-11-20). Extism itself is alive and maintained — the framework row stays
  valid, the platform row does not.
- **E2B's MCP server is unmaintained; the SDK is active.** `e2b-dev/mcp-server`
  archived 2026-04-16; e2b@2.52.0 shipped 2026-10-01. Earlier revisions of this
  document quoted a startup degradation (~100 ms → ~1 s) without labelling its
  source; E2B's current docs publish runtime ceilings only, so the figure is now
  marked as what it is — a community measurement from issue #3012.
- **Wassette has a release line (v0.8.0, 2026-09-29) but no metering**;
  resource limits are future work, and the README/FAQ statements about
  production readiness contradict each other.
- **astrid-runtime/astrid is new to this table** and is the reason §4.1's
  framing was too broad — see §4.3.
- **Daytona's repo was archived on 2026-10-03** while its docs still carry the
  "under 90ms" claim.
- **No new supply-chain incident is asserted here.** A further sweep on
  2026-10-03 (six searches) found no MCP-related supply-chain incident with a
  verifiable primary source dated after 2026-09-18 — none verifiable in this
  window. The incidents in the rows above are the ones already sourced in §7.

**Vendor guidance for running MCP servers (quoted, third-party statements,
retrieved 2026-10-03):**

- **Anthropic, Claude Code sandboxing docs:** uses macOS Seatbelt on macOS and
  Linux bubblewrap; "The sandbox is off by default"; "The sandbox covers shell
  commands only"; "Claude's file tools, MCP servers, and hooks run outside it";
  on native Windows commands execute unsandboxed; the built-in proxy neither
  terminates nor inspects TLS.
- **OpenAI, Codex:** an "OS-enforced sandbox", default with no network and
  writes limited to the workspace; the docs warn that prompt injection makes the
  agent follow untrusted instructions and that devcontainers "do not prevent
  every attack".
- Both describe the boundary as opt-in and partial (shell commands, or writes
  and network only) rather than as the default execution path for tools — and
  neither documents a per-call cost receipt; not verified beyond the quoted
  pages.

## 4. Positioning of ephemora-cell-mcp

**What it brings (only what is evidenced):**

1. **Isolation is the default architecture, not a feature flag.** The guest never
   sees host FS/env/network — this is not configurable but rather the
   sandbox intervention. (Benchmark agent: the naive counter-probe reads `/etc/passwd`.)
   The same replay runs against WASI 0.2 components: symlink/traversal denial plus
   call-time socket denial are measured on the component path, not assumed.
2. **Measured install footprint:** 1 runtime dep (wasmtime),
   ~24 MB installed, no Node and no npm transitive tree (server-filesystem:
   52 package dirs / 22.2 MB measured 2026-09-18, pinned v2025.3.28 — see
   §4.2), no npx execution of unpinned code.
3. **Per-call cost receipt AND a cross-run history — two evidence axes:** every
   call carries `_meta.execution` (fuel_consumed, elapsed_ms, wasmtime_version) —
   deterministic fuel metering (spread 0). The §4.1 measurement records, for every
   candidate in the set, which response fields a caller receives.
   Updated 2026-10-04: the 1.1.0 line (cut 2026-10-04, not yet published on PyPI) closes the second axis too —
   `LedgerEntry` (ADR-011) hash-links records across runs (default-off, host-side,
   linkage verifiable without a key), so Cell matches astrid's signed-history
   property on that axis rather than stopping at per-call. The receipt is also
   self-reported `_meta` on a result: the 2026-07-28 schema has no
   attestation/signature field and no CPU- or memory-budget declaration, and the
   spec says such values are "not verified by the protocol" and that callers
   "SHOULD NOT rely on them for security decisions". Cell answers that caveat
   rather than ignoring it: with `--receipt-signing-key` each receipt carries a
   DSSE signature (`_meta.attestation`) over the same canonical bytes, verifiable
   out-of-band by the caller with the operator's public key — so the receipt
   stops being merely self-reported.
4. **Local and offline:** no cloud round trip, no registry requirement, no
   microVM latency (E2B: network round trip; its current docs publish runtime
   ceilings, not start latency — the ~1 s at 100 concurrent is a community
   measurement, §3), no container latency (Docker wrapper: +490 ms, a
   third-party figure from EnkryptAI's walkthrough, not a Docker value).
5. **A Wassette parallel, with a production-ready core:** the same
   WASM deny-by-default philosophy (Wasmtime), but Cell ships 901 CI-enforced
   tests (4 skipped) with security gates (pip-audit, SBOM, bandit) and an
   active release line; Wassette itself declares itself "not production ready".
   Status 2026-10-03: Wassette v0.8.0 lists memory, CPU-time and execution-time
   limits as future work (`docs/concepts.md`), so it has neither metering nor
   per-call evidence today (§2 footnote 5).

**Honest limitations (not hidden):**

- **No network in the sandbox guest** — tools like `fetch` (HTTP) deliberately
  do not exist. Web research tools require a host-side gateway with an
  allowlist (the mcp.run platform model; that platform now redirects to
  turboMCP, see §3).
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
- **No evidence history:** the per-call receipt is not hash-linked to the
  previous one, so dropping or reordering an accumulated log of receipts is not
  detectable from Cell's own output. astrid has that property and Cell does not
  (§4.3); it is also what the protocol layer does not provide — the 2026-07-28
  schema defines no attestation field (§3).
- **Reach:** astrid carries 10 279 stars against our 46 (both counted
  2026-10-03), with a company and a contributor base behind it. Stated plainly
  in §4.3, not argued away.

### 4.1 Per-call evidence, measured (2026-09-18; framing corrected 2026-10-03)

The same kind of call against every locally measurable candidate; the table
records what the caller actually receives. Evidence:
`benchmarks/results/2026-09-18/05_per_call_evidence.json` (`measured:true`),
repro: `python benchmarks/per_call_evidence.py`.

**The framing used until 2026-09-18 — "ask any sandbox vendor for per-call
signed evidence — most return an exit code" — no longer holds and is withdrawn.**
It measured one axis and spoke about the whole market. Sandbox evidence exists
on two distinct axes, and neither implies the other:

- **Per-call cost receipt (what this section measures):** what the caller
  gets back on each `tools/call` — Cell returns fuel consumed, elapsed time,
  memory, output bytes, warnings and the security baseline. Among the locally
  measurable candidates below, the container and subprocess rows do return only
  stdout and an exit code.
- **Evidence history (not measured here):** an append-only, tamper-evident
  record across calls. `astrid-runtime/astrid` operates a signed, hash-chained
  audit chain in which each entry seals the hash of its predecessor, held as
  JSONL per principal and independently verifiable (verified 2026-10-03, §4.3).
  Cell ships no equivalent chain, and the 2026-07-28 protocol defines no field
  for either axis (§3).

The correct short sentence is therefore: *the locally measurable non-Cell
candidates return exit codes rather than receipts, and astrid returns no
per-call receipt to the caller either — it keeps a signed history instead.*

| Candidate (call) | Caller receives | Execution receipt |
|---|---|---|
| **ephemora-cell-mcp** (`echo`) | text content **+ `_meta.execution`** | **YES** — fuel consumed/budget, memory, output bytes, warnings, security baseline (wasmtime version, limits, preopens); RFC 8785-canonicalizable, sign-ready |
| **ephemora-cell-mcp** (`get-policy`) | policy report | **YES** — computed by the same code path that enforces it |
| `server-filesystem@2025.3.28` (`read_file`) | file text | no — content only |
| `docker run` (stock container) | stdout + exit code | no |
| plain subprocess | stdout + exit code | no |

Candidates without a local install path (E2B cloud, the former mcp.run
platform, Wassette binary, astrid) remain literature rows in §3 — they are not
measured here and never presented as if they were. The gap runs both ways, and
for astrid it is documented on the record (2026-10-03): it has **no WASI
Preview1 core-module support** — code search `repo:astrid-runtime/astrid` for
`wasi_snapshot_preview1` returns 0 hits, `preview1` 1 hit — and **no embedding
path without its own install/mount story** (no `pip` path; filesystem access via
macOS FSKit or Linux FUSE). §4.3 lays this out axis by axis.

### 4.2 Attack surface, measured (2026-09-18)

What actually lands on the machine when a user installs a candidate.
Evidence: `benchmarks/results/2026-09-18/06_attack_surface_audit.json`
(`measured:true`), repro: `python benchmarks/attack_surface_audit.py`.
Version + date per row; re-run before citing.

| Candidate | Install footprint (measured) | Repro |
|---|---|---|
| ephemora-cell (PyPI, fresh venv) | **2 distributions** (package + its single dep `wasmtime`), 36.2 MB site-packages | `python3 -m venv v && v/bin/pip install ephemora-cell` |
| server-filesystem@2025.3.28 (npm) | **52 package dirs**, 22.2 MB node_modules | `npm install @modelcontextprotocol/server-filesystem@2025.3.28` |
| python:3.12-slim (image) | 46.8 MB uncompressed, digest in evidence | `docker pull python:3.12-slim` |
| node:24-alpine (image) | 58.9 MB uncompressed, digest in evidence | `docker pull node:24-alpine` |

> The earlier "118 npm packages" figure counted an unpinned install of the
> filesystem server; the pinned 2025.3.28 measures 52. Both are historical —
> the current measurement is the table above.

### 4.3 Head-to-head: astrid-runtime/astrid (verified 2026-10-03)

Added 2026-10-03. `astrid-runtime/astrid` ships an evidence mechanism of its own,
which is exactly why the §4.1 framing had to be corrected. Its README states the
thesis as: "Agent frameworks put trust in the prompt. Astrid puts it in the
runtime." Capsules run in Wasmtime "with no syscalls, no file descriptors, and no
host memory", and every side effect is a capability-checked host call over a
WIT-typed ABI. Nothing in this section was run locally — the astrid column quotes
its repository, docs and source files as of 2026-10-03; the Cell column refers to
the measurements in §2, §4.1, §4.2 and §5.

| Axis | astrid-runtime/astrid (2026-10-03) | ephemora-cell-mcp |
|---|---|---|
| Engine | Wasmtime, component model only; capsules with "no syscalls, no file descriptors, and no host memory" | Wasmtime 47.0.1 (pip wheel); a fresh engine per `tools/call` on the shipped stdio path (ADR-002), pooled warm runs on the benchmark path (§2) |
| WASI surface — Preview1? | **No.** Components only: code search `repo:astrid-runtime/astrid` for `wasi_snapshot_preview1` = 0 hits, `preview1` = 1 hit | **Yes.** `wasi_snapshot_preview1` core modules are the primary surface (`docs/languages.md`), with WASI 0.2 components on the same baseline (§4 item 1) |
| CPU cap | Fuel ledger exists — `astrid-capsule-types/src/fuel_ledger.rs`, header verbatim: "Accumulates the wasmtime fuel (exact deterministic guest-instruction count) each principal burns inside pooled interceptor calls … summed cross-capsule into one per-principal total". The same module comment says "Scope today: TELEMETRY. charge() is the only mutator and there is no read/deny path yet … The run-loop CPU bound remains enforced separately by the epoch-interrupt mechanism", while `changes/1992.added.md` documents a `--cpu-rate` quota that sets `max_cpu_fuel_per_sec`. Presented as it is documented: the ledger is evidenced, enforcement is documented inconsistently | `max_fuel` per call, enforced: `fuel_exhausted` measured on the `busy` guest, memory limit measured at 1537 pages (96 MB) (§5.2), count deterministic with spread 0 (§2) |
| Multi-tenancy | Per-principal isolation of KV, secrets, home directory, quotas and audit chain; live capsule lifecycle without a restart; bundled MCP gateways whose lifetime is coupled to the client connection | No per-principal isolation and no cross-call guest state: one session, a new sandbox per call. The 1.1.0 line (not yet published on PyPI) adds **attribution, not isolation** — a tenant is a billing/aggregation identity with cumulative cross-run caps (ADR-012), charged in `WASISandbox.run`; the MCP server supplies no tenant identity (source is operator policy), so aggregation is operator-labelled, not platform per-principal |
| Network model | Host calls only. File paths, network hosts and tools are signed ed25519 grants — principal-bound, time-limited, globally revocable (documented, not run locally here) | No network in the guest (call-time socket denial measured, §4 item 1). Egress is host-mediated after the run (`--egress-allow`), allowlist + redirect/resolve-time SSRF revalidation; the 1.1.0 line (cut 2026-10-04, not yet published on PyPI) adds per-tool **signed-grant envelopes** whose time-limit, usage cap and revocation are enforced by a `GrantLedger` (ADR-013, fail-closed) — matching astrid's grant SHAPE on the local build path, and the grant is now AUTHENTICATED on load — a DSSE envelope signed by a key in an operator trust root kept outside the grants directory (`grant_trust.py`, ADR-013) — while revocation stays per next-call, not in-flight |
| Evidence: per call vs. history | **History:** signed, hash-chained audit chain — every entry seals the hash of its predecessor, JSONL, one chain per principal, independently verifiable. **Per call:** no instruction or cost figure returned to the caller, consistent with the ledger's documented "no read/deny path yet" | **Per call:** `_meta.execution` cost receipt on every response, RFC 8785-canonicalizable and sign-ready (§4.1). **History:** none in the released 1.0.5 — receipts are not hash-linked there, so reordering or dropping them is not detectable from Cell's own output. The 1.1.0 line (not yet published on PyPI) adds `LedgerEntry` (ADR-011): a signed JSONL chain over both records of every run, linkage verifiable without a key |
| Embedding / footprint | `brew install astrid` or `cargo install` (Rust 1.95+); filesystem access mounts through macOS FSKit (macOS 26+, signed app plus extension approval) or Linux FUSE; Windows is tested in CI but explicitly absent from the release archives. No footprint measured here | `pip install ephemora-cell`: 2 distributions, 36.2 MB site-packages, 52.3 MB peak RSS, importable as a library (§2, §4.2); no daemon, no FUSE/FSKit mount and no Node in the documented install path |
| Maturity / reach | 10 279 stars, 141 forks, 25 watchers, 240 open issues, 889 PRs; repo created 2026-02-15, org `astrid-runtime` since 2026-07-10, last push 2026-10-03; release v2026.9.4 (2026-09-20); primary author Joshua J. Bouw with 698 of roughly 735 commits, company @unicitynetwork ("Unicity Labs": org since 2024-10, 80 public repos, 23 253 followers) | 46 stars (2026-10-03); release line 1.0.5 in `pyproject.toml`, `serverInfo` 0.1.0 in the dated §2 and §5.4 runs; suite measured 2026-10-04: 808 collected / 804 passing / 4 skipped |
| License | Dual "MIT OR Apache-2.0" ("at your option"), copyright "Joshua J. Bouw and Unicity Labs" | BUSL-1.1 (`LICENSE`), source-available rather than OSI-open, change date four years per version |

**Where astrid is ahead.** It is a multi-principal platform: aggregation and
quotas are per principal, isolated KV/secrets/home, and a live capsule lifecycle
without a restart — Cell's new tenant budgets are per-run attribution charged at
the library/CLI layer with no platform identity source, and its engine rebuilds
per call. Its signed grants are also a shipped, globally-revocable capability
bound to a principal; Cell's 1.1 grant enforces the same fields (time, cap,
revocation) on the host build path but does not yet verify the grant signature on
load, and its revocation is per next mediated call rather than in-flight. Both
edges are reach and productisation, not missing capability on the axes Cell has
now built.

**Where Cell is structurally not copyable by astrid.** Preview1 core modules:
astrid is components-only, so a Preview1 guest has no execution path there — that
includes this project's AOT tier (Rust, Go, C, AssemblyScript, Zig per
`docs/languages.md`) and the pinned CPython-WASI guest (`wasi-python 3.10`,
`interpreter` profile, same document). Embedding: Cell is a `pip` install and an
import with no daemon and no FUSE or FSKit mount in the documented install path
(§4.2), whereas astrid's documented install is `brew`/`cargo` plus a mounted
filesystem. Per-call cost receipt to the caller: astrid's ledger is documented as
telemetry-scope with no read path yet, so no per-call instruction count leaves
the runtime, while Cell attaches one to every response. These are non-overlapping
axes, not a ranking. With the 1.1.0 line (cut 2026-10-04, not yet published on PyPI) the previously one-sided axes
also narrow: Cell now hash-links its evidence across runs (ADR-011), aggregates
consumption per tenant with cumulative caps (ADR-012), and enforces egress as a
time-limited, usage-capped, revocable grant (ADR-013) — closing the "astrid has
it, Cell does not" gaps on those three axes rather than extending the copyable-
no axes above.

**Reach, stated honestly.** astrid has 10 279 stars against our 46 (both counted
2026-10-03), 889 pull requests, and a named commercial copyright holder
("Joshua J. Bouw and Unicity Labs"; the author's profile lists @unicitynetwork,
an org since 2024-10 with 80 public repos and 23 253 followers). One observation
about its numbers, offered as an observation and not as evidence: its
star-to-watcher ratio is flat at 10 279 : 25. The star history was not
retrievable through the API during this check, so nothing here claims how those
stars accumulated.

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
OS-sensitive. Reproduction: [`benchmarks/mcp_cve_replay.py`](../benchmarks/mcp_cve_replay.py) — a deterministic harness that pins the vulnerable server version, replays both attack paths via a real MCP stdio client against the same fixtures, and runs positive controls on both sides. Live re-run 2026-09-17 (`benchmarks/results/2026-09-17/mcp_cve_replay.json`, `measured:true`): the vulnerable reference leaked both intents (symlink and prefix), the Cell engine blocked all of them (ENOTCAPABLE/EPERM at the engine level) with the granted-capability control succeeding.

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

**Status today (2026-10-03) — added without rewriting the dated run above:** the
table records the 2026-08-20 observation, `protocolVersion: 2025-06-18`, and
stays as it was measured. The server itself now negotiates the 2026-07-28 era:
`MODERN_PROTOCOL_VERSION = "2026-07-28"` in
[`ephemora_cell_mcp/protocol.py:27`](../ephemora_cell_mcp/protocol.py), with
`2025-06-18`, `2025-03-26` and `2024-11-05` retained as the legacy set for the
initialize handshake. A re-run of the Inspector against the current build is
open — not verified here.

### 5.5 Cross-platform suite + scale (DGX Spark)

**Test suite + build harness on DGX (Grace arm64):** 271 passed / 1 skipped
(macOS-only `-/private` symlink test, correctly not applicable on Linux) in
27.8 s; macOS: 272/272 — state of the joint run at that date; the suite
comprises 905 collected tests today (measured 2026-10-05) — 901 passing (4 skipped)
against `pytest --collect-only`. Containment mock run `docker_socket`:
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
- **SandboxEscapeBench** (UK AISI + Oxford, ICML 2026, arXiv 2603.02277, v3
  2026-08-01): 18 scenarios across three container-isolation layers, 803
  samples. Measured escape rates: 0.50 (GPT-5), 0.27 (GPT-5.2), 0.49
  (Claude Opus 4.5); the paper states "we observe zero success on levels 4 and
  5". gVisor is described but not evaluated. → An argument against "Docker is
  enough" *at the easier levels*; the one-line summary used in earlier
  revisions of this document ("frontier models reliably escape") overstated it,
  corrected 2026-10-03.
- **Kernel-primitive comparison** (arXiv 2606.08433v1): arrakis, e2b,
  microsandbox, gVisor and Daytona compared across 14 kernel primitives —
  "runc accumulated 4 Escape-class vulnerabilities whereas gVisor had none"
  over 24 months.
- **AgentDojo** (ETH, arXiv 2406.13352): prompt injection cannot be solved
  by sandboxing — the sandbox is a necessary, not a sufficient condition.
  The vendor guidance quoted in §3 says the same thing in product terms
  (OpenAI on prompt injection, Anthropic on what the sandbox does not cover).
- **"Breaking the Protocol"** (arXiv 2601.17549): MCP amplifies attack success
  by 23–41%; ATTESTMCP lowers ASR 52.8%→12.4% at 8.3 ms overhead.
  → per-call attestation is a research direction, not a protocol feature: the
  2026-07-28 schema defines no attestation or signature field (§3), so Cell's
  `_meta.execution` receipt is application-level and self-reported.

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
- Wassette: https://github.com/microsoft/wassette (v0.8.0, README banner,
  `docs/faq.md`, `docs/concepts.md` — all re-read 2026-10-03)
- astrid: https://github.com/astrid-runtime/astrid (README, `fuel_ledger.rs`,
  `changes/1992.added.md`, repository metadata and code search — 2026-10-03) ·
  https://github.com/unicitynetwork
- mcp.run / turboMCP: https://mcp.run (HTTP/2 301 → https://turbomcp.ai/,
  `curl -sIL`, 2026-10-03) · https://turbomcp.ai/ ·
  https://github.com/extism/extism (5 784 stars, v1.30.0 2026-06-04) ·
  https://github.com/dylibso/mcp.run-servlets (archived, last push 2025-11-20)
- E2B: https://github.com/e2b-dev/e2b · https://e2b.dev/pricing ·
  https://github.com/e2b-dev/mcp-server (archived 2026-04-16) ·
  https://github.com/e2b-dev/infra/issues/3012 (community measurement,
  2026-06-15 — not a vendor figure)
- Cloudflare Code Mode docs (2026-06-24, "experimental") — repo probe
  `cloudflare/code-mode` returned 404 on 2026-10-03 · Datadog:
  https://docs.datadoghq.com/mcp_server/code_execution — repo probe
  `DataDog/mcp-code-mode` returned 404 on 2026-10-03
- Modal, Runloop and Vercel Sandbox: vendor documentation and pricing pages as
  quoted in §3 (Vercel Sandbox docs dated 2026-09-22), retrieved 2026-10-03 ·
  Daytona: https://github.com/daytonaio/daytona (archived 2026-10-03)
- Docker MCP Gateway: docs.docker.com (MCP Gateway / Docker AI Governance,
  invite-only statement, retrieved 2026-10-03)
- Docker MCP overhead: https://github.com/enkryptai/secure-mcp-gateway/blob/main/docs/sandbox_walkthrough.md
  (third-party +490 ms figure — EnkryptAI's own "Which Sandbox Should You Pick?"
  table, not a Docker-published value)
- Vendor guidance: Anthropic Claude Code sandboxing documentation and OpenAI
  Codex sandbox documentation, both quoted verbatim in §3 (retrieved
  2026-10-03; page URLs not pinned in this document)
- MCP protocol + registry: specification 2026-07-28 (Security Best Practices,
  `schema.json` with 155 `$defs`, `_meta` guidance) ·
  https://github.com/modelcontextprotocol/registry (v1.8.1, push 2026-09-30) ·
  https://github.com/modelcontextprotocol/servers (90 978 stars, release
  2026.8.31) and `servers-archived` ·
  https://github.com/advisories/GHSA-vjqx-cfc4-9h6v (CVE-2026-27735, git
  path traversal) · four May-2026 registry advisories
  CVE-2026-44430/-44429/-44428/-44427 · GHSA-2v5f-5r6w-p67r (CVE-2026-45781,
  patched in 1.7.9)
- Motivational (measured:false): SABER / SandboxEscapeBench
  https://arxiv.org/abs/2603.02277 + https://www.aisi.gov.uk/blog/can-ai-agents-escape-their-sandboxes-a-benchmark-for-safely-measuring-container-breakout-capabilities;
  Trail of Bits skill-scanner bypasses (Judson & Hess, 2026) via
  https://tldrsec.com (2026-06-04 issue)
- 2026 probe classes: https://github.com/bytecodealliance/wasmtime/security/advisories/GHSA-vqjp-4c8c-hfgg
  (FS escape companions, CVE-2026-47261),
  https://www.ox.security/blog/cve-2026-82533-deepseek-harness-ai-agent-sandbox-escape
  (supervisor control-plane reachability),
  https://arxiv.org/abs/2603.22489 (Securing the MCP: A Dual-Axis Survey —
  tool poisoning, handoff erosion)
- Supply chain: https://snyk.io/blog/malicious-mcp-server-on-npm-postmark-mcp-harvests-emails/,
  https://www.heise.de/en/news/Supply-chain-worm-with-its-own-MCP-server-spreads-via-GitHub-11190731.html,
  https://www.ox.security/blog/shai-hulud-outbreak-debrief-the-worm-evolves-into-mcp/,
  https://blog.gitguardian.com/breaking-mcp-server-hosting/,
  https://github.com/modelcontextprotocol/registry/security/advisories/GHSA-2v5f-5r6w-p67r,
  https://securelist.com/model-context-protocol-for-ai-integration-abused-in-supply-chain-attacks/117473/
- SandboxEscapeBench: https://arxiv.org/abs/2603.02277 ·
  MCP-SandboxScan: https://arxiv.org/abs/2601.01241 ·
  AgentDojo: https://arxiv.org/abs/2406.13352 ·
  Breaking the Protocol: https://arxiv.org/abs/2601.17549 ·
  kernel-primitive comparison: https://arxiv.org/abs/2606.08433

**Deliberately NOT used** (not verifiable, despite search results):
CVE-2025-52185, GHSA-2wqr-h6r2-7m7g, GHSA-5226-3rvg-hp4x,
GHSA-8qf9-62x2-82pp, CVE-2026-4270, "StargateVoyager" (CVE-2025-4237 is
a PCMan FTP bug, no MCP relation).

**Not available as of 2026-10-03, and therefore not claimed anywhere above:**
astrid's star history (not retrievable through the API — §4.3 gives the
snapshot counts and the flat star-to-watcher ratio as an observation only, no
adoption trend for any candidate); any MCP supply-chain incident with a
verifiable primary source dated after 2026-09-18 (six searches, none verifiable
in this window); a current Inspector run against the 2026-07-28 negotiation
(§5.4 stays the dated 2026-08-20 record); any footprint number for astrid,
E2B, Wassette or turboMCP — those rows are literature, not measurement.
