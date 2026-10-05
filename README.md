# Ephemora-cell

**Ephemora-cell is an ephemeral, stateless, capability-bound execution boundary for untrusted AI and agent-generated code.**

```text
create → constrain → execute → prove → destroy
```

Every execution starts from a clean state, runs under limits the host granted — fuel, memory, time, I/O, output size, filesystem and network capability — can produce signed evidence of what happened, and ends without carrying execution state into the next run.

> **The evidence persists. The execution state does not.**

**Ephemeral. Stateless. Capability-bound. Verifiable.**

No execution state or authority is inherited implicitly. Named state is a separate, bounded capability the host wires in on purpose — not execution persistence, and not storage ([Stateless by construction](#stateless-by-construction)).

Built for **AI agents, MCP tools, plugins, code interpreters, and other untrusted workloads** — the integration path is `AI Agent / Application → Tool / Plugin / MCP → Ephemora-cell → WASM module`. The picture below draws one execution of it: what the boundary grants, what it denies by default, and what survives.

<p align="center">
  <a href="https://pypi.org/project/ephemora-cell/"><img src="https://img.shields.io/pypi/v/ephemora-cell" alt="PyPI"></a>
  <a href="https://www.python.org/downloads/"><img src="https://img.shields.io/badge/python-3.10%2B-blue" alt="Python 3.10+"></a>
  <a href="LICENSE"><img src="https://img.shields.io/badge/license-BUSL--1.1-blue" alt="License: BUSL-1.1 (source-available; converts to Apache-2.0 four years after each release)"></a>
  <a href="https://github.com/MichaelS1011/ephemora-cell"><img src="https://img.shields.io/badge/status-stable-brightgreen" alt="Status"></a>
  <a href="https://github.com/MichaelS1011/ephemora-cell/stargazers"><img src="https://img.shields.io/github/stars/MichaelS1011/ephemora-cell" alt="GitHub stars"></a>
</p>

<p align="center">
  <a href="https://github.com/MichaelS1011/ephemora-cell/actions/workflows/ci.yml"><img src="https://img.shields.io/github/actions/workflow/status/MichaelS1011/ephemora-cell/ci.yml.svg?label=CI" alt="CI"></a>
  <a href="https://github.com/MichaelS1011/ephemora-cell/actions/workflows/ci.yml"><img src="https://img.shields.io/badge/tests-957_passing-brightgreen" alt="Tests — see CI"></a>
  <a href="https://github.com/MichaelS1011/ephemora-cell/actions/workflows/ci.yml"><img src="https://img.shields.io/badge/coverage-90%25-brightgreen" alt="Coverage — see CI"></a>
  <a href="https://github.com/MichaelS1011/ephemora-cell/actions/workflows/ci.yml"><img src="https://img.shields.io/badge/types-mypy%20clean-brightgreen" alt="Type-checked with mypy — see CI"></a>
  <a href="https://github.com/MichaelS1011/ephemora-cell/actions/workflows/ci.yml"><img src="https://img.shields.io/badge/format-black%20%2B%20ruff-green" alt="Formatted with black, linted with ruff"></a>
  <a href="https://github.com/MichaelS1011/ephemora-cell/security/code-scanning"><img src="https://img.shields.io/badge/security-fuzz%20%2B%20cve%20%2B%20sast-brightgreen" alt="scheduled WASM fuzz smoke + pip-audit CVE + bandit SAST + OSSF Scorecard in CI"></a>
  <a href="https://github.com/MichaelS1011/ephemora-cell/actions/workflows/wasi-conformance.yml"><img src="https://img.shields.io/badge/WASI--Preview1-conformant-green" alt="WASI conformance"></a>
</p>

<p align="center">
  <a href="https://registry.modelcontextprotocol.io/v0/servers?search=ephemora-cell-mcp"><img src="https://img.shields.io/badge/MCP-Registry-blue" alt="Listed in the official MCP Registry (newest published entry: 1.0.4.3)"></a>
  <a href="https://glama.ai/mcp/servers/MichaelS1011/ephemora-cell"><img src="https://glama.ai/mcp/servers/MichaelS1011/ephemora-cell/badges/score.svg" alt="Glama classification — read it from the live badge"></a>
</p>

<p align="center">
  <a href="#quick-start">Quick Start</a> ·
  <a href="#what-cell-enforces">Enforcement</a> ·
  <a href="#stateless-by-construction">Statelessness</a> ·
  <a href="#security-evidence">Security evidence</a> ·
  <a href="#mcp-integration">MCP</a> ·
  <a href="#performance">Benchmarks</a> ·
  <a href="#documentation">Docs</a>
</p>

**Latest release: [v1.1.0](https://github.com/MichaelS1011/ephemora-cell/releases/tag/v1.1.0) · [PyPI](https://pypi.org/project/ephemora-cell/) · [signed GitHub release](https://github.com/MichaelS1011/ephemora-cell/releases) · BUSL-1.1.** Release notes: [CHANGELOG.md](CHANGELOG.md) · supported versions and the 2026-09-24 wasmtime advisory wave, triaged with measured evidence: [SECURITY.md](SECURITY.md) · latest reproducible measurement: 2026-10-02 interpreter-guest run, [`benchmarks/results/`](benchmarks/results/) · measured counts per installation state: [docs/release_assurance.md](docs/release_assurance.md).

<p align="center">
  <picture>
    <source media="(prefers-color-scheme: dark)" srcset="assets/hero-dark.svg">
    <img src="assets/hero-light.svg" alt="One execution: an agent hands untrusted code to the Ephemora-cell capability boundary, which grants explicit capabilities and budgets, denies network and process access by default, and returns a bounded result with a signed record while the execution state is destroyed — create, constrain, execute, prove, destroy">
  </picture>
</p>

## Why this boundary exists

Wasmtime gives you a WASM runtime. Cell builds the application-level boundary around it — WASM is the mechanism, the **controlled execution of untrusted code** is the product:

```text
Wasmtime:            Ephemora-cell:
    Execute WASM         Execute WASM
                         + define capabilities
                         + enforce budgets (fuel, memory, time, I/O)
                         + bound output
                         + collect execution metadata
                         + produce execution records (sign-ready)
                         + integrate with agents and MCP
```

The question that decides whether agent-executed code is safe: *how do you let an agent run untrusted code without that code getting ambient access to your host, your credentials, your network or unlimited compute?* Raw runtimes leave that boundary to you. Cell **is** that boundary — an operator can still grant a capability explicitly, and every grant shows up in the run's own record.

Agent-generated code differs from application code: it can be buggy, computationally unbounded, unexpectedly expensive — or hostile. So the runtime **enforces** boundaries instead of documenting them ([What Cell enforces](#what-cell-enforces)), and a result is not just a return value: every execution answers three questions at once, attached as `_meta.execution`, canonicalized (RFC 8785 JCS) and signable.

| | Answer | Example fields |
|---|---|---|
| **RESULT** | what came back | `status`, `stdout`, `exit_code` |
| **COST** | what it cost | `fuel_consumed`, `elapsed_ms` |
| **POLICY** | under which rules it ran | memory limit, preopens, network policy, `wasmtime_version` |

"Verifying. Not claimed." is data, not a slogan: rewrite one field of a record and `verify()` fails — runnable demo in `python examples/signed_record_demo.py`. Runtime + security boundary + accounting, in one `pip install`.

Cell is **not** a general-purpose container replacement. It targets high-frequency, untrusted agent and MCP workloads that want a small capability surface and explicit accounting, and for agent infrastructure it can sit as a lightweight execution backend beneath an existing harness rather than requiring a new framework. The trade is explicit: less generality than a full Linux sandbox, in exchange for a smaller execution surface, tighter capability control and lower per-call overhead — measured per path in [Performance](#performance).

## Quick Start

Three commands: install Cell, run something untrusted, read its audited receipt.

**1 — Install** (use a virtualenv; on Ubuntu ≥ 23.04 / Fedora a bare `pip install` is refused by PEP 668. Windows: use Git Bash or WSL, and `python` instead of `python3`):

```bash
python3 -m venv .venv && source .venv/bin/activate
python -m pip install ephemora-cell
```

**2 — Run something untrusted** (the repo ships examples, or bring any `.wasm`):

```bash
git clone https://github.com/MichaelS1011/ephemora-cell.git && cd ephemora-cell
ephemora-cell run examples/hello.wasm --isolated
```

*(adds OS-level process isolation around the run — recommended for code you didn't build; the cost of each path is measured in [Performance](#performance))*

```text
Hello from Ephemora Cell!
```

**3 — Read the audited receipt** — same run, machine-readable. Here a hostile module (`examples/fuel_bomb.wasm`) is given a 100-unit fuel budget and stopped, exactly as budgeted:

```bash
ephemora-cell run examples/fuel_bomb.wasm --fuel 100 --isolated --json
```

```json
{
  "status": "fuel_exhausted",
  "exit_code": 0,
  "fuel_consumed": 100,
  "fuel_budget": 100,
  "stdout_bytes": 0
}
```

Same from Python — every result carries status, cost and captured output (full surface in [API, CLI and integrations](#api-cli-and-integrations)):

```python
from ephemora_cell import run_wasm

result = run_wasm("examples/fuel_bomb.wasm", max_fuel=100)
result.status           # <ExecutionStatus.FUEL_EXHAUSTED: 'fuel_exhausted'>
result.fuel_consumed    # 100 — the budget, not an estimate
result.stdout           # '' — captured output, capped at 10 KB
```

Failures come back **graded, not crashing**: an infinite loop returns `status: "fuel_exhausted"` with its receipt, a memory hog `memory_exceeded`, a crash a non-zero exit code — the same statuses the [auto-grader](examples/auto_grader.py) and the CI test-bench job consume. On the isolated path a failure stays contained to a disposable worker with OS-level limits and a hard termination.

**Where to next:** agent/tool isolation → [MCP integration](#mcp-integration) · CI gating for untrusted PRs → [the composite action](#github-action) · CLI reference and usage recipes (also the troubleshooting list) → [docs/recipes.md](docs/recipes.md).

![Terminal demo: install of 1.1.0 from PyPI, a sandboxed run, its JSON report naming the boundary it ran under, a fuel bomb stopped at its 100-unit budget, the live 8-vector check with its positive controls, and a signed record whose verification flips to False after one edited field](assets/demo.gif)

*Real CLI session — every line is verbatim output of the command printed above it. Install is the 1.1.0 wheel from PyPI; the `examples/` and `benchmarks/` paths are a clone of the repo, and the last scene needs the optional `tools-signing` extra installed just before it. The arc is one execution: fresh run → the boundary it got (fuel, memory limit, preopens, `allow_fsync: false`) → a runaway module stopped at exactly 100 of 100 units → denials measured against the live runtime, positive controls included → signed evidence that detects a single rewritten field. Wall-clock and throughput are deliberately not in the frames: they are platform-dependent, and a demo that shows them ages into a false claim.*

## What Cell enforces

Cell assumes **guest code is untrusted**. The host decides what the guest can reach, and the runtime enforces that decision per execution — the guest cannot switch it off, and a widened run attests that it was widened. By default the guest gets **no ambient access**: no network, no arbitrary filesystem, no process spawning, no unrestricted environment, and bounded CPU, memory, time and output. Granting any of those is an explicit, recorded host decision.

* **Capability, not convention.** Preopens are revalidated at grant time, and the host does not follow guest-writable names: host-side artifact reads use `O_NOFOLLOW` plus descriptor-level regular-file validation, with atomic publication on shared paths ([SECURITY.md](SECURITY.md#host-side-file-boundaries--the-host-never-follows-what-the-guest-can-write-2026-10-05)).
* **Resource limits with exact accounting.** Fuel stops a loop at the budget it was given, the epoch deadline is the net under everything fuel does not count, and memory, output and host-I/O work each carry their own wall (table below).
* **Stateless execution.** No sandbox directory, no engine reuse of a previous run's state, no inherited authority ([Stateless by construction](#stateless-by-construction)).
* **Mediated egress, authenticated before enforced.** By default no guest connection succeeds — Preview1 exposes no socket surface, and the WASI 0.2 path denies `connect` at call time — so there is nothing to mediate until a host opens it. Where an operator does, each grant is a DSSE envelope signed by a key in a trust root kept **outside** the grants directory — a key delivered with the artefact proves nothing about it — and a grant *narrows* the operator allowlist rather than replacing it: per URL, per redirect hop, per resource cap, with window, cap and revocation enforced per request. `--egress-grants-required` removes the fallback ([ADR-013](docs/decisions/ADR-013-egress-host-mediation-and-grant-form.md), [docs/egress_patterns.md](docs/egress_patterns.md)).
* **Resolved addresses pinned.** A name answering with loopback, RFC1918, CGNAT, link-local or metadata space is refused at resolve time, and the vetted address is the one connected to — classified by Cell's own address registry, not by `ipaddress.is_private` ([SECURITY.md](SECURITY.md), DNS-rebinding note).
* **Signed evidence.** Receipts sign the exact canonical bytes shown to the caller and carry a fresh `report_id` plus issue time; the verifier, outside Cell, decides whether it has seen one before. A valid signature proves those bytes, not that the execution was safe, and grants no authority when the audience is wrong — a receipt is not a grant and a grant is not a receipt ([SECURITY.md](SECURITY.md#signature-semantics--what-is-signed-who-may-sign-what-that-proves)).
* **Fail-closed as a default posture.** A broken grant set, an unreadable ledger, an empty authority directory or a malformed request produces an audited refusal, not a silent pass — and refuses at startup where startup is the safe moment.

**Security is never opt-in.** Every execution — in-process or isolated — runs under enforced fuel, memory, wall-clock and output limits: the caller sets their size, not their existence. Two deliberate exceptions exist and are named wherever they matter: `max_wasm_bytes` (how big a module a run may load — 32 MiB everywhere except the `interpreter` profile, which raises it to 512 MiB for bring-your-own guests) and `allow_fsync` (whether WASI sync calls are permitted — no shipped profile turns it on; only an explicit `--allow-fsync` does). Both are attested in the signed baseline, so a widened run never reads like a default one. The one thing you choose is the process boundary: add `--isolated` (or call `run_isolated()`) when the module comes from outside your own build — agent output, third-party plugins, PR-contributed code.

The enforced defaults:

| Resource | Default |
|---|---|
| WASM memory | 128 MB (`Store.set_limits`) |
| Fuel / CPU budget | 1,000,000 — a run cannot overshoot its fuel; ~13 fuel/iteration measured (R² = 1.000), per-platform ([docs/performance.md](docs/performance.md)) |
| Wall-clock timeout | 30 s (epoch interruption) |
| Captured stdout/stderr | 10 KB |
| Network | disabled by default — Preview1: no socket APIs; WASI 0.2: linked, denied at call time (measured) |
| Host filesystem | denied by default; 14 dangerous dirs blocked (`/dev`, `/proc`, `/sys`, …) |
| Process exec / fork | unavailable in WASI |
| Threading | disabled (`wasm_threads=False`) |

The same rule governs **language features**: every WebAssembly proposal Cell's shipped WASI surface does not need is enforced off in the engine config (threads, function-references, exceptions, GC, tail-calls, stack-switching — attested in every `security_baseline`, compile-probe-tested per release). That is structural, not caution for its own sake: the 2025/26 advisory record repeats one pattern — sandboxes diverge where a proposal quietly flipped to default-on. Cell keeps that surface at zero and pays in what guests *can't* run, not in what the host can't guarantee ([full proposal table and per-advisory triage](SECURITY.md#proposal-policy--set-not-inherited-2026-09-25)).

Beyond those: I/O budgets (`io_cpu_seconds` / `io_budget_bytes` — walls for host work, not just guest compute), dual-ABI, memory64 opt-in, GC-heap declared cap, bounded named state and host-mediated egress. Which control runs on which execution path — and what "documented-trusted" means where a kernel wall would be your own process — is the per-control [execution-path matrix](SECURITY.md#execution-paths--which-control-runs-where) in [SECURITY.md](SECURITY.md).

### The trust chain around the sandbox

Around the sandbox sits a verifiable trust chain for third-party tools:

<picture>
  <source media="(prefers-color-scheme: dark)" srcset="assets/trust-chain-dark.svg">
  <img src="assets/trust-chain-light.svg" alt="Trust chain: vendor signs manifest, host verifies fail-closed, Cell sandbox runs, signed execution record">
</picture>

Anything failing verification is rejected before a single instruction executes — execution never depends on a happy path. Third-party tools ship an Ed25519-signed manifest (RFC 8785 JCS); the server verifies signature **and module hash** before registering, and a bare `.wasm` without a valid manifest never loads in signed-tools mode (`--require-signed-tools pub.pem`). An agent can only *propose* a tool — a `tool.request.json` in an operator-allowlisted directory, verified before it installs and announces it. The agent proposes; the host disposes ([ADR-006](docs/decisions/ADR-006-governed-tool-loading.md)).

Any run folds into a tamper-evident record covering status, fuel, timing and the attested security baseline. Each run's pre-exec record and receipt can be sealed into a signed, hash-chained `LedgerEntry` JSONL chain (`sequence` + `prev_hash`) — continuous and ordered, linkage verifiable without a key, authorship only with one, and blind to a chain truncated at its end, which is stated and tested ([ADR-011](docs/decisions/ADR-011-execution-ledger-chain.md); `ephemora-cell ledger <path>`). Cumulative tenant budgets (`--tenant`, `--tenant-book`, `--tenant-max-runs`) reserve a ceiling before the run, settle what it consumed and refuse the next one over cap with a receipt naming the account — a billing identity, not an isolation boundary, and with no mid-run kill ([ADR-012](docs/decisions/ADR-012-tenant-attribution-and-cumulative-budgets.md)).

## Stateless by construction

**No execution state survives into the next execution.** Not a sandbox directory, not an engine's cached state, not a capability, not an environment — the only thing that can cross a run boundary is named state a host deliberately carries in itself, described at the end of this section. The claim is one named test per word in [`tests/test_execution_invariants.py`](tests/test_execution_invariants.py): nothing left to reuse after a run (`cleanup()` returns the residue, so a surviving directory is a failed assertion); run B reads nothing run A left; no operation carries ungranted authority, and the run attests exactly which preopens it got; the receipt verifies over the exact bytes shown to the caller, with a foreign key and an edited field both refused.

The main measurement: **1 000 / 300 / 40 consecutive run-pairs** on the engine-pool, per-run-engine and isolated-subprocess paths — **0 leaks on each** — plus 40 audits whose writer was SIGKILLed mid-append ([`benchmarks/statelessness_probe.py`](benchmarks/statelessness_probe.py), result in [`benchmarks/results/2026-10-05/`](benchmarks/results/2026-10-05/statelessness_invariants.json)). The default I/O budget forces a per-run engine, so the probe lifts it and tests the pooled path too — a statelessness test that never did would be testing the wrong path.

**Named state is a different thing, and it is the host's.** Cell ships no session store and never creates one on your behalf: an integrator can pass a bounded `StateStore` (`StateStore(max_entries=64, max_value_bytes=262144, max_total_bytes=1048576)`) into a run. That store is not execution state — nothing is inherited, and nothing reaches disk. But it is a host-held object, so a host that deliberately passes the same store into the next run carries named state across executions **by design**: `tests/test_state.py::TestStateImports::test_gate_demo_counter_across_three_runs` threads a counter through three isolated runs exactly that way. Persistence here is a capability the host grants, never a default, and it is still not storage
([ADR-004](docs/decisions/ADR-004-named-state.md)).

What you can build on that surface — LLM-generated code under explicit limits, MCP tools in a bounded environment, user-uploaded plugins without host-level access, agent tool runtimes, verifiable execution records for grading or audit — is the same `run_wasm` / `run_isolated` / MCP API throughout; patterns with working code, including serverless, air-gapped validation, WASI 0.2 components and FastAPI, are in [docs/recipes.md](docs/recipes.md).

## MCP integration

Listed in the official MCP Registry as `io.github.MichaelS1011/ephemora-cell-mcp` (stdio via PyPI). The registry's newest published entry is **1.0.4.3**: the 1.1.0 metadata is prepared in [`server.json`](server.json) and validated, and publishing it still waits on publisher authorization (the registry login is an interactive device flow). Glama indexes the same server — its grade is a live classification, so read it from the badge above rather than from a sentence here.

```bash
pip install ephemora-cell
ephemora-cell-mcp          # bundled tools: clock + echo; --tools-dir ./tools replaces the bundled set with your own

# One-line setup for GitHub Copilot in VS Code:
code --add-mcp '{"name":"Ephemora Cell","command":"ephemora-cell-mcp"}'
```

Ask your agent for the current time: the answer comes from the bundled `clock` tool — a WASM module reading only the WASI real-time clock — and the call report shows exactly what that answer cost.

**Ephemora-cell, the MCP server and every tool execution run entirely on your machine. Your chosen client or model may be local or remote — Cell is not part of either.** The server is a plain stdio process installed from PyPI: Cell requires no API key and no cloud account, and tools execute offline inside the WASM sandbox (no network unless you explicitly allow it host-side). Point Claude Desktop, VS Code/Copilot, Codex, LM Studio or a local-model stack at it — the sandbox side never leaves your hardware. Requirements of the chosen client or model provider are independent of Cell, and how much the agent gets out of the tools depends on that client's tool-calling ability; the sandbox adds no requirement beyond a local machine.

**What you get per call:**

- **Untrusted tools, locally.** Every tool is a WASM module inside a Cell sandbox — no ambient network, fuel- and memory-bounded, output-capped. A misbehaving tool hits the sandbox wall, not your host.
- **Verifiable, not just installable.** Each result carries its execution record (`_meta.execution`); the native `get-policy` tool reports the exact per-tool policy computed from the same code path that enforces it, so report and enforcement cannot drift. The protocol does not verify `_meta`, so `--receipt-signing-key` adds a DSSE signature (`_meta.attestation`) over the same bytes, verifiable out-of-band with the operator's public key, and `max_age_seconds` lets a caller refuse a stale receipt. Policy reads are tools, policy writes are host decisions: an agent cannot grant itself network or filesystem access.
- **A long-lived server, a fresh execution.** Under the `2026-07-28` stateless revision a current-revision client skips the `initialize` handshake while handshake-era clients (Claude Desktop, VS Code, Codex, …) keep working unchanged, both eras served from one process and tested against the official SDK in CI. The point of the split: **an MCP server may be long-lived while every execution inside it is fresh** — each `tools/call` starts a new sandbox that inherits nothing. Revision handling, the ordering rule (legacy traffic before `initialize` is refused with `-32600` before any WASM runs), `ttlMs`/`cacheScope` and the exemption rule: [docs/mcp.md](docs/mcp.md).

Per-call cost of each MCP path: [Performance](#performance). **vs Microsoft Wassette:** Wassette is Microsoft's capability-based runtime for MCP tools on the same Wasmtime family — its OCI pull model moves the trust decision to install time; Cell adds what a caller can *verify per call* ([docs/comparison-mcp-servers.md](docs/comparison-mcp-servers.md), re-verified 2026-09-18).

This is an execution boundary, not a claim that guest software is trustworthy. Cell does not evaluate whether a module is malicious or correct — a guest can still misbehave *within* the budgets it was given.

## Security evidence

Six measured rungs, strongest first, each with its reproduce command and its committed raw evidence — the ladder table, the probe-equivalence methodology, the attack results matrix and the CVE replay detail: [docs/security_posture.md](docs/security_posture.md).

1. **MCP CVE replays** — real exploit paths of two patched CVEs denied at the engine level, governed loading failing closed on a tampered payload, plus a measured call-time socket denial on WASI 0.2 components.
2. **SandboxEscapeBench-18 mapping** — the UK AI Security Institute's 18 container/Kubernetes escape scenarios mapped to their closest WASM equivalent: **8 execution-tested and denied, 10 not expressible** on the WASI surface. Applicability stated, not stretched: the primitives those escapes rely on (privileged modes, namespaces, cgroups, raw sockets) do not exist here, and no model is in the loop.
3. **8 attack intents × 3 boundaries** — same intents, same exit-code rule, nothing hardcoded: stock Docker 0/8 blocked · hardened Docker 2/8 · Cell **8/8** (default configuration, WASI Preview1 path), identical on macOS arm64 and DGX Spark GB10. **`ALLOWED` there means the tested primitive stays available to guest code *inside* that sandbox — not that anything reached the host, and not a ranking of the boundaries.** gVisor measures 8/8 ALLOWED for exactly that reason: it walls the host off and keeps the Linux ABI for the guest. The WASI 0.2 component path is a separate boundary and does not carry the sync blockade today — measured, not inferred ([SECURITY.md](SECURITY.md)).
4. **Official WASI and core-spec conformance** — **72 pass / 1 documented by-design xfail / 0 fail** on the pinned wasi-testsuite preview-1 suite, and **31,931 pass** on the official WebAssembly core spec with every deviation classified and none unexpected; re-run weekly in CI, raw JSON committed. This is standards conformance, not a security certification — no third party certifies Cell ([conformance/README.md](conformance/README.md)).
5. **2026 probe classes** — the CVE-2026-47261 companion FS vectors (trailing-slash, hardlink, rename, TRUNCATE), persistence-worm and control-plane probes, all denied with granted positive controls on every class.
6. **Statelessness probe and cross-architecture determinism** — the run-pair sweep in [Stateless by construction](#stateless-by-construction), and fuel deterministic per platform (spread 0), platform-bound and never comparable across hosts.

**What we do not compare — and why.** Prompt-injection suites (garak, InjecAgent) test the model and agent layer, not the execution boundary — out of scope for an execution sandbox. Cloud sandbox providers are cited from third-party sources with their source status, and third-party numbers never appear in the same table as our measured cells.

**Can you break Cell?** Found an execution path that violates the documented security boundary — an escape, a budget bypass, an attestation gap? That is exactly the report we want: [SECURITY.md](SECURITY.md#reporting-a-vulnerability) (private disclosure, responsible handling). The [threat model](docs/threat-model.md) and its documented residual risks tell you where to aim; the methodology sections in [docs/security_posture.md](docs/security_posture.md) tell you how we measure. Security research on Cell is welcome.

## Performance

**What does the boundary cost? 0.376 ms** — the warm wall-clock overhead a sandboxed run adds over the same work run bare (measured, not estimated).

*Latest reproducible benchmark — 2026-09-14 · Mac M5 · wasmtime 47.0.1 · `hello.wasm` · n=1000. Every number below regenerates from a fresh clone.*

| Path | Per call | Why this number |
|---|---|---|
| Library, **pooled** engine (`io_budget_bytes=None`) | **0.51 ms** median (p95 0.89) | cached engine, trusted workloads |
| Library, **default** per-run engine (64 MiB I/O budget) | 0.94 ms median (p95 1.15) | fresh engine per run so the I/O wall holds |
| Library, **`run_isolated()`** | ~10–100 ms | disposable worker process, OS rlimits, hard kill |
| MCP stdio server, default | ~12 ms | fresh sandbox per `tools/call`, measured end-to-end |
| MCP stdio server, `--pooled` | ~0.5 ms | verified tools on the pooled engine; the relaxed I/O wall is attested in `get-policy` |

Cold vs warm (n=300 each, first run discarded): cold 0.59 ms guest / 0.99 ms wall, warm 0.55 ms guest / 0.93 ms wall — that warm gap is the 0.376 ms (`overhead_warm_ms`, `benchmarks/results/2026-09-14/pov_benchmark.json`). Against a container cold-start on the same machine (n=100 per image): `docker run` `python:3.12-slim` 185.9 ms vs Cell 0.49 ms = **383×** — a container-cold-start vs invoked-WASM comparison for this workload, not a general claim that WASM beats Docker. Throughput on this host: ~3M executions/hour per core on the one-liner path, ~5.5M on the pooled hot loop. Sandbox tax on an industry-standard workload (EEMBC CoreMark 1.01): the Cell layer costs **8.6 %** over the bare wasmtime engine on macOS arm64 and **9.9 %** on DGX Spark GB10, and instruction-level fuel metering a further **14.7 %** and **12.6 %** respectively — with wasmer and wasm3 as external controls.

Full matrices, per-run scores, agentic workloads and the third-party positioning: [docs/performance.md](docs/performance.md). Reproduce: `python benchmarks/pool_vs_budget.py` · `python benchmarks/competitive_benchmark.py` · `python benchmarks/coremark_wasi.py --rounds 3` · `python benchmarks/determinism_probe.py` (raw results with `measured:true` committed under [`benchmarks/results/`](benchmarks/results/)).

Two caveats that survive every release: **fuel is per-platform** — deterministic per host (`fuel_spread: 0` on every machine measured) but never comparable across hosts. And **every number here is a Cranelift number** — the Python binding cannot select an interpreted backend (Pulley/Winch unreachable, asserted in `tests/test_surface_audit.py`), so no fallback can silently change the posture.

## API, CLI and integrations

Cell executes the `.wasm` — it does not know the source language. The enforcement stack (module → engine → capability surface → budgets → record) is diagrammed in [docs/security_posture.md](docs/security_posture.md#the-wasi-sandbox-surface-visually). The primary API is deliberately simple, and that is what makes execution suitable for auditing, policy enforcement and resource accounting — not just running code.

```python
from ephemora_cell import run_wasm, run_isolated, WASIConfig, WASISandbox

result = run_wasm("tool.wasm", max_fuel=1_000_000, timeout_seconds=30)
result.status        # SUCCESS | ERROR | TIMEOUT | FUEL_EXHAUSTED | MEMORY_EXCEEDED
result.exit_code
result.stdout        # 10 KB cap
result.elapsed_ms
result.fuel_consumed

# OS-level process wall for untrusted guests:
result = run_isolated("tool.wasm", config=WASIConfig(max_fuel=500_000))
```

`run_isolated()` takes the same configuration and returns the report fields as a dict. Disk quota (`disk_quota_bytes`) and the GC-heap cap (`max_gc_heap_mb`) are `WASIConfig` knobs; named state is a host-supplied `StateStore` passed to the run, not a config flag; the component path is selected per call via `run_wasm(..., abi="component")` — [docs/recipes.md](docs/recipes.md) has the recipes.

**CLI** — five verbs cover the loop, and the same commands are a development loop (edit, run, read the receipt) with no Dockerfile and no image build:

```text
ephemora-cell run       Execute a WASM module (--json, --isolated, --fuel, --stdin, --profile, --abi, --tenant)
ephemora-cell inspect   Imports, exports, memory — what a module wants, before you run it
ephemora-cell benchmark Cold/warm latency and fuel spread
ephemora-cell build     Compile Rust/Go/C/AssemblyScript/Zig straight to WASM
ephemora-cell ledger    Verify a run chain: linkage and order, and what it cannot prove
```

`ephemora-cell --help` and [docs/recipes.md](docs/recipes.md) for the full reference.

**Languages.** Any language that compiles to WASM runs; the five tier-1 toolchains (Rust, Go, C, AssemblyScript, Zig) are each built **and executed** by a CI gate on every push. Running Python is measured as a bring-your-own guest: a pinned `wasi-python 3.10` under `--profile interpreter`, 25 in-process and 15 isolated boots per workload, every run `success` — not a CI gate, because the 22 MB guest binary is not committed. What does *not* run: native Python, Node.js/npm packages, Linux/ELF binaries; GC/threads-based ports stay locked until the GC-heap gate opens. Compile commands, gates and the measured interpreter numbers: [docs/languages.md](docs/languages.md); posture: [ADR-009](docs/decisions/ADR-009-language-support.md). Profiles (`plugin`, `llm`, `edge`, `default`, `analytical`, `interpreter`) are budget presets — `interpreter` is the preset for running a bring-your-own interpreter as the guest, and it ships no interpreter, opens no sync exception and grants no filesystem or environment access.

### GitHub Action

Untrusted PR code in CI: the repo ships a composite action that runs a module in the Cell sandbox and returns graded outputs, with the isolated subprocess path on by default.

```yaml
- id: run-tool
  uses: MichaelS1011/ephemora-cell/action@v1.1.0   # pin a release tag, not a branch
  with:
    module: path/to/module.wasm   # e.g. built from a PR-provided recipe
    profile: llm
    fuel: 500000
- run: echo "status=${{ steps.run-tool.outputs.status }} fuel=${{ steps.run-tool.outputs.fuel_consumed }}"
```

Non-success statuses fail the step (`fail-on: non-success`, default) — a module that burns its budget or trips the memory cap cannot take your workflow with it. Inputs, outputs, failure semantics and how this repo's own demo workflow proves both directions on every push (a benign module succeeds; `examples/fuel_bomb.wasm` at `fuel: 100` must fail with `fuel_exhausted` and `fuel_consumed == 100`): [`action/README.md`](action/README.md).

CI runs two framework-adjacent integration suites against real SDKs — `integration/test_hermes_subagent.py` and `integration/test_nemoclaw_isolation.py`. The other scripts in [`integration/`](integration/) (LangGraph, CrewAI, AutoGen, OpenAI Agents SDK, Semantic Kernel) are examples that need their own SDK install and are not CI-gated; nothing here claims otherwise.

## Limitations

**Cell is:** the minimal execution boundary for untrusted code — a WASM/WASI sandbox with explicit capabilities and budgets, a resource-accounted runtime, an embeddable Python library, a CLI, an MCP execution layer.

**Cell is not:** a persistent workspace · a VM · a container orchestrator or a general container replacement · a malware detector · a multi-tenant cloud platform · an agent framework · an LLM · a code generator. It writes nothing to disk and inherits nothing between runs; named state lives only while the host keeps its store alive — see [Stateless by construction](#stateless-by-construction).

Use Cell when: code is untrusted or dynamically generated · tools come from third parties · an AI agent executes arbitrary programs · you need explicit resource budgets · you need structured execution metadata. Cell is optimized for bounded executions, not long-running service workloads — for full Linux service semantics, use an appropriate container or microVM boundary (measured third-party comparison: [docs/performance.md](docs/performance.md)).

What each enforced control does **not** claim — every row is an honest boundary, tested at the boundary:

| Enforced control | Does guarantee | Does **not** guarantee |
|---|---|---|
| Memory cap (default 128 MB) | guest cannot exceed the configured heap | correct guest behavior — a bug inside the budget is the guest's bug |
| Fuel budget | no unbounded CPU burn; execution stops at the limit | malware detection — hostile code that stays within budget runs fine; nothing inspects what the module *means* |
| Wall-clock timeout | no runaway execution; epoch interruption fires | that the app logic is correct or fast |
| Network denial (default posture) | no guest connection succeeds by default — Preview1 exposes no socket API, the WASI 0.2 path denies `connect` at call time | safe behavior *within* granted capabilities — exfiltration via an allowed channel (e.g. writing secrets to a granted preopen) stays the integrator's concern ([SECURITY.md](SECURITY.md)) |
| Filesystem capability control (preopen only, default deny) | file access limited to explicitly mounted dirs | full VM semantics — mounted-path content is exactly what the integrator chose to expose |
| Output caps (default 10 KB) | captured output is bounded; unbounded prints cannot fill the host disk | that truncated output is complete — inspect `result.stdout` and the record |

> **The goal is narrow: make untrusted execution cheap enough and controlled enough that an application can safely do it by default.**

Full details: [SECURITY.md](SECURITY.md) (policy, known limitations) · [docs/threat-model.md](docs/threat-model.md) (adversary model, trust boundaries, resource-exhaustion matrix) · [docs/security_posture.md](docs/security_posture.md) (evidence ladder, attack-surface verification, related research).

**Roadmap** — stable themes, no dates promised; the gated detail lives in [SECURITY.md](SECURITY.md) and [docs/observations.md](docs/observations.md): qualifying a newer Wasmtime line, re-running the fuel-determinism and FS-escape gates against it · WASI 0.3, gated until its surface ships in the Python wheels and has its own budget qualification · shared-everything threads as a separately security-reviewed opt-in with thread-aware fuel and wall-clock accounting ([docs/threads_roadmap.md](docs/threads_roadmap.md)) · continuous fuzzing over today's scheduled fuzz smokes, targeting the parser/verifier surfaces and the invariants above.

## Testing & Verification

**Release gate, measured on a fresh clone of the release commit** — not a per-host constant: 957 tests passing (4 skipped) · 89.98% statement coverage, shown as 90% (Cell + MCP, gate 80%) · 8/8 attack vectors blocked (default posture, WASI Preview1 path) · 72-pass official wasi-testsuite conformance (pinned, 0 fail) · CI-enforced on every push (tests, coverage, pip-audit, SBOM, bandit, official MCP SDK interop) — plus, on that same clone: a wheel-only smoke against the installed artifact (recorded in the v1.1.0 GitHub release) and an sdist clean-room container run.

**What "the suite" means here — one canonical number.** 957/4 (961 collected) is what `pytest` reports on the environment CI uses on both legs: `requirements.txt` (the pinned `wasmtime`), the test deps, and the optional `tools-signing` extra (`cryptography>=42`) that every Ed25519 path needs. The count is machine-checked against `pytest --collect-only` by `scripts/check_test_count.py`, so the release-count sentences cannot drift from the code. The figures around it — the minimal-install count without `cryptography`, the sdist container range, the toolchain-skip asymmetry, what host load does to the `io_cpu_seconds` watchdog — each describe a different installation state and are kept with their conditions in [docs/release_assurance.md](docs/release_assurance.md), re-measured by hand at each release rather than by the guard.

## Documentation

**Security & evidence** · [SECURITY.md](SECURITY.md) — policy, execution-path matrix, vulnerability reporting · [docs/threat-model.md](docs/threat-model.md) — trust boundaries, adversary model, resource-exhaustion matrix · [docs/security_posture.md](docs/security_posture.md) — evidence ladder, results tables, CVE replay detail · [conformance/README.md](conformance/README.md) — official wasi-testsuite and core-spec results · [docs/release_assurance.md](docs/release_assurance.md) — measured counts per installation state · [docs/security_review_2026-10-05.md](docs/security_review_2026-10-05.md) — what six red-team lanes found, what closed with a biting test, the three posture decisions the operator made afterwards (grant scope, ungranted tools, handshake order), the second pass that audited that same day's code, and the items left open with the reason

**Getting started** · [Quick Start](#quick-start) · [docs/recipes.md](docs/recipes.md) — usage patterns (FastAPI, serverless, air-gapped, WASI 0.2) and troubleshooting · [`integration/`](integration/) — agent-framework examples

**Performance** · [docs/performance.md](docs/performance.md) — benchmarks, CoreMark sandbox tax, per-path latency · [`benchmarks/results/`](benchmarks/results/) — raw `measured:true` JSON

**Integrations & languages** · [docs/mcp.md](docs/mcp.md) — MCP server · [docs/comparison-mcp-servers.md](docs/comparison-mcp-servers.md) — CVE-to-probe mapping · [`action/README.md`](action/README.md) — composite GitHub Action · [docs/languages.md](docs/languages.md) — compile matrix and interpreter guests · [docs/egress_patterns.md](docs/egress_patterns.md) — sanctioned API-call patterns · [docs/observations.md](docs/observations.md) — the watch items we are deliberately not acting on, each with its exit condition

**Decisions & changes** · [ADR-001…013](docs/decisions/) — all decision records, including ADR-006 on who may change a running workload's security boundary · `examples/signed_record_demo.py` — sign and tamper-check a run · [CHANGELOG.md](CHANGELOG.md)

**Enterprise** · [docs/enterprise.md](docs/enterprise.md) — isolation vs. operation: when that conversation is worth having

## License

Ephemora-cell is licensed under the [Business Source License 1.1](LICENSE) (BUSL-1.1) — source-available, not open source.

- **Free for non-production use** — evaluation, development, research, testing.
- **Business/production use requires a license from Ephemora** — see [docs/enterprise.md](docs/enterprise.md).
- **Automatic conversion:** each version converts to **Apache 2.0** four years after its first public release.
- **License history by version:** versions ≤ 1.0.4.3 are Apache-2.0. Versions 1.0.5 and later are BUSL-1.1 ([ADR-010](docs/decisions/ADR-010-relicensing-bsl11.md)).

Ephemora-cell is the standalone execution boundary — no Ephemora dependency. The Ephemora enterprise edition builds on this boundary for production and regulated deployments: Cell is complete for isolation, the enterprise edition is complete for operation.

---
mcp-name: io.github.MichaelS1011/ephemora-cell-mcp

---

*One agent action. One bounded execution. One controlled result.*

Created by [Michael Soppa](https://www.linkedin.com/in/michael-soppa).
