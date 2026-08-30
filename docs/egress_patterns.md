# Secure API egress patterns for sandboxed agents

**Part 1 — Catalog of workarounds (2026-08-28)** · Part 2 (pattern specification) and
the reference implementation follow below and in `ephemora_cell/egress_sidecar.py`, respectively.
Decision basis: ADR-002 (`docs/decisions/ADR-002-io-budget-egress.md`).

## Why this catalog exists

Ephemora Cell exposes **no sockets** — verified by `benchmarks/verify_8_vectors.py`
(vectors 1–3: no network imports in the WASI surface). WASI 0.3 (released 2026-06-11) brings
native async for Components, but **no stable sockets in wasmtime-py**; the
wasi-sockets/wasi-http proposal track is separate from 0.3. As long as the official mechanism is missing,
the community builds workarounds — and that is exactly where the damage happens: the sandbox architecture
is replaced by hacks that either effectively riddle the isolation with holes or
resemble unvetted egress freedom. The research names the problem: execution security
for coding agents is fragmented ([Balkanization of Execution-Security Research,
arXiv 2607.05743](https://arxiv.org/html/2607.05743v1)), and WASM-based
MCP tool sandboxes such as SandScope ([MCP-SandboxScan, arXiv 2601.01241](https://arxiv.org/html/2601.01241v2))
show that isolation + registry is the viable path.

Observed reality 2025/2026: egress proxy allowlists are the dominant pattern
([INNOQ](https://www.innoq.com/en/blog/2026/03/dev-sandbox-network/)), sometimes with TLS re-signing
([Agyn](https://agyn.io/blog/ai-agent-sandboxing-filesystem-network-isolation)); that is exactly where
exfiltration paths emerge when secrets and egress bypass can be combined
([Penligent: Claude Code Sandbox Bypass](https://www.penligent.ai/hackinglabs/claude-code-sandbox-bypass/)),
and sandbox boundaries are circumvented via configuration/file manipulation
([Pillar: Week of Sandbox Escapes](https://www.pillar.security/blog/the-week-of-sandbox-escapes),
[Cymulate: CBSE](https://cymulate.com/blog/the-race-to-ship-ai-tools-left-security-behind-part-1-sandbox-escape/)).

## Catalog: patterns for how agents build "egress" these days

### W1 — Filesystem tunneling (shared directory + host poller)

**How:** The guest writes a request into a shared/preopened directory; a host daemon
(cron, watcher, agent loop) picks it up, performs the API call, and places the response back.

- ✅ stays isolated: no socket in the guest; skills remain capability-based.
- ❌ riddled with holes when: the directory is shared with host/agent state (Cymulate-CBSE class:
  manipulation of "trusted" files has effects outside), the poller executes **blindly**
  (URL/method/headers chosen by the guest → arbitrary egress under host identity), no
  schema validation, no rate limits, no audit trail, race conditions (a response from
  another session gets picked up).
- **Verdict: dangerous in its usual form.** The idea is right — the execution must
  be mediated (→ P1, Part 2).

### W2 — Stdout/stdin RPC: guest asks on stdout, host answers on stdin

**How:** The guest tool prints `{"http_request": ...}` to stdout; the agent framework (MCP server,
runner) parses it, fetches, and injects the response into the next call.

- ✅ stays isolated: egress runs entirely in the host; no persistent state.
- ❌ riddled with holes when: the protocol is not separated from the tool result (response splicing into
  guest data, prompt injection via the response back into the agent context), the host does **not**
  enforce an allowlist (the guest picks the target), no authenticity (any response can come from anywhere).
- **Verdict: half-okay as ad hoc, dangerous as infrastructure.** No audit standard, no
  budget; response integrity depends on the runner.

### W3 — Host sidecar process per run (container thinking transferred to WASM)

**How:** Alongside the sandbox runs a dedicated proxy/process (network namespace, allowlist, optionally
TLS re-signing) — the browser/container model ([INNOQ](https://www.innoq.com/en/blog/2026/03/dev-sandbox-network/),
[NemoClaw #307](https://github.com/NVIDIA/NemoClaw/issues/307)).

- ✅ stays isolated: the egress policy lies outside the guest's scope; centrally auditable.
- ❌ riddled with holes when: the sidecar defaults generously (`ALLOW ALL` instead of an allowlist, empirically
  the most common exception lever), certificates/secrets end up in the guest (MITM re-signing needs
  a trust anchor — [Agyn](https://agyn.io/blog/ai-agent-sandboxing-filesystem-network-isolation)),
  and when the sidecar hangs inside the sandbox's access domain (the sandbox can reconfigure sidecar settings
  via the shared FS — CBSE class).
- **Verdict: the right target model for MicroVM/container stacks; for Cell (WASM in-process)
  the network-namespace lever is missing — here P1 is the WASM-native equivalent.**

### W4 — Runtime fork / custom host imports with socket semantics

**How:** wasmtime is forked or patched via a feature flag so that the guest gets `socket_*`
imports (homegrown WASI sockets), sometimes with proxy wiring built into the import.

- ✅ stays isolated: technically nothing — if the import exists, the guest has a socket
  (capabilities are reinvented without an audit model).
- ❌ riddled with holes: firmware drift (every wasmtime update breaks the fork), no isolation-
  based permission model (fuel/limits do not cover sockets — the fuel inventory covers
  Preview1 only), the community standard is shattered instead of extended.
- **Verdict: to be rejected.** This is exactly what ADR-002 answers: controlled host imports
  are the way, but as a **generic, audited capability mechanism** (like the
  opt-in state import, ADR-004), not as a socket equivalent.

### W5 — "Softening" isolation via configuration

**How:** `allow_dirs=("/",)`, mark binaries as "trusted", `max_fuel=None` +
`io_cpu_seconds=None` + preopen the agent home, so that the guest can fetch/proxy itself
(read scripts, configs, SSH keys).

- ✅ stays isolated: nothing. This is the documented trusted mode.
- ❌ riddled with holes: everything — combinable with secret access → exfiltration
  ([Penligent](https://www.penligent.ai/hackinglabs/claude-code-sandbox-bypass/)).
- **Verdict: not a pattern but a misuse case.** The security baseline in the ExecutionReport
  (S2: `effective_preopens`, limits) makes exactly this visible — read the report, don't
  soften the boundaries.

### W6 — Spawn and tunnel abuse in the agent host (from the escape research)

**How:** The agent (not the guest) uses host capabilities — remote tunnels, config paths,
tool chains — to cross the sandbox boundary administratively
([NomShub/Straiker](https://www.straiker.ai/blog/nomshub-cursor-remote-tunneling-sandbox-breakout),
[Pillar](https://www.pillar.security/blog/the-week-of-sandbox-escapes)).

- ❌ riddled with holes: the host trust domain; the WASM guest is innocent.
- **Verdict: outside Cell's responsibility** (Cell cannot heal host-agent mistakes),
  but relevant for the pattern documentation: P1 (Part 2) must build the guest→host boundary so that
  it does not become the new CBSE weak point (the request document is UNTRUSTED input for the host).

## Pattern assessment (summary)

| Pattern | Isolation preserved? | Auditable? | Budgetable? | Verdict |
|---|---|---|---|---|
| W1 FS tunneling (raw) | partially | no | no | dangerous |
| W2 stdio RPC (ad hoc) | yes | rarely | no | ok for ad hoc |
| W3 sidecar proxy | yes | yes | yes | target model (not WASM-native) |
| W4 runtime fork/socket import | **no** | no | no | to be rejected |
| W5 configuration softening | **no** | visible in report | n/a | misuse |
| W6 host-agent abuse | n/a (host) | depends on host | no | outside Cell |

**Conclusion:** In 2026 there is no community standard for "sandboxed tool calls an API" that
unites isolation + audit + budget. The community builds W1–W3 dialects with the gaps
documented above. Cell's answer is the **host sidecar pattern P1** (Part 2): the good
idea from W1/W2 (request artifact across the boundary) with the discipline from W3 (allowlist,
validation, budget, audit trace in the ExecutionReport) — implementable without a runtime fork,
compatible with the WASI 0.3 timeline.

---

# Part 2 — Pattern specification

## P1 — Host sidecar pattern (recommended pattern for Cell)

**Principle:** The guest produces a **request artifact** as a file in its sandbox directory
(`/sandbox`, byte-budgeted and auditable per ADR-002). The **host** (MCP server, runner,
agent executor) reads the artifact AFTER the run, treats it as UNTRUSTED input, validates it
against an explicit policy, performs the API call itself, and produces a **response artifact**.
At no point does the guest have a socket or direct egress.

**Contract (request artifact `sidecar.request.json`):**

```json
{
  "url": "https://api.example.com/v1/weather?city=ber",
  "method": "GET",
  "headers": {"Accept": "application/json"},
  "body": null
}
```

- Strict schema: unknown top-level keys → rejection (fail closed).
- `headers` is an allowlist set (Content-Type, Accept); `Authorization` & Co. are set by the
  HOST (credentials stay in the host domain — the guest cannot exfiltrate them).
- Size: the request artifact is subject to the sandbox's `io_budget_bytes` wall.

**Policy (configured host-side, never guest-controlled):**

- `allowed_endpoints`: scheme + host + path prefix (e.g. `https://api.example.com/v1/`);
  URL matching exactly against these entries, no wildcard hosts, no userinfo in URLs,
  no redirects across host boundaries.
- `allowed_methods` (default: GET/POST), `max_response_bytes` (default 64 KiB), `timeout_seconds`.
- Every decision (allowed/denied) produces an **audit entry**; the mediator's responses
  carry `ok: false, error: "denied by egress policy"` instead of silent rejection.

**Audit trace:** Every mediated request is recorded as an entry (`url`, `method`, `status`,
`bytes`, `decision`, `elapsed_ms`) in the host's result context — in the MCP stack
naturally under `_meta` next to the ExecutionReport. The report attests the
sandbox boundary (S2: `effective_preopens`, budgets); the egress trace attests what
left the host.

**What stays isolated:** the guest without a socket, without host FS outside the capabilities, without
credentials. **What is deliberately NOT isolated:** the host-side execution (trusted),
the response data (untrusted CONTENT — the prompt injection risk lies with the agent context,
not with the isolation; the response artifact is versioned in machine-readable form).

**Why nothing else:** W4 (runtime fork with sockets) breaks the standard model, W1/W2
lack validation/audit/budget — P1 is W1/W2's idea with W3's discipline, implementable
without the namespace lever (ADR-002).

## P2 — WASI 0.3 outlook

- WASI 0.3 (2026-06-11) brings native async/streams for **Components** — relevant for
  state handling, not for sockets.
- Sockets/HTTP remain separate proposal tracks and are not stably bound in wasmtime-py.
  Until then ADR-002 applies: **no socket exposure**, P1 is the way.
- Outlook: if `wasi-http`/`wasi-sockets` stabilize in wasmtime-py, P1 can keep the same
  host-side policy core and swap only the transport (artifact → controlled
  host import) — the policy/audit layer is built transport-independently.
