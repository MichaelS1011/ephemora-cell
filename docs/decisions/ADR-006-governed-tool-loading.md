# ADR-006: Governed Dynamic Tool Loading (Request-File, Verify-Before-Register)

- **Status:** Adopted (2026-09-12, decision D1) — the verify-before-
  register gate (`tool_registry.sign_manifest`/`verify_manifest` over
  RFC 8785 JCS, signed-tools registry enforcement fail-closed, server
  flag `--require-signed-tools`, `sign_tool` utility) AND the request-
  file loading loop (`--tool-requests-dir` + `Server.process_tool_requests`
  with path allowlist, module-hash binding via `wasm_sha256`, rescan +
  `notifications/tools/list_changed`). Remaining: operator-facing
  integrations (watcher daemons, registry pull) build on the same gate.
- **Date:** 2026-09-05
- **Context:** MCP clients surface per-server tool pickers and meta tools
  (see Microsoft Wassette's `list-components` / `load-component` /
  `grant-*-permission` surface); the MCP adapter already ships one native
  read-only meta tool (`get-policy`, ADR-free additive in 1.0.1)
- **Predecessor:** ADR-002 (Egress Model), `ExecutionReport.sign()`
  (SEP-2787-style signing primitive, present since 1.0.0)

## Context

`ToolRegistry` scans the tools directory once at server start
(`ephemora_cell_mcp/tool_registry.py`); the tool set is frozen for the
lifetime of the process, and `initialize` advertises
`listChanged: False`. Agent users ask for runtime tool management —
loading a new `.wasm` tool without restarting the server. The naive
version of this (an MCP tool that copies any file from anywhere into the
tools dir) moves the trust decision into the chat session: a
prompt-injected agent could install attacker-controlled tooling
mid-session. That is precisely the install-time trust decision Cell's
model keeps OUT of the guest.

## Decision

1. **Capability changes are host decisions, not chat decisions.** The
   agent proposes; the host disposes. There is no agent-callable
   `grant-network-permission` / `grant-storage-permission` (see the
   position below) and no unrestricted `load-component`.
2. **Load via request file, same pattern as the mediated browser
   capability (ADR-007) and the egress sidecar:** the guest or client
   writes a `tool.request.json` into `/sandbox` (or the operator drops a
   signed artifact into an allowlisted directory). The HOST validates:
   (a) path allowlist, (b) SEP-2787-style signature over the module
   (verify-before-register — the same gate a future OCI registry pull
   must pass), (c) registry policy (profile can only be narrowed by
   sidecar, never widened — existing `_config_for` rule).
3. **On success** the server rescans the registry, emits
   `notifications/tools/list_changed`, and flips the `initialize`
   capability `listChanged: True` once loading is enabled.
4. **Read-only introspection ships first** (`get-policy`, 1.0.1): the
   agent can SEE effective policy (fuel, memory, preopens configured,
   network policy, wasmtime version — derived from the same
   `_config_for()` path execution uses, so report and enforcement cannot
   drift) but cannot CHANGE it.

## Position: why no `grant-*-permission` meta tools

Wassette exposes network/storage grants as chat tools. Cell structurally
cannot and should not: the WASI surface exposes no socket APIs (network
is not a grantable capability, only a host-side mediator policy —
ADR-002), and filesystem preopens are deny-by-default with sidecar
narrowing. Making grants agent-callable would convert the security
boundary into a prompt-surface. Policy READS are tools; policy WRITES
are host operations with an audit trace.

## Consequences

- `get-policy` (read-only) is safe to ship now; load/unload follow the
  request-file gate above and land with signature verification.
- Dynamic loading changes the failure model of `tools/list` (rescan can
  fail); rescan errors must be reported as `isError` results, never as
  silent empty registries.
- Trust moves to artifacts, not to the session: an untrusted request
  file is inert by construction.

## Amendment (2026-09-25): atomic publication & per-call module binding

The verify-before-register gate verified bytes at scan/install time but
bound only the PATH: the registry stored no digest, execution re-read the
file on every call, and nothing prevented a partially-written file from
being registered. Two hardenings close this, Wassette-load-path class:

1. **Atomic publication (producer side).** Every producer that publishes
   into a tools/ or requests directory writes through
   `ephemera_cell._fsutil` (temp file in the destination directory +
   fsync + `os.replace`): the governed-load install (sidecar FIRST,
   module LAST — a racing scan only ever sees a bare `.wasm`, which
   signed-tools mode rejects), `sign_tool`'s manifest rewrite, and the
   rust builder's `--out` publish. The governed install reads the module
   once and hashes the in-memory copy (`tool_wasm_sha256_bytes`), so the
   verified digest and the installed bytes cannot diverge.
2. **Consumer load-guard + per-call binding.** `ToolRegistry._build_spec`
   registers only settled modules (two reads agree), with wasm magic and
   within the subprocess size cap. In signed-tools mode the spec carries
   the register-time digest (`ToolSpec.wasm_sha256`) and EVERY execution
   binds to it: `WASISandbox.run(expected_sha256=...)` reads the bytes
   once, verifies them and compiles exactly those bytes — preview1,
   component and subprocess worker paths alike. A swapped on-disk file
   fails closed with "module hash mismatch" instead of executing.
   Legacy (unsigned) mode deliberately keeps the disk-truth convention:
   the file on disk is the authority, the sidecar is metadata only.
3. **Content-keyed module cache.** `EnginePool` keys compiled modules by
   content hash instead of (path, mtime, size): a swap can neither
   poison an entry via the old stat-then-open race nor serve a stale
   module for a mtime-preserving replacement (`cp -p`).
4. **Deferred, never half-parsed.** Request files that are not yet
   settled are deferred to the next tick (`pending` in the report, key
   present only when non-empty) instead of emitting transient
   rejections.

Consequences: the request-file REPORT shape gains an optional `pending`
key (additive); `ToolSpec` gains an optional trailing field;
`WASISandbox.run` gains a keyword-only `expected_sha256`; the module
cache key changes (internal). All previously documented contracts —
request-file format, CLI flags, `sign_manifest`/`verify_manifest` — are
unchanged.
