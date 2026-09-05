# ADR-006: Governed Dynamic Tool Loading (Request-File, Verify-Before-Register)

- **Status:** Proposed (implementation targeted after 1.0.1)
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
