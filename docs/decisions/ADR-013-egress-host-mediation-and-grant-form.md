# ADR-013: Egress Goes Host-Mediated — a Real Caller, a Form-Only Grant

- **Status:** Accepted
- **Date:** 2026-10-04
- **Predecessors:** ADR-002 (per-run I/O walls and the host-sidecar egress
  pattern), ADR-008 (record split, frozen schemas), ADR-011 (chain across runs),
  ADR-012 (tenant attribution — the same single-writer discipline)
- **Basis:** A Security-Architecture review of `ephemora_cell/egress_sidecar.py`
  and the MCP call path on 2026-10-04, which found the mediator had **no
  production caller**: `mediate`/`execute_request`/`run_sidecar_cycle` were
  imported only by `tests/test_egress_sidecar.py`, never by
  `ephemora_cell_mcp/`.

## Context (verified, not assumed)

1. **The guest cannot reach the network, and that is the enforced property.**
   WASI Preview1 and the Cell's component linker expose no socket API and never
   link `wasi:http` (`SECURITY.md`, pinned in `tests/test_surface_audit.py`).
   A tool that needs an API writes `sidecar.request.json` into its own sandbox
   dir; nothing in the sandbox makes an outbound call.
2. **The mediator was correct but dead.** G-A (the redirect-revalidation and
   segment-prefix fixes) is landed and measured. But a policy that no shipped
   code path executes is exactly the "documented, not enforced" surface this
   product criticises in others — shipping a *grant control layer* on top of it
   would have widened, not narrowed, that gap.
3. **There is no synchronous egress inside a run.** Mediation reads the
   artifact AFTER the guest exits, so a guest cannot block on a response within
   the same run — confirmed by the same reasoning that bounds ADR-002's I/O
   walls. Response delivery to a follow-up run is therefore a host concern
   (state store or an explicit preopen), not something this trace provides.
4. **Sandbox lifecycle forces an ordering.** The MCP engine runs a fresh sandbox
   per call and `cleanup()` removes the dir. Mediation must therefore happen in
   `execute()` after `run()` and **before** `cleanup()`, or the artifact is
   already gone.

## Decision

1. **Give the mediator a real caller: the MCP engine, opt-in.**
   `CellToolEngine.__init__` takes an `egress_policy: EgressPolicy | None`
   (`ephemora_cell_mcp/engine.py`); `__main__.py` exposes it as
   `--egress-allow URL_PREFIX` (repeatable) + `--egress-timeout` +
   `--egress-max-response-bytes`. When set, `execute()` calls
   `_mediate_egress(result.sandbox_dir)` before cleanup; the resulting decision
   (audit fields + response document) rides on `CellOutcome.egress`.
2. **Absent policy or absent artifact is byte-silent.** With no policy, or with
   no `sidecar.request.json`, `execute()` produces the same `_meta` it always
   did — the `egress` key is added only when a decision actually happened. A
   present-but-malformed artifact is NOT silent: the mediator parses untrusted
   bytes fail-closed and emits a `denied` audit entry, so a broken request
   surfaces instead of disappearing.
3. **The decision is surfaced, not just logged.** `_build_call_result` attaches
   `_meta["egress"] = [...]` when present (read via `getattr`, so an
   outcome without the field is simply "no egress"). This is the MCP-visible
   proof of what the host allowed or refused and why.
4. **The grant is frozen as a FORM, not a control.** `EgressGrant`
   (`egress_sidecar.py`) fixes the envelope — `grant_id`, `tool`,
   `allowed_endpoints`, `allowed_methods`, `not_before`, `not_after`,
   `max_calls`, `key_id` — and a JCS `canonical_bytes()` recipe identical to
   every other record. But ONLY the endpoint/method allowlist is real today:
   `to_dict()` carries `"enforced": "allowlist-only"` in its own payload, and
   `policy()` returns exactly that enforced subset. **Expiry, usage caps and
   revocation are recorded, not checked** — no shipped code compares them to a
   clock, a counter or a revocation list.
5. **Usage bookkeeping is deliberately NOT reused from ADR-012.** When grant
   enforcement lands, it wants its own single-writer book (`_appendlog`), not
   `TenantStore`: a tenant bills compute, a grant bounds egress, and coupling a
   revocation to the other axis's book is a dependency that buys nothing.

## Consequences

**Gained**

- `egress_sidecar` moves from a reference module to a path a shipped server
  executes when the operator asks — the honest precondition for ever calling it
  a control.
- Every mediated call leaves an audit line under `_meta`, with the allowlist
  entry matched or the reason refused, and (post-G-A) the redirect hops
  actually attempted.
- `get-policy` reports a server-wide `egress` attestation in both shapes:
  `{"mediation": "disabled"}` by default, the enabled endpoints +
  `enforced: "allowlist-only"` for a plain policy, and `grant_enforcement:
  "ledger-backed"` with the per-grant window/cap/revocation state when a grant
  and a `GrantLedger` are wired. An operator can read from the control plane
  exactly which gates are real.
- **Grant enforcement landed (Prio 1).** `ephemora_cell/grant_ledger.py`
  (`GrantLedger`) is the consumer that reads `not_before`/`not_after`/`max_calls`
  and honours a revocation. `egress_sidecar.mediate_with_grant` gates a request
  through it, and `CellToolEngine`/`Server` route a tool's grant through that
  path (revocation/window/cap decided and charged in one critical section,
  mirroring `TenantStore.admit`). A request denied by the allowlist never
  reaches the ledger, so a denied call spends no grant slot.
- **DNS-rebinding closed at resolve time (Prio 2).** Every mediated connect —
  the request and each followed redirect — resolves its hostname through a
  thread-local `socket.getaddrinfo` shim that drops loopback, RFC1918, CGNAT
  (100.64/10), link-local, multicast, reserved and unspecified addresses; a name
  with no public answer is refused. Validate and connect share the one
  `getaddrinfo` call, so there is no window for the answer to rebind between
  check and use — the residual the redirect revalidation left open. An
  IP-**literal** allowlist entry is operator intent and stays reachable (a
  deliberate `--egress-allow http://127.0.0.1:PORT` still works).

**Accepted costs and limits (stated, not hidden)**

- **Default off.** No deployment mediates unless it passes `--egress-allow`.
  A tool that writes a request artifact in a deployment without the flag gets
  no mediation and no `_meta.egress` — the artifact simply goes unread with the
  sandbox.
- **The grant object is enforced only with a ledger attached.** A bare
  `EgressGrant` whose fields nobody reads is still just an allowlist — so
  `CellToolEngine` refuses to construct with `egress_grants` but no
  `grant_ledger` (fail-closed), rather than silently downgrading a cap or an
  expiry to nothing. With a ledger, `max_calls` is inclusive (N admits N, not
  N+1) and window bounds are parsed fail-closed (a naive/offsetless timestamp
  is refused, not assumed local).
- **Grant SIGNATURE verification is still open.** Grants now reach the engine
  from the shipped CLI (`--egress-grants-dir DIR --grant-ledger PATH`, loaded
  fail-closed by `egress_sidecar.load_egress_grants`), but that loader does NOT
  authenticate the envelope — a file the host reads is operator intent. The
  loader that verifies each grant's Ed25519 signature (reusing the
  `verify_manifest` path with `alg` pinned) and refuses a grant that does not
  verify is not wired in. Until it is, do not claim "signed grants are verified".
- **Revocation is per mediated call, not in-flight.** The correct wording is
  "effective at the next mediated call; already-delivered response artifacts
  are not recalled" — never "instantly revocable".
- **Response delivery across runs is unresolved.** The response artifact is
  written into a dir that cleanup removes; a follow-up run cannot see it. That
  needs a persistent surface (state store or explicit preopen) and is out of
  scope here.
- **SSRF filter applies to hostnames, not IP literals (by design).** An operator
  who allowlists `http://127.0.0.1:PORT` or a private IP literal meant it — that
  path stays reachable. The rebinding surface (a NAME whose A record moves into
  private space) is closed by the resolve-time filter; a name resolving only to
  forbidden space is refused.
- **The guard was vetting the wrong host when a proxy sat in the environment
  (found and closed 2026-10-04).** With `http_proxy` set, urllib does not resolve
  the URL host at all — it resolves and connects to the PROXY, so the shim was
  asked for `('proxy.internal', 8080)` for a request aimed at `api.example.com`.
  The filter then proved something about the proxy and nothing about the target,
  and the "checked IP == connected IP" claim was void. `execute_request` now
  builds its opener with `ProxyHandler({})`: a mediated egress goes direct to the
  allowlisted origin. A deployment that needs an egress proxy must make that an
  explicit configuration decision; inheriting it from the ambient shell is where
  the bypass lived. Pinned by
  `TestSSRFAdversarialFamilies::test_ambient_proxy_env_does_not_move_the_resolution_target`.
- **Adversarial coverage of the filtered families (2026-10-04).** Beyond
  loopback: scoped IPv6 link-local (`fe80::1%eth0`), both cloud-metadata
  addresses (169.254.169.254 / 169.254.170.2), the CGNAT edges, IPv4-mapped IPv6
  (`::ffff:127.0.0.1`), 6to4 and NAT64 prefixes that embed a private v4 address,
  multicast, unspecified and the documentation ranges — with a public positive
  control that includes the deliberate case `::ffff:8.8.8.8` staying reachable
  (the guard refuses the family an address MAPS to, not the notation). A
  redirect that introduces a second NAME after the first answer was already
  vetted is tested against a real 302 into an allowlisted name answering with
  the metadata address. Multi-A: private siblings are dropped in order, an
  all-private answer fails closed.
- **Pinning is asserted at the OS boundary, not inferred.**
  `TestResolvePinningTOCTOU` intercepts the socket the stdlib builds from the
  filtered addrinfo list, so the tests show which addresses `connect()` was
  actually handed: one resolution per hop, no private sibling among them.
  Degrading the filter (returning the unfiltered list) turns five of these tests
  red — they are gates, not documentation.

## Roadmap (remaining, not in 1.1)

Grant ENFORCEMENT (window/cap/revocation via `GrantLedger`, critical-section
charge mirroring `TenantStore.admit`) and the resolve-time SSRF filter are both
landed. What remains:

- **Signed-grant verification.** The CLI loader reads grants and enforces them,
  but does not yet verify the Ed25519 signature. What remains is a startup path
  that checks each envelope's signature (reusing `tool_registry.verify_manifest`
  with `alg` pinned) and refuses a grant that does not verify — so a grant is
  trusted by its signature, not only because the host passed the file in.

That is the one remaining egress claim not yet earned: the enforcement and the
resolve-time boundary are real; the grant's authentication on the startup path
is not.

## Evidence

- `ephemora_cell_mcp/engine.py` (`egress_policy`, `_mediate_egress`, the
  before-cleanup call in `execute`), `ephemora_cell_mcp/server.py`
  (`_build_call_result` → `_meta["egress"]`), `ephemora_cell_mcp/__main__.py`
  (`--egress-allow`), `ephemora_cell/egress_sidecar.py` (`EgressGrant`,
  `GRANT_SCHEMA_VERSION`).
- **Enforcement (Prio 1):** `ephemora_cell/grant_ledger.py` (`GrantLedger`,
  `record_call`/`revoke`/`usage`/`verify`, `_apply` tamper fold),
  `egress_sidecar.mediate_with_grant` (allowlist-before-charge ordering), and
  the engine routing (`CellToolEngine(egress_grants=…, grant_ledger=…)`,
  `Server(egress_grants=…, grant_ledger=…)`). Tests: `tests/test_grant_ledger.py`
  (18 — inclusive cap under 20 contending threads, refusal spends no slot,
  `not_before`/`not_after` boundary-exclusive, `Z` accepted / naive refused,
  revocation within an open window, edited or dropped call line caught, the
  truncated tail NOT detectable from the file alone), and
  `TestEngineGrantEnforcement` in `tests/test_egress_sidecar.py` (grant charges
  each fetch and stops at the cap; revocation refuses; an off-allowlist request
  spends no slot; grants are keyed by tool name; grants-without-ledger fail
  closed at construction).
- **SSRF (Prio 2):** `egress_sidecar._guarded_getaddrinfo` / `_ip_blocked` /
  `_egress_context` and `EgressPolicy.resolver`; the guard wraps `socket.getaddrinfo`
  only for the duration of a mediated fetch on that thread. Tests:
  `TestSSRFGuard` in `tests/test_egress_sidecar.py` (the blocked-address matrix
  incl. CGNAT; the shim drops forbidden IPs and raises when none are safe; an
  IP-literal host passes unfiltered; `mediate` denies a name that rebinds to
  `169.254.169.254` with `limit: "ssrf"` and opens no socket).
- `tests/test_egress_sidecar.py` — `TestEngineEgressTrace` (no policy is silent;
  no artifact is silent; an on-policy request is mediated against a local server
  and the response artifact written; an off-policy request is denied and never
  fetched; a malformed artifact denies rather than goes quiet; `execute()`
  mediates before `cleanup()`, proven by the response artifact existing at
  cleanup time), `TestServerMetaEgress` (`_meta` shape unchanged with no
  egress; the decision appears under `_meta.egress` when present), and
  `TestEgressGrantForm` (canonical bytes stable and field-sensitive; `policy()`
  is the allowlist; the `enforced: "allowlist-only"` marker is in the payload;
  expiry/cap are constructible but not validated as controls).
- `tests/test_mcp_adapter.py` — `test_get_policy_reports_egress_disabled`
  (both get-policy shapes attest mediation off by default) and
  `test_get_policy_reports_egress_enabled_as_allowlist_only` (a wired policy
  discloses endpoints, caps and `enforced: "allowlist-only"`).
