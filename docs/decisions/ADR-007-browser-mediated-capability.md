# ADR-007: Browser Interaction Is Out of Scope by Design — Mediated Capability via Host Sidecar

- **Status:** Accepted
- **Date:** 2026-09-05 (reviewed internally; recorded here to prevent
  re-litigation)
- **Predecessor:** ADR-002 (I/O Budget + Egress Model)

## Context (structural, not a gap)

Cell constrains guest CODE: fuel, memory, wall clock, output caps,
deny-by-default filesystem. A browser interaction — a click on "Send",
typing into a page — is not guest compute. There is nothing for Cell to
meter: no WASM instruction consumes fuel, no host syscall carries the
action. A browser click is therefore OUTSIDE Cell **by design**, not
missing functionality.

## Decision

1. **No browser inside the sandbox.** Cell will never embed, spawn, or
   proxy a browser engine as guest code. Nothing changes in the sandbox
   core.
2. **Mediated capability, same pattern as egress (ADR-002):**
   - the guest writes a `browser.request.json` into `/sandbox`
     (structured request: URL allowlist hint, action, payload);
   - the host validates the request against an operator-owned allowlist;
   - an ISOLATED browser VM (separate host process/VM, never the guest)
     executes the action and writes an audit trace;
   - no socket ever touches the guest — the guest sees only the request
     file and (optionally) a bounded result file.
3. **Hybrid delivery:**
   - a small **reference sidecar** ships in an open-source Cell release
     to prove the pattern end to end (measured, with the honesty gate:
     claimed only after it runs in CI);
   - a **governed enterprise module** (fleet orchestration, evidence
     custody) stays on the Ephemora side and is NOT documented in this
     repository (IP posture: Cell = measured primitives; Ephemora =
     custody/evidence recipes).

## Why this keeps the model clean

- **Cell stays pure:** one job — meter and bound guest code. A browser
  has unbounded, un-meterable host semantics; folding it in would break
  the "Verified. Not claimed." accounting.
- **The chain stays auditable:** request file → host validation →
  isolated executor → audit trace is the same auditable hop the egress
  mediator already established.
- **No new trust surface:** the guest cannot reach the browser VM — not
  via sockets (none exist), not via the filesystem (deny-by-default,
  `/sandbox` request files only), not via the environment.

## Consequences

- Marketing/docs may describe browser interaction only as *mediated,
  host-side* — never as a Cell feature, until the reference sidecar
  ships with numbers.
- The reference sidecar follows the ADR-006 trust shape: the agent
  proposes via request file; the host validates against allowlists;
  every accepted/denied request is traceable.
