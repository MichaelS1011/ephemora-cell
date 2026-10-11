# ADR-014: Effective-Enforcement Attestation — Signed Evidence Describes What Held, Not What Was Configured

- **Status:** Accepted
- **Date:** 2026-10-11

## Context

A signed `security_baseline` attests the *configured* posture of a run, and a
signature proves the exact bytes it covers. But a configured knob is not the
same as a wall that actually held on the path the guest executed. Two risk
entries from the CTO working-backwards programme (docs/program/07) turned on
this gap:

- **R-06** — a receipt did not say whether the guest ran in-process (documented
  walls only) or in the isolated subprocess worker (OS walls: RLIMITs, per-file
  disk quota, rusage watchdog, hard kill). A verifier had to *infer* the
  guarantee from the deployment.
- **R-07** — `allow_fsync: false` was attested on **every** ABI, but the WASI
  sync blockade (P1 #12) exists **only on the preview1 path**: the sandbox
  traps `fd_sync`/`fd_datasync`/`fd_psync` at the call layer there. The WASI 0.2
  component path links `wasi:filesystem` through `Linker.add_wasip2()`, where no
  such trap exists. A component run signing `allow_fsync: false` therefore
  attested a durability wall its execution path never carried.

The attempted fix for R-07 — installing a call-trap on the component path via a
`Linker` shadow of `[method]descriptor.sync` — was **measured and rejected**
(2026-10-11): wasmtime-py 47 accepts the shadow and instantiates, but the guest
sync still reaches the host, so the shadow is silently ineffective. Simulating a
control that does not bite would itself be a false attestation. The decision was
therefore to make the *claim honest* rather than make the *path falsely equal*.

## Decision

**Signed evidence must describe effective enforcement, not merely configured
intent.** The signed baseline gains three additive, host-side runtime facts
(derived at the source, never trusted from a guest or inferred by a reader):

1. `execution_mode ∈ {in_process, subprocess}` — the isolation path that actually
   ran the guest (R-06).
2. `abi ∈ {preview1, component}` — the ABI actually executed. Under `auto`, the
   ABI resolved from the binary's magic bytes, never the requested mode (R-07).
3. `sync_blockade_enforced: bool` — whether the sync blockade was actually in
   effect, derived from the single-source predicate `sync_blockade_holds(abi,
   allow_fsync)`. Truth table (the only sanctioned rows):

   | Execution | `allow_fsync` | `sync_blockade_enforced` |
   |---|---|---|
   | preview1 | `false` | `true`  |
   | preview1 | `true`  | `false` |
   | component| `false` | `false` |
   | component| `true`  | `false` |

Supporting rules, binding:

- **Fail-closed.** A missing or unprovable enforcement status is NEVER read as
  `true`. `effective_sync_blockade(baseline)` returns `False` for a legacy record
  without the field; only an explicit `true` counts as blocked. An unknown `abi`
  or `execution_mode` is refused (`ValueError`) rather than stamped.
- **Backward compatibility (WP-L4-2 pattern).** The fields are opt-in: a run that
  resolves no ABI leaves them absent, so existing canonical bytes stay
  byte-identical and no historical signed record changes shape. Verifier
  semantics are pinned: legacy records carry NO enforcement guarantee and must
  not be retro-read as one.
- **No silent downgrade.** `WASISandbox.run(require_sync_blockade=True)` refuses,
  BEFORE any spawn/compile, a run whose path cannot enforce the blockade. This is
  not a component ban — legitimate component workloads (including `componentize-py`)
  run unchanged unless the caller names the guarantee they cannot meet.
- **Claim ≠ truth.** A valid signature still proves only the integrity of the
  record's statements, not their real-world correctness; the record now states
  correctness conditions (`sync_blockade_enforced`) so a verifier can act on them.

## Consequences

- Positive: R-06 and R-07 close on evidence — a receipt can no longer claim a
  sync blockade a component run never enforced, and direct/subprocess/auto paths
  attest consistently. The preview1/component sync asymmetry is a first-class,
  signed fact, not a documentation footnote.
- Accepted limitation (kept explicit, NOT faked as covered): the component path
  still has no sync blockade. This ADR makes that *honest and machine-checkable*;
  a real component-side trap would require an engine capability wasmtime-py 47 does
  not expose, and is deferred to the M2 engine line (see ADR-013 WASIp3 gate-off
  posture and `scripts/check_wasmtime_patch.py`).
- Test surface: `tests/test_sync_enforcement_attestation.py` (behavioural truth
  table incl. real blocked/reached sync, component write reaching the host, auto
  resolution, subprocess source-stamp, the strict gate) and
  `tests/test_execution_report.py::TestSyncBlockadeEnforcement` (signing, tamper
  flips of `abi`/`sync_blockade_enforced`, legacy byte-identity).
- Reversible? No — the fields are additive and opt-in, so removing them would only
  reduce attestation, never widen a guarantee; but the honesty invariant (a claim
  must match enforcement) is a permanent posture, not a toggle.
