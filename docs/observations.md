# Observation List — watch items with an exit condition, not worries

Status: **live, reviewed per release**
Document owner: Release & Quality Engineering
Last updated: 2026-10-04 (wasmtime-py 47.0.1; ADR-011/012/013 landed on main)

This page holds the two things this project is deliberately *not* acting on
yet, written so a future release can decide from evidence rather than memory.
An item leaves this list only when its exit condition is met — not when it stops
feeling concerning. Each entry states what we believe, what we measured, what
would change the answer, and the check that detects the change.

---

## O1 — astrid's enforcement maturity (they have the envelope; do they have the gate?)

**What they ship** (retrieved 2026-10-03, [comparison](comparison-mcp-servers.md)):
a signed, hash-linked audit chain across calls, ed25519 capability grants, and a
per-principal fuel ledger (`fuel_ledger.rs`).

**The thing to watch:** their own module comment scopes the ledger to
*"Scope today: TELEMETRY. `charge()` is the only mutator and there is no
read/deny path yet"* — as recorded, it does not refuse a run. At the same time
their changelog (`changes/1992.added.md`) documents a `--cpu-rate` quota setting
`max_cpu_fuel_per_sec`. The comparison therefore states it as found and does not
resolve the contradiction: **the ledger is evidenced, enforcement is documented
inconsistently** ([comparison §CPU cap](comparison-mcp-servers.md)).

That is a different axis from ours, not a weaker version of it: `--cpu-rate` (if
real) is a per-second rate limit, while ADR-012 is a cumulative all-time budget
that refuses *before* the run and bills what the run consumed. Neither claim
implies the other, and we should not let "we enforce" slide into "they don't".

**Why we do not copy or panic:** the audit-chain and per-principal-ledger ideas
are now matched in kind (ADR-011 chain; ADR-012 book + admission). Their
structural differences from us — components-only, installed through a daemon
plus FUSE/FSKit, versus a pip-importable library — are documented in the
comparison's §4.3 and do not change based on what they enforce.

**Exit condition — the contradiction resolves in either direction.** If their
source/README drops the "TELEMETRY" scope or documents a deny path, our
"enforced, not just recorded" line must become a specific comparison (cumulative
vs rate), not a general claim. If they confirm telemetry-only, the comparison may
say so once, dated — and still not as a permanent competitor fact.

**Check:** re-read `fuel_ledger.rs` scope, `--cpu-rate` and their README each
release; if anything moved, re-run the comparison's §4.3 and re-date every
"they only report / we enforce" sentence in
[README.md](../README.md) / [comparison](comparison-mcp-servers.md).

---

## O2 — the M2 engine wheel (patched wasmtime exists upstream; the Python binding lags)

**What we measured** (2026-10-02/03, [SECURITY.md](../SECURITY.md),
[CHANGELOG](../CHANGELOG.md)): the 2026 advisory wave — GHSA-j366-h8gg-77pm
(`poll_oneoff` host work charges no fuel, reproduced on our pin),
GHSA-96f6-r43r-8c24 (`fd_readdir` leaks host padding via any preopen),
GHSA-gqmc-89g8-p25r (no exposure: we always install bounded sinks), and
RUSTSEC-2026-0324. Upstream fixes land in the **48.0.4 / 49.0.2** engine lines —
the watcher's M2 target, deliberately **one step above** the advisory wave's own
48.0.3/49.0.1 fix line, because the 2026-10-02 wave is not closed at 48.0.3
(SECURITY.md).

**The gap:** `scripts/check_wasmtime_patch.py` on 2026-10-04 reports
**48.0.4, 49.0.2 and 47.0.4 all "(noch nicht auf PyPI)"**. There is no wheel to
install, so there is nothing to upgrade to; the hardened interim posture (pin
47.0.1, proposals enforced-off, the `poll_oneoff` and preopen facts documented
rather than papered over) stays active.

**Why we do not build on a source patch:** the engine is reached through
wasmtime-py; carrying a private patched build would diverge our "every number on
this page is a Cranelift number" attestation from what anyone else can install,
and is a larger honesty risk than waiting one wheel release.

**Exit condition — a patch wheel exists and passes M2.** When
`check_wasmtime_patch.py` stops exiting 1: install the patched line, re-run the
full gate (tests + `verify_8_vectors.py` + the `poll_oneoff` and
component-sync probes, which are self-checking), and only then retire the
"host work inside a WASI call is uncharged" qualifier from SECURITY.md — the
probe exits non-zero the day that line changes, so we cannot forget it.

**Check:** `scripts/watch_upstream.py` / `check_wasmtime_patch.py` exit code in
CI (a waiting state exits 1 by design, so a green watcher *means* a wheel is
there); re-measure the `poll_oneoff` fuel curve on the new pin before claiming
the advisory is closed for us.
