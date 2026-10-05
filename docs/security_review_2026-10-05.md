# Security review 2026-10-05 — what the red-team lanes found and what they did not

**Scope.** Six read-only lanes attacked the 1.1.0 release candidate from the
outside: authority semantics, filesystem paths, egress/SSRF depth, cryptographic
semantics, product invariants, and the MCP protocol surface. Lanes were forbidden
from editing the tree; every finding below is either fixed with a test that bites
(verified by degrading the fix and watching it go red) or listed under *not closed*
with the reason. This document is the boundary of what 1.1.0 claims.

**Method, because it matters more than the list.** Each lane ran against the real
code on the release SHA, not against the docs: live mediators against local HTTP
origins, real Ed25519 envelopes, guests executed through the sandbox, the server
driven as a subprocess with raw NDJSON. A finding counts only with a payload or a
line number. Where a lane's claim turned out to be wrong under measurement, it is
recorded as wrong (two cases below) — a review that is never wrong about anything
has not been checked.

---

## Closed on this branch

| # | Finding | Severity | Fix | Gate |
|---|---|---|---|---|
| 1 | Guest-created **relative symlink** at `sidecar.response.json`; the mediator wrote through it → arbitrary host file write as the server user (WASI refuses absolute targets, accepts relative) | P0 | `O_NOFOLLOW` + regular-file check on the descriptor actually obtained + atomic publication for every host-side touch of a guest-writable name | `tests/test_host_file_boundaries.py` |
| 2 | Grants directory unreadable or empty → **zero authorities installed**, zero errors, `get-policy` still attesting "every grant file verified" (`Path.glob` swallows `OSError`) | P0 | enumerate with `scandir`, surface the error, refuse an empty grants directory (loader and CLI) | `tests/test_grant_trust.py`, `tests/test_mcp_main.py` |
| 3 | Symlink/swap of the ledger, trust root or grant file silently resets caps, windows and revocation | P1 | same no-follow rule for `_appendlog`, `GrantTrustRoot.load`, `load_egress_grants` | `tests/test_grant_ledger.py`, `tests/test_grant_trust.py` |
| 4 | Corrupt or unwritable ledger raised **past** the mediator → fetch denied but no audit line, no `_meta.egress`, one bad line switched off every grant | P1 | audited denial with `limit: "ledger"`; `get-policy` degrades to `ledger_state: "unreadable-for-some-grants"` instead of dying | `tests/test_grant_ledger.py`, `tests/test_mcp_adapter.py` |
| 5 | `http.client` exceptions (tab-in-authority `InvalidURL`, >100 headers, junk status line) escaped `mediate()`: no decision recorded at all | P1 | caught, audited as denials with `limit: "transport"` | `TestTransportWalls` |
| 6 | `timeout_seconds` bounded one socket op → trickling peer pinned a host thread, per hop | P1 | one wall-clock deadline for the whole fetch, non-blocking `read1` chunking | `TestTransportWalls::test_wall_clock_deadline_stops_a_trickling_peer` |
| 7 | Redirect trail recorded a hop the stdlib refused to dispatch, entry read `allowed, fetch failed` | P2 | loop limits mirrored before recording; reaching them is a denial naming the hop | `TestTransportWalls::test_a_hop_the_loop_limit_refused_is_not_reported_as_followed` |
| 8 | `http://:@host` passed the userinfo check (empty username is falsy); `:@` reached the `Host:` header | P2 | any `@` in the netloc is refused | `TestTransportWalls::test_empty_userinfo_is_refused_not_mangled` |
| 9 | One undecodable stdin byte killed the server (rc=1, buffered responses lost) | P1 | transport reads bytes, decodes with replacement → `-32700`, keeps serving | `tests/test_transport.py`, `tests/test_mcp_adapter.py` |
| 10 | Oversized-line cap applied **after** buffering (40 MB without newline → ~87 MB RSS) | P2 | cap applied while reading | `tests/test_transport.py` |
| 11 | Leftover bytes after a line boundary were dropped → one read carrying two messages answered only the first | P1 | carry buffer | `tests/test_transport.py` |
| 12 | `NaN`/`Infinity` request ids echoed back produced a frame strict parsers reject | P2 | non-finite ids refused at the edge; `allow_nan=False` on send | `tests/test_transport.py` |
| 13 | Host traceback (`site-packages`, absolute paths) handed to any client as `stderr` | P1 | `ExecutionResult.host_traceback`; client sees the message only | `tests/test_host_file_boundaries.py` |
| 14 | Guest stdout `{"status":"success-fake"}` overwrote host fields inside the error document | P2 | host facts merged last | `tests/test_mcp_adapter.py` |
| 15 | `cleanup()` used `rmtree(ignore_errors=True)` and reported success over a surviving sandbox; unreadable capture reported as empty output | P1 | residue returned and logged; capture failure said in the string | `tests/test_host_file_boundaries.py` |
| 16 | DSSE entries declaring `alg` were ignored; a receipt verifier accepted **any** payload type (grant envelope as receipt) | P2 | declared `alg` checked; receipt audiences pinned | `tests/test_signed_receipt.py` |
| 17 | Non-canonical base64 in a grant envelope (same bytes, two spellings) | P2 | canonical base64 required | `tests/test_grant_trust.py` |
| 18 | Unreconstructable grant payload raised bare `ValueError` past a caller catching `GrantTrustError` | P2 | wrapped | `tests/test_grant_trust.py` |
| 19 | Governed tool-request evaluation swallowed its report | P2 | logged (`serve` now warns instead of `pass`) | none — observability, and the swallow was the bug; no gate claims it |
| 20 | Request artifact read unbounded before the size check | P2 | bounded at the read (1 MiB) | `tests/test_host_file_boundaries.py` |
| 21 | The pooled execution path — the one where reuse is the risk — was **never exercised** by the statelessness test, because the default byte wall forces a per-run engine | P1 | invariants lifted deliberately, engine identity asserted stable | `tests/test_execution_invariants.py` |

**Packaging, from the clean-room lane (P1, closed):** installing the sdist alone
in `python:3.12-slim` and running the suite it ships produced **65 failures** —
the sdist carried `tests/*.py` but not `conftest.py` and not the
`tests/fixtures/*.wasm` those tests need, and six modules put their grant-safe
scratch under `$HOME`, which is `/root` in a container and therefore correctly
refused by the denylist. After shipping the fixtures (`MANIFEST.in`), resolving the
tool directory from the imported package, and moving fixtures to a temp root:
**803 passed / 102 skipped / 0 failed** as root on linux/amd64, with the
repository-inspection modules skipped by name and stated reason rather than
failing. `tests/conftest.py` records the rule: the suite is written for a
checkout; what can run from an installed artifact does, and what cannot says why.

Two **lane claims that measurement refuted**, kept here because the reviewer is
owed the correction, not silence: the case-variant preopen bypass (`/ETC`) is
already closed by canonical-path comparison — `realpath("/ETC")` returns the
stored case on APFS — and the "grant re-signature after edit" attack is covered by
the canonical-payload pin; both are now pinned by tests instead of by prose.

## Measured, not asserted

`benchmarks/statelessness_probe.py` →
`benchmarks/results/2026-10-05/statelessness_invariants.json`: 1000 consecutive
run-pairs (A writes a marker to its scratch, to stdout, into a generated
identifier; B tries to see it) on the pooled path (0 leaks, 2000 distinct sandbox
directories, 1.16 ms/pair), the per-run-engine path (0 leaks, 1.995 ms/pair) and
the isolated-subprocess path (0 leaks, 107 ms/pair). 40 audit books whose writer
was SIGKILLed mid-append were all self-consistent, 0 silently wrong. A positive
control proves the reader detects a legitimately present marker.

Suite on this SHA: **929 passed / 4 skipped (933 collected)**, 90 % statement
coverage; minimal install without `cryptography`: 824 passed / 66 skipped
(890 collected), 81 %.

## Closed after the review by operator decision

Three of the open items below were posture questions, not defects, and the
operator decided each one on 2026-10-05. Every one of the four new gates was
proved to bite by deleting the enforcement and watching only its own tests go
red (degradation, not coverage):

| Decision | Semantics now | Gate | Red when the enforcement is removed |
|---|---|---|---|
| **D2** — grant scope | A signed grant is intersected with `--egress-allow`: the ceiling is validated **before** the ledger charges, so a granted endpoint outside the operator's list is denied (`limit: "server-policy"`) and spends no slot. With no server-wide list the grant is the whole authority | `TestEngineGrantEnforcement.test_a_grant_never_widens_the_server_wide_allowlist` (+ its positive control) | 1 test |
| **D1** — ungranted tools | `--egress-grants-required` denies mediation for a tool with no grant (`limit: "grant-required"`) instead of falling back to the allowlist; default stays off, and `get-policy` discloses the live posture as `ungranted_tools`. Constructing an engine with the flag and no grants raises | `test_grants_required_denies_an_ungranted_tool_without_falling_back`, `…_still_mediates_a_granted_tool`, `TestGrantScopeDisclosure` (4), `TestGrantsRequiredFlag` (3 CLI) | 1 test + 1 construction error |
| **D3** — handshake order | A handshake-era request before `initialize` is `-32600` before the engine is reached; a second `initialize` on the same process too; `server/discover` and version-carrying (`_meta`) stateless requests stay reachable | `tests/test_mcp_adapter.py::TestHandshakeOrder` (10) | 4 + 1 tests |

D3 was checked against the specification rather than against habit: the legacy
revisions make initialization "the first interaction" and say other requests
"are not possible until initialization has completed" (2025-03-26), while
`2026-07-28` states "There is no negotiation handshake" and serves a
version-carrying request independently — so a blanket gate would have broken
the stateless era the server promises, and gating `server/discover` would have
hidden the era probe the spec tells a dual-era client to send first. No current
revision (2024-11-05 → 2026-07-28) prescribes an error code for the
pre-initialize case, and none addresses a repeated `initialize`; `-32600` and
the refusal are this server's documented choices.

## Not closed (deliberate, and the reason)

1. **Key status is a startup property** — a key retired mid-run keeps the grants
   already loaded in that process. Documented in SECURITY.md; a runtime lease
   would need a mechanism the release has no place for.
2. **Library path is unauthenticated by design** — an embedder constructing
   `Server(egress_grants=…)` installs the objects it is handed; there is no file
   to verify. `verified_by` names the loader so the disclosure cannot be reused
   to claim what did not happen. The same holds for the ceiling: an embedder that
   passes `egress_policy=None` has no server-wide list to intersect with, and
   `grant_scope` reports that.
3. **Trust-root distribution** — Cell verifies against a root; where the root
   comes from (config management, signed bundle, pinned release key) is the
   operator's trust channel. Same open piece as which issuer key a caller trusts
   for receipts.
4. **Clock is trusted** — `issued_at` freshness and grant windows read wall time;
   a rolled-back clock can keep an expired grant live in a running process. A
   monotonic/lease bound is a design question, not a patch.
5. **Not fuzzed, not property-tested, not long-run** — the parser/verifier surfaces
   (grant envelope, trust root, URL/egress, receipt verifier) are good fuzz
   targets and the invariants above are natural property tests; hours-long nightly
   runs are post-1.1 work. `docs/threads_roadmap.md` and `docs/observations.md`
   carry the other standing items.
6. **Orphan sweep** — an abrupt `SIGKILL` of the worker leaves its sandbox and
   capture directories behind and nothing removes old ones at startup; on a
   long-lived host that is disk growth, not a boundary break.
7. **`ENOSPC` mislabeling in the output sink** (every write error is reported as
   "no space") and **the governed-load bookkeeping divergence** after a crash
   between install and unlink (a still-present request is re-reported as a name
   collision although the tool did install). Both are correctness, not boundary.

## What a signature means here (stated once, in three answers)

What is signed is `canonical_bytes(record)` inside a DSSE v1 PAE with the
artifact's audience; who may sign is an operator-anchored key, never one the
artefact names; what a valid signature proves is that a trusted signer attests
those exact bytes — not that the execution was safe, and not authority across
audiences. Replay detection stays outside: **Cell proves uniqueness, the verifier
decides whether it has been seen before**, because the evidence persists while the
execution state does not.
