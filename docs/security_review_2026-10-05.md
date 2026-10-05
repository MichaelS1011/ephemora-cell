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
failing — **superseded below**: re-measuring this at the next commit showed the
fixture shipping had disabled those very skips, so the 803/102/0 line described a
tree that could not have produced it. See "A second red-team pass".

`tests/conftest.py` records the rule that survived the correction: the suite is
written for a checkout; what can run from an installed artifact does, and what
cannot says why — and the check that tells the two apart must not be satisfiable
by anything the distribution ships.

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

Suite on this SHA (`0712875`, re-verified clean clone): **952 passed / 4 skipped (956 collected)**, 89.9 % statement
coverage (the README badge shows the rounded 90 %); minimal install in a checkout without `cryptography`: 845 passed / 66 skipped
(911 collected), 81 %.

## Closed after the review by operator decision

Three of the open items below were posture questions, not defects, and the
operator decided each one on 2026-10-05. Every one of the four new gates was
proved to bite by deleting the enforcement and watching only its own tests go
red (degradation, not coverage):

| Decision | Semantics now | Gate | Red when the enforcement is removed |
|---|---|---|---|
| **D2** — grant scope | A signed grant is intersected with `--egress-allow`: the ceiling is validated **before** the ledger charges, so a granted endpoint outside the operator's list is denied (`limit: "server-policy"`) and spends no slot. With no server-wide list the grant alone decides | `TestEngineGrantEnforcement.test_a_grant_never_widens_the_server_wide_allowlist` (+ its positive control) | 1 test |
| **D1** — ungranted tools | `--egress-grants-required` denies mediation for a tool with no grant (`limit: "grant-required"`) instead of falling back to the allowlist; default stays off, and `get-policy` discloses the live posture as `ungranted_tools` | `test_grants_required_denies_an_ungranted_tool_without_falling_back`, `…_still_mediates_a_granted_tool`, `TestGrantScopeDisclosure` (4), `TestGrantsRequiredFlag` (3 CLI) | 1 test |
| **D3** — handshake order | A handshake-era request before `initialize` is `-32600` before the engine is reached; a second `initialize` on the same process too; `server/discover` and version-carrying (`_meta`) stateless requests stay reachable | `tests/test_mcp_adapter.py::TestHandshakeOrder` (11) | 4 + 1 tests |

D3 was checked against the specification rather than against habit: the legacy
revisions make initialization the first interaction and say other requests
"are not possible until initialization has completed" (2025-03-26), while
`2026-07-28` states "There is no negotiation handshake" and serves a
version-carrying request independently — so a blanket gate would have broken
the stateless era the server promises, and gating `server/discover` would have
hidden the era probe the spec tells a dual-era client to send first. No current
revision (2024-11-05 → 2026-07-28) prescribes an error code for the
pre-initialize case, and none addresses a repeated `initialize`; `-32600` and
the refusal are this server's documented choices.

## A second red-team pass, against the code that had just landed

Six findings, all of them in the D1/D2/D3 code and none of them disputed — the
point of running the lane again immediately was to catch exactly this: a gate
that is real in its own test and incomplete in the path around it.

| # | Finding | Sev | Closure | Gate (red when the fix is reverted) |
|---|---|---|---|---|
| 1 | The ceiling was checked for the URL the guest wrote, but `execute_request` handed the redirect revalidator the **grant** policy alone: a `302` into a sibling prefix the operator excluded was fetched, audit reading `allowed, fetched, status 200` (2 served paths measured) | P1 | every hop revalidated against grant AND ceiling; ceiling refusal audited `limit: "server-policy"` | 1 (`test_a_redirect_hop_must_also_clear_the_server_wide_allowlist`) + positive control that an in-ceiling hop still fetches |
| 2 | `EgressGrant.policy()` is rebuilt from endpoints+methods, so byte/time limits came from the dataclass defaults — an operator `--egress-max-response-bytes 256` was replaced by 64 KiB whenever a grant existed (8 203 bytes delivered) | P1 | strictest of grant/ceiling wins, including the ceiling's resolver | 1 (`test_the_server_wide_resource_caps_narrow_a_grant_too`) |
| 3 | `SplitResult.port` validates lazily and was read OUTSIDE the guard: `http://allowlisted-host:70000/…` raised past `validate_request` and past the mediator into a -32603 with no audit entry and no `_meta.egress` | P2 | whole match guarded; absurd port is an audited denial | 2 (policy path + grant path) |
| 4 | The handshake exemption keyed on the presence of `params._meta`, so a request naming a HANDSHAKE-era version there was served `tools/call` before `initialize` — the malicious-client case, re-opened by my own gate | P2 | exemption only for versions that are not handshake-era; unsupported still answers -32022 | 1 (`test_a_legacy_version_in_meta_does_not_buy_a_handshake_free_call`) |
| 5 | `CellToolEngine(grants_required=True, grant_ledger=…)` built with no grants, denied every call, and `get-policy` reported `mediation: disabled` — a posture nothing could observe | P2 | guard demands grants AND a ledger | 2 |
| 6 | The strict-mode denial returned before the request-artifact check, so an ungranted tool that attempted no egress grew an `_meta.egress` | P2 | denial issued after the artifact exists | 2 (silent without artifact, audited with) |
| 7 | (Follow-up I ran on that lane's nit list) The engine looked grants up by the **dict key** a caller passed, while the signed payload names a `tool` — a grant signed for one tool mediated another and spent its cap. Measured before the fix: `allowed` for a tool the document never named | P1 | the engine re-keys by `grant.tool` and refuses two grants claiming one tool; the loader already did this | 1 (`test_a_grant_authorizes_the_tool_its_payload_names`), book-based |

Also fixed by this round outside the egress surface: the checkout detector in
`tests/conftest.py` was made TRUE by the fixtures the previous commit started
shipping, so an unpacked sdist ran the repository-inspection modules and
produced 16 failures + 4 errors where this document had recorded **803 passed /
102 skipped / 0 failed** — a number that could not have come from that tree. The
predicate now keys on `docs/` + `scripts/` (never shipped by a distribution,
always present in a clone or a source export), `tests/test_checkout_skip_policy.py`
(5) pins both halves, and the re-measurement is **753 passed / 136 skipped / 0
errors** in the container with a native control run at 763/127/0 — itself a
figure that needed re-measuring, see below.

**The container leg, measured three more times since:** at `7f9e860` on a quiet host the
clean room is **fully green — 770 passed / 138 skipped / 0 failures, 0 errors**
(exit 0); at `3e3d32c` (this branch's final measured state) the same leg reports
**772 passed / 138 skipped / 0 errors** with **one** failure on a host running other
work in parallel. Under heavier load the same tree reported two failures
(`test_100_parallel_runs_no_fd_exhaustion` and `test_run_isolated_component`), and
both passed when run standalone in the same container and natively (5.88 s). So the
earlier sentence "exactly one failure, QEMU-only" was too narrow: what is actually
observed is that the `io_cpu_seconds` watchdog can refuse legitimate isolated runs
when the host is contended, because it compares ABSOLUTE worker CPU — interpreter and
engine startup, inflated ~70x by amd64-under-QEMU emulation and further by scheduler
pressure — against a fixed budget, while the guest itself needs ~12 ms. That is open
item 9 below, recorded as an accounting question with a reproduction condition, not
as a passed gate and not as a product defect. A packaging claim that only holds when
nobody else is using the machine is a claim about the machine.

## A third pass: this branch's own documentation audited against its own code

The last round was not an attack on new code but a check of what the docs on this
branch claim. One P1 and four smaller mismatches, all closed, each with the number of
tests that go red when the closure is reverted:

| # | Finding | Sev | Closure | Red when reverted |
|---|---|---|---|---|
| 1 | **"The host never follows a name someone else can create" was not universal.** Governed loading read proposals with plain `Path.read_text()` / `Path.read_bytes()` (inside `read_stable_bytes`) and enumerated with `Path.glob` — the same swallow-`OSError` pattern this document condemns for the grants dir. A writer of that directory could plant `x.tool.request.json -> ../../../../…` and the server parsed the TARGET. Deferring an unreadable name was the worse failure: a link can never settle, so it would sit in `pending` forever and nothing would ever be decided | P1 | `os.scandir` enumeration (failure surfaces as `error` in the report), explicit refusal **with a reason** unless the entry is a regular file readable without following links, authoritative read through `read_regular_nofollow`, and `read_stable_bytes` itself no-follows | 2 (proposal gates) + 2 (stability seam) |
| 2 | `--egress-grants-required` was **unreachable in a grant-only deployment**: `policy is None → return ()` sat in front of the denial, so an ungranted tool got silence while `get-policy` attested "denied (--egress-grants-required)" | P2 | denial moved ahead of the policy question, still behind the artifact check | 3 |
| 3 | The ceiling's `timeout_seconds` narrowing had no test at all | P2 | behaviour-level gate: origin answers after 2.0 s, ceiling 0.4 s → stopped early and delivered nothing | 1 |
| 4 | "strictest of the two, **including the ceiling's resolver**" overstated: `EgressGrant` has no resolver field, so both precedence orders resolve identically | P2 | order written so resolution can only come from the operator, plus a structural assertion that `EgressGrant.policy().resolver is None` — the claim is checkable now instead of decorative | n/a (no behavioural delta; that is the finding) |
| 5 | Stale class arithmetic inside this release's own entries (`TestHandshakeOrder` written as 10 while it is 11, plus six class sizes that had grown since their sentence was written) | P2 | counts re-derived from collection | `check_test_count.py --strict` |

Two more corrections came out of the same sweep: SECURITY.md's handshake paragraph now
names `params._meta` as the place a request declares its version (the location the
specification's own `tools/call` example uses), and the append-log's no-`O_NOFOLLOW`
fallback was dead code — opening a symlink on such a platform does not raise, so a
check sitting in `except OSError` never ran. It is a pre-open check now.

The final one came from the operator reading the release docs rather than from an
agent: §2 of `docs/comparison-mcp-servers.md` attributed its 2026-08-20 benchmark to
"Cell 2.1.1". Nothing supports that label. The pre-squash history that could have
placed it is gone, no 2026-08-20 artifact is checked in (the earliest results dir is
2026-08-25), and the one version record near that date — `11_sbom_audit.json` — lists
`ephemora-cell 2.1.0`, a different number. So the label was removed rather than
reinterpreted: rewriting it as 1.1.0 would have dated the table to a build it was
never run on. `benchmarks/pocs/limits_poc/README.md` carried the same string in its
own dated header and got the same treatment; the raw SBOM artifact was left exactly as
recorded. The comparison doc now states the rule where the table is: the Cell version
was not independently preserved, and no version is inferred retroactively. The
adjacent maturity row was fixed in the same commit for the same class of reason — it
still asserted "release line 1.0.5 in `pyproject.toml`", a present-tense claim that
had been false since the 1.1.0 bump, and it carried a stale suite figure that the
count guard does not see because that row uses no guarded phrasing.

## A fourth pass: the release CI matrix caught what every local pass had missed

The release was signed off on a local gate that ran CPython 3.12/3.13-class builds
on one machine. The pushed CI matrix — 2 OSes × 3.10/3.11/3.12/3.13 — came back red
in two places, on two supported interpreter builds: macos-latest + 3.11.9 (2 failures)
and macos-latest + 3.10.11 (21 failures). The same matrix was green on the previous
release SHA `c466158` with identical interpreter patch versions, so both findings
belong to this branch.

| # | Finding | Sev | Closure | Red when reverted |
|---|---|---|---|---|
| 1 | **The resolve-time SSRF filter decided by CPython patch release.** `_ip_blocked` was six `ipaddress` properties plus a CGNAT network. Those properties are not stable across patch releases: `2002:7f00:1::` — 127.0.0.1 written as 6to4 — was "global" on 3.10.11, 3.11.8 and 3.11.9 and "private" from 3.12.10 on, while `::ffff:8.8.8.8` was "reserved" (refused) on the old builds and reachable on the new, and 3.12.10+ refused the whole `2002::/16` including public-embedded addresses. A boundary whose meaning changes when the operator patches Python is not a boundary, and the direction that mattered was the permissive one: on the oldest supported build a hostname could resolve to loopback through the guard | P1 | Cell's own special-use registry replaces the stdlib predicates. The three families that carry an IPv4 destination (`::ffff:0:0/96`, `2002::/16`, `64:ff9b::/96`) are decoded from `packed` bytes and judged by the DESTINATION; Teredo (`2001::/23`) is refused outright because its embedded address is obfuscated and therefore undecidable. A frozen 67-address decision set (50 refused / 17 reachable) is byte-identical on ten CPython builds: 3.10.11, 3.10.20, 3.11.8, 3.11.9, 3.11.15, 3.12.10, 3.12.13, 3.13.0, 3.13.14, 3.14.7 (identical sha256 over the decision vector). A further gate flips `is_private`/`is_reserved`/`is_global` on `IPv6Address` to the opposite answer and requires every decision to hold, which is what proves the stdlib is not consulted | 6 on 3.10.11 |
| 2 | **19 guest runs returned `ExecutionStatus.ERROR` with `list indices must be integers or slices, not function`** on macos-latest + 3.10.11 in the release run — Preview1 and Component paths, engine and MCP channel alike | open | Not yet root-caused; see the four measurements below. The interpreter build and wasmtime are ruled out, and so is the machine: the same runner passed both the minimal runs and a full suite with `--no-cov` | — |

Measurements for #2, in order, all on the runner that failed (macos-26-arm64,
CPython 3.10.11 from the actions python-versions build, wasmtime
`47.0.1-py3-none-macosx_11_0_arm64`):

1. Raw wasmtime with no Cell code, same guest shape, zero fuel: traps
   `all fuel consumed` as expected. wasmtime and the interpreter build are not
   sufficient.
2. One minimal Cell run through `WASISandbox`: `FUEL_EXHAUSTED` / `SUCCESS` /
   `SUCCESS` (in-process, default, isolated subprocess). Cell's happy path works
   on that machine.
3. The two failing pytest cases run alone: `2 passed`. So the failure needs the
   rest of the suite in the same process.
4. The whole suite with `--no-cov --tb=line`: `948 passed / 2 failed` — only the
   SSRF pair, no defect-B string anywhere in the log. So coverage instrumentation
   or the `-v --tb=short` invocation the release job uses is the remaining
   difference; a round-3 diagnostic run pins it.

Locally, CPython 3.10.11 (python-build-standalone, same macOS major version and
arch) with pytest 8.4.2 and the repo's coverage addopts runs the whole suite green
except the same two SSRF cases — the standalone build does not reproduce it either.

**Rules this round adds.**

* The release gate must include the CI matrix itself; a local gate that runs one
  interpreter generation proves nothing about `requires-python = ">=3.10"`.
* "No known P0 bypass remains" is a claim about the OLDEST supported interpreter
  first, because that is where a stdlib-semantics assumption is most likely to
  still hold.
* A security decision that is derived from stdlib semantics is a dependency on a
  release note. Own the registry, and gate the decision set for
  interpreter-independence — including the direction that over-blocks, because a
  positive control is part of a filter's definition.

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

8. **The lint toolchain is unpinned in CI.** `.github/workflows/ci.yml` runs
   `pip install black ruff`, so the formatter judging the tree is whatever PyPI
   serves that day — the dev venv (black 26.5.1) and a fresh CI resolve (26.10.0)
   have already disagreed on `assert cond, (msg)` wrapping. Both agree on this tree
   today (verified against both binaries), but the gate is not reproducible by
   construction. Pinning it changes CI, so it is the operator's call rather than a
   silent edit during a freeze.
9. **`io_cpu_seconds` counts the whole worker process, startup included — and a
   contended host can therefore refuse a legitimate run.** The
   watchdog compares absolute `getrusage(RUSAGE_SELF)`; the report's
   `io_cpu_used_seconds` is a delta from process start. The message now quotes the
   compared value, so the two no longer contradict each other, but the underlying
   choice — should a guest be charged for the interpreter and engine it made the
   host load? — is an enforcement-semantics decision, not a message fix, and the
   release does not make it. Measured consequence: 100 parallel isolated runs pass
   natively (0.01 s guest CPU, 12 ms) and fail 4-6 of 100 under amd64-under-QEMU
   emulation, where startup alone costs 0.4-1.8 s.
10. **The passing count is host-dependent, the collection is not.** Of the 4
   toolchain skips in `tests/test_builder.py`, three run because a toolchain is
   missing and one (`.zig`) is skipped *because* zig is installed; on a zig-free
   host the same commit reports 953 passed / 3 skipped. `check_test_count.py`
   hard-checks collection (956) and the documented pair, so a host with a different
   toolchain mix shows up as a strict-mode badge mismatch rather than a silent lie.

   **Correction to this item, measured 2026-10-05 — the record above stands as it
   was written, this is what the follow-up found:** the zig-free half is wrong. The
   skip pair swaps and the totals do not move. Re-measured on this host with `zig`
   masked out of `PATH` and the rest of the toolchain intact, `tests/test_builder.py`
   reports **20 passed / 4 skipped with zig present** (the `.zig` *guidance* test
   skips, `tests/test_builder.py:337`) and **20 passed / 4 skipped without zig** (the
   `.zig` build-and-run test skips, `tests/test_builder.py:232`) — a different test
   carries the fourth skip, which is what `README.md` states. What this item got
   right and still holds: the guard pins the *collection*, so a host with a different
   toolchain mix surfaces as a strict-mode mismatch rather than a silent lie.

## What a signature means here (stated once, in three answers)

What is signed is `canonical_bytes(record)` inside a DSSE v1 PAE with the
artifact's audience; who may sign is an operator-anchored key, never one the
artefact names; what a valid signature proves is that a trusted signer attests
those exact bytes — not that the execution was safe, and not authority across
audiences. Replay detection stays outside: **Cell proves uniqueness, the verifier
decides whether it has been seen before**, because the evidence persists while the
execution state does not.
