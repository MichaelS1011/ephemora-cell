# ADR-011: Execution Ledger — a Hash Chain Across Runs, as a Separate Envelope

- **Status:** Accepted
- **Date:** 2026-10-03
- **Predecessors:** ADR-008 (record split and standard envelopes), ADR-010
  (licensing, unchanged by this decision)
- **Basis:** Code inspection of `ephemora_cell/execution_report.py` on
  2026-10-03 plus a market comparison against
  [`astrid-runtime/astrid`](https://github.com/astrid-runtime/astrid) (retrieved
  2026-10-03), which ships a signed, hash-linked audit chain across calls.

## Context (verified, not assumed)

1. **One run is already provable; a sequence of runs is not.**
   `verify_chain()` (`ephemora_cell/execution_report.py:535-563`) checks that a
   signed receipt's `back_link` names the pre-exec record id AND its canonical
   digest. That binds two records of the SAME run. Nothing in either record
   refers to the run before it, so a verifier holding a folder of records cannot
   tell whether one is missing, whether two were reordered, or whether the
   newest one is actually the newest.
2. **The receipt has no identity to chain on.** `ExecutionReport.to_dict()`
   emits `status`, `exit_code`, `elapsed_ms`, `fuel_consumed`, `fuel_budget`,
   `fuel_utilization`, `memory_mb`, `stdout_bytes`, `stderr_bytes`, `warnings`,
   `security_baseline` (measured 2026-10-03) — no `id`. The pre-exec record has
   `id`, `module_sha256`, `config_fingerprint`, `input_hash`, `record_type`,
   `timestamp`, `security_baseline`. Chain positions therefore anchor on the
   pre-exec identity plus both canonical digests.
3. **The record schema is frozen.** ADR-008 states: "The `to_dict()` schema of
   plain reports is frozen (compat-pinned in tests); `back_link` is additive"
   (`docs/decisions/ADR-008-record-split-and-standard-envelopes.md:67-69`).
4. **The position in a chain is not knowable before the run finishes.**
   `sequence` and `prev_hash` exist only at append time — after the pre-exec was
   signed ("signed before the guest runs", ADR-008) and after the receipt was
   produced. Putting them inside a record would either require re-signing a
   record whose whole point is pre-execution commitment, or would make the field
   a claim nobody assigned.
5. **Timestamps cannot order runs.** The isolated path executes in a subprocess
   (`ephemora_cell/process_executor.py`), the in-process and MCP paths do not; two
   runs can finish in the same millisecond and arrive out of order. Any ordering
   rule based on wall-clock is therefore wrong by construction.

## Decision

**A new, separate envelope: `LedgerEntry` + `Ledger` in `ephemora_cell/ledger.py`
(DSSE type `https://ephemora.dev/ledger-entry.v1`).** Records stay as they are;
the chain is an additional object that references them by digest.

1. **Entry payload** is JCS-canonical (RFC 8785) and carries
   `ledger_version`, `sequence`, `appended_at`, `prev_hash`, `pre_exec_id`,
   `pre_exec_digest`, `receipt_digest`, `module_sha256`, `config_fingerprint`.
   Digests use the same recipe as `verify_chain` (SHA-256 over the canonical
   payload minus `signature`), so an entry and a verifier compute the same value
   from the same record.
2. **Linkage is keyless and authenticity is signed — two separate claims.**
   `chain_break()`/`verify_ledger()` check `sequence` (0, then +1) and
   `prev_hash` (digest of the previous entry, genesis expects 64 zero bytes) with
   no key at all. Signatures are checked only when a verifier is supplied, under
   the same `expected_alg` pin the records use (one implementation:
   `ExecutionReport.verify`, so an entry can never verify under looser rules than
   a record).
3. **One writer assigns positions.** `Ledger.append()` takes an exclusive
   `flock` on the JSONL file, reads the last line, assigns `sequence`/`prev_hash`,
   signs, appends and `fsync`es — all inside the lock. Arrival order IS chain
   order; a verifier checks sequence monotonicity and never timestamp
   monotonicity. `flock` is advisory and per-host, so this is a
   single-host-single-writer design (see Consequences).
4. **Append-only at the syscall level, deliberately not atomic-replace.** The
   writer uses `O_APPEND` and never the `_atomic_write` helper
   (`ephemora_cell/_fsutil.py:42-58`), which renames a temp file over the target —
   correct for config, wrong for a chain.
5. **Default-off, host-side, no guest path.** Nothing in the run path creates a
   ledger; `Ledger(path)` creates no file (a constructor or a `head()` query must
   not leave files behind) and the first append does. A ledger path is operator
   state and is never placed under `allow_dirs`/preopens, consistent with the
   write-once-per-session state model in ADR-004 and
   `tests/test_persistence_worm.py`.
6. **A tail window guard instead of silent self-healing.** `append()` reads only
   the last 64 KiB for the tail line; a file whose final line does not fit raises
   instead of starting a second chain nobody asked for.
7. **`ephemora-cell ledger <path>` verifies what a CLI can verify**: linkage and
   order, and it prints that authorship is NOT proved (the CLI holds no key) and
   that a chain truncated at the end is invisible from the file alone.

## Consequences

**Gained**

- Reordering, deleting or editing an entry now breaks verification, and the
  break is reported with the entry position (`chain_break`) rather than as a bare
  `False`.
- An auditor without any key can still prove the sequence is continuous —
  linkage is not a trust decision.
- Existing signed records stay byte-identical: no schema bump, no re-signing, no
  new verifier obligations. This is pinned by test, not by argument.

**Accepted costs and limits (stated, not hidden)**

- **Truncation from the head's end is undetectable from the file alone.**
  A shorter chain that is internally consistent verifies. Closing this needs an
  externally anchored head (a signed checkpoint published somewhere else, or a
  transparency log) — deliberately NOT part of this ADR; it is the next decision
  and it needs a place to publish to.
- **Single writer per ledger file.** `flock` is advisory; NFS semantics vary, so
  multi-host writes to one file are out of scope until there is a real deployment
  that needs them.
- **Chain growth is unbounded and fsync-per-append costs durability time.**
  Rotation policy (per epoch, per year) is undecided; entries are small (~300 B).
- **Key rotation is not addressed here.** `keyid` is carried in the DSSE form
  only; a policy for which key signed which stretch of a chain is open.
- MCP-side exposure (an opt-in flag that appends automatically, and a query tool
  for the head) is a follow-up: the library and CLI are the shipped surface now.

## Evidence

- `ephemora_cell/ledger.py` (this decision implemented),
  `tests/test_ledger_chain.py` — 28 tests, including
  `test_records_are_unchanged_when_no_ledger_is_used`,
  `test_truncated_tail_is_not_detectable_from_the_file_alone`,
  `test_linkage_verifies_without_any_key`,
  `test_concurrent_appends_produce_one_gapless_chain` (8 writers, 40 appends,
  sequences 0..39, no gap), and
  `test_entry_digests_use_the_same_recipe_as_verify_chain`.
- Market motivation: astrid's chain claim quoted from its README
  ("each entry seals the hash of the one before it and is signed"), retrieved
  2026-10-03; its per-principal fuel ledger
  (`crates/astrid-capsule-types/src/fuel_ledger.rs`, same date) is documented by
  its own author as telemetry-scope — which is why this ADR does not treat
  "they meter CPU" and "we meter CPU" as a difference worth copying.
