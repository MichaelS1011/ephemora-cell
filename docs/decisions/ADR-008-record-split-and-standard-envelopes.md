# ADR-008: Record split (pre-exec + receipt with backLink) and open-standard signing envelopes

- **Status:** Adopted (2026-09-25)
- **Context:** Execution records are sign-ready since 1.0.0
  (`ExecutionReport.sign()`, SEP-2787-style, RFC 8785 JCS; signed tool
  manifests via ADR-006). External review of the 2026 agent-security
  literature (USENIX 2026 finding: agent trust architectures fail at
  the VERIFICATION step, not the attestation step) motivates two
  upgrades: (1) a verifier must be able to check what a run CLAIMED it
  would do BEFORE trusting what it SAYS it did, and (2) the signed
  artifacts should be consumable by open ecosystems, not only by Cell.

## Decision

1. **Pre-execution attestation.** `PreExecutionRecord` is a typed,
   signed record built before the guest runs:
   `record_type = "ephemora.pre_exec.v1"`, `id` (uuid4 hex), UTC
   `timestamp`, `module_sha256` (the exact bytes to execute),
   `config_fingerprint` (`policy_fingerprint()` — JCS over every wall
   the guest experiences: fuel, memory, timeout, threads, memory64,
   GC heap, disk quota, I/O budgets, allow_dirs, allow_env NAMES ONLY
   — values are secrets, not policy), `input_hash` (JCS over argv +
   stdin) and the security baseline. Signing conventions are identical
   to `ExecutionReport.sign()`: signer-agnostic callables, JCS
   canonical input, hex signature, `alg` covered.

2. **Receipt binding.** `ExecutionReport` gains an OPTIONAL
   `back_link = {pre_exec_id, pre_exec_digest}` field. It is `None` by
   default and `to_dict()` output is byte-identical to the documented
   `_meta.execution` schema unless the caller opts in — existing
   reports, tests and consumers are unaffected. When set, the link is
   INSIDE the signed receipt payload (signature-covered).
   `verify_chain(pre_exec, receipt, verifier)` fails closed unless both
   halves verify with the same verifier AND the back_link references
   exactly that pre-exec record (id + digest of its canonical payload).

3. **DSSE envelopes.** `dsse_sign()/dsse_verify()/dsse_pae()` implement
   DSSE v1: signatures over the Pre-Authentication Encoding
   (`"DSSEv1" || LE32(len(type)) || type || LE32(len(payload)) ||
   payload`), payload = the JCS canonical bytes; ALL envelope
   signatures must verify, zero signatures fail closed.
   `report.to_dsse()` / `pre_exec.to_dsse()` emit interoperable
   envelopes for the in-toto/TUF ecosystem. These are PARALLEL formats
   to the native sign()/verify() (which keep the payload native JSON,
   per SEP-2787) — the payload digest is the same across formats.

4. **Detached JWS.** `detached_jws_sign()/detached_jws_verify()`
   produce/verify compact JWS with unencoded payload (RFC 7797:
   header `{"alg", "b64": false, "crit": ["b64"]}`, empty payload
   segment, signing input = `ASCII(header) || '.' || JCS(payload)`).
   The verifier supplies the payload — detached by design, so the
   record can travel out-of-band.

5. **Transparency-ready, not transparency-coupled.** An inclusion proof
   (e.g. Rekor-v2 style) is an ordinary payload field added BEFORE
   signing — automatically covered by the signature, no format change.
   Cell ships NO network client and no new dependency: a transparency
   integration would be a host-side concern (optional extra, lazy
   import — the `tools-signing` pattern). The int>2^53 precision
   caveat for cross-ecosystem JCS implementations applies (Python ints
   serialize exactly; JS consumers round to doubles) — documented,
   unchanged from the existing JCS implementation.

## Consequences

- One keypair can now sign a whole run chain: manifest (ADR-006) →
  pre-exec → receipt, all verified by one verifier call sequence.
- The `to_dict()` schema of plain reports is frozen (compat-pinned in
  tests); `back_link` is additive.
- DSSE/JWS helpers are pure functions over bytes/dicts — no I/O, no
  dependencies, no network.
- `examples/signed_record_demo.py` demonstrates the full chain end to
  end (pre-exec → receipt → DSSE), with tamper/wrong-reference
  negatives printed verbatim.

## Shipped status (2026-10-04)

The envelope primitives above are now wired to the MCP call path: with
`--receipt-signing-key` the server emits `_meta.attestation` — a DSSE v1
envelope over `canonical_bytes(_meta.execution)` — so the per-call receipt, which
the MCP spec explicitly declines to verify ("callers SHOULD NOT rely on them for
security decisions"), becomes verifiable out-of-band by a caller holding the
operator's public key. `execution_report.verify_execution_attestation` binds the
check: it fails closed unless the envelope's `payloadType`, its payload (exactly
`canonical_bytes(execution)`) and the DSSE signature all agree, so a host cannot
sign one receipt and present another. Off by default; an unconfigured deployment's
`_meta` is unchanged. Pinned in `tests/test_signed_receipt.py`. The signing trust
root (which issuer keys a caller trusts) is an operator decision — the same open
piece as grant-signature verification in ADR-013.

## Replay binding added (2026-10-04, same release)

A signed receipt by itself proves a **shape**, not an **execution**: two calls of
one tool with one outcome canonicalize to nearly the same bytes, so a captured
receipt can be presented again for a call that never happened. The signing path
now puts a one-of-one block INSIDE the signed payload
(`ExecutionReport.evidence`, schema `ephemora-execution-evidence.v1`):

* `report_id` — a fresh 128-bit nonce per receipt, so receipts are
  distinguishable and a caller's seen-set has something to key on;
* `issued_at` — aware UTC; a naive stamp is refused at construction, because
  "12:00" without a zone is a guess a replay can hide in;
* `tool` — the receipt answers for exactly this tool, which stops an honest
  `echo` receipt being presented as evidence about a different tool;
* `schema` — the tag is signed, so a verifier that requires freshness can tell
  "this predates the field" apart from "this is forged".

`verify_execution_attestation(..., max_age_seconds=...)` puts an age requirement
on top of the cryptographic one: a missing evidence block, a naive stamp, a stamp
older than the window, or one more than 60 s into the future all fail closed —
while a valid signature over an old receipt still verifies without the argument,
because the age requirement belongs to the caller, not to the format.

Honest limits this does NOT remove: **the caller must dedupe `report_id`** — we
sign a nonce but keep no server-side seen-list (that would be the append-only
book's job, and this path stays stateless), and **the trust root remains an
operator decision**. A report without a signer never receives `evidence`, so its
bytes and `_meta` are identical to before; `get-policy` discloses the schema
under `receipt_signing.evidence`.
