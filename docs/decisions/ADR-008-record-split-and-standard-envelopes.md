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
