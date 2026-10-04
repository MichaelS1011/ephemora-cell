"""Verifiable execution records — sign a Cell run, detect tampering.

Runnable companion to the docs/recipes.md section "Verifiable execution
records". Needs the optional cryptography extra (Cell itself ships no
crypto dependency — signers/verifiers are opaque bytes->bytes callables):

    pip install 'ephemora-cell[tools-signing]'

Every run of the demo prints verify=True for the intact record and
verify=False after a single field is rewritten. It then demonstrates the
ADR-008 record split: a signed PRE-execution attestation (what the run
WILL do: module digest, policy fingerprint, input digest) joined to the
signed receipt via back_link, plus a DSSE envelope for ecosystem interop.
"""

from __future__ import annotations

import hashlib
import tempfile
from pathlib import Path

import wasmtime
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

from ephemora_cell import (
    ExecutionReport,
    PreExecutionRecord,
    WASIConfig,
    WASISandbox,
    dsse_verify,
    verify_chain,
)
from ephemora_cell.execution_report import canonical_bytes


def _ed25519_verify(key: Ed25519PrivateKey):
    """bytes->bytes verifier built around the operator's public key."""
    from cryptography.exceptions import InvalidSignature

    public = key.public_key()

    def _verify(canonical: bytes, signature: bytes) -> bool:
        try:
            public.verify(signature, canonical)
            return True
        except InvalidSignature:
            return False

    return _verify


def main() -> None:
    key = Ed25519PrivateKey.generate()  # BYO keys — Cell never sees storage
    config = WASIConfig(max_fuel=1_000_000)

    with tempfile.TemporaryDirectory() as tmp:
        module = Path(tmp) / "hello.wasm"
        module.write_bytes(wasmtime.wat2wasm(b'(module (func (export "_start")))'))
        sandbox = WASISandbox(config=config)
        try:
            result = sandbox.run(str(module))
        finally:
            sandbox.cleanup()

    report = ExecutionReport(
        status=result.status.value,
        exit_code=result.exit_code,
        elapsed_ms=result.elapsed_ms,
        fuel_consumed=result.fuel_consumed,
        fuel_budget=config.max_fuel,
    ).apply_config(config, effective_preopens=result.effective_preopens)

    # sign(): the RFC 8785 (JCS) canonicalization of the whole record —
    # status, fuel, timing AND the security baseline — is the signing input.
    signed = report.sign(key.sign, alg="EdDSA")
    print("record:", signed["status"], "| fuel:", signed["fuel_consumed"])
    print("verify(intact):", ExecutionReport.verify(signed, _ed25519_verify(key)))

    # Tamper: one rewritten field breaks the signature — the record cannot
    # be quietly amended after the fact. (+1 guarantees an actual change:
    # a minimal module can legitimately consume exactly 1 fuel unit.)
    signed["fuel_consumed"] = signed["fuel_consumed"] + 1
    print("verify(tampered):", ExecutionReport.verify(signed, _ed25519_verify(key)))

    # ------------------------------------------------------------------
    # ADR-008 record split: pre-exec attestation + receipt, joined by
    # back_link. The verifier can check what the run CLAIMED it would do
    # before trusting what it SAYS it did — with the same key.
    # ------------------------------------------------------------------
    module_bytes = wasmtime.wat2wasm(b'(module (func (export "_start")))')
    pre = PreExecutionRecord.build(
        module_bytes=module_bytes,
        config=config,
        stdin_data=None,
    )
    signed_pre = pre.sign(key.sign, alg="EdDSA")

    # The receipt links back: id + digest of the pre-exec's canonical
    # payload, INSIDE the signed receipt payload (signature-covered).
    pre_digest = hashlib.sha256(
        canonical_bytes({k: v for k, v in signed_pre.items() if k != "signature"})
    ).hexdigest()
    report2 = ExecutionReport(
        status=result.status.value,
        exit_code=result.exit_code,
        elapsed_ms=result.elapsed_ms,
        fuel_consumed=result.fuel_consumed,
        fuel_budget=config.max_fuel,
    ).apply_config(config, effective_preopens=result.effective_preopens)
    report2.back_link = {"pre_exec_id": signed_pre["id"], "pre_exec_digest": pre_digest}
    signed_receipt = report2.sign(key.sign, alg="EdDSA")

    print(
        "chain(intact):",
        verify_chain(signed_pre, signed_receipt, _ed25519_verify(key)),
    )
    # A receipt that references a DIFFERENT pre-exec record does not verify:
    # the chain binds this receipt to exactly that attestation.
    other_pre = PreExecutionRecord.build(
        module_bytes=module_bytes + b"\x00",
        config=config,
        stdin_data=None,
    ).sign(key.sign, alg="EdDSA")
    print(
        "chain(wrong pre-exec):",
        verify_chain(other_pre, signed_receipt, _ed25519_verify(key)),
    )

    # DSSE envelope: the same receipt wrapped for the in-toto/TUF
    # ecosystem — the signature is over the DSSE PAE.
    envelope = report2.to_dsse(key.sign, alg="EdDSA", key_id="demo-key")
    print("dsse(intact):", dsse_verify(envelope, _ed25519_verify(key)))

    # ------------------------------------------------------------------
    # ADR-011 chain ACROSS RUNS. verify_chain() above binds two records of
    # ONE run; nothing there can see a run before or after it. The Ledger
    # appends a signed entry per run that seals the previous entry's digest,
    # so a whole sequence becomes edit/drop/reorder evident. The position is
    # assigned by ONE writer under a lock (this loop is that writer) and the
    # embedder — never Cell — holds the key.
    # ------------------------------------------------------------------
    from ephemora_cell import Ledger, LedgerEntry, chain_break, verify_ledger

    def sign_pair(wat: bytes) -> tuple[dict, dict]:
        """One run -> a signed (pre-exec, receipt) pair, back-linked."""
        mb = wasmtime.wat2wasm(wat)
        with tempfile.TemporaryDirectory() as t2:
            mod = Path(t2) / "m.wasm"
            mod.write_bytes(mb)
            sbx = WASISandbox(config=config)
            try:
                res = sbx.run(str(mod))
            finally:
                sbx.cleanup()
        p = PreExecutionRecord.build(module_bytes=mb, config=config).sign(
            key.sign, alg="EdDSA"
        )
        pd = hashlib.sha256(
            canonical_bytes({k: v for k, v in p.items() if k != "signature"})
        ).hexdigest()
        r = ExecutionReport(
            status=res.status.value,
            exit_code=res.exit_code,
            elapsed_ms=res.elapsed_ms,
            fuel_consumed=res.fuel_consumed,
            fuel_budget=config.max_fuel,
        )
        r.apply_config(config, effective_preopens=res.effective_preopens)
        r.back_link = {"pre_exec_id": p["id"], "pre_exec_digest": pd}
        return p, r.sign(key.sign, alg="EdDSA")

    with tempfile.TemporaryDirectory() as t:
        chain = Ledger(Path(t) / "ledger.jsonl")
        for _ in range(3):
            pre, rec = sign_pair(b'(module (func (export "_start")))')
            chain.append(LedgerEntry.from_records(pre, rec), key.sign, alg="EdDSA")

        print("ledger entries:", len(chain.entries()))
        # Linkage is not a trust decision: sequence + prev_hash continuity
        # needs no key at all.
        print("chain(intact, no key):", chain.verify())
        # Authorship does — the same file checked against the public key.
        print("chain(intact, signed):", chain.verify(_ed25519_verify(key)))

        # Edit one sealed field and the NEXT entry stops linking to it.
        forged = chain.entries()
        forged[1]["receipt_digest"] = "0" * 64
        print("break after edit:", chain_break(forged))

        # What the chain cannot see from the file alone: a history chopped
        # short at the head's end still links. Closing that needs an external
        # anchor for the current head — ADR-011 leaves it open by decision.
        print("truncated tail still links:", verify_ledger(chain.entries()[:2]))


if __name__ == "__main__":
    main()
