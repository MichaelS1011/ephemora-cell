"""Verifiable execution records — sign a Cell run, detect tampering.

Runnable companion to the docs/recipes.md section "Verifiable execution
records". Needs the optional cryptography extra (Cell itself ships no
crypto dependency — signers/verifiers are opaque bytes->bytes callables):

    pip install 'ephemora-cell[tools-signing]'

Every run of the demo prints verify=True for the intact record and
verify=False after a single field is rewritten.
"""

from __future__ import annotations

import tempfile
from pathlib import Path

import wasmtime
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

from ephemora_cell import ExecutionReport, WASIConfig, WASISandbox


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


if __name__ == "__main__":
    main()
