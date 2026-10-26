"""The pre-exec -> receipt chain around a real sandbox run.

The envelope tests pin the bytes. This test pins the product path: the module
that is hashed in the pre-exec record is the module the sandbox actually ran,
the report carries the real status/fuel, and the signed back_link binds that
report to this exact pre-exec record.
"""

from __future__ import annotations

import hashlib
import os
import sys
from pathlib import Path

sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))

from ephemora_cell import (
    ExecutionReport,
    ExecutionStatus,
    PreExecutionRecord,
    WASIConfig,
    WASISandbox,
    verify_chain,
)
from ephemora_cell.execution_report import canonical_bytes

_SIGN_KEY = b"real-path-chain-key"
_MODULE = Path(__file__).resolve().parent.parent / "examples" / "hello.wasm"


def _signer(data: bytes) -> bytes:
    return hashlib.sha256(_SIGN_KEY + data).digest()


def _verifier(canonical: bytes, signature: bytes) -> bool:
    return signature == hashlib.sha256(_SIGN_KEY + canonical).digest()


def _run_and_build_chain():
    config = WASIConfig(max_fuel=2_000_000, timeout_seconds=5, max_memory_mb=64)
    pre = PreExecutionRecord.build(
        module_path=str(_MODULE),
        config=config,
        args=[],
        stdin_data=None,
        record_id="real-run-pre-1",
        timestamp="2026-10-23T00:00:00.000Z",
    )
    signed_pre = pre.sign(_signer, alg="EdDSA")
    sandbox = WASISandbox(config=config)
    try:
        result = sandbox.run(
            str(_MODULE), args=[], use_subprocess=False, trust="trusted"
        )
    finally:
        sandbox.cleanup()
    report = ExecutionReport(
        status=result.status.value,
        exit_code=result.exit_code,
        elapsed_ms=result.elapsed_ms,
        fuel_consumed=result.fuel_consumed,
        fuel_budget=config.max_fuel,
        stdout_bytes=len(result.stdout.encode("utf-8")),
        stderr_bytes=len(result.stderr.encode("utf-8")),
    ).apply_config(
        config,
        effective_preopens=result.effective_preopens,
        execution_mode=result.execution_mode,
        abi=result.abi,
    )
    digest = hashlib.sha256(
        canonical_bytes({k: v for k, v in signed_pre.items() if k != "signature"})
    ).hexdigest()
    report.back_link = {"pre_exec_id": pre.id, "pre_exec_digest": digest}
    return result, report, signed_pre, report.sign(_signer, alg="EdDSA")


def test_real_run_chain_verifies_and_binds_the_actual_module():
    result, report, signed_pre, signed_receipt = _run_and_build_chain()
    assert result.status == ExecutionStatus.SUCCESS
    assert report.fuel_consumed is not None and report.fuel_consumed > 0
    assert verify_chain(signed_pre, signed_receipt, _verifier)


def test_chain_rejects_a_receipt_bound_to_another_pre_record():
    _result, _report, _signed_pre, signed_receipt = _run_and_build_chain()
    other = PreExecutionRecord.build(
        module_bytes=b"\x00asm\x01\x00\x00\x00",
        config=WASIConfig(max_fuel=2_000_000, timeout_seconds=5, max_memory_mb=64),
        record_id="other-pre",
        timestamp="2026-10-23T00:00:00.000Z",
    )
    signed_other = other.sign(_signer, alg="EdDSA")
    assert not verify_chain(signed_other, signed_receipt, _verifier)


def test_chain_rejects_tampered_real_report():
    _result, _report, signed_pre, signed_receipt = _run_and_build_chain()
    signed_receipt["status"] = "success"  # same value; mutate a measured field
    signed_receipt["fuel_consumed"] = 0
    assert not verify_chain(signed_pre, signed_receipt, _verifier)
