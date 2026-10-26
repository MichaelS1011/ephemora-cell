# SPDX-License-Identifier: BUSL-1.1
# Copyright 2026 Michael Soppa

"""Signed execution evidence from the CLI run path (v1.2 v1.2).

A real run must be able to produce an artefact that ``verify`` actually checks,
and tampering with it must be detected. The whole chain is driven as real
processes; the keys are generated per test and never committed.
"""

from __future__ import annotations

import base64
import io
import json
import os
import subprocess
import sys

sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))

import pytest

crypto = pytest.importorskip(
    "cryptography", reason="signing needs the optional cryptography package"
)
from cryptography.hazmat.primitives import serialization as ser  # noqa: E402
from cryptography.hazmat.primitives.asymmetric.ed25519 import (  # noqa: E402
    Ed25519PrivateKey,
)

REPO = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
ECHO_WASM = os.path.join(REPO, "ephemora_cell_mcp", "tools", "echo.wasm")


def _cli(*args):
    return subprocess.run(
        [sys.executable, "-m", "ephemora_cell.cli", *args],
        capture_output=True,
        text=True,
        timeout=180,
        cwd=REPO,
    )


@pytest.fixture()
def keypair(tmp_path):
    key = Ed25519PrivateKey.generate()
    priv = tmp_path / "sign.pem"
    pub = tmp_path / "sign.pub.pem"
    priv.write_bytes(
        key.private_bytes(ser.Encoding.PEM, ser.PrivateFormat.PKCS8, ser.NoEncryption())
    )
    pub.write_bytes(
        key.public_key().public_bytes(
            ser.Encoding.PEM, ser.PublicFormat.SubjectPublicKeyInfo
        )
    )
    return str(priv), str(pub)


def _sign_a_run(tmp_path, keypair):
    priv, _ = keypair
    evidence = tmp_path / "run.evidence.json"
    result = _cli("run", ECHO_WASM, "--evidence", str(evidence), "--evidence-key", priv)
    assert result.returncode == 0, result.stdout + result.stderr
    assert evidence.is_file()
    return evidence


def test_a_real_run_emits_evidence_that_verifies(tmp_path, keypair):
    _, pub = keypair
    evidence = _sign_a_run(tmp_path, keypair)
    result = _cli("verify", str(evidence), "--key", pub)
    assert result.returncode == 0, result.stdout + result.stderr
    assert "verified: yes" in result.stdout


def test_evidence_without_a_key_is_refused_up_front(tmp_path):
    evidence = tmp_path / "x.json"
    result = _cli("run", ECHO_WASM, "--evidence", str(evidence))
    assert result.returncode == 2
    assert "--evidence needs --evidence-key" in result.stderr
    assert not evidence.exists()


def test_verify_without_a_key_refuses_to_imply_it_checked(tmp_path, keypair):
    evidence = _sign_a_run(tmp_path, keypair)
    result = _cli("verify", str(evidence))
    assert result.returncode == 3
    assert "no key supplied" in result.stdout


def test_tampering_the_payload_breaks_verification(tmp_path, keypair):
    _, pub = keypair
    evidence = _sign_a_run(tmp_path, keypair)
    original = evidence.read_text(encoding="utf-8")
    document = json.loads(original)
    payload = document["payload"]
    index = len(payload) // 2
    document["payload"] = (
        payload[:index] + ("A" if payload[index] != "A" else "B") + payload[index + 1 :]
    )
    # Control: the mutation must actually change the artefact, or the test
    # proves nothing about integrity.
    assert document["payload"] != payload
    evidence.write_text(json.dumps(document, indent=2), encoding="utf-8")

    result = _cli("verify", str(evidence), "--key", pub)
    assert result.returncode == 1, result.stdout + result.stderr
    assert "signature verification FAILED" in result.stdout


def test_tampering_the_signature_breaks_verification(tmp_path, keypair):
    _, pub = keypair
    evidence = _sign_a_run(tmp_path, keypair)
    document = json.loads(evidence.read_text(encoding="utf-8"))
    signature = document["signatures"][0]["sig"]
    document["signatures"][0]["sig"] = (
        "A" if signature[0] != "A" else "B"
    ) + signature[1:]
    assert document["signatures"][0]["sig"] != signature
    evidence.write_text(json.dumps(document, indent=2), encoding="utf-8")

    result = _cli("verify", str(evidence), "--key", pub)
    assert result.returncode == 1
    assert "signature verification FAILED" in result.stdout


def test_the_signed_record_carries_a_replay_binding(tmp_path, keypair):
    """v1.2: report_id + issued_at make the receipt one-of-one and ageable."""
    evidence = _sign_a_run(tmp_path, keypair)
    document = json.loads(evidence.read_text(encoding="utf-8"))
    payload = json.loads(base64.b64decode(document["payload"]))
    binding = payload["evidence"]
    assert binding["schema"] == "ephemora-execution-evidence.v1"
    assert binding["report_id"]
    assert binding["tool"] == "echo.wasm"
    # An aware UTC stamp: a naive one could be re-read as local time.
    assert binding["issued_at"].endswith("+00:00")


def test_a_missing_key_file_is_a_clean_caller_error(tmp_path):
    evidence = tmp_path / "x.json"
    result = _cli(
        "run", ECHO_WASM, "--evidence", str(evidence), "--evidence-key", "/nope.pem"
    )
    assert result.returncode == 2
    assert "--evidence-key" in result.stderr
    assert not evidence.exists()


def test_signed_evidence_carries_the_retry_history(tmp_path, keypair, monkeypatch):
    """A crash that led to a retry is part of the signed record, not stdout-only."""
    import ephemora_cell
    import ephemora_cell.cli as cli
    from ephemora_cell.wasi_runtime import ExecutionResult, ExecutionStatus

    class FakeSandbox:
        def __init__(self, config=None):
            self.config = config

        def run(self, *args, **kwargs):
            return ExecutionResult(
                status=ExecutionStatus.SUCCESS,
                exit_code=0,
                stdout="ok",
                stderr="",
                elapsed_ms=1.0,
                fuel_consumed=1,
                abi="preview1",
                guest_exit_observed=True,
                worker_attempts=2,
                first_attempt_crashed=True,
                first_attempt_error="worker crashed: tokio-rt-worker panicked",
                first_attempt_stdout_bytes=5,
                first_attempt_stderr_bytes=7,
                first_attempt_wall_ms=42,
            )

        def cleanup(self):
            pass

    monkeypatch.setattr(ephemora_cell, "WASISandbox", FakeSandbox)
    monkeypatch.setattr(sys, "stdin", io.StringIO(""))
    priv, _ = keypair
    evidence = tmp_path / "run.evidence.json"
    monkeypatch.setattr(
        sys,
        "argv",
        [
            "ephemora-cell",
            "run",
            ECHO_WASM,
            "--json",
            "--evidence",
            str(evidence),
            "--evidence-key",
            priv,
        ],
    )
    with pytest.raises(SystemExit) as exc_info:
        cli.main()
    assert exc_info.value.code == 0
    envelope = json.loads(evidence.read_text(encoding="utf-8"))
    payload = json.loads(base64.b64decode(envelope["payload"]))
    assert payload["status"] == "success"
    assert payload["worker_attempts"] == 2
    assert payload["first_attempt_crashed"] is True
    assert "tokio-rt-worker panicked" in payload["first_attempt_error"]
    assert payload["first_attempt_output_bytes"] == 12
    assert payload["first_attempt_wall_ms"] == 42
    assert payload["first_attempt_fuel_consumed"] is None


def test_signed_evidence_marks_unknown_first_attempt_output(
    tmp_path, keypair, monkeypatch
):
    """A missing report is signed as unknown, not as a measured zero."""
    import ephemora_cell
    import ephemora_cell.cli as cli
    from ephemora_cell.wasi_runtime import ExecutionResult, ExecutionStatus

    class FakeSandbox:
        def __init__(self, config=None):
            self.config = config

        def run(self, *args, **kwargs):
            return ExecutionResult(
                status=ExecutionStatus.SUCCESS,
                exit_code=0,
                stdout="ok",
                stderr="",
                elapsed_ms=1.0,
                fuel_consumed=1,
                abi="preview1",
                guest_exit_observed=True,
                worker_attempts=2,
                first_attempt_crashed=True,
                first_attempt_error="worker crashed: panic",
                first_attempt_fuel_consumed=None,
                first_attempt_stdout_bytes=None,
                first_attempt_stderr_bytes=None,
                first_attempt_output_unknown=True,
                first_attempt_execution_started=True,
                first_attempt_report_bytes=12,
                first_attempt_worker_stderr_bytes=5,
                first_attempt_wall_ms=42,
            )

        def cleanup(self):
            pass

    monkeypatch.setattr(ephemora_cell, "WASISandbox", FakeSandbox)
    monkeypatch.setattr(sys, "stdin", io.StringIO(""))
    priv, _ = keypair
    evidence = tmp_path / "run.evidence.json"
    monkeypatch.setattr(
        sys,
        "argv",
        [
            "ephemora-cell",
            "run",
            ECHO_WASM,
            "--json",
            "--evidence",
            str(evidence),
            "--evidence-key",
            priv,
        ],
    )
    with pytest.raises(SystemExit) as exc_info:
        cli.main()
    assert exc_info.value.code == 0
    envelope = json.loads(evidence.read_text(encoding="utf-8"))
    payload = json.loads(base64.b64decode(envelope["payload"]))
    assert payload["first_attempt_output_bytes"] is None
    assert payload["first_attempt_output_unknown"] is True
    assert payload["first_attempt_report_bytes"] == 12
    assert payload["first_attempt_worker_stderr_bytes"] == 5
    assert payload["first_attempt_fuel_consumed"] is None


def test_signed_evidence_carries_a_single_attempt_unknown_marker(
    tmp_path, keypair, monkeypatch
):
    """A one-attempt run with no recoverable report is still signed unknown."""
    import ephemora_cell
    import ephemora_cell.cli as cli
    from ephemora_cell.wasi_runtime import ExecutionResult, ExecutionStatus

    class FakeSandbox:
        def __init__(self, config=None):
            self.config = config

        def run(self, *args, **kwargs):
            return ExecutionResult(
                status=ExecutionStatus.SUCCESS,
                exit_code=0,
                stdout="ok",
                stderr="",
                elapsed_ms=1.0,
                fuel_consumed=1,
                abi="preview1",
                guest_exit_observed=True,
                worker_attempts=1,
                first_attempt_crashed=False,
                first_attempt_output_unknown=True,
                first_attempt_stdout_bytes=None,
                first_attempt_stderr_bytes=None,
                first_attempt_report_bytes=2,
            )

        def cleanup(self):
            pass

    monkeypatch.setattr(ephemora_cell, "WASISandbox", FakeSandbox)
    monkeypatch.setattr(sys, "stdin", io.StringIO(""))
    priv, _ = keypair
    evidence = tmp_path / "run.evidence.json"
    monkeypatch.setattr(
        sys,
        "argv",
        [
            "ephemora-cell",
            "run",
            ECHO_WASM,
            "--json",
            "--evidence",
            str(evidence),
            "--evidence-key",
            priv,
        ],
    )
    with pytest.raises(SystemExit) as exc_info:
        cli.main()
    assert exc_info.value.code == 0
    envelope = json.loads(evidence.read_text(encoding="utf-8"))
    payload = json.loads(base64.b64decode(envelope["payload"]))
    assert payload["first_attempt_output_bytes"] is None
    assert payload["first_attempt_output_unknown"] is True
    assert payload["first_attempt_report_bytes"] == 2
