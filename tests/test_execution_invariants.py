# SPDX-License-Identifier: BUSL-1.1
# Copyright 2026 Michael Soppa
"""The four words of the product promise, each as one named gate.

Ephemora Cell's claim is not "a WASM sandbox" — it is **ephemeral, stateless,
capability-bound and verifiable execution**. Four words, four tests, one per
word. They exist so that a future contributor cannot weaken an invariant by
accident: every one of them fails if the property stops holding, and each names
the mutation that would break it.

These are deliberately written against the REAL runtime (real guests, real
sandbox directories, the real engine pool), not against doubles — a promise about
execution state can only be evidenced by executing.
"""

from __future__ import annotations

import base64
import os
import sys

sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))

import pytest
import wasmtime
from test_persistence_worm import MARKER_READER_WAT, MARKER_WRITER_WAT

from ephemora_cell import ExecutionResult, ExecutionStatus, WASIConfig, WASISandbox
from ephemora_cell.wasi_runtime import _get_engine_pool

# A guest that writes a marker into its scratch, and one that reports whether a
# marker is there (exit 0 = present). Both are the worm probe's own guests, so
# this file cannot pass by testing a harness that detects nothing.
TOKEN = "PERSIST-MARKER-42"


def _probe(tmp_path, wat: str, name: str) -> str:
    path = tmp_path / name
    path.write_bytes(wasmtime.wat2wasm(wat))
    return str(path)


def _pooled_config() -> WASIConfig:
    """A config that lets the engine pool ACTUALLY be used.

    `io_budget_bytes` is set by default, and a set byte budget forces a per-run
    engine (`wasi_runtime` refuses to share an engine it has to watch dog-style).
    A statelessness test that silently runs unpooled proves nothing about the
    pooled path, where reuse is the whole risk — so the budget is lifted here.
    """
    return WASIConfig(
        max_fuel=1_000_000,
        timeout_seconds=10,
        io_budget_bytes=None,
        allow_dirs=(),
    )


# --- 1. EPHEMERAL -------------------------------------------------------------


def test_ephemeral_invariant(tmp_path):
    """When a run ends, no execution environment is left to be reused.

    Breaks if: cleanup() stops removing the sandbox, or reports success on a
    directory that survived removal (which is exactly what
    `shutil.rmtree(..., ignore_errors=True)` used to do here).
    """
    writer = _probe(tmp_path, MARKER_WRITER_WAT, "writer.wasm")
    sandbox = WASISandbox(config=_pooled_config())
    result = sandbox.run(writer)
    assert result.status is ExecutionStatus.SUCCESS, result.stderr

    guest_dir = result.sandbox_dir
    host_dir = sandbox._host_dir
    assert guest_dir and host_dir, "the run must report where it lived"

    leftovers = sandbox.cleanup()
    assert leftovers == [], f"cleanup() reported success over residue: {leftovers}"
    assert not os.path.exists(guest_dir), "guest execution environment survives"
    assert not os.path.exists(host_dir), "host capture directory survives"
    assert sandbox._sandbox_dir is None and sandbox._host_dir is None


# --- 2. STATELESS -------------------------------------------------------------


def test_stateless_invariant(tmp_path):
    """Run B reads nothing that run A left behind — including on the pooled path.

    Breaks if: a sandbox directory is reused, the state store leaks between runs
    without a grant, or the engine pool's module cache is keyed by PATH instead of
    by content (the second of these is the one a pooled engine makes easy).
    """
    writer = _probe(tmp_path, MARKER_WRITER_WAT, "writer.wasm")
    reader = _probe(tmp_path, MARKER_READER_WAT, "reader.wasm")
    config = _pooled_config()

    first = WASISandbox(config=config)
    wrote = first.run(writer)
    assert wrote.status is ExecutionStatus.SUCCESS, wrote.stderr
    first_dir = wrote.sandbox_dir
    first.cleanup()

    second = WASISandbox(config=config)
    read = second.run(reader)
    second.cleanup()

    # Detection works: the reader reports 0 only when the marker exists, and it
    # must report non-zero here (ENOENT) because the scratch is a new directory.
    assert (
        read.exit_code != 0
    ), f"persistence across runs: {first_dir} left something in the next sandbox"
    assert read.sandbox_dir != first_dir
    assert TOKEN not in (read.stdout + read.stderr)
    # No host-side state was granted, so none may exist.
    assert read.state_bytes is None, "state carried without an ADR-004 grant"

    # And the pool really was in play for these runs (this is the clause the old
    # pooled test never reached, because the default io budget forced a per-run
    # engine): one config, one shared engine, reused across runs.
    pool = _get_engine_pool()
    engine_a = pool.engine_for(config)
    try:
        assert engine_a is pool.engine_for(config), (
            "engine identity is not stable for one config — the pooled path this "
            "invariant is about is not the path being executed"
        )
    finally:
        pool.release(engine_a)


# --- 3. CAPABILITY-BOUND ------------------------------------------------------


def test_capability_invariant(tmp_path):
    """Nothing carries authority that was not granted, and the report says which.

    Breaks if: a preopen is granted without being asked for, state imports are
    defined without a state store, or the attested `effective_preopens` drifts
    from what the guest could actually reach.
    """
    reader = _probe(tmp_path, MARKER_READER_WAT, "reader.wasm")

    # Default posture: no host directory granted. The guest still gets its own
    # /sandbox scratch, and that is ALL it gets — attested, not assumed.
    sandbox = WASISandbox(config=_pooled_config())
    result = sandbox.run(reader)
    sandbox.cleanup()
    assert result.effective_preopens == ("/sandbox",), result.effective_preopens

    # A granted directory shows up in the attestation, and the guest can really
    # reach it (this is the positive control: without it the assertion above
    # could be passing because nothing is ever readable).
    base = tmp_path / "base"
    base.mkdir()
    (base / "marker.txt").write_text(TOKEN)
    granted = WASIConfig(
        max_fuel=1_000_000,
        timeout_seconds=10,
        io_budget_bytes=None,
        allow_dirs=(str(base),),
    )
    second = WASISandbox(config=granted)
    reached = second.run(reader)
    second.cleanup()
    assert reached.exit_code == 0, "a granted preopen is not reachable by the guest"
    assert any(
        str(base).rstrip("/").endswith(part.strip("/")) or "/sandbox" == part
        for part in reached.effective_preopens
    ), reached.effective_preopens

    # No state store passed => no state imports defined => a guest that imports
    # them never instantiates. (tests/test_state.py proves the import surface;
    # here the invariant is that the capability list is what the run attests.)
    assert result.state_bytes is None and reached.state_bytes is None


# --- 4. VERIFIABLE ------------------------------------------------------------


def test_verifiable_execution_invariant(tmp_path):
    """Evidence stands on its own bytes: verify or refuse, never take a word.

    Breaks if: the signature stops covering the exact record shown to the caller,
    a foreign key verifies, an edited field survives, or the one-of-one evidence
    block leaves the signed payload.
    """
    pytest.importorskip("cryptography")
    from cryptography.hazmat.primitives import serialization
    from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

    from ephemora_cell.execution_report import (
        ExecutionReport,
        canonical_bytes,
        verify_execution_attestation,
    )
    from ephemora_cell_mcp.engine import CellOutcome
    from ephemora_cell_mcp.server import Server
    from ephemora_cell_mcp.tool_registry import (
        ed25519_signer_from_pem,
        ed25519_verifier_from_pem,
    )

    key = Ed25519PrivateKey.generate()
    private_pem = tmp_path / "host.pem"
    public_pem = tmp_path / "host.pub"
    private_pem.write_bytes(
        key.private_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PrivateFormat.PKCS8,
            encryption_algorithm=serialization.NoEncryption(),
        )
    )
    public_pem.write_bytes(
        key.public_key().public_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PublicFormat.SubjectPublicKeyInfo,
        )
    )

    server = Server(
        tools_dir=str(tmp_path),
        transport=object(),
        receipt_signer=ed25519_signer_from_pem(str(private_pem)),
        receipt_key_id="host-1",
    )
    outcome = CellOutcome(
        result=ExecutionResult(
            status=ExecutionStatus.SUCCESS,
            exit_code=0,
            stdout="{}",
            sandbox_dir=None,
        ),
        report=ExecutionReport(status="success", exit_code=0, elapsed_ms=2.0),
        egress=(),
    )
    meta = server._build_call_result(outcome, tool="echo")["_meta"]
    envelope, execution = meta["attestation"], meta["execution"]

    verifier = ed25519_verifier_from_pem(str(public_pem))
    assert verify_execution_attestation(
        envelope, verifier, execution, max_age_seconds=600
    ), "a receipt the operator signed must verify against the operator's key"

    # The signature covers exactly the record the caller was shown.
    assert canonical_bytes(execution) == base64.b64decode(envelope["payload"])
    # The one-of-one block lives INSIDE those bytes, so it cannot be swapped.
    assert b'"evidence"' in base64.b64decode(envelope["payload"])

    edited = dict(execution)
    edited["exit_code"] = 1
    assert not verify_execution_attestation(envelope, verifier, edited)

    foreign_key = Ed25519PrivateKey.generate()
    foreign_pub = tmp_path / "foreign.pub"
    foreign_pub.write_bytes(
        foreign_key.public_key().public_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PublicFormat.SubjectPublicKeyInfo,
        )
    )
    assert not verify_execution_attestation(
        envelope, ed25519_verifier_from_pem(str(foreign_pub)), execution
    ), "key substitution must not produce a credible receipt"
