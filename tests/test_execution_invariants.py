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
import stat
import sys

sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))

import pytest
import wasmtime
from test_persistence_worm import MARKER_READER_WAT, MARKER_WRITER_WAT

from ephemora_cell import ExecutionResult, ExecutionStatus, WASIConfig, WASISandbox
from ephemora_cell.execution_report import TRUST_TRUSTED
from ephemora_cell.wasi_runtime import _get_engine_pool

# A guest that writes a marker into its scratch, and one that reports whether a
# marker is there (exit 0 = present). Both are the worm probe's own guests, so
# this file cannot pass by testing a harness that detects nothing.
TOKEN = "PERSIST-MARKER-42"

# A guest that writes to BOTH output streams and reads stdin. Needed because the
# stdout/stderr capture is written by the byte sink in `_sandbox_common`, while a
# guest that only writes a file exercises nothing there: measured during the
# pre-push review, the sink's append-mode open had never been executed by the
# suite that claims capture files are owner-only.
SINK_WRITER_WAT = """
(module
  (import "wasi_snapshot_preview1" "fd_write"
    (func $fd_write (param i32 i32 i32 i32) (result i32)))
  (import "wasi_snapshot_preview1" "fd_read"
    (func $fd_read (param i32 i32 i32 i32) (result i32)))
  (memory (export "memory") 1)
  (data (i32.const 64) "OUT-MARKER-7f3a\\n")
  (data (i32.const 128) "ERR-MARKER-7f3a\\n")
  (func (export "_start")
    ;; iovec for stdout: base 64, len 16
    (i32.store (i32.const 16) (i32.const 64))
    (i32.store (i32.const 20) (i32.const 16))
    ;; iovec for stderr: base 128, len 16
    (i32.store (i32.const 24) (i32.const 128))
    (i32.store (i32.const 28) (i32.const 16))
    ;; one read of stdin into the scratch area at 256
    (i32.store (i32.const 32) (i32.const 256))
    (i32.store (i32.const 36) (i32.const 64))
    (drop (call $fd_read (i32.const 0) (i32.const 32) (i32.const 1) (i32.const 40)))
    (drop (call $fd_write (i32.const 1) (i32.const 16) (i32.const 1) (i32.const 0)))
    (drop (call $fd_write (i32.const 2) (i32.const 24) (i32.const 1) (i32.const 4)))))
"""


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
    # The ephemerality guarantee is about the in-process sandbox/host directory
    # lifecycle the parent object owns; the mandate's default posture would run
    # the guest in a worker (a separate process) where these parent-side
    # attributes are never populated. Declare the sanctioned in-process path.
    result = sandbox.run(writer, trust=TRUST_TRUSTED)
    assert result.status is ExecutionStatus.SUCCESS, result.stderr

    guest_dir = result.sandbox_dir
    host_dir = sandbox._host_dir
    assert guest_dir and host_dir, "the run must report where it lived"

    leftovers = sandbox.cleanup()
    assert leftovers == [], f"cleanup() reported success over residue: {leftovers}"
    assert not os.path.exists(guest_dir), "guest execution environment survives"
    assert not os.path.exists(host_dir), "host capture directory survives"
    assert sandbox._sandbox_dir is None and sandbox._host_dir is None


def test_ephemeral_component_run_delegated_by_the_facade(tmp_path):
    """A component run through the facade is ephemeral for the facade's caller too.

    The facade answers a component by building a private `ComponentSandbox`
    (`wasi_runtime.py`), running it and discarding the object. That capture
    directory belongs to the inner object, so the facade's own `cleanup()` cannot
    reach it — an operator who follows the documented lifecycle (run, then
    `cleanup()`) is left with the guest's stdin and stdout on disk indefinitely,
    while the promise above says a run leaves nothing reusable behind.

    Breaks if: the delegation stops pairing its run with the inner cleanup.
    """
    component = os.path.join(os.path.dirname(__file__), "fixtures", "hello02.wasm")
    base = tmp_path / "base"
    base.mkdir()
    sandbox = WASISandbox(
        config=WASIConfig(
            max_memory_mb=128, max_fuel=50_000_000, sandbox_base_dir=str(base)
        )
    )
    result = sandbox.run(
        component,
        abi="component",
        trust=TRUST_TRUSTED,
        stdin_data="token=not-a-real-credential-7f3a",
    )
    assert result.status is ExecutionStatus.SUCCESS, result.stderr

    survivors = sorted(p.name for p in base.iterdir() if p.name.startswith("ephemora_"))
    assert survivors == [], f"the delegated run orphaned its capture dir: {survivors}"
    assert sandbox.cleanup() == []


def test_capture_files_are_owner_only(tmp_path):
    """What a run writes to disk is readable by its owner and by nobody else.

    The capture files hold the caller's own stdin and the guest's output. The
    directory around them is created by `mkdtemp` (0700), but a file opened with
    the plain built-in inherits the process umask and lands at 0644 — group and
    world read bits on a file the product has no reason to expose. The promise is
    about the run leaving nothing readable behind; it is not satisfied by a parent
    directory alone, because a caller may place the run inside a directory that
    other processes already share.

    Breaks if: a capture file is created without owner-only permission bits.
    """
    module = _probe(tmp_path, MARKER_WRITER_WAT, "writer.wasm")
    base = tmp_path / "base"
    base.mkdir()
    sandbox = WASISandbox(
        config=WASIConfig(max_fuel=None, timeout_seconds=60, sandbox_base_dir=str(base))
    )
    result = sandbox.run(
        module, trust=TRUST_TRUSTED, stdin_data="token=not-a-real-credential-7f3a"
    )
    assert result.status is ExecutionStatus.SUCCESS, result.stderr

    host_dir = sandbox._host_dir
    assert host_dir is not None, "the in-process run must own a capture directory"
    names = sorted(os.listdir(host_dir))
    assert names, "the run produced no capture file to inspect"
    for name in names:
        mode = os.stat(os.path.join(host_dir, name)).st_mode
        shared = mode & (stat.S_IRGRP | stat.S_IWGRP | stat.S_IROTH | stat.S_IWOTH)
        assert (
            shared == 0
        ), f"{name} is reachable beyond its owner: {oct(stat.S_IMODE(mode))}"


def test_every_capture_sink_is_owner_only(tmp_path):
    """stdin, stdout AND stderr — the sink path, not just the stdin path.

    The claim in `open_private` is about every host-side capture file. The leg
    above drives a guest that writes a file inside its sandbox, so the stdout and
    stderr sink (which opens in APPEND mode through the same helper) never ran:
    measured during the pre-push review, that line had zero coverage. A guest
    that writes both streams proves the sink's bits are owner-only too.

    Breaks if: any capture sink is opened without owner-only permission bits.
    """
    module = _probe(tmp_path, SINK_WRITER_WAT, "sinks.wasm")
    base = tmp_path / "base"
    base.mkdir()
    sandbox = WASISandbox(
        config=WASIConfig(max_fuel=None, timeout_seconds=60, sandbox_base_dir=str(base))
    )
    result = sandbox.run(
        module, trust=TRUST_TRUSTED, stdin_data="token=not-a-real-credential-7f3a"
    )
    assert result.status is ExecutionStatus.SUCCESS, result.stderr
    # the guest really produced both streams — otherwise the file set below could
    # be satisfied by a run that wrote nothing
    assert "OUT-MARKER-7f3a" in result.stdout, result.stdout
    assert "ERR-MARKER-7f3a" in result.stderr, result.stderr

    host_dir = sandbox._host_dir
    assert host_dir is not None
    names = sorted(os.listdir(host_dir))
    assert {"stdin.txt", "stdout.txt", "stderr.txt"} <= set(names), names
    for name in names:
        mode = os.stat(os.path.join(host_dir, name)).st_mode
        shared = mode & (stat.S_IRGRP | stat.S_IWGRP | stat.S_IROTH | stat.S_IWOTH)
        assert (
            shared == 0
        ), f"{name} is reachable beyond its owner: {oct(stat.S_IMODE(mode))}"
    assert sandbox.cleanup() == []


def test_component_route_capture_is_owner_only(tmp_path):
    """The WASI 0.2 route gets the same inspection as the Preview1 route.

    The facade deletes a delegated component run's directory inside `run()`, so
    the bits on that route were never looked at. Driven through the primitive
    directly, which is also the entry point a caller can use on its own.

    Breaks if: the component route's capture files are created world-readable.
    """
    from ephemora_cell.wasi_02 import ComponentSandbox

    component = os.path.join(os.path.dirname(__file__), "fixtures", "hello02.wasm")
    base = tmp_path / "base"
    base.mkdir()
    sandbox = ComponentSandbox(
        WASIConfig(max_memory_mb=128, max_fuel=50_000_000, sandbox_base_dir=str(base))
    )
    try:
        result = sandbox.run(component, stdin_data="token=not-a-real-credential-7f3a")
        assert result.status is ExecutionStatus.SUCCESS, result.stderr
        host_dir = sandbox._host_dir
        assert host_dir is not None, "the component run owns a capture directory"
        names = sorted(os.listdir(host_dir))
        assert names, "the component run produced no capture file"
        for name in names:
            mode = os.stat(os.path.join(host_dir, name)).st_mode
            shared = mode & (stat.S_IRGRP | stat.S_IWGRP | stat.S_IROTH | stat.S_IWOTH)
            assert (
                shared == 0
            ), f"{name} is reachable beyond its owner: {oct(stat.S_IMODE(mode))}"
    finally:
        assert sandbox.cleanup() == []


def test_open_private_corrects_pre_existing_bits(tmp_path):
    """Owner-only is a property of the open, not only of the creation.

    `O_CREAT`'s mode argument is IGNORED when the file already exists, so a
    capture path that survived with 0644 kept 0644 through the hardened helper —
    measured during the pre-push review. The helper has to set the bits on the
    descriptor it just opened.

    Breaks if: open_private leaves an existing file's group or world bits alone.
    """
    from ephemora_cell._sandbox_common import open_private

    for preset, mode in ((0o644, "w"), (0o666, "ab"), (0o640, "wb")):
        path = str(tmp_path / f"capture-{oct(preset)[2:]}.txt")
        fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, preset)
        os.close(fd)
        os.chmod(path, preset)  # independent of the process umask
        with open_private(path, mode) as handle:
            handle.write(b"x" if "b" in mode else "x")
        assert (
            stat.S_IMODE(os.stat(path).st_mode) == 0o600
        ), f"preset {oct(preset)} survived as {oct(stat.S_IMODE(os.stat(path).st_mode))}"


def test_component_cleanup_reports_a_directory_it_cannot_remove(tmp_path):
    """A failed removal is reported, on the component route as on the facade.

    `ignore_errors=True` with no return value made an undeletable capture
    directory read as "cleaned". The promise is that nothing survives; a
    survivor must be visible to the caller and to the log.

    Breaks if: cleanup() returns nothing while the directory is still there.
    """
    from ephemora_cell.wasi_02 import ComponentSandbox

    component = os.path.join(os.path.dirname(__file__), "fixtures", "hello02.wasm")
    base = tmp_path / "base"
    base.mkdir()
    sandbox = ComponentSandbox(
        WASIConfig(max_memory_mb=128, max_fuel=50_000_000, sandbox_base_dir=str(base))
    )
    result = sandbox.run(component)
    assert result.status is ExecutionStatus.SUCCESS, result.stderr
    host_dir = sandbox._host_dir
    assert host_dir is not None
    os.chmod(host_dir, 0o500)  # no write permission -> entries cannot be unlinked
    try:
        leftovers = sandbox.cleanup()
        assert leftovers == [host_dir], (
            f"cleanup reported {leftovers} while {host_dir} still exists: "
            f"{os.path.isdir(host_dir)}"
        )
    finally:
        os.chmod(host_dir, 0o700)
        import shutil

        shutil.rmtree(host_dir, ignore_errors=True)


def test_facade_carries_residue_from_a_delegated_component_run(tmp_path, monkeypatch):
    """The delegation must not swallow what the primitive reports.

    The facade's own cleanup loop can only see directories it created itself, so
    a component run's residue reaches the caller only if the delegation hands it
    over. Driven through a REAL delegated run with only the removal outcome
    substituted — the wiring is what this pins, not the accumulator arithmetic.

    Breaks if: the delegation calls cleanup() and discards its result.
    """
    from ephemora_cell import wasi_02

    survivor = "/nonexistent/ephemora_host_probe_survivor"
    monkeypatch.setattr(
        wasi_02.ComponentSandbox,
        "cleanup",
        lambda self: [survivor],
        raising=True,
    )
    component = os.path.join(os.path.dirname(__file__), "fixtures", "hello02.wasm")
    base = tmp_path / "base"
    base.mkdir()
    sandbox = WASISandbox(
        config=WASIConfig(
            max_memory_mb=128, max_fuel=50_000_000, sandbox_base_dir=str(base)
        )
    )
    result = sandbox.run(component, abi="component", trust=TRUST_TRUSTED)
    assert result.status is ExecutionStatus.SUCCESS, result.stderr
    assert sandbox._delegated_residue == [survivor], sandbox._delegated_residue
    assert sandbox.cleanup() == [survivor]


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
