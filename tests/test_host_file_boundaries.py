# SPDX-License-Identifier: BUSL-1.1
# Copyright 2026 Michael Soppa
"""The host must never be the thing that follows a path the guest controls.

Ephemora Cell's file boundary is enforced by preopens, and that holds for the
guest: wasmtime refuses to resolve a link out of a granted directory. But the
host also opens paths inside the guest's own sandbox — the sidecar request and
response artifacts — and there the protection has to come from THIS side. A
`path_symlink` with a RELATIVE target is accepted by WASI
(`../../../..` resolves wherever the host's cwd-relative open lands, and an
absolute target is what gets refused, errno ENOTCAPABLE), so an ordinary
`Path.read_bytes()` / `write_text()` on a guest-created name is a guest-authored
pointer into the host user's files.

These tests are the gate for that class of bug: every one plants a link or a
non-regular file at a host-read or host-written name and asserts the host
refuses it — with an audit line, not silence.
"""

from __future__ import annotations

import json
import os
import sys
from pathlib import Path

sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))

import pytest

from ephemora_cell._fsutil import read_regular_nofollow
from ephemora_cell._sandbox_common import read_capped_output
from ephemora_cell.egress_sidecar import (
    REQUEST_FILENAME,
    REQUEST_MAX_BYTES,
    RESPONSE_FILENAME,
)
from ephemora_cell.wasi_runtime import WASIConfig, WASISandbox
from ephemora_cell_mcp.engine import CellToolEngine

POLICY_ENDPOINT = "http://127.0.0.1:1/refuse-me"


def _engine() -> CellToolEngine:
    from ephemora_cell.egress_sidecar import EgressPolicy

    return CellToolEngine(
        egress_policy=EgressPolicy(allowed_endpoints=(POLICY_ENDPOINT,))
    )


def _sandbox_with(tmp_path, name: str, target: Path | None = None, body: str = ""):
    sandbox = tmp_path / "sandbox"
    sandbox.mkdir(exist_ok=True)
    path = sandbox / name
    if target is not None:
        path.symlink_to(target)
    else:
        path.write_text(body)
    return str(sandbox)


# --- the request artifact: a name the guest can point anywhere ----------------


def test_host_does_not_read_through_a_planted_symlink(tmp_path):
    """Request artifact is a link to a host file → refused, and its target is
    never opened (the proof is a target whose contents would have been parsed)."""
    secret = tmp_path / "host_secret.json"
    secret.write_text(json.dumps({"url": POLICY_ENDPOINT, "method": "GET"}))
    sandbox_dir = _sandbox_with(tmp_path, REQUEST_FILENAME, target=secret)

    entries = _engine()._mediate_egress(sandbox_dir, "echo")

    assert len(entries) == 1, entries
    audit = entries[0]
    assert audit["decision"] == "denied", audit
    assert "symbolic link" in audit["reason"], audit
    # The client-facing reason must not carry the absolute host path either.
    assert str(tmp_path) not in audit["reason"], audit
    assert "sidecar.request.json" not in json.dumps(audit["response"])


def test_host_does_not_write_through_a_planted_symlink(tmp_path):
    """The escape this actually enabled: a link at the RESPONSE name made the
    host truncate and overwrite a file outside the sandbox with host-written
    JSON. The victim must keep its bytes, and the artifact must appear in the
    sandbox as a regular file."""
    victim = tmp_path / "victim.txt"
    victim.write_text("PRE-EXISTING HOST CONTENT")
    sandbox_dir = _sandbox_with(
        tmp_path,
        REQUEST_FILENAME,
        body=json.dumps({"url": "http://not-allowlisted.invalid/x", "method": "GET"}),
    )
    (Path(sandbox_dir) / RESPONSE_FILENAME).symlink_to(victim)

    entries = _engine()._mediate_egress(sandbox_dir, "echo")

    assert entries and entries[0]["decision"] == "denied", entries
    assert victim.read_text() == "PRE-EXISTING HOST CONTENT", (
        "the host wrote THROUGH a guest-planted link — arbitrary host file "
        "overwrite as the server user"
    )
    response = Path(sandbox_dir) / RESPONSE_FILENAME
    # The name now holds a regular file the host published atomically — the link
    # was replaced, never written through.
    assert response.is_symlink() is False
    assert json.loads(response.read_text())["ok"] is False


def test_request_must_be_a_regular_file(tmp_path):
    """A directory (or a FIFO) at the artifact name is refused, not opened."""
    sandbox = tmp_path / "sandbox"
    sandbox.mkdir()
    (sandbox / REQUEST_FILENAME).mkdir()

    entries = _engine()._mediate_egress(str(sandbox), "echo")

    assert len(entries) == 1 and entries[0]["decision"] == "denied", entries


def test_oversized_request_is_refused_at_the_read_not_after_it(tmp_path):
    """The host parser must not allocate whatever the guest decided to write."""
    sandbox_dir = _sandbox_with(
        tmp_path, REQUEST_FILENAME, body="[" + "1" * (REQUEST_MAX_BYTES + 8) + "]"
    )

    entries = _engine()._mediate_egress(sandbox_dir, "echo")

    assert len(entries) == 1 and entries[0]["decision"] == "denied", entries
    assert "byte limit" in entries[0]["reason"], entries[0]["reason"]
    assert str(tmp_path) not in entries[0]["reason"], entries[0]


def test_absent_artifact_stays_silent(tmp_path):
    """Positive control for the refusals above: no file is not a denial, it is no
    egress surface at all (the documented quiet case)."""
    sandbox = tmp_path / "sandbox"
    sandbox.mkdir()
    assert _engine()._mediate_egress(str(sandbox), "echo") == ()


# --- the helper itself --------------------------------------------------------


def test_read_regular_nofollow_refuses_links_and_directories(tmp_path):
    file = tmp_path / "real.txt"
    file.write_text("content")
    assert read_regular_nofollow(file) == b"content"

    link = tmp_path / "link.txt"
    link.symlink_to(file)
    with pytest.raises(OSError):
        read_regular_nofollow(link)

    directory = tmp_path / "dir"
    directory.mkdir()
    with pytest.raises(OSError):
        read_regular_nofollow(directory)

    with pytest.raises(OSError):
        read_regular_nofollow(file, 3)


# --- ephemeral: a residue must be a fact, not a rumour -----------------------


@pytest.mark.skipif(
    sys.platform != "linux" and not sys.platform.startswith("darwin"),
    reason="POSIX unlink permissions",
)
@pytest.mark.skipif(os.geteuid() == 0, reason="root ignores directory permissions")
def test_cleanup_reports_a_directory_it_could_not_remove(tmp_path):
    """`shutil.rmtree(..., ignore_errors=True)` made a failed cleanup look like
    a successful one. The promise is that no execution environment survives."""
    # A guest built here, not an example shipped in the repo: this gate has to run
    # from an installed artifact too, where `examples/` does not exist.
    import wasmtime

    guest = tmp_path / "quiet.wasm"
    guest.write_bytes(
        wasmtime.wat2wasm(
            '(module (import "wasi_snapshot_preview1" "proc_exit" '
            '(func $exit (param i32))) (func (export "_start") '
            "(call $exit (i32.const 0))))"
        )
    )
    sandbox = WASISandbox(config=WASIConfig(max_fuel=1_000_000, timeout_seconds=10))
    result = sandbox.run(str(guest))
    guest_dir = result.sandbox_dir
    assert guest_dir and os.path.isdir(guest_dir)

    # Make removal fail for real: a child directory the user may not write to.
    blocker = Path(guest_dir) / "blocker"
    blocker.mkdir()
    inside = blocker / "file.txt"
    inside.write_text("x")
    os.chmod(blocker, 0o500)
    try:
        leftovers = sandbox.cleanup()
    finally:
        os.chmod(blocker, 0o700)

    assert leftovers, "cleanup() claimed success over a surviving sandbox dir"
    assert any(str(guest_dir) in item for item in leftovers), leftovers


@pytest.mark.skipif(os.geteuid() == 0, reason="root ignores file permissions")
def test_read_capped_output_does_not_report_an_unreadable_capture_as_empty(tmp_path):
    """A capture file that exists but cannot be read is NOT 'the guest printed
    nothing' — that confusion turns a lost output into a confident record."""
    missing = tmp_path / "gone.txt"
    assert read_capped_output(str(missing)) == ""

    unreadable = tmp_path / "capture.txt"
    unreadable.write_text("output")
    os.chmod(unreadable, 0)
    try:
        reported = read_capped_output(str(unreadable))
    finally:
        os.chmod(unreadable, 0o644)
    assert reported != "", "unreadable capture reported as empty success"
    assert "could not read" in reported, reported


def test_a_host_side_run_failure_keeps_its_traceback_off_the_guest_surface(tmp_path):
    """The runtime, not a hand-built outcome: a guest that fails to instantiate
    inside the HOST used to return the host stack as `stderr`, which the MCP
    layer then hands to the client."""
    import wasmtime

    from ephemora_cell import ExecutionStatus

    broken = tmp_path / "broken.wasm"
    broken.write_bytes(wasmtime.wat2wasm("""
            (module
              (import "wasi_snapshot_preview1" "path_open"
                (func $po (param i32) (result i32)))  ;; wrong signature
              (func (export "_start") (drop (call $po (i32.const 3))))
            )
            """))
    sandbox = WASISandbox(config=WASIConfig(max_fuel=1_000_000, timeout_seconds=10))
    result = sandbox.run(str(broken))
    residue = sandbox.cleanup()
    assert residue == []
    assert result.status is not ExecutionStatus.SUCCESS, result.status
    assert "Traceback" not in result.stderr, result.stderr[:300]
    assert "site-packages" not in result.stderr, result.stderr[:300]
    assert (
        result.host_traceback and "Traceback" in result.host_traceback
    ), "the operator side lost the diagnostic the client side just gave up"
