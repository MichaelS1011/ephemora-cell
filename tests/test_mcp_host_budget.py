# SPDX-License-Identifier: BUSL-1.1
# Copyright 2026 Michael Soppa

"""v1.2 — the MCP path spends the host-wide account, not only the CLI.

The CLI admits a run against a shared book before the guest starts. The MCP
server used to execute tools with no cumulative cap at all, so an enforcing
deployment that set a host budget on the CLI could be bypassed by calling the
same tools over MCP. These cases drive the real server entry point and assert
that (a) the cap is enforced before the guest, (b) two server processes on one
book share one cap, and (c) subjects are separate tenant accounts.
"""

from __future__ import annotations

import json
import os
import subprocess
import sys
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from ephemora_cell.tenant import CumulativeBudget, TenantStore
from ephemora_cell_mcp.__main__ import main as server_main
from ephemora_cell_mcp.authz import Authorizer, ToolPolicy
from ephemora_cell_mcp.engine import CellToolEngine, accounting_tenant
from ephemora_cell_mcp.server import Server

REPO = Path(__file__).resolve().parent.parent
TOOLS = REPO / "ephemora_cell_mcp" / "tools"

INITIALIZE = {
    "jsonrpc": "2.0",
    "id": 1,
    "method": "initialize",
    "params": {
        "protocolVersion": "2025-06-18",
        "capabilities": {},
        "clientInfo": {"name": "host-budget-probe", "version": "0"},
    },
}


def _policy(subjects: dict[str, list[str]]) -> Authorizer:
    return Authorizer(
        ToolPolicy.from_dict(
            {
                "policy_version": "test-1",
                "subjects": [
                    {
                        "subject": name,
                        "permissions": [{"tool": tool} for tool in tools],
                    }
                    for name, tools in subjects.items()
                ],
            }
        )
    )


def _call(request_id: int, name: str = "echo") -> dict:
    return {
        "jsonrpc": "2.0",
        "id": request_id,
        "method": "tools/call",
        "params": {"name": name, "arguments": {"n": request_id}},
    }


def _payload(calls: int) -> str:
    requests = [INITIALIZE] + [_call(i) for i in range(2, calls + 2)]
    return "\n".join(json.dumps(r) for r in requests) + "\n"


def _responses(stdout: str) -> list[dict]:
    return [json.loads(line) for line in stdout.splitlines() if line.strip()]


def _is_error(response: dict) -> bool:
    result = response.get("result")
    return bool(isinstance(result, dict) and result.get("isError"))


def _text(response: dict) -> str:
    return response["result"]["content"][0]["text"]


def _server_args(tmp_path: Path, book: Path, *extra: str) -> list[str]:
    policy = tmp_path / "policy.json"
    policy.write_text(
        json.dumps(
            {
                "policy_version": "1.2.0-1",
                "subjects": [{"subject": "alice", "permissions": [{"tool": "echo"}]}],
            }
        ),
        encoding="utf-8",
    )
    return [
        sys.executable,
        "-m",
        "ephemora_cell_mcp",
        "--tools-dir",
        str(TOOLS),
        "--tool-policy",
        str(policy),
        "--subject",
        "alice",
        "--tenant-book",
        str(book),
        *extra,
    ]


def test_the_stdio_server_refuses_runs_beyond_the_host_cap(tmp_path):
    book = tmp_path / "book.jsonl"
    proc = subprocess.run(
        _server_args(tmp_path, book, "--host-max-runs", "1"),
        input=_payload(2),
        capture_output=True,
        text=True,
        timeout=180,
        cwd=str(REPO),
    )
    assert proc.returncode == 0, proc.stderr
    calls = [r for r in _responses(proc.stdout) if r.get("id") in (2, 3)]
    assert len(calls) == 2
    assert not _is_error(calls[0]), _text(calls[0])
    assert _is_error(calls[1])
    assert "host budget exhausted" in _text(calls[1]), _text(calls[1])
    tenants = {
        json.loads(line)["tenant"]
        for line in book.read_text(encoding="utf-8").splitlines()
        if '"tenant"' in line
    }
    assert tenants == {"mcp:s:alice"}, tenants


_CHILD = r"""
import os, sys, time
start = sys.argv[1]
sys.argv = [sys.argv[0], *sys.argv[2:]]
while not os.path.exists(start):
    time.sleep(0.002)
from ephemora_cell_mcp.__main__ import main
raise SystemExit(main())
"""


def test_two_server_processes_share_one_host_cap(tmp_path):
    book = tmp_path / "book.jsonl"
    start = tmp_path / "go"
    args = _server_args(tmp_path, book, "--host-max-runs", "10")
    children = [
        subprocess.Popen(
            [sys.executable, "-c", _CHILD, str(start), *args[3:]],
            stdin=subprocess.PIPE,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True,
            cwd=str(REPO),
        )
        for _ in range(2)
    ]
    start.write_text("go", encoding="utf-8")
    outputs = []
    try:
        for child in children:
            out, err = child.communicate(_payload(10), timeout=240)
            assert child.returncode == 0, err
            outputs.append(out)
    finally:
        for child in children:
            if child.poll() is None:
                child.kill()
    admitted = [
        response
        for stdout in outputs
        for response in _responses(stdout)
        if response.get("id") not in (1, None) and not _is_error(response)
    ]
    refused = [
        response
        for stdout in outputs
        for response in _responses(stdout)
        if response.get("id") not in (1, None) and _is_error(response)
    ]
    assert len(admitted) == 10, (len(admitted), len(refused))
    assert len(refused) == 10
    assert all("host budget exhausted" in _text(r) for r in refused)


def test_a_cap_without_a_book_is_refused_at_startup(tmp_path, capsys):
    assert server_main(["--host-max-runs", "1"]) == 2
    err = capsys.readouterr().err
    assert "need --tenant-book" in err, err


def test_a_cap_with_an_unsafe_book_is_refused_at_startup(tmp_path, capsys):
    target = tmp_path / "real.jsonl"
    target.write_text("", encoding="utf-8")
    link = tmp_path / "link.jsonl"
    os.symlink(target, link)
    assert server_main(["--tenant-book", str(link), "--host-max-runs", "1"]) == 2
    assert "symbolic link" in capsys.readouterr().err


def test_a_cap_without_a_store_is_refused_by_the_engine():
    with pytest.raises(ValueError, match="require a tenant_store"):
        CellToolEngine(host_budget=CumulativeBudget(max_runs=1))


def test_subjects_are_separate_tenant_accounts(tmp_path):
    book = tmp_path / "book.jsonl"
    store = TenantStore(book)
    per_subject = CumulativeBudget(max_runs=1)

    def server_for(subject: str) -> Server:
        return Server(
            tools_dir=TOOLS,
            engine=CellToolEngine(tenant_store=store, tenant_budget=per_subject),
            authorizer=_policy({subject: ["echo"]}),
            subject=subject,
        )

    alice = server_for("alice")
    bob = server_for("bob")
    for server in (alice, bob):
        server.handle_message(INITIALIZE)

    def call(server: Server, request_id: int) -> dict:
        return server.handle_message(_call(request_id))[0]

    assert not _is_error(call(alice, 2))
    refused = call(alice, 3)
    assert _is_error(refused)
    assert "tenant budget exhausted" in _text(refused)
    assert not _is_error(call(bob, 4))
    assert _is_error(call(bob, 5))

    tenants = {
        json.loads(line)["tenant"]
        for line in book.read_text(encoding="utf-8").splitlines()
        if '"tenant"' in line
    }
    assert {"mcp:s:alice", "mcp:s:bob"} <= tenants, tenants


def test_a_flagless_server_on_a_capped_book_adopts_the_cap(tmp_path):
    """F1: the cap is recorded in the book, not only in one process's flags."""
    book = tmp_path / "book.jsonl"
    first = subprocess.run(
        _server_args(tmp_path, book, "--host-max-runs", "2"),
        input=_payload(1),
        capture_output=True,
        text=True,
        timeout=180,
        cwd=str(REPO),
    )
    assert first.returncode == 0, first.stderr
    assert not _is_error(_responses(first.stdout)[1])

    second = subprocess.run(
        _server_args(tmp_path, book),
        input=_payload(3),
        capture_output=True,
        text=True,
        timeout=180,
        cwd=str(REPO),
    )
    assert second.returncode == 0, second.stderr
    calls = [r for r in _responses(second.stdout) if r.get("id") in (2, 3, 4)]
    assert len(calls) == 3
    assert not _is_error(calls[0]), _text(calls[0])
    assert _is_error(calls[1]) and _is_error(calls[2])
    assert "host budget exhausted" in _text(calls[1])


def test_a_looser_cap_than_recorded_is_refused_at_startup(tmp_path):
    book = tmp_path / "book.jsonl"
    first = subprocess.run(
        _server_args(tmp_path, book, "--host-max-runs", "2"),
        input=_payload(1),
        capture_output=True,
        text=True,
        timeout=180,
        cwd=str(REPO),
    )
    assert first.returncode == 0, first.stderr
    looser = subprocess.run(
        _server_args(tmp_path, book, "--host-max-runs", "5"),
        input=_payload(0),
        capture_output=True,
        text=True,
        timeout=180,
        cwd=str(REPO),
    )
    assert looser.returncode == 2, looser.stderr
    assert "exceeds the cap" in looser.stderr
    assert "recorded" in looser.stderr


def test_a_zero_or_negative_cap_is_refused_cleanly(capsys):
    assert server_main(["--host-max-runs", "0"]) == 2
    assert "positive integer" in capsys.readouterr().err
    assert server_main(["--host-max-fuel=-1"]) == 2
    assert "positive integer" in capsys.readouterr().err


def test_an_injected_engine_with_a_book_is_refused(tmp_path):
    store = TenantStore(tmp_path / "book.jsonl")
    with pytest.raises(ValueError, match="injected"):
        Server(
            engine=CellToolEngine(),
            tenant_store=store,
            host_budget=CumulativeBudget(max_runs=1),
        )


def test_subject_labels_cannot_fold_together():
    assert accounting_tenant(None) == "mcp:unattributed"
    assert accounting_tenant("unattributed") == "mcp:s:unattributed"
    assert accounting_tenant("a@b") != accounting_tenant("a_b")
    escaped = accounting_tenant("a@b").removeprefix("mcp:s:")
    assert accounting_tenant(escaped) != accounting_tenant("a@b")
    long = "x" * 90
    assert accounting_tenant(long) != accounting_tenant("x" * 89 + "y")


def test_a_group_writable_book_is_refused_at_startup(tmp_path, capsys):
    book = tmp_path / "book.jsonl"
    book.write_text("", encoding="utf-8")
    os.chmod(book, 0o664)
    try:
        assert server_main(["--tenant-book", str(book)]) == 2
        assert "group- or world-writable" in capsys.readouterr().err
    finally:
        os.chmod(book, 0o600)


def test_a_refusal_leaves_no_open_reservation(tmp_path):
    book = tmp_path / "book.jsonl"
    proc = subprocess.run(
        _server_args(tmp_path, book, "--host-max-runs", "1"),
        input=_payload(2),
        capture_output=True,
        text=True,
        timeout=180,
        cwd=str(REPO),
    )
    assert proc.returncode == 0, proc.stderr
    calls = [r for r in _responses(proc.stdout) if r.get("id") in (2, 3)]
    assert not _is_error(calls[0]), _text(calls[0])
    assert _is_error(calls[1])
    usage = TenantStore(book).usage("mcp:s:alice")
    assert usage.runs == 1
    assert usage.inflight == 0
    lines = [json.loads(line) for line in book.read_text().splitlines()]
    assert sum(1 for line in lines if line.get("kind") == "admit") == 1
    assert sum(1 for line in lines if line.get("kind") == "refuse") == 1


def test_the_host_fuel_cap_refuses_before_the_guest(tmp_path):
    book = tmp_path / "book.jsonl"
    proc = subprocess.run(
        _server_args(tmp_path, book, "--host-max-fuel", "1"),
        input=_payload(1),
        capture_output=True,
        text=True,
        timeout=180,
        cwd=str(REPO),
    )
    assert proc.returncode == 0, proc.stderr
    call = next(r for r in _responses(proc.stdout) if r.get("id") == 2)
    assert _is_error(call)
    assert "host budget exhausted" in _text(call)
    usage = TenantStore(book).usage("mcp:s:alice")
    assert usage.runs == 0
    assert usage.inflight == 0


def test_the_per_subject_cap_is_enforced(tmp_path):
    book = tmp_path / "book.jsonl"
    proc = subprocess.run(
        _server_args(tmp_path, book, "--tenant-max-runs", "1"),
        input=_payload(2),
        capture_output=True,
        text=True,
        timeout=180,
        cwd=str(REPO),
    )
    assert proc.returncode == 0, proc.stderr
    calls = [r for r in _responses(proc.stdout) if r.get("id") in (2, 3)]
    assert not _is_error(calls[0]), _text(calls[0])
    assert _is_error(calls[1])
    assert "tenant budget exhausted" in _text(calls[1])
