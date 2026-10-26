# SPDX-License-Identifier: BUSL-1.1
# Copyright 2026 Michael Soppa

"""v1.2 — default-deny and the explicit legacy opt-in, over the real stdio process.

Before this change ``python -m ephemora_cell_mcp`` with no ``--tool-policy`` let an
authenticated client call every registered tool (a warning, no enforcement). Now
no policy means no authorized tool call; the pre-1.2 posture is only reachable by
naming ``--legacy-allow-all``.
"""

from __future__ import annotations

import json
import subprocess
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

import pytest

REPO = Path(__file__).resolve().parent.parent
TOOLS = REPO / "ephemora_cell_mcp" / "tools"

INITIALIZE = {
    "jsonrpc": "2.0",
    "id": 1,
    "method": "initialize",
    "params": {
        "protocolVersion": "2025-06-18",
        "capabilities": {},
        "clientInfo": {"name": "ap04-probe", "version": "0"},
    },
}
CALL = {
    "jsonrpc": "2.0",
    "id": 2,
    "method": "tools/call",
    "params": {"name": "echo", "arguments": {"x": 1}},
}


def _drive(*extra_args):
    payload = "\n".join(json.dumps(r) for r in (INITIALIZE, CALL)) + "\n"
    proc = subprocess.run(
        [
            sys.executable,
            "-m",
            "ephemora_cell_mcp",
            "--tools-dir",
            str(TOOLS),
            *extra_args,
        ],
        input=payload,
        capture_output=True,
        text=True,
        timeout=180,
        cwd=str(REPO),
    )
    responses = [json.loads(line) for line in proc.stdout.splitlines() if line.strip()]
    return proc, responses


def _call_result(responses):
    return next(r.get("result") for r in responses if r.get("id") == 2)


@pytest.mark.skipif(
    not (TOOLS / "echo.wasm").exists(), reason="package tool module not present"
)
def test_no_policy_denies_every_tool_call():
    pytest.importorskip("wasmtime", reason="the run leg needs the wasm runtime")
    proc, responses = _drive()
    assert proc.returncode == 0, proc.stderr
    result = _call_result(responses)
    assert result.get("isError") is True
    assert "not authorized" in result["content"][0]["text"]


@pytest.mark.skipif(
    not (TOOLS / "echo.wasm").exists(), reason="package tool module not present"
)
def test_legacy_allow_all_is_the_only_way_back_to_the_old_posture():
    pytest.importorskip("wasmtime", reason="the run leg needs the wasm runtime")
    proc, responses = _drive("--legacy-allow-all")
    assert proc.returncode == 0, proc.stderr
    result = _call_result(responses)
    assert result.get("isError") is not True
    assert "_meta" in result
    assert "per-tool authorization is OFF" in proc.stderr


# --- v1.2: no start / env / flag combination reaches a permissive mode ----
# In-process over the shipped entry point; every case returns rc=2 BEFORE the
# server serves, so it is fast and never binds a transport.

from ephemora_cell_mcp.__main__ import main  # noqa: E402
from ephemora_cell_mcp.subject_binding import (  # noqa: E402
    ENV_SUBJECT_FROM_UPSTREAM,
    ENV_SUBJECT_SECRET,
)


def _valid_policy(tmp_path) -> str:
    path = tmp_path / "policy.json"
    path.write_text(
        json.dumps(
            {
                "policy_version": "1.2.0-1",
                "subjects": [{"subject": "alice", "permissions": [{"tool": "echo"}]}],
            }
        ),
        encoding="utf-8",
    )
    return str(path)


def test_upstream_subject_mode_without_a_policy_refuses_to_start(tmp_path, monkeypatch):
    monkeypatch.setenv(ENV_SUBJECT_FROM_UPSTREAM, "1")
    monkeypatch.delenv(ENV_SUBJECT_SECRET, raising=False)
    assert main(["--tools-dir", str(tmp_path)]) == 2


def test_upstream_subject_mode_with_a_policy_but_no_secret_refuses(
    tmp_path, monkeypatch
):
    monkeypatch.setenv(ENV_SUBJECT_FROM_UPSTREAM, "1")
    monkeypatch.delenv(ENV_SUBJECT_SECRET, raising=False)
    code = main(
        ["--tools-dir", str(tmp_path), "--tool-policy", _valid_policy(tmp_path)]
    )
    assert code == 2


def test_a_policy_needs_a_subject_or_upstream_mode(tmp_path, monkeypatch):
    monkeypatch.delenv(ENV_SUBJECT_FROM_UPSTREAM, raising=False)
    code = main(
        ["--tools-dir", str(tmp_path), "--tool-policy", _valid_policy(tmp_path)]
    )
    assert code == 2


def test_policy_and_legacy_allow_all_are_mutually_exclusive(tmp_path, monkeypatch):
    monkeypatch.delenv(ENV_SUBJECT_FROM_UPSTREAM, raising=False)
    code = main(
        [
            "--tools-dir",
            str(tmp_path),
            "--tool-policy",
            _valid_policy(tmp_path),
            "--subject",
            "alice",
            "--legacy-allow-all",
        ]
    )
    assert code == 2
