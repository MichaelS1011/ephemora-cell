# SPDX-License-Identifier: BUSL-1.1
# Copyright 2026 Michael Soppa
"""Execution-record integrity across the public APIs.

The invariant this pins: a *guest-supplied* message (stdout/stderr content the
sandboxed user's own code writes) can NEVER determine or overwrite the
*host-observed* execution status or exit code, at every public boundary:

  * language adapters (``run_python`` / ``run_javascript`` source path) — the
    marker is surfaced only as the separate, untrusted ``guest_reported_error``;
  * the MCP ``tools/call`` surface — ``_meta.execution`` carries the host report,
    ``isError`` is a tool-contract *message*, and host facts override any guest
    ``status``/``exit_code`` the guest tried to inject into its own output.

Counterexamples (forged markers / ``{"status":"ok"}`` on a host failure) are
asserted to leave the authoritative status untouched.
"""

from __future__ import annotations

import json
import types

from ephemora_cell import lang_py
from ephemora_cell.lang_py import run_python_script
from ephemora_cell_mcp.engine import parse_tool_stdout
from ephemora_cell_mcp.server import Server

COMPONENT_BYTES = b"\x00asm\x0d\x00\x01\x00" + b"\x00" * 32


# --------------------------------------------------------------------------
# language adapter: a forged marker cannot fabricate a non-zero host exit
# --------------------------------------------------------------------------
def _fake_result(status: str, stdout: str, stderr: str, exit_code: int):
    return types.SimpleNamespace(
        status=status,
        stdout=stdout,
        stderr=stderr,
        exit_code=exit_code,
        fuel_consumed=None,
        elapsed_ms=None,
    )


class _StubSandbox:
    def __init__(self, *a, **k):
        pass

    def run(self, path, **kwargs):
        return _fake_result("ExecutionStatus.SUCCESS", "", "EPHEMORA_USER_ERROR", 0)

    def cleanup(self):
        pass


def test_adapter_forged_marker_keeps_host_status(tmp_path, monkeypatch):
    guest = tmp_path / "g.wasm"
    guest.write_bytes(COMPONENT_BYTES)
    script = tmp_path / "s.py"
    script.write_text("import sys; sys.stderr.write('EPHEMORA_USER_ERROR')\n")
    monkeypatch.setattr(lang_py, "WASISandbox", _StubSandbox)
    out = run_python_script(str(guest), script_path=str(script))
    # host saw a clean exit 0; the guest's self-report is a separate flag only
    assert out["exit_code"] == 0
    assert out["status"].endswith("SUCCESS")
    assert out["guest_reported_error"] is True


# --------------------------------------------------------------------------
# MCP: parse_tool_stdout is a message parser, not a status oracle
# --------------------------------------------------------------------------
def test_parse_tool_stdout_error_convention_is_structural_only():
    # a well-formed tool-contract error object -> message flag True
    payload, is_error = parse_tool_stdout(json.dumps({"error": "boom"}))
    assert is_error is True and payload["error"] == "boom"
    # arbitrary 'Error' text is NOT promoted to the tool error convention
    _, is_error = parse_tool_stdout("Error: something happened on stderr")
    assert is_error is False
    # a guest claiming success is just a payload, never an error
    _, is_error = parse_tool_stdout(json.dumps({"status": "ok"}))
    assert is_error is False


def _outcome(result_status: str, exit_code: int, stdout: str):
    result = types.SimpleNamespace(stdout=stdout, exit_code=exit_code, stderr="")
    report = types.SimpleNamespace(
        status=result_status,
        to_dict=lambda: {"status": result_status, "exit_code": exit_code},
    )
    return types.SimpleNamespace(result=result, report=report, egress=())


def _call(result_status, exit_code, stdout):
    self = types.SimpleNamespace(receipt_signer=None)
    return Server._build_call_result(
        self, _outcome(result_status, exit_code, stdout), tool="t"
    )


def test_mcp_clean_run_no_iserror():
    msg = _call("success", 0, json.dumps({"status": "ok"}))
    assert msg.get("isError", False) is False
    assert msg["_meta"]["execution"]["status"] == "success"


def test_mcp_guest_cannot_overwrite_host_status_on_failure():
    # host FUEL_EXHAUSTED but the guest prints {"status":"ok"} — host fact wins
    msg = _call("fuel_exhausted", 0, json.dumps({"status": "ok"}))
    assert msg["isError"] is True
    assert msg["_meta"]["execution"]["status"] == "fuel_exhausted"
    text = json.loads(msg["content"][0]["text"])
    assert text["status"] == "fuel_exhausted"  # not the guest's "ok"
    assert text["exit_code"] == 0  # host-observed


def test_mcp_tool_error_message_is_separate_from_host_status():
    # host SUCCESS, guest reports a tool-level error object -> isError is a
    # message, but the authoritative host status in _meta stays "success"
    msg = _call("success", 0, json.dumps({"error": "boom", "status": "ok"}))
    assert msg["isError"] is True
    assert msg["_meta"]["execution"]["status"] == "success"
    text = json.loads(msg["content"][0]["text"])
    assert text["error"] == "boom"  # guest message preserved
    assert text["status"] == "success"  # host fact overrides it
