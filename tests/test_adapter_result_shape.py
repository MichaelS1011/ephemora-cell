# SPDX-License-Identifier: BUSL-1.1
# Copyright 2026 Michael Soppa

"""Characterization tests: the adapter result shape per language path.

Pins the CURRENT observable contract of the four adapter entry paths: six base
keys everywhere, the parsed ``output`` everywhere, ``guest_reported_error``
exactly on the paths that apply the marker today (python component,
javascript source), and ``exit_status_fidelity`` everywhere — the record's own
statement about whether the guest's exit status could reach the host at all
(``docs/languages.md``, ``tests/test_guest_exit_code_fidelity.py``). The two
marker-less paths (python preview1, javascript module) are pinned **as
marker-less** — closing that gap is a separate, explicitly labeled change with
its own justification, never part of a refactor. The sandboxes are stubbed, so
this runs in milliseconds and never executes a guest.
"""

from __future__ import annotations

import os
import sys
import types
from pathlib import Path

sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))

import wasmtime

from ephemora_cell import lang_js, lang_py

_BASE = {
    "status",
    "stdout",
    "stderr",
    "exit_code",
    "fuel_consumed",
    "elapsed_ms",
    # the measurement base of the shared run document, produced
    # through the same ExecutionReport the wasm path and the signed record use.
    # A language run used to report none of these, so `run --json` had two
    # shapes depending on the file extension.
    "fuel_budget",
    "fuel_utilization",
    "memory_mb",
    "stdout_bytes",
    "stderr_bytes",
    "warnings",
    "security_baseline",
}
#: every path states how much of the guest's exit status can reach the host
_FIDELITY = "exit_status_fidelity"
_COMPONENT_BYTES = b"\x00asm\x0d\x00\x01\x00"
_MINIMAL_CORE_WAT = (
    '(module (import "wasi_snapshot_preview1" "proc_exit" (func (param i32))) '
    '(memory (export "memory") 1) (func (export "_start") i32.const 0 call 0))'
)


def _real_core_module(tmp_path: Path) -> Path:
    """A genuinely parseable Preview1 core module (the inspector compiles it)."""
    path = tmp_path / "core.wasm"
    path.write_bytes(wasmtime.wat2wasm(_MINIMAL_CORE_WAT))
    return path


def _fake_result(
    stdout: str = "",
    stderr: str = "",
    exit_code: int = 0,
    *,
    status: str = "ExecutionStatus.SUCCESS",
    abi: str | None = "preview1",
    guest_exit_observed: bool = True,
):
    return types.SimpleNamespace(
        status=status,
        stdout=stdout,
        stderr=stderr,
        exit_code=exit_code,
        fuel_consumed=None,
        elapsed_ms=None,
        # the two facts the fidelity claim is derived from — a stub that omits
        # them is a stub that never ran a guest, and the helper now says so
        abi=abi,
        guest_exit_observed=guest_exit_observed,
    )


class _StubSandbox:
    stderr = ""
    stdout = ""
    status = "ExecutionStatus.SUCCESS"
    abi: str | None = "preview1"
    guest_exit_observed = True

    def __init__(self, *a, **k):
        pass

    def run(self, path, **kwargs):
        assert kwargs.get("use_subprocess") is True, "worker path must be pinned"
        return _fake_result(
            stdout=self.stdout,
            stderr=self.stderr,
            status=self.status,
            abi=self.abi,
            guest_exit_observed=self.guest_exit_observed,
        )

    def cleanup(self):
        pass


def test_python_component_path_shape(tmp_path, monkeypatch):
    guest = tmp_path / "c.wasm"
    guest.write_bytes(_COMPONENT_BYTES)
    script = tmp_path / "s.py"
    script.write_text("print(1)\n")
    monkeypatch.setattr(lang_py, "WASISandbox", _StubSandbox)
    _StubSandbox.stderr = "EPHEMORA_USER_ERROR"
    # The distinction this route exists to pin: the GUEST here does leave through
    # its exit interface (observed=True), yet the claim stays `none`, because the
    # program the caller handed over is the SCRIPT and this guest's loader returns
    # on SystemExit — so the script's own status never arrives either way.
    _StubSandbox.abi = "component"
    _StubSandbox.guest_exit_observed = True
    try:
        out = lang_py.run_python_script(str(guest), script_path=str(script))
    finally:
        _StubSandbox.abi = "preview1"
    assert set(out) == _BASE | {"output", "guest_reported_error", _FIDELITY}
    assert out["guest_reported_error"] is True
    # nothing on this path measures resident memory, so the shared field must
    # say "not measured" instead of a fabricated zero (same rule as a wasm run)
    assert out["memory_mb"] is None
    # the shipped component guest's loader returns on SystemExit, so no script
    # exit status ever leaves it (measured; docs/languages.md)
    assert out[_FIDELITY] == "none"


def test_python_preview1_path_shape(tmp_path, monkeypatch):
    stdlib = tmp_path / "stdlib"
    stdlib.mkdir()
    script = tmp_path / "s.py"
    script.write_text("print(1)\n")
    core = _real_core_module(tmp_path)
    monkeypatch.setattr(lang_py, "WASISandbox", _StubSandbox)
    _StubSandbox.stderr = "EPHEMORA_USER_ERROR"
    out = lang_py.run_python_script(
        str(core), stdlib_dir=str(stdlib), script_path=str(script)
    )
    assert set(out) == _BASE | {"output", _FIDELITY}  # marker-less path, pinned as-is
    # the Preview1 interpreter's proc_exit reaches the host as the run's own
    # exit status (measured: sys.exit(3) reports 3) — and that word is now
    # DERIVED from the run's facts, not named by this route
    assert out[_FIDELITY] == "exact"


def test_a_host_stop_on_the_preview1_python_route_is_not_attested_as_exact(
    tmp_path, monkeypatch
):
    """A fuel stop produced no guest exit, so no exit status may be attested.

    This is the case a per-route literal could not express: the same channel
    delivers the script's own number when the guest exits and delivers NOTHING
    when the host stops the run. Claiming `exact` there would sign an exit code
    the host never observed.
    """
    stdlib = tmp_path / "stdlib"
    stdlib.mkdir()
    script = tmp_path / "s.py"
    script.write_text("while True: pass\n")
    core = _real_core_module(tmp_path)
    monkeypatch.setattr(lang_py, "WASISandbox", _StubSandbox)
    _StubSandbox.status = "ExecutionStatus.FUEL_EXHAUSTED"
    _StubSandbox.guest_exit_observed = False
    try:
        out = lang_py.run_python_script(
            str(core), stdlib_dir=str(stdlib), script_path=str(script)
        )
    finally:
        _StubSandbox.status = "ExecutionStatus.SUCCESS"
        _StubSandbox.guest_exit_observed = True
    assert out[_FIDELITY] == "none", out
    assert out["exit_status_fidelity"] == "none"


def test_javascript_module_path_shape(tmp_path, monkeypatch):
    core = _real_core_module(tmp_path)
    monkeypatch.setattr(lang_js, "WASISandbox", _StubSandbox)
    _StubSandbox.stderr = "EPHEMORA_USER_ERROR"
    out = lang_js.run_javascript_module(str(core), input_json={"a": 1})
    assert set(out) == _BASE | {"output", _FIDELITY}  # marker-less path, pinned as-is
    # a caller-built guest IS the program on this entry and the run goes over
    # the Preview1 ABI, whose exit status the host observes directly (measured
    # through this same entry in tests/test_guest_exit_code_fidelity.py)
    assert out[_FIDELITY] == "exact"


def test_a_host_stop_on_the_javascript_module_route_is_not_attested_as_exact(
    tmp_path, monkeypatch
):
    """The route that used to name `exact` unconditionally, pinned at its other pole."""
    core = _real_core_module(tmp_path)
    monkeypatch.setattr(lang_js, "WASISandbox", _StubSandbox)
    _StubSandbox.status = "ExecutionStatus.FUEL_EXHAUSTED"
    _StubSandbox.guest_exit_observed = False
    try:
        out = lang_js.run_javascript_module(str(core), input_json={"a": 1})
    finally:
        _StubSandbox.status = "ExecutionStatus.SUCCESS"
        _StubSandbox.guest_exit_observed = True
    assert out["status"] == "ExecutionStatus.FUEL_EXHAUSTED", out
    assert out[_FIDELITY] == "none", out


def test_javascript_source_path_shape(tmp_path, monkeypatch):
    core = _real_core_module(tmp_path)
    monkeypatch.setattr(lang_js, "WASISandbox", _StubSandbox)
    _StubSandbox.stderr = "EPHEMORA_USER_ERROR"
    # the QuickJS harness decides, so the run attests no guest exit — measured:
    # a thrown error and process.exit(5) both come back success/0
    _StubSandbox.guest_exit_observed = False
    try:
        out = lang_js.run_javascript_source(str(core), source="1;")
    finally:
        _StubSandbox.guest_exit_observed = True
    assert set(out) == _BASE | {"output", "guest_reported_error", _FIDELITY}
    assert out["guest_reported_error"] is True
    assert out[_FIDELITY] == "none"
