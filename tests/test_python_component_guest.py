"""Tests for the modern Python *component* guest path in lang_py.

Added 2026-10-15: the adapter now auto-detects a WASI-0.2 component
guest from its bytes and runs the user's own Python script through the isolated
subprocess worker — no ``stdlib_dir``, no manual hunting, no host fallback. These
tests pin that routing and the graceful ``EPHEMORA_USER_ERROR`` handling without
needing the 19 MB guest binary, plus an opt-in real round-trip when a component
guest is supplied out-of-band.
"""

import hashlib
import os
from typing import ClassVar

import pytest

from ephemora_cell import lang_py
from ephemora_cell.lang_py import (
    _COMPONENT_PREAMBLE,
    AdapterPolicyError,
    run_python_script,
)

# A component is \0asm + layer 0x0d + version; anything else is treated as a
# core module (the interpreter path) by the byte sniff.
COMPONENT_BYTES = _COMPONENT_PREAMBLE + b"\x00" * 24


def _fake_result(status, stdout, stderr, exit_code):
    class _R:
        pass

    r = _R()
    r.status = status
    r.stdout = stdout
    r.stderr = stderr
    r.exit_code = exit_code
    r.fuel_consumed = 1
    r.elapsed_ms = 1
    return r


class _RecordingSandbox:
    """Stand-in for WASISandbox that captures how the component path is called."""

    last: ClassVar[dict] = {}

    def __init__(self, config=None):
        _RecordingSandbox.last["config"] = config

    def run(self, path, **kwargs):
        _RecordingSandbox.last.update(kwargs)
        _RecordingSandbox.last["path"] = path
        # simulate the guest: if the staged script raised, echo the marker
        stderr = (
            "EPHEMORA_USER_ERROR\nTraceback...\n"
            if "boom" in (kwargs.get("stdin_data") or "")
            else ""
        )
        # stdin carries caller data, not the code; return a benign success unless
        # the marker was injected via the pre-staged script content.
        return _fake_result("ExecutionStatus.SUCCESS", "{}", stderr, 0)

    def cleanup(self):
        pass


@pytest.fixture
def comp_guest(tmp_path):
    g = tmp_path / "guest.wasm"
    g.write_bytes(COMPONENT_BYTES)
    return str(g)


@pytest.fixture
def script(tmp_path):
    s = tmp_path / "user.py"
    s.write_text("print('hi')\n")
    return str(s)


def test_is_component_detects_preamble(comp_guest):
    assert lang_py._is_component_guest(comp_guest) is True


def test_is_component_false_for_core_and_missing(tmp_path):
    core = tmp_path / "core.wasm"
    core.write_bytes(b"\x00asm\x01\x00\x00\x00" + b"\x00" * 8)
    assert lang_py._is_component_guest(str(core)) is False
    assert lang_py._is_component_guest(str(tmp_path / "nope.wasm")) is False


def test_component_path_needs_no_stdlib_and_mounts_work(
    comp_guest, script, monkeypatch
):
    monkeypatch.setattr(lang_py, "WASISandbox", _RecordingSandbox)
    _RecordingSandbox.last = {}
    out = run_python_script(comp_guest, script_path=script, input_json={"n": 1})
    assert out["status"].endswith("SUCCESS")
    seen = _RecordingSandbox.last
    assert seen.get("abi") == "component"
    assert seen.get("use_subprocess") is True
    # caller data goes to the guest's real stdin as JSON
    assert seen.get("stdin_data") == '{"n": 1}'
    # the script dir is mounted at /work (staged main.py)
    cfg = seen["config"]
    assert any(m.split("::")[1] == "/work" for m in cfg.allow_dirs)


def test_component_path_forwards_user_args_to_the_guest(
    comp_guest, script, monkeypatch
):
    """``run --language python s.py -- a b`` must not silently drop ``a b``.

    Measured against the real CPython-WASI component guest: the component
    runner's argv DOES reach the exec'd script (``sys.argv`` came back
    ``["wasm-module", "a", "b"]``), so the adapter has no excuse for discarding
    the caller's arguments. The runner supplies argv[0] itself, so the user's
    args occupy the guest's ``sys.argv[1:]``.
    """
    monkeypatch.setattr(lang_py, "WASISandbox", _RecordingSandbox)
    _RecordingSandbox.last = {}
    run_python_script(comp_guest, script_path=script, args=("a", "b"))
    seen = _RecordingSandbox.last
    assert list(seen.get("args") or []) == ["a", "b"]


def test_component_requires_existing_guest_and_script(comp_guest, monkeypatch):
    monkeypatch.setattr(lang_py, "WASISandbox", _RecordingSandbox)
    with pytest.raises(AdapterPolicyError):
        run_python_script(comp_guest, script_path="/no/such.py")


def test_component_guest_reported_error_is_separate_from_host_status(
    tmp_path, monkeypatch
):
    # Integrity rule: the guest self-reports a user fault via the marker while
    # the host observes a clean exit 0 / SUCCESS. The record keeps them apart:
    # the report is surfaced, but it never fabricates a non-zero exit or
    # overrides status.
    script = tmp_path / "bad.py"
    script.write_text("boom\n")

    class _ErrSandbox(_RecordingSandbox):
        def run(self, path, **kwargs):
            return _fake_result(
                "ExecutionStatus.SUCCESS", "", "EPHEMORA_USER_ERROR\n", 0
            )

    monkeypatch.setattr(lang_py, "WASISandbox", _ErrSandbox)
    out = run_python_script(_make(tmp_path), script_path=str(script))
    assert out["guest_reported_error"] is True
    assert out["exit_code"] == 0  # host-observed, not fabricated
    assert out["status"].endswith("SUCCESS")


def test_component_forged_marker_cannot_change_host_status(tmp_path, monkeypatch):
    # Counterexample: adversarial user code prints the marker on a *successful*
    # run. The marker is untrusted stderr, so host status/exit are untouched.
    script = tmp_path / "spoof.py"
    script.write_text("import sys; sys.stderr.write('EPHEMORA_USER_ERROR')\n")

    class _SpoofSandbox(_RecordingSandbox):
        def run(self, path, **kwargs):
            return _fake_result(
                "ExecutionStatus.SUCCESS", "ok", "EPHEMORA_USER_ERROR", 0
            )

    monkeypatch.setattr(lang_py, "WASISandbox", _SpoofSandbox)
    out = run_python_script(_make(tmp_path), script_path=str(script))
    assert out["exit_code"] == 0
    assert out["status"].endswith("SUCCESS")


def test_component_host_observed_failure_is_not_masked(tmp_path, monkeypatch):
    # A real host-observed failure is reported as observed regardless of stderr
    # text; a marker-less run never invents a guest report.
    script = tmp_path / "loop.py"
    script.write_text("while True: pass\n")

    class _FuelSandbox(_RecordingSandbox):
        def run(self, path, **kwargs):
            return _fake_result("ExecutionStatus.FUEL_EXHAUSTED", "", "out of fuel", 0)

    monkeypatch.setattr(lang_py, "WASISandbox", _FuelSandbox)
    out = run_python_script(_make(tmp_path), script_path=str(script))
    assert out["status"].endswith("FUEL_EXHAUSTED")  # host truth preserved
    assert out["guest_reported_error"] is False  # no marker -> no report


def _make(tmp_path):
    g = tmp_path / "g.wasm"
    g.write_bytes(COMPONENT_BYTES)
    return str(g)


def test_interpreter_core_module_still_requires_stdlib(monkeypatch, tmp_path):
    # legacy path preserved: a core-module guest with no stdlib_dir is refused
    core = tmp_path / "core.wasm"
    core.write_bytes(b"\x00asm\x01\x00\x00\x00" + b"\x00" * 8)
    script = tmp_path / "s.py"
    script.write_text("pass\n")
    monkeypatch.setattr(lang_py, "WASISandbox", _RecordingSandbox)
    with pytest.raises(AdapterPolicyError):
        run_python_script(str(core), script_path=str(script))  # stdlib_dir omitted


@pytest.mark.parametrize("case", [{"n": 10, "msg": "round"}])
def test_component_guest_real_roundtrip(case):
    """Full isolated run against a supplied modern component guest (opt-in)."""
    guest = os.environ.get("EPHEMORA_PY_COMPONENT_GUEST")
    if not guest or not os.path.exists(guest):
        pytest.skip("no component guest at EPHEMORA_PY_COMPONENT_GUEST")
    expected = os.environ.get("EPHEMORA_PY_COMPONENT_GUEST_SHA256")
    if expected:
        digest = hashlib.sha256(open(guest, "rb").read()).hexdigest()
        assert digest == expected, "component guest digest mismatch — refusing"
    import tempfile

    d = tempfile.mkdtemp()
    script = os.path.join(d, "prog.py")
    with open(script, "w") as handle:
        handle.write(
            "import json, sys\n"
            "data = json.load(sys.stdin)\n"
            "print(json.dumps({'answer': data['n'] + 30, "
            "'echo': data['msg'] + '!'}, sort_keys=True))\n"
        )
    result = run_python_script(
        guest,
        script_path=script,
        input_json=case,
        expected_sha256=expected or None,
    )
    assert result["status"].endswith("SUCCESS")
    assert result["output"] == {"answer": case["n"] + 30, "echo": case["msg"] + "!"}


def test_component_guest_real_args_reach_sys_argv():
    """Opt-in: the forwarded args must be visible to the exec'd script.

    The recording test above pins the CALL shape; this one proves the guest
    effect, so the claim in ``docs/languages.md`` (user args occupy
    ``sys.argv[1:]``, ``argv[0]`` stays the runner's neutral tag) is checked
    against a real CPython rather than asserted. Skipped whenever no component
    guest is supplied out-of-band, like the round-trip test beside it.
    """
    guest = os.environ.get("EPHEMORA_PY_COMPONENT_GUEST")
    if not guest or not os.path.exists(guest):
        pytest.skip("no component guest at EPHEMORA_PY_COMPONENT_GUEST")
    expected = os.environ.get("EPHEMORA_PY_COMPONENT_GUEST_SHA256")
    if expected:
        digest = hashlib.sha256(open(guest, "rb").read()).hexdigest()
        assert digest == expected, "component guest digest mismatch — refusing"
    import json
    import tempfile

    d = tempfile.mkdtemp()
    script = os.path.join(d, "argv.py")
    with open(script, "w") as handle:
        handle.write("import json, sys\nprint(json.dumps({'argv': sys.argv}))\n")
    result = run_python_script(
        guest,
        script_path=script,
        args=("a", "b"),
        expected_sha256=expected or None,
    )
    assert result["status"].endswith("SUCCESS"), result["stderr"]
    argv = json.loads(result["stdout"].strip()[result["stdout"].index("{") :])["argv"]
    assert argv[1:] == ["a", "b"]
    # no host path is leaked into the guest's argv[0]
    assert argv[0] == "wasm-module"


def test_component_guest_hard_timeout_leaves_no_scratch(tmp_path, monkeypatch):
    """A parent SIGKILL must not strand the worker's capture directory.

    The guest's sleep blocks outside WASI safepoints, so the worker has to be
    killed by the parent. Child-process cleanup cannot run at that point; the
    parent owns and removes the worker's scratch root.
    """
    guest = os.environ.get("EPHEMORA_PY_COMPONENT_GUEST")
    if not guest or not os.path.exists(guest):
        pytest.skip("no component guest at EPHEMORA_PY_COMPONENT_GUEST")
    expected = os.environ.get("EPHEMORA_PY_COMPONENT_GUEST_SHA256")
    if expected:
        digest = hashlib.sha256(open(guest, "rb").read()).hexdigest()
        assert digest == expected, "component guest digest mismatch — refusing"

    import tempfile
    from dataclasses import replace

    from ephemora_cell.profiles import get as get_profile

    monkeypatch.setenv("TMPDIR", str(tmp_path))
    monkeypatch.setattr(tempfile, "tempdir", str(tmp_path))
    script = tmp_path / "sleep.py"
    script.write_text("import time\nprint('marker', flush=True)\ntime.sleep(30)\n")
    config = replace(
        get_profile("interpreter"),
        timeout_seconds=1,
        sandbox_base_dir=str(tmp_path),
    )

    result = run_python_script(
        guest,
        script_path=str(script),
        config=config,
        expected_sha256=expected or None,
    )

    assert result["status"].endswith("TIMEOUT"), result
    residue = sorted(p.name for p in tmp_path.glob("ephemora_*"))
    assert residue == [], f"worker scratch survived the parent kill: {residue}"
