"""Tests for the QuickJS *source-interpreter* JavaScript path in lang_js.

Added 2026-10-15: a user's OWN JavaScript is run inside the isolated
WASM sandbox on a QuickJS (quickjs-ng via rquickjs) interpreter guest — no host
Node.js, no manual compile, no in-process fallback. These tests pin the adapter's
staging + admission + graceful-error behaviour without the guest binary, plus an
opt-in real round-trip when a source-interpreter guest is supplied out-of-band.
"""

import hashlib
import os
from typing import ClassVar

import pytest

from ephemora_cell import lang_js
from ephemora_cell.lang_js import AdapterPolicyError, run_javascript_source


def _interpreter_guest_or_skip() -> str:
    """The supplied QuickJS interpreter guest, or skip this real-guest leg."""
    guest = os.environ.get("EPHEMORA_JS_INTERPRETER_GUEST")
    if not guest or not os.path.exists(guest):
        pytest.skip("no JS interpreter guest at EPHEMORA_JS_INTERPRETER_GUEST")
    return guest


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
    last: ClassVar[dict] = {}

    def __init__(self, config=None):
        _RecordingSandbox.last["config"] = config

    def run(self, path, **kwargs):
        _RecordingSandbox.last.update(kwargs)
        # capture whether the adapter staged the script + input before the
        # throwaway /work dir is removed (the run happens while it exists)
        cfg = _RecordingSandbox.last.get("config")
        if cfg and cfg.allow_dirs:
            host_work = cfg.allow_dirs[0].split("::")[0]
            _RecordingSandbox.last["staged_main"] = os.path.exists(
                os.path.join(host_work, "main.js")
            )
            _RecordingSandbox.last["staged_input"] = os.path.exists(
                os.path.join(host_work, "input.json")
            )
        return _fake_result("ExecutionStatus.SUCCESS", "", "", 0)

    def cleanup(self):
        pass


# a minimal Preview1 core module the inspector accepts (imports before memory)
def _core_module(tmp_path, name="g.wasm"):
    p = tmp_path / name
    p.write_bytes(
        b'(module (import "wasi_snapshot_preview1" "proc_exit"'
        b" (func (param i32))) (memory 1))"
    )
    return str(p)


def test_requires_exactly_one_of_source_or_script(tmp_path):
    guest = _core_module(tmp_path)
    with pytest.raises(AdapterPolicyError):
        run_javascript_source(guest)  # neither
    with pytest.raises(AdapterPolicyError):
        run_javascript_source(guest, source="x", script_path=guest)  # both


def test_missing_script_path_fails_before_sandbox(tmp_path, monkeypatch):
    monkeypatch.setattr(lang_js, "WASISandbox", _RecordingSandbox)
    _RecordingSandbox.last = {}
    guest = _core_module(tmp_path)
    with pytest.raises(AdapterPolicyError):
        run_javascript_source(guest, script_path="/no/such.js")


def test_non_module_guest_refused(tmp_path):
    bad = tmp_path / "bad.wasm"
    bad.write_bytes(b'(module (import "env" "x" (func)))')
    with pytest.raises(AdapterPolicyError):
        run_javascript_source(str(bad), source="1+1")


def test_source_staged_to_work_and_input_written(tmp_path, monkeypatch):
    monkeypatch.setattr(lang_js, "WASISandbox", _RecordingSandbox)
    _RecordingSandbox.last = {}
    guest = _core_module(tmp_path)
    out = run_javascript_source(guest, source="console.log(1)", input_json={"a": 1})
    assert out["status"].endswith("SUCCESS")
    cfg = _RecordingSandbox.last["config"]
    assert any(m.split("::")[1] == "/work" for m in cfg.allow_dirs)
    # the guest sees main.js (+ input.json) under /work at run time
    assert _RecordingSandbox.last["staged_main"] is True
    assert _RecordingSandbox.last["staged_input"] is True


def test_user_error_marker_maps_to_flag(tmp_path, monkeypatch):
    # Integrity rule: a guest-reported fault is surfaced, but it stays separate
    # from the host-observed status/exit and never fabricates a non-zero exit
    # code.
    class _Err(_RecordingSandbox):
        def run(self, path, **kwargs):
            return _fake_result(
                "ExecutionStatus.SUCCESS", "", "EPHEMORA_USER_ERROR: boom", 0
            )

    monkeypatch.setattr(lang_js, "WASISandbox", _Err)
    guest = _core_module(tmp_path)
    out = run_javascript_source(guest, source="bad @@")
    assert out["guest_reported_error"] is True
    assert out["exit_code"] == 0
    assert out["status"].endswith("SUCCESS")


def test_forged_js_marker_cannot_change_host_status(tmp_path, monkeypatch):
    # Counterexample: user JS prints the marker on a clean run. The untrusted
    # stderr must not alter the authoritative host fields.
    class _Spoof(_RecordingSandbox):
        def run(self, path, **kwargs):
            return _fake_result(
                "ExecutionStatus.SUCCESS", "fine", "EPHEMORA_USER_ERROR", 0
            )

    monkeypatch.setattr(lang_js, "WASISandbox", _Spoof)
    guest = _core_module(tmp_path)
    out = run_javascript_source(guest, source="console.log('fine')")
    assert out["exit_code"] == 0
    assert out["status"].endswith("SUCCESS")


@pytest.mark.parametrize("case", [{"n": 10, "msg": "round"}])
def test_js_interpreter_guest_real_roundtrip(case):
    """Full isolated run of the user's own JS against a supplied guest (opt-in)."""
    guest = _interpreter_guest_or_skip()
    expected = os.environ.get("EPHEMORA_JS_INTERPRETER_GUEST_SHA256")
    if expected:
        digest = hashlib.sha256(open(guest, "rb").read()).hexdigest()
        assert digest == expected, "interpreter guest digest mismatch — refusing"
    result = run_javascript_source(
        guest,
        source=(
            "console.log(JSON.stringify({answer: input.n + 30, "
            "echo: input.msg + '!'}))"
        ),
        input_json=case,
        expected_sha256=expected or None,
    )
    assert result["status"].endswith("SUCCESS")
    assert result["output"] == {"answer": case["n"] + 30, "echo": case["msg"] + "!"}
    # the adapter states what its ABI can attest: the harness returns 0 for the
    # guest export, never the user program's own exit status
    assert result["exit_status_fidelity"] == "none", result


class TestTheQuickJSHarnessDecidesWhatLeaves:
    """The source route's fidelity is a property of the GUEST, measured here.

    Every case below runs the pinned QuickJS interpreter guest. What is being
    pinned is not that a failure is invisible — it is that the host never
    claims to have seen an exit status it cannot see, and that a deliberate
    ``process.exit()`` is reported as the guest's own claim rather than as a
    host-attested exit code.
    """

    def _run(self, guest, source):
        digest = hashlib.sha256(open(guest, "rb").read()).hexdigest()
        return run_javascript_source(guest, source=source, expected_sha256=digest)

    def test_a_thrown_error_leaves_as_success_with_the_guest_marker(self, tmp_path):
        guest = _interpreter_guest_or_skip()
        out = self._run(guest, "console.log('before'); throw new Error('boom');")
        assert out["status"].endswith("SUCCESS"), out
        assert out["exit_code"] == 0, out
        assert out["guest_reported_error"] is True, out
        assert out["exit_status_fidelity"] == "none", out
        assert "before" in out["stdout"]

    @pytest.mark.parametrize("code", [5, 0])
    def test_process_exit_is_not_an_attested_host_exit_code(self, code):
        """``process.exit(5)`` must not become ``exit_code: 5`` — and ``exit(0)``
        is not quietly a success either: the harness raises on any process.exit,
        so both arrive as success/0 carrying only the guest's own marker.
        """
        guest = _interpreter_guest_or_skip()
        out = self._run(guest, f"console.log('x'); process.exit({code});")
        assert (out["status"].endswith("SUCCESS"), out["exit_code"]) == (True, 0), out
        assert out["exit_status_fidelity"] == "none", out
        assert out["guest_reported_error"] is True, out
