"""Contract tests for the unified language entry point (lang).

The dispatcher must stay thin and fail closed: unknown languages refuse
before any adapter exists, and every adapter must return the identical
result shape. No test here runs a real interpreter guest.
"""

import pytest

from ephemora_cell import lang
from ephemora_cell.lang import LanguagePolicyError, available_languages, run_language
from ephemora_cell.lang_guest import GuestNotInstalled
from ephemora_cell.lang_js import AdapterPolicyError

# minimal, inspector-acceptable Preview1 module (imports before memory)
MIN_MODULE = (
    b'(module (import "wasi_snapshot_preview1" "proc_exit"'
    b" (func (param i32))) (memory 1))"
)
RESULT_KEYS = {
    "status",
    "stdout",
    "stderr",
    "exit_code",
    "fuel_consumed",
    "elapsed_ms",
    "output",
    # added as a labelled contract change in 1.2.0: every adapter states how
    # much of the guest's own exit status its ABI can deliver at all
    "exit_status_fidelity",
    # added as a labelled contract change in 1.2.0: the base a
    # `run module.wasm` document carries, produced by the same ExecutionReport
    # the wasm path and the signed record use — a language run that reported
    # none of these gave one command two document shapes
    "fuel_budget",
    "fuel_utilization",
    "memory_mb",
    "stdout_bytes",
    "stderr_bytes",
    "warnings",
    "security_baseline",
}


class _Result:
    status = "ExecutionStatus.SUCCESS"
    stdout = '{"answer": 40, "echo": "baz!"}\n'
    stderr = ""
    exit_code = 0


class _FakeSandbox:
    def __init__(self, *a, **k):
        pass

    def run(self, path, **k):
        return _Result()

    def cleanup(self):
        pass


def test_core_package_does_not_import_language_modules():
    """Neither the dispatcher nor an adapter may be imported eagerly."""
    import subprocess
    import sys

    code = (
        "import sys; import ephemora_cell; "
        "print(any(m.startswith('ephemora_cell.lang') for m in sys.modules))"
    )
    out = subprocess.run(
        [sys.executable, "-c", code], capture_output=True, text=True, check=True
    )
    assert out.stdout.strip().endswith("False")


def test_unknown_language_is_a_policy_error():
    with pytest.raises(LanguagePolicyError):
        run_language("ruby", entrypoint="whatever.wasm")


def test_policy_error_is_a_valueerror():
    assert issubclass(LanguagePolicyError, ValueError)


def test_registry_and_available_languages_agree():
    assert available_languages() == tuple(sorted(lang._ADAPTERS))
    assert "javascript" in available_languages()
    assert "python" in available_languages()


def test_missing_entrypoint_refuses(monkeypatch, no_packaged_guest):
    """No entrypoint + no installed guest fails closed: the dispatcher resolves
    the guest before any adapter/sandbox exists, so nothing runs and no download
    happens -- the refusal names the single documented install command."""
    monkeypatch.delenv("EPHEMORA_BYO_JS_GUEST", raising=False)
    monkeypatch.delenv("EPHEMORA_BYO_JS_SHA256", raising=False)
    with pytest.raises(GuestNotInstalled) as excinfo:
        run_language("javascript")
    message = str(excinfo.value).lower()
    assert "javascript" in message
    assert "pip install" in message


def test_result_contract_identical_across_adapters(monkeypatch, tmp_path):
    """JS and Python adapters must return exactly the same result keys."""
    from ephemora_cell import lang_js, lang_py

    wasm = tmp_path / "g.wasm"
    wasm.write_bytes(MIN_MODULE)
    script = tmp_path / "s.py"
    script.write_text("pass\n")

    monkeypatch.setattr(lang_js, "WASISandbox", _FakeSandbox)
    monkeypatch.setattr(lang_py, "WASISandbox", _FakeSandbox)
    js = run_language("javascript", entrypoint=str(wasm), input_json={"n": 10})
    py = run_language(
        "python",
        entrypoint=str(wasm),
        stdlib_dir=str(tmp_path),
        script_path=str(script),
    )
    assert set(js) == RESULT_KEYS == set(py)
    # parsed JSON output is part of the shared shape
    assert js["output"] == {"answer": 40, "echo": "baz!"} == py["output"]


def test_adapter_refusal_passes_through_unchanged(tmp_path):
    """Guest admission failures stay AdapterPolicyError, not routing errors."""
    bad = tmp_path / "bad.wasm"
    bad.write_bytes(b'(module (import "env" "trap" (func)))')
    with pytest.raises(AdapterPolicyError):
        run_language("javascript", entrypoint=str(bad))


class TestLazyTopLevelApi:
    """run_python/run_javascript are lazy, understandable top-level entries."""

    def test_names_are_declared_in_all(self):
        import ephemora_cell

        for name in (
            "run_python",
            "run_javascript",
            "run_language",
            "available_languages",
        ):
            assert name in ephemora_cell.__all__

    def test_attribute_access_resolves_to_dispatcher_backed_callable(self):
        import ephemora_cell
        from ephemora_cell import lang

        # Access imports lang on demand; the top-level name is the same callable
        # that delegates to the dispatcher (identity through the lazy loader).
        assert ephemora_cell.run_python is lang.run_python
        assert ephemora_cell.run_javascript is lang.run_javascript

    def test_top_level_run_delegates_to_language(self, monkeypatch):
        import ephemora_cell
        from ephemora_cell import lang

        calls: list[tuple[str, dict]] = []

        def fake_run_language(language, **kwargs):
            calls.append((language, kwargs))
            return {"status": "stub"}

        monkeypatch.setattr(lang, "run_language", fake_run_language)
        ephemora_cell.run_python(script_path="tool.py")
        ephemora_cell.run_javascript(entrypoint="a.wasm")
        assert [c[0] for c in calls] == ["python", "javascript"]
        assert calls[0][1] == {"script_path": "tool.py"}

    def test_unknown_attribute_still_raises(self):
        import ephemora_cell

        with pytest.raises(AttributeError):
            _ = ephemora_cell.run_ruby
