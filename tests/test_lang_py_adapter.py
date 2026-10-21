"""Tests for the experimental Python adapter (lang_py).

The adapter is opt-in and must stay that way: these tests pin the admission
policy (fail-closed BEFORE any sandbox exists, mandatory -B) and — when a
CPython-WASI guest is provided out-of-band via environment — the JSON
round-trip through the isolated path. The 22 MB guest binary is intentionally
not committed (BYO policy, ADR-009 D2).
"""

import hashlib
import os

import pytest

from ephemora_cell import lang_py
from ephemora_cell.lang_py import (
    AdapterPolicyError,
    run_python_script,
    validate_guest,
)

GUEST_ENV = "EPHEMORA_BYO_PYTHON_GUEST"
GUEST_SHA_ENV = "EPHEMORA_BYO_PYTHON_GUEST_SHA256"
STDLIB_ENV = "EPHEMORA_BYO_PYTHON_STDLIB"

# WAT text is not a parseable core module binary: admission must fail closed.
WAT_TEXT = b'(module (import "env" "trap" (func)))'

ROUNDTRIP_SCRIPT = """\
import json, sys
data = json.load(sys.stdin)
print(json.dumps({"answer": data["n"] + 30, "echo": data["msg"] + "!"},
                 sort_keys=True))
"""


def _pytest_skip_unless_guest():
    guest = os.environ.get(GUEST_ENV)
    stdlib = os.environ.get(STDLIB_ENV)
    if (
        not guest
        or not os.path.exists(guest)
        or not stdlib
        or not os.path.isdir(stdlib)
    ):
        pytest.skip(f"no BYO CPython-WASI guest set ({GUEST_ENV}/{STDLIB_ENV})")
    return guest, stdlib


def test_core_package_does_not_import_adapter():
    """The adapter must not be pulled in by importing the package itself."""
    import subprocess
    import sys

    code = (
        "import sys; import ephemora_cell; "
        "print('ephemora_cell.lang_py' in sys.modules)"
    )
    out = subprocess.run(
        [sys.executable, "-c", code], capture_output=True, text=True, check=True
    )
    assert out.stdout.strip().endswith("False")


def test_validate_fails_closed_on_non_module(tmp_path):
    bad = tmp_path / "not_a_module.wasm"
    bad.write_bytes(WAT_TEXT)
    with pytest.raises(AdapterPolicyError):
        validate_guest(str(bad))


def test_run_never_touches_sandbox_when_admission_fails(tmp_path, monkeypatch):
    """A rejected guest must not reach the execution path at all."""
    called = []

    class _Sandbox:
        def __init__(self, *a, **k):
            pass

        def run(self, *a, **k):
            called.append(True)
            raise AssertionError("must not run")

        def cleanup(self):
            pass

    monkeypatch.setattr(lang_py, "WASISandbox", _Sandbox)
    bad = tmp_path / "not_a_module.wasm"
    bad.write_bytes(WAT_TEXT)
    script = tmp_path / "s.py"
    script.write_text(ROUNDTRIP_SCRIPT)
    with pytest.raises(AdapterPolicyError):
        run_python_script(str(bad), stdlib_dir=str(tmp_path), script_path=str(script))
    assert called == []


def test_missing_paths_fail_closed_without_sandbox(tmp_path, monkeypatch):
    called = []

    class _Sandbox:
        def __init__(self, *a, **k):
            pass

    monkeypatch.setattr(lang_py, "WASISandbox", _Sandbox)
    guest = tmp_path / "guest.wasm"  # does not exist
    with pytest.raises(AdapterPolicyError):
        run_python_script(
            str(guest),
            stdlib_dir=str(tmp_path),
            script_path=str(tmp_path / "s.py"),
        )
    assert called == []


def test_policy_error_is_a_valueerror():
    assert issubclass(AdapterPolicyError, ValueError)


def test_dontwrite_flag_is_mandatory(tmp_path, monkeypatch):
    """Whatever the caller passes in args, the worker command starts -B."""
    seen = {}

    class _Result:
        status = "ExecutionStatus.SUCCESS"
        stdout = "{}"
        stderr = ""
        exit_code = 0

    class _Sandbox:
        def __init__(self, *a, **k):
            pass

        def run(self, path, *, args=None, **k):
            seen["args"] = list(args or [])
            return _Result()

        def cleanup(self):
            pass

    monkeypatch.setattr(lang_py, "WASISandbox", _Sandbox)
    # a minimal, inspector-acceptable Preview1 module (imports before memory)
    wasm = tmp_path / "g.wasm"
    wasm.write_bytes(
        b'(module (import "wasi_snapshot_preview1" "proc_exit"'
        b" (func (param i32))) (memory 1))"
    )
    script = tmp_path / "s.py"
    script.write_text("pass\n")
    result = run_python_script(
        str(wasm),
        stdlib_dir=str(tmp_path),
        script_path=str(script),
        args=("-c", "print(1)"),
    )
    assert seen["args"][0] == "-B"
    assert result["status"].endswith("SUCCESS")


@pytest.mark.parametrize("case", [{"n": 10, "msg": "baz"}])
def test_cpython_guest_json_roundtrip(case, tmp_path):
    """Full isolated round-trip against a pinned CPython-WASI guest."""
    guest, stdlib = _pytest_skip_unless_guest()
    expected = os.environ.get(GUEST_SHA_ENV)
    if expected:
        digest = hashlib.sha256(open(guest, "rb").read()).hexdigest()
        assert digest == expected, "BYO guest digest mismatch — refusing"
    script = tmp_path / "roundtrip.py"
    script.write_text(ROUNDTRIP_SCRIPT)
    result = run_python_script(
        guest,
        stdlib_dir=stdlib,
        script_path=str(script),
        input_json=case,
        expected_sha256=expected or None,
    )
    assert result["status"].endswith("SUCCESS")
    # fixture contract: same n+30 / msg+"!" as the Javy and matrix fixtures
    assert result["output"] == {"answer": case["n"] + 30, "echo": case["msg"] + "!"}
