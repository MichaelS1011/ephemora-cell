"""Tests for the experimental JavaScript adapter (lang_js).

The adapter is opt-in and must stay that way: these tests pin the admission
policy (fail-closed BEFORE any sandbox exists) and — when a Javy-built guest
is provided out-of-band via environment — the JSON round-trip through the
isolated path. The guest binary is intentionally not committed (BYO policy).
"""

import hashlib
import os

import pytest

from ephemora_cell import lang_js
from ephemora_cell.lang_js import (
    AdapterPolicyError,
    run_javascript_module,
    validate_guest,
)

GUEST_ENV = "EPHEMORA_BYO_JAVY_GUEST"
GUEST_SHA_ENV = "EPHEMORA_BYO_JAVY_GUEST_SHA256"

# WAT text is not a parseable core module binary: admission must fail closed.
WAT_TEXT = b'(module (import "env" "trap" (func)))'


def _pytest_skip_unless_guest():
    path = os.environ.get(GUEST_ENV)
    if not path or not os.path.exists(path):
        pytest.skip(f"no BYO Javy guest set ({GUEST_ENV})")
    return path


def test_core_package_does_not_import_adapter():
    """The adapter must not be pulled in by importing the package itself."""
    import subprocess
    import sys

    code = (
        "import sys; import ephemora_cell; "
        "print('ephemora_cell.lang_js' in sys.modules)"
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

    monkeypatch.setattr(lang_js, "WASISandbox", _Sandbox)
    bad = tmp_path / "not_a_module.wasm"
    bad.write_bytes(WAT_TEXT)
    with pytest.raises(AdapterPolicyError):
        run_javascript_module(str(bad))
    assert called == []


def test_policy_error_is_a_valueerror():
    assert issubclass(AdapterPolicyError, ValueError)


@pytest.mark.parametrize("case", [{"n": 10, "msg": "baz"}])
def test_javy_guest_json_roundtrip(case):
    """Full isolated round-trip against a pinned Javy-built guest."""
    guest = _pytest_skip_unless_guest()
    expected = os.environ.get(GUEST_SHA_ENV)
    if expected:
        digest = hashlib.sha256(open(guest, "rb").read()).hexdigest()
        assert digest == expected, "BYO guest digest mismatch — refusing"
    result = run_javascript_module(
        guest, input_json=case, expected_sha256=expected or None
    )
    assert result["status"].endswith("SUCCESS")
    # fixture contract: json_roundtrip.js maps n+30 / msg+"!"
    assert result["output"] == {"answer": case["n"] + 30, "echo": case["msg"] + "!"}
