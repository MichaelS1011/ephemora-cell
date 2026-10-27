# SPDX-License-Identifier: BUSL-1.1
# Copyright 2026 Michael Soppa
"""Agent-surface criterion 3: an agent/workflow input cannot elevate trust.

The shared framework executor takes a *model-supplied* module path. Model output
is untrusted, so the executor must confine execution to the operator's allowlist
and refuse anything else fail-closed — before any sandbox is created. These tests
pin the success path (an allowlisted workload) and the refusal/error paths
(arbitrary path, traversal, missing file), asserting nothing runs when denied.

The same criterion extends the boundary to the four risks a *model-supplied* path
actually carries: path normalisation, symlinks, malformed (non-string / NUL)
input, module identity, and the check-to-use (TOCTOU) window between
authorising a path and loading it.
"""

from __future__ import annotations

import hashlib
import os
from dataclasses import replace
from pathlib import Path
from typing import ClassVar

import pytest

from integration import ephemora_cell_agent_executor as executor_mod
from integration.ephemora_cell_agent_executor import EphemoraCellExecutor

WORKLOADS = Path(__file__).resolve().parent.parent / "benchmarks" / "workloads"
HELLO = WORKLOADS / "hello_rust.wasm"
WASM_MAGIC = b"\x00asm\x01\x00\x00\x00"


def test_allowlisted_workload_executes():
    ex = EphemoraCellExecutor(max_fuel=200_000, timeout=5)
    res = ex.execute(str(HELLO))
    # ran through the sandbox: a real status, not the policy refusal sentinel
    assert res.status != "policy_denied"
    assert isinstance(res.elapsed_ms, float)


def test_arbitrary_host_path_is_denied(tmp_path):
    ex = EphemoraCellExecutor()
    stray = tmp_path / "evil.wasm"
    stray.write_bytes(b"\x00asm\x01\x00\x00\x00")  # outside the allowed roots
    res = ex.execute(str(stray))
    assert res.status == "policy_denied"
    assert res.blocked is True
    assert res.stdout == "" and res.stderr == ""


def test_path_traversal_outside_roots_is_denied():
    ex = EphemoraCellExecutor()
    # a traversal that resolves out of the workload root must not be authorised
    sneaky = str(WORKLOADS / ".." / ".." / ".." / "etc" / "passwd")
    res = ex.execute(sneaky)
    assert res.status == "policy_denied"
    assert res.blocked is True


def test_explicit_root_allows_that_directory(tmp_path):
    # an operator widening the allowlist is honoured (host decision, not model's)
    mod = tmp_path / "m.wasm"
    mod.write_bytes(b"\x00asm\x01\x00\x00\x00")
    ex = EphemoraCellExecutor(allowed_roots=(str(tmp_path),))
    res = ex.execute(str(mod))
    assert res.status != "policy_denied"


def test_no_sandbox_created_on_denial(monkeypatch):
    # denied path must short-circuit before WASISandbox is ever built
    from integration import ephemora_cell_agent_executor as mod

    def _boom(*a, **k):
        raise AssertionError("sandbox must not be constructed for a denied path")

    monkeypatch.setattr(mod, "WASISandbox", _boom)
    ex = EphemoraCellExecutor()
    res = ex.execute("/etc/passwd")
    assert res.status == "policy_denied"


# --- malformed model output must refuse, never crash the tool call ---


@pytest.mark.parametrize("bad", [None, 1234, ["a"], {"p": "a"}, b"hello.wasm"])
def test_non_string_argument_is_denied_not_raised(bad):
    ex = EphemoraCellExecutor()
    res = ex.execute(bad)  # type: ignore[arg-type]
    assert res.status == "policy_denied"
    assert res.reason == "path_not_a_string"
    assert res.blocked is True


def test_nul_byte_and_blank_paths_are_denied():
    ex = EphemoraCellExecutor()
    assert ex.execute("hello\x00.wasm").reason == "path_malformed"
    assert ex.execute("   ").reason == "path_malformed"


# --- symlink handling ---


def test_symlink_in_allowed_root_reaching_outside_is_denied(tmp_path):
    outside = tmp_path / "outside"
    outside.mkdir()
    secret = outside / "secret.wasm"
    secret.write_bytes(WASM_MAGIC)
    root = tmp_path / "root"
    root.mkdir()
    link = root / "lookalike.wasm"
    link.symlink_to(secret)  # final component is a symlink out of the root
    ex = EphemoraCellExecutor(allowed_roots=(str(root),))
    res = ex.execute(str(link))
    assert res.status == "policy_denied"
    assert res.reason == "outside_allowed_roots"


def test_symlink_inside_the_allowed_root_still_runs(tmp_path, monkeypatch):
    root = tmp_path / "root"
    root.mkdir()
    real = root / "real.wasm"
    real.write_bytes(WASM_MAGIC)
    link = root / "via-link.wasm"
    link.symlink_to(real)
    recorded: dict[str, object] = {}

    class _Fake:
        def __init__(self, config=None):
            pass

        def run(self, path, **kwargs):
            recorded["path"] = path
            recorded["digest"] = kwargs.get("expected_sha256")
            return _ok_result(Path(path).read_bytes())

        def cleanup(self):
            pass

    monkeypatch.setattr(executor_mod, "WASISandbox", _Fake)
    res = EphemoraCellExecutor(allowed_roots=(str(root),)).execute(str(link))
    assert res.status == "success"
    # authorised identity is the resolved target's bytes, not the link's name
    assert res.module_sha256 == hashlib.sha256(real.read_bytes()).hexdigest()


def test_non_regular_file_is_denied(tmp_path):
    root = tmp_path / "root"
    root.mkdir()
    fifo = root / "pipe.wasm"
    os.mkfifo(str(fifo))
    ex = EphemoraCellExecutor(allowed_roots=(str(root),))
    res = ex.execute(str(fifo))
    assert res.status == "policy_denied"
    assert res.reason == "not_a_regular_file"


def test_module_size_cap_is_enforced_before_staging(tmp_path):
    root = tmp_path / "root"
    root.mkdir()
    big = root / "big.wasm"
    big.write_bytes(WASM_MAGIC + b"x" * 4096)
    ex = EphemoraCellExecutor(allowed_roots=(str(root),))
    ex.config = replace(ex.config, max_wasm_bytes=128)
    res = ex.execute(str(big))
    assert res.status == "policy_denied"
    assert res.reason and res.reason.startswith("module_too_large")


# --- module identity and the check-to-use window ---


class _Recording:
    """Stand-in sandbox that records what it was handed (no real execution)."""

    last: ClassVar[dict[str, object]] = {}

    def __init__(self, config=None):
        pass

    def run(self, path, **kwargs):
        _Recording.last = {"path": path, **kwargs}
        return _ok_result(Path(path).read_bytes())

    def cleanup(self):
        pass


def _ok_result(module_bytes: bytes):
    from ephemora_cell.wasi_runtime import ExecutionResult, ExecutionStatus

    return ExecutionResult(
        status=ExecutionStatus.SUCCESS,
        exit_code=0,
        stdout="",
        stderr="",
        elapsed_ms=1.0,
    )


def test_executed_bytes_are_bound_to_the_authorised_digest(tmp_path, monkeypatch):
    root = tmp_path / "root"
    root.mkdir()
    mod = root / "m.wasm"
    mod.write_bytes(WASM_MAGIC + b"\x01\x02\x03")
    monkeypatch.setattr(executor_mod, "WASISandbox", _Recording)
    res = EphemoraCellExecutor(allowed_roots=(str(root),)).execute(str(mod))
    assert res.status == "success"
    digest = hashlib.sha256(mod.read_bytes()).hexdigest()
    assert _Recording.last["expected_sha256"] == digest
    assert res.module_sha256 == digest


def test_swap_after_authorisation_cannot_change_executed_bytes(tmp_path, monkeypatch):
    # TOCTOU: rewrite the allowlisted path between authorisation and load. The
    # run must still carry the bytes that were authorised, from a private copy.
    root = tmp_path / "root"
    root.mkdir()
    mod = root / "m.wasm"
    original = WASM_MAGIC + b"\x01\x02\x03"
    mod.write_bytes(original)
    digest = hashlib.sha256(original).hexdigest()

    class _Swapper(_Recording):
        def run(self, path, **kwargs):
            mod.write_bytes(WASM_MAGIC + b"TAMPORED-PAYLOAD")  # mid-flight swap
            _Recording.last = {"path": path, **kwargs}
            return _ok_result(Path(path).read_bytes())

    monkeypatch.setattr(executor_mod, "WASISandbox", _Swapper)
    res = EphemoraCellExecutor(allowed_roots=(str(root),)).execute(str(mod))
    assert res.status == "success"
    assert res.module_sha256 == digest
    # what ran was the staged copy under the authorised digest, never the path
    # the model named (which the attacker had already rewritten)
    assert Path(str(_Recording.last["path"])) != mod.resolve()
    assert _Recording.last["expected_sha256"] == digest
    assert mod.read_bytes() != original  # the host file really was swapped


# --- operator digest pins (artefact identity allowlist) ---


def test_pinned_digest_mismatch_is_denied(tmp_path):
    root = tmp_path / "root"
    root.mkdir()
    mod = root / "m.wasm"
    mod.write_bytes(WASM_MAGIC)
    ex = EphemoraCellExecutor(
        allowed_roots=(str(root),), allowed_sha256={str(mod): "0" * 64}
    )
    res = ex.execute(str(mod))
    assert res.status == "policy_denied"
    assert res.reason and res.reason.startswith("digest_pin_mismatch")


def test_pinning_mode_refuses_modules_without_a_pin(tmp_path):
    root = tmp_path / "root"
    root.mkdir()
    mod = root / "m.wasm"
    mod.write_bytes(WASM_MAGIC)
    other = root / "other.wasm"
    other.write_bytes(WASM_MAGIC)
    ex = EphemoraCellExecutor(
        allowed_roots=(str(root),),
        allowed_sha256={str(mod): hashlib.sha256(WASM_MAGIC).hexdigest()},
    )
    assert ex.execute(str(mod)).status != "policy_denied"  # pinned + matching
    assert ex.execute(str(other)).reason == "module_not_pinned"


def test_real_workload_runs_with_its_measured_pin():
    digest = hashlib.sha256(HELLO.read_bytes()).hexdigest()
    ex = EphemoraCellExecutor(
        max_fuel=200_000, timeout=5, allowed_sha256={str(HELLO): digest}
    )
    res = ex.execute(str(HELLO))
    assert res.status == "success"
    assert res.module_sha256 == digest


FIXTURES = Path(__file__).resolve().parent / "fixtures"


class TestTheAgentSurfaceCannotReachTheLanguageAdapterGap:
    """Which caller can actually be misled by a lost script exit status.

    The measured gap lives in the language adapters: ``run_python``/
    ``run_javascript`` (library) and ``run --language`` (CLI) execute a script
    INSIDE an interpreter guest, and on those routes the guest harness — not the
    host — decides what leaves the export, so ``sys.exit(3)`` arrives as
    success/0. The two surfaces an agent talks to do not route a script there,
    and this pins why:

    * the executor authorises module BYTES, so a source script is refused as
      ``not_a_wasm_module`` before any adapter is consulted;
    * a component that hard-exits non-zero still comes back blocked, because the
      core reports the failure it observed (``exit_status_fidelity`` says how
      much of the guest's number survived — see
      ``tests/test_guest_exit_code_fidelity.py``).

    Removing either leg would silently widen what a model-supplied call can make
    look like a success.
    """

    @staticmethod
    def _executor(root: Path):
        return EphemoraCellExecutor(
            max_fuel=50_000_000, timeout=20, allowed_roots=(str(root),)
        )

    def test_a_source_script_is_refused_before_any_adapter_runs_it(self, tmp_path):
        ex = self._executor(tmp_path)
        script = tmp_path / "exit3.py"
        script.write_text("import sys\nsys.exit(3)\n", encoding="utf-8")
        res = ex.execute(str(script))
        assert (res.status, res.blocked, res.reason) == (
            "policy_denied",
            True,
            "not_a_wasm_module",
        ), res

    def test_a_component_hard_exit_is_blocked_not_success(self):
        ex = self._executor(FIXTURES)
        res = ex.execute(str(FIXTURES / "exit3_02.wasm"))
        assert res.status == "error", res
        assert res.blocked is True
        # the code wasmtime actually observed; the guest's own 3 does not
        # survive this ABI, and nothing here invents it
        assert res.exit_code == 1, res


def test_the_shipped_mcp_package_reaches_no_language_adapter():
    """The MCP server executes packaged ``.wasm`` tools, not user scripts.

    The agent-facing MCP surface must stay free of the ``--language`` routing
    that carries the adapter gap, so the absence is asserted against the shipped
    sources rather than argued in a document.
    """
    mcp_root = Path(__file__).resolve().parent.parent / "ephemora_cell_mcp"
    offenders = {
        path.name: entry
        for path in sorted(mcp_root.rglob("*.py"))
        for entry in ("run_language", "run_python", "run_javascript", "script_path")
        if entry in path.read_text(encoding="utf-8")
    }
    assert offenders == {}, offenders
