# SPDX-License-Identifier: BUSL-1.1
# Copyright 2026 Michael Soppa
"""CHARACTERIZATION test for the documented exit-status fidelity gap.

``docs/languages.md`` states it under the heading "One fidelity gap, stated
rather than hidden": the WASI-0.2 component Python guest runs the user's script
inside an embedded interpreter and reports only whether its own export
succeeded, so the script's own exit status never reaches the host — a script
calling ``sys.exit(3)`` comes back ``status: success`` / ``exit_code: 0`` /
CLI exit ``0``, while the legacy Preview1 interpreter route and a plain ``.wasm``
run both propagate exit ``3``.

This file FIXATES that difference. It does not ask which behaviour is right and
it proposes no repair: a component export that cannot carry an exit status is
the guest's, not something the adapter can invent. What it prevents is the
documentation drifting behind reality in either direction — if a future change
makes the component route propagate exit statuses, this test fails and the
"fidelity gap" paragraph has to be deleted on purpose; if a change makes the
legacy route LOSE propagation, it fails too.

Three legs, deliberately at different availability costs:

1. a plain ``.wasm`` run — always executable here (the module is built from
   WAT at test time), so the contrast leg needs no guest;
2. the component route — opt-in on ``EPHEMORA_PY_COMPONENT_GUEST``;
3. the legacy Preview1 interpreter route — opt-in on the existing
   ``EPHEMORA_BYO_PYTHON_GUEST`` / ``EPHEMORA_BYO_PYTHON_STDLIB`` pins.

Legs 2 and 3 SKIP with a stated reason when no guest is supplied; they never
fail a run for want of a 20 MB bring-your-own binary, and nothing is downloaded.
"""

from __future__ import annotations

import json
import os
import subprocess
import sys
from pathlib import Path

import pytest
import wasmtime

REPO = Path(__file__).resolve().parent.parent
FIXTURES = REPO / "tests" / "fixtures"

#: gate for the modern component guest (same name as the existing opt-in pins)
COMPONENT_GUEST_ENV = "EPHEMORA_PY_COMPONENT_GUEST"
#: gates for the legacy Preview1 interpreter (same names as test_lang_py_adapter)
BYO_GUEST_ENV = "EPHEMORA_BYO_PYTHON_GUEST"
BYO_STDLIB_ENV = "EPHEMORA_BYO_PYTHON_STDLIB"

#: the component header: \0asm + layer 0x0d. Used only to keep leg 3 honest —
#: a component guest pinned as BYO would otherwise be measured as if it were
#: the legacy route, and the leg would "pass" for the wrong reason.
COMPONENT_PREAMBLE = b"\x00asm\x0d\x00\x01\x00"

EXIT3_SCRIPT = "import sys\nprint('before-exit')\nsys.exit(3)\n"


#: The plain-module contrast legs build a Preview1 module that hard-exits with a
#: given code — one template, so the two legs cannot drift apart.
def _exit_wat(code: int) -> bytes:
    """A Preview1 module that hard-exits the process with ``code``."""
    return (
        "(module\n"
        '  (import "wasi_snapshot_preview1" "proc_exit" (func $exit (param i32)))\n'
        '  (memory (export "memory") 1)\n'
        f'  (func (export "_start") i32.const {code} call $exit))\n'
    ).encode()


def _exit_module(tmp_path: Path, code: int) -> Path:
    path = tmp_path / f"exit{code}.wasm"
    path.write_bytes(wasmtime.wat2wasm(_exit_wat(code)))
    return path


def _cli(
    argv: list[str], env: dict[str, str] | None = None
) -> subprocess.CompletedProcess:
    return subprocess.run(
        [sys.executable, "-m", "ephemora_cell.cli", *argv],
        capture_output=True,
        text=True,
        input="",
        timeout=600,
        cwd=str(REPO),
        env=env,
    )


def _component_guest_or_skip() -> str:
    guest = os.environ.get(COMPONENT_GUEST_ENV)
    if not guest or not os.path.exists(guest):
        pytest.skip(
            f"no component Python guest at {COMPONENT_GUEST_ENV} "
            "(bring-your-own guest required; nothing is downloaded)"
        )
    return str(Path(guest).resolve())


def _legacy_guest_or_skip() -> tuple[str, str]:
    guest = os.environ.get(BYO_GUEST_ENV)
    stdlib = os.environ.get(BYO_STDLIB_ENV)
    if (
        not guest
        or not os.path.exists(guest)
        or not stdlib
        or not os.path.isdir(stdlib)
    ):
        pytest.skip(
            f"no legacy Preview1 interpreter pinned via {BYO_GUEST_ENV}/"
            f"{BYO_STDLIB_ENV} (bring-your-own guest required; nothing is downloaded)"
        )
    if Path(guest).read_bytes()[:8] == COMPONENT_PREAMBLE:
        pytest.skip(
            f"{BYO_GUEST_ENV} points at a WASI-0.2 component, not the legacy "
            "Preview1 interpreter — this leg would measure the wrong route"
        )
    return str(Path(guest).resolve()), str(Path(stdlib).resolve())


def _byo_env(guest: str, *, stdlib: str | None) -> dict[str, str]:
    env = dict(os.environ)
    env[BYO_GUEST_ENV] = guest
    if stdlib is None:
        # a component guest takes no stdlib, and an ambient pin would route
        # this leg to the legacy interpreter
        env.pop(BYO_STDLIB_ENV, None)
    else:
        env[BYO_STDLIB_ENV] = stdlib
    env.pop("EPHEMORA_BYO_PYTHON_SHA256", None)
    return env


class TestPlainWasmRunPropagatesTheGuestExitStatus:
    """Contrast leg 1/3: no language adapter, no guest — always runs here."""

    def test_proc_exit_3_becomes_cli_exit_3(self, tmp_path):
        module = _exit_module(tmp_path, 3)
        proc = _cli(["run", str(module)])
        assert proc.returncode == 3, (proc.stdout, proc.stderr)

    def test_the_json_report_carries_the_same_status_and_code(self, tmp_path):
        module = _exit_module(tmp_path, 3)
        proc = _cli(["run", str(module), "--json"])
        assert proc.returncode == 3, proc.stderr
        doc = json.loads(proc.stdout)
        assert doc["status"] == "error"
        assert doc["exit_code"] == 3
        # the Preview1 ABI hands the guest's own number to the host, so the
        # report may say so
        assert doc["exit_status_fidelity"] == "exact"


class TestComponentWasmExitIsReportedAsFailureWithoutAFabricatedCode:
    """A component that exits non-zero is never a success — and its number is
    not carried by this ABI (measured: a Rust wasip2 guest run through
    ``std::process::exit(3)`` and through ``exit(7)`` both surface to wasmtime
    as ``Exited with i32 exit status 1``). The host therefore reports failure
    with the one code it actually observed, and the record says which part of
    the guest's status survived. This leg needs no language guest, so CI runs
    it on every push.
    """

    def test_non_zero_component_exit_is_an_error_not_a_success(self):
        proc = _cli(["run", str(FIXTURES / "exit3_02.wasm"), "--json"])
        doc = json.loads(proc.stdout)
        assert doc["status"] == "error", doc
        assert doc["exit_code"] == 1, doc
        assert proc.returncode == 1, (proc.returncode, doc)
        assert doc["exit_status_fidelity"] == "non_zero_only", doc

    def test_component_and_preview1_fidelity_are_distinguished(self, tmp_path):
        """The two ABIs are not described by the same claim, measured side by
        side in one test: 7 arrives intact over Preview1 and as "non-zero" only
        over the component ABI."""
        module = _exit_module(tmp_path, 7)
        preview = json.loads(_cli(["run", str(module), "--json"]).stdout)
        component = json.loads(
            _cli(["run", str(FIXTURES / "exit3_02.wasm"), "--json"]).stdout
        )
        assert (preview["exit_code"], preview["exit_status_fidelity"]) == (7, "exact")
        assert (component["exit_code"], component["exit_status_fidelity"]) == (
            1,
            "non_zero_only",
        )


class TestJavascriptModuleEntryRunsOnThePreview1Channel:
    """Why ``run_javascript_module`` may say ``exact`` and ``run_javascript_source``
    may not — measured through the entries themselves, not asserted from the
    ABI name.

    The module entry takes a Preview1 core module and the module IS the program,
    so its ``proc_exit`` status is the run's exit status and the host sees it
    (a plain ``proc_exit(7)`` module arriving as 7 here is that measurement).
    The source entry instead runs the user's program INSIDE a QuickJS harness
    guest, and that harness decides what leaves — measured on the pinned guest
    in ``TestTheQuickJSHarnessDecidesWhatLeaves``
    (``tests/test_js_source_guest.py``, opt-in with the interpreter guest).
    """

    def test_proc_exit_through_the_module_entry_arrives_exactly(self, tmp_path):
        from ephemora_cell import lang_js

        module = _exit_module(tmp_path, 7)
        out = lang_js.run_javascript_module(str(module))
        assert out["exit_status_fidelity"] == "exact", out
        assert out["exit_code"] == 7, out
        assert "SUCCESS" not in str(out["status"]), out


class TestComponentRouteReportsSuccessForSysExit3:
    """The documented gap itself (leg 2/3) — opt-in, real CPython guest."""

    def test_cli_reports_zero_and_success_for_a_script_that_exits_3(self, tmp_path):
        guest = _component_guest_or_skip()
        script = tmp_path / "exit3.py"
        script.write_text(EXIT3_SCRIPT)
        proc = _cli(
            ["run", str(script), "--language", "python", "--json"],
            env=_byo_env(guest, stdlib=None),
        )
        doc = json.loads(proc.stdout)
        # MEASURED, and deliberately not repaired: the script's own exit status
        # is invisible to the host. status/exit_code are the HOST-observed
        # worker result; the guest never got a channel to report 3.
        assert doc["status"] == "success", doc
        assert doc["exit_code"] == 0, doc
        assert proc.returncode == 0, (proc.returncode, doc)
        # the record states that plainly instead of implying an attested 0
        assert doc["exit_status_fidelity"] == "none", doc
        # the script did run — the gap is about status, not about silence
        assert "before-exit" in doc["stdout"]
        # and no marker appeared, so nothing is even claimed as a guest error
        assert doc["guest_reported_error"] is False

    def test_an_uncaught_exception_is_still_only_a_guest_claim(self, tmp_path):
        """The other half of the same paragraph: a script that RAISES is
        reported by the guest's marker, which is recorded as
        ``guest_reported_error`` and never turns into a non-zero exit.
        """
        guest = _component_guest_or_skip()
        script = tmp_path / "raise.py"
        script.write_text("print('before-raise')\nraise ValueError('r4')\n")
        proc = _cli(
            ["run", str(script), "--language", "python", "--json"],
            env=_byo_env(guest, stdlib=None),
        )
        doc = json.loads(proc.stdout)
        assert doc["status"] == "success", doc
        assert doc["exit_code"] == 0, doc
        assert proc.returncode == 0, (proc.returncode, doc)
        assert doc["guest_reported_error"] is True, doc


class TestLegacyInterpreterRoutePropagatesSysExit3:
    """Contrast leg 3/3: the Preview1 interpreter really does propagate."""

    def test_cli_exit_3_and_error_status_on_the_legacy_route(self, tmp_path):
        guest, stdlib = _legacy_guest_or_skip()
        script = tmp_path / "exit3.py"
        script.write_text(EXIT3_SCRIPT)
        proc = _cli(
            ["run", str(script), "--language", "python", "--json"],
            env=_byo_env(guest, stdlib=stdlib),
        )
        doc = json.loads(proc.stdout)
        assert doc["status"] == "error", doc
        assert doc["exit_code"] == 3, doc
        assert proc.returncode == 3, (proc.returncode, doc)
        assert doc["exit_status_fidelity"] == "exact", doc
        assert "before-exit" in doc["stdout"]


class TestTheCliNamesTheMissingAttestation:
    """The bounded failure mode, tested without a guest.

    A caller that only reads ``status`` must not be able to mistake this route
    for an attested success, so the CLI states the limitation where the caller
    is looking: in the machine-readable document, and — for a human reading the
    terminal — as one stderr note next to the guest's own output. Stdout stays
    the guest's bytes, exactly as on the other routes.

    The adapter is stubbed here because the fidelity NOTE is CLI behaviour; the
    fidelity VALUE per route is pinned by the real-guest legs above and by
    ``tests/test_adapter_result_shape.py``.
    """

    @staticmethod
    def _adapter_result(
        fidelity: str,
        status: str = "ExecutionStatus.SUCCESS",
        exit_code: int = 0,
    ) -> dict:
        return {
            "status": status,
            "stdout": "visible\n",
            "stderr": "",
            "exit_code": exit_code,
            "fuel_consumed": None,
            "elapsed_ms": None,
            "output": None,
            "exit_status_fidelity": fidelity,
        }

    def _run(
        self,
        monkeypatch,
        fidelity: str,
        extra: list[str],
        status: str = "ExecutionStatus.SUCCESS",
        exit_code: int = 0,
    ) -> int:
        from ephemora_cell import cli, lang

        def fake(language: str, **kwargs):
            return self._adapter_result(fidelity, status=status, exit_code=exit_code)

        monkeypatch.setattr(lang, "run_language", fake)
        # main() reads sys.argv, so the CLI is driven through the same entry the
        # console script uses rather than through a private helper
        monkeypatch.setattr(
            sys,
            "argv",
            ["ephemora-cell", "run", "script.py", "--language", "python", *extra],
        )
        with pytest.raises(SystemExit) as excinfo:
            cli.main()
        return excinfo.value.code

    def test_note_on_stderr_when_the_guest_cannot_report(
        self, tmp_path, monkeypatch, capsys
    ):
        monkeypatch.chdir(tmp_path)
        (tmp_path / "script.py").write_text("print(1)\n")
        code = self._run(monkeypatch, "none", [])
        captured = capsys.readouterr()
        assert code == 0
        assert captured.out == "visible\n", captured.out
        assert "does not report its script's exit status" in captured.err

    def test_no_note_when_the_exit_status_is_attested(
        self, tmp_path, monkeypatch, capsys
    ):
        monkeypatch.chdir(tmp_path)
        (tmp_path / "script.py").write_text("print(1)\n")
        code = self._run(monkeypatch, "exact", [])
        captured = capsys.readouterr()
        assert code == 0
        assert "exit status" not in captured.err, captured.err

    def test_json_document_carries_the_field(self, tmp_path, monkeypatch, capsys):
        monkeypatch.chdir(tmp_path)
        (tmp_path / "script.py").write_text("print(1)\n")
        code = self._run(monkeypatch, "none", ["--json"])
        captured = capsys.readouterr()
        assert code == 0
        doc = json.loads(captured.out)
        assert doc["exit_status_fidelity"] == "none"

    def test_a_guest_code_that_would_mask_to_zero_still_exits_nonzero(
        self, tmp_path, monkeypatch
    ):
        """A guest-reported 256 is a genuine failure, but ``sys.exit`` hands the
        shell one byte of its argument — reported verbatim the process would
        leave status 0 while the document says ``error``."""
        monkeypatch.chdir(tmp_path)
        (tmp_path / "script.py").write_text("print(1)\n")
        code = self._run(
            monkeypatch,
            "exact",
            [],
            status="ExecutionStatus.ERROR",
            exit_code=256,
        )
        assert code == 1, code


class TestARejectedLoadFailsClosedWithoutSoftening:
    """What ``exit_status_fidelity`` claims about a run that never started.

    ``run --abi preview1`` on a component binary is rejected by the loader
    before any guest runs. The CLI has to fail closed — error status, exit 1 —
    and the fidelity field describes the guest's exit as the host OBSERVED it, so
    a run in which no guest ever left says ``none``. It used to report ``exact``
    here by reading the width of the routed ABI, which attested an exit channel
    nothing travelled through; the contract is in ``docs/cli-errors.md``. The
    rejection is still never softened into a success.
    """

    def test_rejected_load_reports_error_and_exits_one(self):
        proc = _cli(
            ["run", str(FIXTURES / "hello02.wasm"), "--abi", "preview1", "--json"]
        )
        doc = json.loads(proc.stdout)
        assert doc["status"] == "error", doc
        assert proc.returncode == 1, (proc.returncode, proc.stderr)
        # nothing reached a guest exit, so nothing may be attested about one: the
        # field reports the guest's exit as OBSERVED, not the width of the ABI
        # that was routed (a caller could otherwise take the host's own 1 for the
        # guest's verdict). docs/cli-errors.md carries the contract.
        assert doc["exit_status_fidelity"] == "none", doc


class TestTheReportedExitCodeFitsOneByte:
    """The CLI's own exit number is a contract, not a passthrough.

    Both run routes share one helper, pinned for the values a guest-reported
    status can carry: a multiple of 256 must not arrive as 0, and a real number
    below 256 must keep its exactness.
    """

    @pytest.mark.parametrize(
        "code,expected",
        [(None, 1), (0, 1), (1, 1), (3, 3), (255, 255), (256, 1), (257, 1), (512, 1)],
    )
    def test_failure_never_collapses_to_zero(self, code, expected):
        from ephemora_cell.cli import _cli_exit_status

        assert _cli_exit_status(True, code) == expected

    def test_success_still_exits_zero(self):
        from ephemora_cell.cli import _cli_exit_status

        assert _cli_exit_status(False, 3) == 0


class TestTheGapIsTheGuestNotTheHost:
    """Where the difference is located, measured on the same run.

    Both routes stage the script, mount ``/work`` and force the disposable
    worker; both report what the worker saw. What differs is the ABI's
    reporting channel, so this pins that the component route is not silently
    skipping the script (it runs and prints) while its exit status is lost.
    """

    def test_component_route_runs_the_script_and_loses_only_the_status(self, tmp_path):
        guest = _component_guest_or_skip()
        script = tmp_path / "stdout_then_exit.py"
        script.write_text(
            "import sys\n"
            "sys.stdout.write('visible\\n')\n"
            "sys.stdout.flush()\n"
            "sys.exit(3)\n"
        )
        proc = _cli(
            ["run", str(script), "--language", "python"],
            env=_byo_env(guest, stdlib=None),
        )
        assert proc.returncode == 0, (proc.stdout, proc.stderr)
        # the script ran to its own exit call, and its output arrived verbatim
        assert proc.stdout == "visible\n", (repr(proc.stdout), proc.stderr)
