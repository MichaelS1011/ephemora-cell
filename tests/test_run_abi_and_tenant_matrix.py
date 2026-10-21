# SPDX-License-Identifier: BUSL-1.1
# Copyright 2026 Michael Soppa
"""Acceptance matrix for ``--abi`` and the ``--tenant`` family on the CLI.

Both halves of this file exist because the pins so far were one-sided:

* ``--abi``: every refusal was tested (``test_cli_new_commands.py`` pins
  ``run --language python --abi preview1`` and the ``policy check`` twin), but
  NO positive case was. A guard that only ever refuses cannot tell an operator
  an overblocking regression apart from correct behaviour — a change that
  started refusing ``run mod.wasm --abi preview1`` or
  ``policy check --language javascript --abi preview1`` would have made the
  suite greener, not louder.
* the ``--tenant`` family: the language path gained the refusal for a cap
  passed WITHOUT ``--tenant`` (``cli.py``, 1.2.0rc2), while the existing
  parametrised refusal list covers ``--allow-dirs``, ``--stdin`` and two
  ``--abi`` values — no tenant flag at all.

Every expectation below was measured against this working tree before the test
was written (the expected column is the measured exit code, not an aspiration).
The two language legs whose success depends on whether a guest happens to be
installed assert ``rc != 2`` plus the absence of the refusal text, so their
meaning cannot change with the developer's environment.
"""

from __future__ import annotations

import json
import subprocess
import sys
from pathlib import Path
from typing import ClassVar

import pytest
import wasmtime

REPO = Path(__file__).resolve().parent.parent
FIXTURES = REPO / "tests" / "fixtures"

# proc_exit(3) with a memory export: a preview1 CORE MODULE whose exit status
# the host propagates, so a run that reached the engine is distinguishable from
# a flag refusal by its exit code alone (3 = ran, 2 = refused by the CLI,
# 1 = refused by the loader).
EXIT3_WAT = b"""
(module
  (import "wasi_snapshot_preview1" "proc_exit" (func $exit (param i32)))
  (memory (export "memory") 1)
  (func (export "_start") i32.const 3 call $exit))
"""

REFUSAL = "cannot carry these flags"


def _run_cli(*args: str) -> subprocess.CompletedProcess:
    return subprocess.run(
        [sys.executable, "-m", "ephemora_cell.cli", *args],
        capture_output=True,
        text=True,
        input="",
        timeout=180,
        cwd=str(REPO),
    )


@pytest.fixture(scope="module")
def core_module(tmp_path_factory) -> str:
    path = tmp_path_factory.mktemp("abi-matrix") / "exit3_core.wasm"
    path.write_bytes(wasmtime.wat2wasm(EXIT3_WAT))
    return str(path)


@pytest.fixture()
def scripts(tmp_path):
    """A Python and a JavaScript script in one directory, by language id."""
    py = tmp_path / "s.py"
    py.write_text("print(1)\n")
    js = tmp_path / "a.js"
    js.write_text("console.log(1)\n")
    return {"python": str(py), "javascript": str(js), "wasm": str(tmp_path)}


class TestAbiIsAcceptedOnThePlainWasmPath:
    """An explicit ``--abi`` is the caller's to make for a .wasm module.

    The measured rule: the flag is never refused, the BYTES decide. A preview1
    core module asked to run as a component fails at the loader (1), a WASI-0.2
    component asked to run as preview1 fails at the parser (1), and each module
    runs under the ABI it actually is (0, or the guest's own exit status).
    Exit 2 anywhere in this table would mean the CLI began refusing a
    combination it can serve.
    """

    @pytest.mark.parametrize(
        "module,abi,expected",
        [
            pytest.param("core", "preview1", 3, id="core-module-as-preview1"),
            pytest.param("core", "auto", 3, id="core-module-as-auto"),
            pytest.param("core", "component", 1, id="core-module-as-component"),
            pytest.param("hello02", "component", 0, id="component-as-component"),
            pytest.param("hello02", "auto", 0, id="component-as-auto"),
            pytest.param("hello02", "preview1", 1, id="component-as-preview1"),
        ],
    )
    def test_the_abi_flag_is_never_refused_on_a_module_run(
        self, module, abi, expected, core_module
    ):
        target = core_module if module == "core" else str(FIXTURES / "hello02.wasm")
        assert Path(target).is_file(), target
        proc = _run_cli("run", target, "--abi", abi)
        # the regression this pins: exit 2 = "this combination is not allowed",
        # which would be a new restriction, not a bug fix
        assert proc.returncode != 2, (abi, proc.stdout, proc.stderr)
        assert REFUSAL not in proc.stderr
        assert "unrecognized arguments" not in proc.stderr
        assert proc.returncode == expected, (abi, proc.stdout, proc.stderr)

    def test_a_component_run_under_an_explicit_abi_still_produces_output(self):
        """Exit 0 alone could be reached without the guest speaking; the
        component fixture's own stdout proves the accepted ABI was executed."""
        proc = _run_cli("run", str(FIXTURES / "hello02.wasm"), "--abi", "component")
        assert proc.returncode == 0, proc.stderr
        assert proc.stdout.strip(), "the component produced no output"


class TestAbiLegsOnTheLanguagePath:
    """``--abi`` on a language run: contradicted values refuse, honoured ones do not.

    The exit-2 legs are pinned elsewhere too and are repeated here as the
    negative poles of this matrix — a matrix is only worth something if both
    poles sit in it. The positive legs (``auto`` for both adapters, and
    ``preview1`` for JavaScript, which IS that adapter's ABI) are the part that
    had no test at all.
    """

    @pytest.mark.parametrize(
        "language,abi,expect_refused",
        [
            pytest.param("python", "auto", False, id="py-auto"),
            pytest.param("python", "preview1", True, id="py-preview1"),
            pytest.param("python", "component", True, id="py-component"),
            pytest.param("javascript", "preview1", False, id="js-preview1-honoured"),
            pytest.param("javascript", "component", True, id="js-component"),
            pytest.param("javascript", "auto", False, id="js-auto"),
        ],
    )
    def test_only_a_contradicting_abi_is_refused(
        self, language, abi, expect_refused, scripts
    ):
        proc = _run_cli("run", scripts[language], "--language", language, "--abi", abi)
        if expect_refused:
            assert proc.returncode == 2, (language, abi, proc.stdout, proc.stderr)
            assert REFUSAL in proc.stderr
            assert f"--abi {abi}" in proc.stderr
            assert proc.stdout.strip() == ""
        else:
            # honoured: 0 with an installed guest, 1 with a guest that failed,
            # 4 when this machine has no such guest (environment class) — never 2
            assert proc.returncode in (0, 1, 4), (language, abi, proc.stderr)
            assert REFUSAL not in proc.stderr

    def test_javascript_preview1_is_honoured_not_refused_on_the_view(self):
        """The exact overblocking case: a JavaScript run IS preview1, so
        asking for preview1 must be answered, not refused."""
        proc = _run_cli(
            "policy",
            "check",
            "--language",
            "javascript",
            "--abi",
            "preview1",
            "--json",
        )
        assert proc.returncode == 0, proc.stderr
        payload = json.loads(proc.stdout)
        assert payload["abi"] == "preview1"

    def test_python_auto_is_honoured_on_the_view(self):
        """``auto`` is never contradicted — the guest's bytes decide, and the
        view reports both ABIs instead of refusing."""
        proc = _run_cli(
            "policy", "check", "--language", "python", "--abi", "auto", "--json"
        )
        assert proc.returncode == 0, proc.stderr
        payload = json.loads(proc.stdout)
        assert payload["abi"] == "auto"
        assert set(payload["sync_blockade"]["per_abi"]) == {"preview1", "component"}


class TestTenantFamilyIsRefusedOnTheLanguagePath:
    """Every member of the ``--tenant`` family refuses on a language run.

    The documented set is four flags (``docs/languages.md`: "refused (exit 2)
    ... and that stays true for a cap passed without ``--tenant``"). The caps
    WITHOUT ``--tenant`` are the part that used to fall through: with no tenant
    id there is nothing to attribute, so a cap would be accepted, ignored, and
    reported as though it held. This class pins the whole family — each flag
    alone, both caps alone, all four together, on the explicit and the
    extension-detected route, for both adapters — and pins the wasm path as the
    positive control, so the refusal cannot spread into a run that does have a
    tenant mechanism.
    """

    FAMILY: ClassVar[list] = [
        pytest.param(["--tenant", "acme"], id="--tenant"),
        pytest.param(["--tenant-book", "book.jsonl"], id="--tenant-book"),
        pytest.param(["--tenant-max-runs", "5"], id="--tenant-max-runs-alone"),
        pytest.param(["--tenant-max-fuel", "100"], id="--tenant-max-fuel-alone"),
        pytest.param(
            [
                "--tenant",
                "acme",
                "--tenant-book",
                "book.jsonl",
                "--tenant-max-runs",
                "5",
                "--tenant-max-fuel",
                "100",
            ],
            id="whole-family",
        ),
    ]

    @pytest.mark.parametrize("flags", FAMILY)
    def test_python_route_refuses_with_exit_2(self, flags, scripts):
        proc = _run_cli("run", scripts["python"], "--language", "python", *flags)
        assert proc.returncode == 2, (flags, proc.stdout, proc.stderr)
        assert REFUSAL in proc.stderr
        assert "--tenant" in proc.stderr
        assert "per-tenant quota is not attributed" in proc.stderr
        # a refusal is not a report
        assert proc.stdout.strip() == ""

    @pytest.mark.parametrize("flags", FAMILY)
    def test_javascript_route_refuses_with_exit_2(self, flags, scripts):
        proc = _run_cli(
            "run", scripts["javascript"], "--language", "javascript", *flags
        )
        assert proc.returncode == 2, (flags, proc.stdout, proc.stderr)
        assert REFUSAL in proc.stderr
        assert "--tenant" in proc.stderr

    @pytest.mark.parametrize("flags", FAMILY)
    def test_extension_detection_takes_the_same_refusal(self, flags, scripts):
        """No ``--language``: the ``.py`` route is the same code path, so it
        must not be more permissive than the explicit one."""
        proc = _run_cli("run", scripts["python"], *flags)
        assert proc.returncode == 2, (flags, proc.stdout, proc.stderr)
        assert REFUSAL in proc.stderr

    def test_a_cap_alone_without_any_tenant_id_is_still_a_refusal(self, scripts):
        """The exact rc2 change, stated as its own case: a number the operator
        believes caps something must not be silently dropped."""
        for flag, value in (
            ("--tenant-max-runs", "5"),
            ("--tenant-max-fuel", "100"),
        ):
            proc = _run_cli(
                "run", scripts["python"], "--language", "python", flag, value
            )
            assert proc.returncode == 2, (flag, proc.stderr)
            assert "--tenant-max-runs/--tenant-max-fuel" in proc.stderr

    def test_the_wasm_path_refuses_a_cap_without_an_account_too(self, core_module):
        """The tenant family behaves the same on every route.

        The wasm path HAS a tenant mechanism, but a cap or a book without
        ``--tenant`` attributes nothing — the number would be accepted, dropped
        and reported as if it guarded something. That is the exact defect 1.2.0rc2
        closed on the language path, so leaving it open here would make the two
        routes disagree about which configurations exist at all.
        """
        for flag, value in (
            ("--tenant-max-runs", "5"),
            ("--tenant-max-fuel", "100"),
            ("--tenant-book", "book.jsonl"),
        ):
            proc = _run_cli("run", core_module, flag, value)
            assert proc.returncode == 2, (flag, proc.stdout, proc.stderr)
            assert "--tenant" in proc.stderr, (flag, proc.stderr)
            assert "refusing instead of ignoring" in proc.stderr, (flag, proc.stderr)

    def test_the_wasm_path_runs_when_the_account_is_there(self, core_module, tmp_path):
        """Positive control against overblocking: with an account the same flags
        reach the engine (measured exit 3 = the guest's own exit status)."""
        book = tmp_path / "book.jsonl"
        proc = _run_cli(
            "run",
            core_module,
            "--tenant",
            "acme",
            "--tenant-book",
            str(book),
            "--tenant-max-runs",
            "5",
        )
        assert proc.returncode == 3, (proc.stdout, proc.stderr)
        assert REFUSAL not in proc.stderr
        assert book.is_file(), "the run did not bill the account it named"


class TestRefusalTextIsActionable:
    """A refusal the operator cannot act on is not a refusal worth having."""

    def test_the_error_lists_the_family_and_names_the_check_command(self, scripts):
        proc = _run_cli(
            "run", scripts["python"], "--language", "python", "--tenant", "acme"
        )
        assert proc.returncode == 2
        assert "refusing instead of ignoring" in proc.stderr
        assert "policy check --language python" in proc.stderr
        for flag in (
            "--tenant",
            "--tenant-book",
            "--tenant-max-runs",
            "--tenant-max-fuel",
        ):
            assert flag in proc.stderr
