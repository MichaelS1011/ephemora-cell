# SPDX-License-Identifier: BUSL-1.1
# Copyright 2026 Michael Soppa
"""CLI acceptance tests for the 1.2.0 product surface: doctor, verify,
policy check and the unified run entry (--language for WASM/Python/JavaScript).

These drive the REAL CLI through a subprocess — the same bytes an operator
gets — and pin the product contract: machine-readable output (--json) with
a schema tag, a human report, a documented exit code, and a clean error (no
traceback) on every failure path. What THIS environment cannot show (a missing
language guest, a wasmtime outside the qualified line) is asserted as the
honest fail-closed behaviour instead of being skipped away.
"""

from __future__ import annotations

import hashlib
import json
import os
import subprocess
import sys
from pathlib import Path
from types import SimpleNamespace

sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))

import pytest

from ephemora_cell import ExecutionReport, PreExecutionRecord, WASIConfig
from ephemora_cell.ledger import Ledger, LedgerEntry, record_digest

REPO = os.path.join(os.path.dirname(__file__), "..")

_CHECK_NAMES = [
    "python",
    "platform",
    "package",
    "runtime-import",
    "runtime-floor",
    "runtime-identity",
    "language-guests",
    "cli-entrypoints",
    "smoke-run",
]


def _run_cli(*args, input=None) -> subprocess.CompletedProcess:
    return subprocess.run(
        [sys.executable, "-m", "ephemora_cell.cli", *args],
        capture_output=True,
        text=True,
        input=input,
        timeout=180,
        cwd=REPO,
    )


# --- ledger fixtures: deterministic signer, same discipline as the ledger
# --- chain tests (a content-identity signer keeps the CLI tests keyless).

_SIGN_KEY = b"deterministic-sign-key"


def _signer(data: bytes) -> bytes:
    return hashlib.sha256(_SIGN_KEY + data).digest()


def _append(ledger: Ledger, n: int = 0) -> dict:
    pre = PreExecutionRecord.build(
        module_bytes=b"\x00asm\x01\x00\x00\x00",
        config=WASIConfig(max_fuel=500_000),
        record_id=f"pre-{n:04d}",
        timestamp=f"2026-10-03T00:00:{n % 60:02d}.000Z",
    )
    signed_pre = pre.sign(_signer, alg="EdDSA")
    report = ExecutionReport(status="success", exit_code=0, elapsed_ms=1.0)
    report.back_link = {
        "pre_exec_id": signed_pre["id"],
        "pre_exec_digest": record_digest(signed_pre),
    }
    signed_receipt = report.sign(_signer, alg="EdDSA")
    return ledger.append(LedgerEntry.from_records(signed_pre, signed_receipt), _signer)


def _write_ledger(path: Path, count: int = 3) -> Path:
    ledger = Ledger(path)
    for n in range(count):
        _append(ledger, n)
    return path


def _ed25519_material():
    """(private key with .sign, public PEM text) over a real Ed25519 key."""
    from cryptography.hazmat.primitives import serialization
    from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

    key = Ed25519PrivateKey.generate()
    pem = (
        key.public_key()
        .public_bytes(
            serialization.Encoding.PEM, serialization.PublicFormat.SubjectPublicKeyInfo
        )
        .decode("utf-8")
    )
    return key, pem


def _guest_installed(language: str) -> bool:
    from ephemora_cell import lang_guest

    try:
        lang_guest.resolve_guest(language)
        return True
    except lang_guest.GuestNotInstalled:
        return False


class TestDoctorCommand:
    """`doctor --json` is machine-readable, its exit code follows the summary."""

    def test_json_schema_checks_and_exit_consistency(self):
        proc = _run_cli("doctor", "--json")
        assert proc.returncode in (0, 1), proc.stderr
        payload = json.loads(proc.stdout)
        assert payload["schema"] == "ephemora-cell/doctor/1"
        assert [c["name"] for c in payload["checks"]] == _CHECK_NAMES
        summary = payload["summary"]
        assert summary["ok"] + summary["warn"] + summary["fail"] == len(_CHECK_NAMES)
        assert set(summary) == {"ok", "warn", "fail"}
        assert payload["ok"] == (summary["fail"] == 0)
        assert proc.returncode == (1 if summary["fail"] else 0)
        for check in payload["checks"]:
            assert check["status"] in ("ok", "warn", "fail")
            assert check["detail"]

    def test_human_report_names_every_check_and_the_summary(self):
        proc = _run_cli("doctor")
        assert proc.returncode in (0, 1)
        for name in _CHECK_NAMES:
            assert name in proc.stdout
        assert "summary:" in proc.stdout
        assert "Traceback" not in proc.stderr + proc.stdout


class TestVerifyCommand:
    """`verify` decides 0 / 1 / 3 from the artefact — never from hope."""

    def test_intact_ledger_verifies_keyless(self, tmp_path):
        path = _write_ledger(tmp_path / "ledger.jsonl")
        proc = _run_cli("verify", str(path))
        assert proc.returncode == 0
        assert "verified: yes" in proc.stdout
        assert "linkage" in proc.stdout

    def test_tampered_ledger_fails(self, tmp_path):
        path = _write_ledger(tmp_path / "ledger.jsonl")
        lines = path.read_text(encoding="utf-8").splitlines()
        entry = json.loads(lines[1])
        entry["prev_hash"] = "0" * 64  # break the linkage of the second entry
        lines[1] = json.dumps(entry)
        path.write_text("\n".join(lines) + "\n", encoding="utf-8")
        proc = _run_cli("verify", str(path), "--json")
        assert proc.returncode == 1
        payload = json.loads(proc.stdout)
        assert payload["schema"] == "ephemora-cell/verify/1"
        assert payload["verified"] is False
        assert payload["errors"]

    def test_missing_artifact_fails_cleanly(self, tmp_path):
        proc = _run_cli("verify", str(tmp_path / "does-not-exist.jsonl"))
        assert proc.returncode == 1
        assert "Traceback" not in proc.stderr
        assert "error:" in proc.stdout

    def test_signed_record_without_key_is_not_verifiable_here(self, tmp_path):
        pytest.importorskip("cryptography")
        key, _pem = _ed25519_material()
        report = ExecutionReport(status="success", exit_code=0, elapsed_ms=1.0)
        signed = report.sign(key.sign, alg="EdDSA")
        path = tmp_path / "record.json"
        path.write_text(json.dumps(signed), encoding="utf-8")

        proc = _run_cli("verify", str(path), "--json")
        assert proc.returncode == 3, proc.stdout + proc.stderr
        payload = json.loads(proc.stdout)
        assert payload["kind"] == "record"
        assert payload["verified"] is False
        assert payload["details"]["key_supplied"] is False
        assert payload["details"].get("not_verifiable_here") is True

    def test_signed_record_with_the_right_key_verifies(self, tmp_path):
        pytest.importorskip("cryptography")
        key, pem = _ed25519_material()
        report = ExecutionReport(status="success", exit_code=0, elapsed_ms=1.0)
        signed = report.sign(key.sign, alg="EdDSA")
        record = tmp_path / "record.json"
        record.write_text(json.dumps(signed), encoding="utf-8")
        public = tmp_path / "public.pem"
        public.write_text(pem, encoding="utf-8")

        proc = _run_cli("verify", str(record), "--key", str(public))
        assert proc.returncode == 0, proc.stdout + proc.stderr
        assert "verified: yes" in proc.stdout

    def test_signed_record_with_a_foreign_key_fails(self, tmp_path):
        pytest.importorskip("cryptography")
        key, _pem = _ed25519_material()
        _other, other_pem = _ed25519_material()
        report = ExecutionReport(status="success", exit_code=0, elapsed_ms=1.0)
        signed = report.sign(key.sign, alg="EdDSA")
        record = tmp_path / "record.json"
        record.write_text(json.dumps(signed), encoding="utf-8")
        foreign = tmp_path / "foreign.pem"
        foreign.write_text(other_pem, encoding="utf-8")

        proc = _run_cli("verify", str(record), "--key", str(foreign))
        assert proc.returncode == 1
        assert "FAILED" in proc.stdout

    def test_unreadable_key_file_is_a_clean_error(self, tmp_path):
        proc = _run_cli(
            "verify", str(tmp_path / "any.json"), "--key", str(tmp_path / "no.pem")
        )
        assert proc.returncode == 1
        assert "cannot read --key file" in proc.stderr
        assert "Traceback" not in proc.stderr


class TestPolicyCheckCommand:
    """`policy check` shows the enforcement before the run — same logic."""

    def test_default_snapshot_is_machine_readable(self):
        proc = _run_cli("policy", "check", "--json")
        assert proc.returncode == 0, proc.stderr
        payload = json.loads(proc.stdout)
        assert payload["schema"] == "ephemora-cell/policy-check/1"
        assert payload["trust"] == "unknown"
        assert payload["fingerprint"]
        assert "security_baseline" in payload
        isolation = payload["isolation"]
        # ADR-015: unknown posture + abi=auto -> worker subprocess, per ABI.
        assert isolation["required"] is True
        assert set(isolation["per_abi"]) and all(
            entry["required"] is True for entry in isolation["per_abi"].values()
        )

    def test_human_report_states_the_mandate(self):
        proc = _run_cli("policy", "check")
        assert proc.returncode == 0
        assert "MANDATORY" in proc.stdout
        assert "fingerprint" in proc.stdout.lower()

    def test_refused_directory_exits_nonzero(self):
        proc = _run_cli("policy", "check", "--allow-dirs", "/etc", "--json")
        assert proc.returncode == 1
        payload = json.loads(proc.stdout)
        refused = payload["preopens"]["refused"]
        assert refused and "/etc" in json.dumps(refused)

    def test_env_names_are_shown_but_values_never_leak(self):
        proc = _run_cli(
            "policy", "check", "--allow-env", "API_TOKEN=TOP-SECRET", "--json"
        )
        assert proc.returncode == 0
        assert "TOP-SECRET" not in proc.stdout + proc.stderr
        payload = json.loads(proc.stdout)
        assert "API_TOKEN" in json.dumps(payload["env"])

    def test_language_python_views_the_interpreter_profile(self):
        """A language run starts from the interpreter profile, so the view of
        ``run --language python`` must describe THAT budget set — showing the
        compiled-module defaults here would pre-approve a configuration that
        never runs."""
        from ephemora_cell import WASIConfig, get_profile
        from ephemora_cell.execution_report import policy_fingerprint

        proc = _run_cli("policy", "check", "--language", "python", "--json")
        assert proc.returncode == 0, proc.stderr
        payload = json.loads(proc.stdout)
        interpreter = get_profile("interpreter")
        assert payload["language"] == "python"
        assert payload["budgets"]["max_memory_mb"] == interpreter.max_memory_mb
        assert payload["fingerprint"] == policy_fingerprint(interpreter)
        assert payload["fingerprint"] != policy_fingerprint(WASIConfig())

    def test_language_javascript_and_explicit_flags_compose(self):
        """The guest default is the base; an explicit flag still wins."""
        proc = _run_cli(
            "policy", "check", "--language", "javascript", "--fuel", "12345", "--json"
        )
        assert proc.returncode == 0, proc.stderr
        payload = json.loads(proc.stdout)
        assert payload["language"] == "javascript"
        assert payload["budgets"]["max_fuel"] == 12345

    def test_language_view_reports_the_adapters_abi_and_its_source(self):
        """A JavaScript run IS preview1 — the CLI must not let a caller relabel it."""
        proc = _run_cli("policy", "check", "--language", "javascript", "--json")
        assert proc.returncode == 0, proc.stderr
        payload = json.loads(proc.stdout)
        assert payload["abi"] == "preview1"
        assert "javascript adapter" in payload["abi_source"]
        # one honest verdict, not a both-ABI hedge that hides the sync blockade
        assert payload["sync_blockade"]["holds"] is True
        assert "per_abi" not in payload["sync_blockade"]
        assert "DIFFERENT digest" in payload["fingerprint_note"]

    def test_an_abi_the_language_adapter_would_override_is_refused(self):
        """Exit 2 with a reason that names WHO decides the ABI.

        The reason must not claim the run could not be that ABI: with a BYO
        legacy Python guest the run really would be preview1. It is refused
        because the caller is not the one choosing it.
        """
        for language, abi in (("javascript", "component"), ("python", "component")):
            proc = _run_cli(
                "policy",
                "check",
                "--language",
                language,
                "--abi",
                abi,
                "--json",
            )
            assert proc.returncode == 2, (language, abi, proc.stdout, proc.stderr)
            assert "does not take the ABI from the caller" in proc.stderr
            assert proc.stdout.strip() == ""

    def test_the_python_abi_is_left_to_the_guest_bytes(self):
        """Python reports both ABIs because the guest's header decides — and
        a caller asking for one of them by hand is refused, not answered."""
        ok = _run_cli(
            "policy", "check", "--language", "python", "--abi", "auto", "--json"
        )
        assert ok.returncode == 0, ok.stderr
        payload = json.loads(ok.stdout)
        assert payload["abi"] == "auto"
        assert set(payload["sync_blockade"]["per_abi"]) == {"preview1", "component"}
        refused = _run_cli(
            "policy", "check", "--language", "python", "--abi", "preview1", "--json"
        )
        assert refused.returncode == 2

    def test_isolated_raises_a_trusted_run_into_the_worker(self):
        """``--isolated`` may only RAISE isolation — and the view must say so."""
        proc = _run_cli(
            "policy",
            "check",
            "--trust",
            "trusted",
            "--abi",
            "preview1",
            "--isolated",
            "--json",
        )
        assert proc.returncode == 0, proc.stderr
        payload = json.loads(proc.stdout)
        assert payload["isolation"]["required"] is True
        assert payload["isolation"]["execution_mode"] == "subprocess"
        assert payload["isolation"]["raised_by"] == "--isolated"

    def test_flags_that_do_not_shape_policy_are_refused(self):
        """The view is scoped to policy: a flag it cannot honour must fail the
        parse instead of quietly describing a different run."""
        for flag in ("--stdin", "--tenant", "--tenant-max-runs"):
            proc = _run_cli("policy", "check", flag, "1")
            assert proc.returncode == 2, (flag, proc.returncode, proc.stderr)

    def test_explicit_trusted_preview1_needs_no_worker(self):
        proc = _run_cli(
            "policy", "check", "--trust", "trusted", "--abi", "preview1", "--json"
        )
        assert proc.returncode == 0
        payload = json.loads(proc.stdout)
        assert payload["isolation"]["required"] is False
        assert "per_abi" not in payload["isolation"]

    def test_policy_without_subcommand_prints_help(self):
        proc = _run_cli("policy")
        assert proc.returncode == 1
        assert "check" in proc.stdout


class TestLanguageRunFlagContract:
    """``run --language`` must not swallow a flag whose value is discarded.

    The adapters rebuild the grant set and never read the CLI's stdin or tenant
    flags, so accepting them would let an operator believe in a permission, an
    input or an attribution the run does not carry. `policy check` already
    refuses the contradicting ABI; the two commands must agree about which
    configurations exist at all.
    """

    @pytest.mark.parametrize(
        "argv,named",
        [
            (["--language", "python", "--allow-dirs", "/tmp"], "--allow-dirs"),
            (["--language", "python", "--stdin", "/tmp/in"], "--stdin"),
            (["--language", "javascript", "--abi", "component"], "--abi component"),
            (["--language", "python", "--abi", "preview1"], "--abi preview1"),
        ],
    )
    def test_discarded_flags_are_refused_with_exit_2(self, tmp_path, argv, named):
        proc = _run_cli("run", str(tmp_path / "s.py"), *argv)
        assert proc.returncode == 2, (argv, proc.stdout, proc.stderr)
        assert named in proc.stderr
        assert "refusing instead of ignoring" in proc.stderr
        # a refusal is not a report: no partial snapshot on stdout
        assert proc.stdout.strip() == ""

    def test_allow_env_is_carried_not_refused(self, tmp_path):
        """The adapters replace ``allow_dirs`` only, so env pairs DO survive —
        refusing this flag would invent a limitation that does not exist.

        Deliberately asserted on the refusal text alone: whether the run then
        succeeds depends on whether this host has a guest installed, and a
        contract test must not change meaning with the developer's environment.
        The script is written because a language run of a MISSING file is the
        caller class (`2`) — on a host that has the guest installed that refusal
        would arrive before any of the outcomes this leg is about.
        """
        (tmp_path / "s.py").write_text("print('ok')\n", encoding="utf-8")
        proc = _run_cli(
            "run", str(tmp_path / "s.py"), "--language", "python", "--allow-env", "A=b"
        )
        assert "cannot carry these flags" not in proc.stderr
        # 2 would mean it was refused; 4 is the environment class naming the
        # guest this host has not installed (docs/cli-errors.md) — neither is a
        # flag refusal.
        assert proc.returncode in (0, 1, 4)

    def test_isolated_is_accepted_because_the_adapter_already_satisfies_it(
        self, tmp_path
    ):
        # the file exists for the same reason as above: this leg is about the
        # flag being carried, not about a missing path
        (tmp_path / "s.py").write_text("print('ok')\n", encoding="utf-8")
        proc = _run_cli(
            "run", str(tmp_path / "s.py"), "--language", "python", "--isolated"
        )
        assert "cannot carry these flags" not in proc.stderr
        assert proc.returncode in (0, 1, 4)


class TestDetectedLanguage:
    """The run router: explicit --language wins, else the file extension."""

    @staticmethod
    def _args(module: str, language: str = "auto") -> SimpleNamespace:
        return SimpleNamespace(module=module, language=language)

    def test_extension_auto_detection(self):
        from ephemora_cell.cli import _detected_language

        assert _detected_language(self._args("script.py")) == "python"
        assert _detected_language(self._args("script.PY")) == "python"
        assert _detected_language(self._args("app.js")) == "javascript"
        assert _detected_language(self._args("app.Js")) == "javascript"
        assert _detected_language(self._args("mod.wasm")) == "wasm"
        assert _detected_language(self._args("no-extension")) == "wasm"

    def test_explicit_language_overrides_the_extension(self):
        from ephemora_cell.cli import _detected_language

        assert _detected_language(self._args("script.py", "wasm")) == "wasm"
        assert _detected_language(self._args("mod.wasm", "python")) == "python"
        assert _detected_language(self._args("mod.wasm", "javascript")) == "javascript"


class TestRunLanguageCommand:
    """One run entry for all three languages; fail-closed without a guest."""

    def test_python_script_runs_or_fails_closed(self, tmp_path):
        script = tmp_path / "hello.py"
        script.write_text("print('hello-from-guest')\n", encoding="utf-8")
        proc = _run_cli("run", str(script), "--timeout", "60")
        if _guest_installed("python"):
            assert proc.returncode == 0, proc.stdout + proc.stderr
            assert "hello-from-guest" in proc.stdout
        else:
            # environment class: the machine lacks the audited guest, and the
            # error names the one documented install command
            assert proc.returncode == 4
            assert "ephemora-cell[python]" in proc.stderr
            assert "Traceback" not in proc.stderr

    def test_javascript_script_runs_or_fails_closed(self, tmp_path):
        script = tmp_path / "hello.js"
        script.write_text("console.log('hello-from-js')\n", encoding="utf-8")
        proc = _run_cli("run", str(script), "--timeout", "60")
        if _guest_installed("javascript"):
            assert proc.returncode == 0, proc.stdout + proc.stderr
            assert "hello-from-js" in proc.stdout
        else:
            assert proc.returncode == 4
            assert "ephemora-cell[javascript]" in proc.stderr
            assert "Traceback" not in proc.stderr

    def test_language_flag_routes_a_script_without_extension(self, tmp_path):
        script = tmp_path / "hello"  # no .py extension: only --language says it
        script.write_text("print('routed')\n", encoding="utf-8")
        proc = _run_cli("run", str(script), "--language", "python", "--timeout", "60")
        if _guest_installed("python"):
            assert proc.returncode == 0, proc.stdout + proc.stderr
            assert "routed" in proc.stdout
        else:
            assert proc.returncode == 4
            assert "ephemora-cell[python]" in proc.stderr

    def test_javascript_rejects_positional_args_cleanly(self, tmp_path):
        script = tmp_path / "tool.js"
        script.write_text("// no-op\n", encoding="utf-8")
        proc = _run_cli("run", str(script), "extra-arg")
        assert proc.returncode == 2
        assert "not supported for JavaScript" in proc.stderr
        assert "Traceback" not in proc.stderr

    def test_budget_flags_are_accepted_for_language_runs(self, tmp_path):
        script = tmp_path / "hello.py"
        script.write_text("print('ok')\n", encoding="utf-8")
        # Interpreter budgets, not the defaults: booting CPython in WASM burns
        # fuel for its own dispatch loop, so a 1 M-fuel run would legitimately
        # stop before the script printed anything — and asserting success on top
        # of that would make the test depend on the host's guest, not on the
        # flag contract it is here to pin.
        proc = _run_cli(
            "run",
            str(script),
            "--memory-mb",
            "1024",
            "--fuel",
            "1000000000",
            "--timeout",
            "120",
            "--json",
        )
        # The unified surface: the same budget flags parse for every language.
        assert "unrecognized arguments" not in proc.stderr
        assert "usage:" not in proc.stderr
        if _guest_installed("python"):
            assert proc.returncode == 0, proc.stdout + proc.stderr
            payload = json.loads(proc.stdout)
            assert payload["language"] == "python"
            assert payload["script"] == str(script)
            # one report shape on 'run --json': a language run must not speak
            # the enum's str() where the wasm branch says "success"
            assert payload["status"] == "success"
        else:
            assert proc.returncode == 4
            assert "ephemora-cell[python]" in proc.stderr

    def test_language_json_reports_the_documented_status_on_a_refused_run(
        self, tmp_path
    ):
        """A starved budget is a HOST verdict, and it must be named the same way
        the wasm branch names it — with the guest's own words kept separate."""
        script = tmp_path / "poor.py"
        script.write_text("print('ok')\n", encoding="utf-8")
        proc = _run_cli(
            "run", str(script), "--language", "python", "--fuel", "1000", "--json"
        )
        if not _guest_installed("python"):
            pytest.skip("no python guest installed out-of-band")
        assert proc.returncode != 0
        payload = json.loads(proc.stdout)
        assert payload["status"] == "fuel_exhausted"
        assert not str(payload["status"]).startswith("ExecutionStatus")


class TestCliSurface:
    """The help lists the whole product; --version stays pinned."""

    def test_help_lists_every_command(self):
        proc = _run_cli("--help")
        assert proc.returncode == 0
        for command in (
            "run",
            "inspect",
            "benchmark",
            "build",
            "ledger",
            "doctor",
            "verify",
            "policy",
        ):
            assert command in proc.stdout

    def test_version_reports_the_prog_name(self):
        proc = _run_cli("--version")
        assert proc.returncode == 0
        assert proc.stdout.startswith("ephemora-cell ")
