# SPDX-License-Identifier: BUSL-1.1
# Copyright 2026 Michael Soppa
"""Error-class contract and runtime qualification.

Working backwards, what a caller needs from ``ephemora``:

* a failure must be classifiable from the exit code alone, because an agent
  branches on it without reading prose;
* an environment whose engine is not the audited build must not run guest code
  silently (the §1.5 counter-hypothesis: "is an unqualified runtime accepted?");
* a refusal must never read as a success — not in the process status, not in the
  machine-readable document, not through an adapter.

GIVEN/WHEN/THEN is spelled out in each test name. Two of these legs drive the CLI
through ``python -c`` with a prologue that replaces the reported wasmtime version
(49.0.0) or hides the module entirely: that is the real installed-code path, not a
patched-out check, and it needs no back door in the product.

The unqualified-engine legs are the *only* place where 49.0.0 appears here; the
product must refuse on it while CI and the qualified wheelhouse carry the patched
build (requirements.lock pins name and sha256).
"""

from __future__ import annotations

import json
import os
import subprocess
import sys
from pathlib import Path

import pytest

from ephemora_cell.runtime_qualification import QUALIFIED_ENGINE_SHA256

REPO = Path(__file__).resolve().parent.parent
FIXTURES = REPO / "tests" / "fixtures"

#: A refusal must name the qualified reference: the line (49.0.3), or — when
#: the installed binary itself differs — the exact qualified digest.
QUALIFIED_REFERENCE_MARKERS = ("49.0.3", QUALIFIED_ENGINE_SHA256[:12])

#: The documented escape hatch, named once so a refusal leg can clear it.
HATCH = "EPHEMORA_ALLOW_UNQUALIFIED_RUNTIME"


def _engine_is_qualified() -> bool:
    # Use the product gate, not just the version line: on the qualified
    # platform the gate also binds the exact native file, so a 49.0.3 metadata
    # string over a swapped binary is not "qualified" for these legs either.
    from ephemora_cell.runtime_qualification import runtime_qualification

    return runtime_qualification()[0]


#: which machine this suite is running on decides which refusal a call meets
#: FIRST (the gate's `environment` before the call's own `caller`) — legs about
#: precedence state that instead of assuming one environment
QUALIFIED_ENGINE_ACTIVE = _engine_is_qualified()


QUALIFIED_ENGINE = pytest.mark.skipif(
    not _engine_is_qualified(),
    reason="this leg is about the qualified engine not being disturbed; on an "
    "engine outside the line the gate refuses by design (covered by the refusal legs)",
)

#: Reports the unpatched 49.0.0 build while the interpreter still loads the real
#: (qualified) library underneath: the version metadata is the gate's input.
PROLOGUE_UNQUALIFIED = (
    "import importlib.metadata as _m;"
    "_v = _m.version;"
    "_m.version = lambda name: '49.0.0' if name == 'wasmtime' else _v(name);"
    "import sys;"
    "from ephemora_cell.cli import main;"
    "sys.argv = ['ephemora', *sys.argv[1:]];"
    "main()"
)

#: The same falsified metadata, for a caller that uses the public API instead of
#: the CLI — the gate's input, not the caller's discipline, has to decide.
UNQUALIFIED_METADATA = (
    "import importlib.metadata as _m\n"
    "_v = _m.version\n"
    "_m.version = lambda name: '49.0.0' if name == 'wasmtime' else _v(name)\n"
)

#: Simulates the runtime package being absent, which is how a broken or
#: deliberately stripped install reaches a new user first.
PROLOGUE_NO_RUNTIME = (
    "import sys\n"
    "class _Block:\n"
    "    def find_spec(self, name, path=None, target=None):\n"
    "        if name == 'wasmtime' or name.startswith('wasmtime.'):\n"
    "            raise ModuleNotFoundError(\"No module named 'wasmtime'\", "
    "name='wasmtime')\n"
    "        return None\n"
    "sys.meta_path.insert(0, _Block())\n"
    "from ephemora_cell.cli import main\n"
    "sys.argv = ['ephemora', *sys.argv[1:]]\n"
    "main()\n"
)


def _child_env(extra: dict[str, str] | None) -> dict[str, str]:
    """Environment for a child CLI process.

    A refusal leg means refusal whatever the developer's shell exported, so the
    hatch is cleared unless the leg asks for it — the same rule the product follows
    (the hatch is opt-in per invocation, never ambient to a test suite).
    """
    env = dict(os.environ)
    env.pop(HATCH, None)
    if extra:
        env.update(extra)
    return env


def _cli(prologue: str, *args: str, env: dict[str, str] | None = None):
    return subprocess.run(
        [sys.executable, "-c", prologue, *args],
        capture_output=True,
        text=True,
        timeout=300,
        cwd=str(REPO),
        env=_child_env(env),
    )


def _plain(*args: str, env: dict[str, str] | None = None):
    return subprocess.run(
        [sys.executable, "-m", "ephemora_cell.cli", *args],
        capture_output=True,
        text=True,
        timeout=300,
        cwd=str(REPO),
        env=_child_env(env),
    )


def _json_document(stdout: str) -> dict:
    # A language guest may write its own bytes before the document; the report
    # starts at the first "{" and is the only JSON object on stdout.
    return json.loads(stdout[stdout.index("{") :])


class TestTheExitCodeIsAClassification:
    """The exit classes are named, public and mutually exclusive."""

    def test_classes_are_declared_on_the_cli(self):
        from ephemora_cell import cli

        assert (
            cli.EXIT_OK,
            cli.EXIT_EXECUTION,
            cli.EXIT_CALLER,
            cli.EXIT_ATTESTATION,
            cli.EXIT_ENVIRONMENT,
        ) == (0, 1, 2, 3, 4)

    def test_every_documented_class_is_reachable_and_distinct(self):
        from ephemora_cell import cli

        codes = {
            cli.EXIT_OK,
            cli.EXIT_EXECUTION,
            cli.EXIT_CALLER,
            cli.EXIT_ATTESTATION,
            cli.EXIT_ENVIRONMENT,
        }
        assert len(codes) == 5, codes
        assert cli.ERROR_CLASSES[cli.EXIT_ENVIRONMENT] == "environment"

    def test_the_contract_is_published_to_users(self):
        docs = (REPO / "docs" / "cli-errors.md").read_text(encoding="utf-8")
        for marker in ("0", "1", "2", "3", "4", "environment", "attestation"):
            assert marker in docs, marker


class TestAnUnqualifiedEngineIsRefused:
    """B03 / L2: the audited runtime is a precondition, not a badge."""

    def test_run_refuses_the_unpatched_engine(self, tmp_path):
        module = FIXTURES / "hello02.wasm"
        proc = _cli(PROLOGUE_UNQUALIFIED, "run", str(module))
        assert proc.returncode == 4, (proc.returncode, proc.stdout, proc.stderr)
        # an operator must be able to ACT on the refusal: it names the engine it
        # rejected and the line to move to
        assert "unqualified" in proc.stderr.lower(), proc.stderr
        assert "wasmtime" in proc.stderr.lower(), proc.stderr
        assert any(
            marker in proc.stderr for marker in QUALIFIED_REFERENCE_MARKERS
        ), proc.stderr
        assert "Traceback" not in proc.stderr, proc.stderr

    def test_the_document_names_the_class_and_never_a_success(self, tmp_path):
        proc = _cli(
            PROLOGUE_UNQUALIFIED, "run", str(FIXTURES / "hello02.wasm"), "--json"
        )
        assert proc.returncode == 4, (proc.returncode, proc.stderr)
        doc = _json_document(proc.stdout)
        assert doc["status"] == "error", doc
        assert doc["error_class"] == "environment", doc
        # nothing ran, so no exit status of a guest may be attested
        assert doc["exit_status_fidelity"] == "none", doc
        assert "runtime_qualification" in doc, doc

    def test_a_language_run_is_refused_the_same_way(self, tmp_path):
        script = tmp_path / "script.py"
        script.write_text("print(1)\n")
        proc = _cli(
            PROLOGUE_UNQUALIFIED, "run", str(script), "--language", "python", "--json"
        )
        assert proc.returncode == 4, (proc.returncode, proc.stdout, proc.stderr)
        doc = _json_document(proc.stdout)
        assert doc["status"] == "error", doc
        assert doc["error_class"] == "environment", doc

    def test_the_operator_can_opt_out_explicitly_and_it_says_so(self):
        proc = _cli(
            PROLOGUE_UNQUALIFIED,
            "run",
            str(FIXTURES / "hello02.wasm"),
            env={HATCH: "1"},
        )
        assert proc.returncode == 0, (proc.returncode, proc.stderr)
        assert "unqualified" in proc.stderr.lower(), proc.stderr

    def test_the_opt_out_is_recorded_in_the_document(self):
        proc = _cli(
            PROLOGUE_UNQUALIFIED,
            "run",
            str(FIXTURES / "hello02.wasm"),
            "--json",
            env={HATCH: "1"},
        )
        assert proc.returncode == 0, (proc.returncode, proc.stderr)
        doc = _json_document(proc.stdout)
        assert doc["status"] == "success", doc
        assert doc["unqualified_runtime_allowed"] is True, doc

    @QUALIFIED_ENGINE
    def test_the_qualified_engine_is_not_disturbed(self):
        proc = _plain("run", str(FIXTURES / "hello02.wasm"), "--json")
        assert proc.returncode == 0, (proc.returncode, proc.stderr)
        doc = _json_document(proc.stdout)
        assert doc["status"] == "success", doc
        assert doc["error_class"] == "none", doc

    def test_the_public_api_refuses_and_creates_no_sandbox(self):
        """GIVEN an agent that skips the CLI and calls ``ephemora_cell.run_isolated``
        WHEN the engine is unqualified THEN no worker runs the guest and the
        result says so — the facade is not the only door (ADR-015).
        """
        module = FIXTURES / "hello02.wasm"
        source = (
            UNQUALIFIED_METADATA
            + "import json, ephemora_cell as ec\n"
            + f"r = ec.run_isolated({str(module)!r})\n"
            + "print(json.dumps({'status': str(r.status), "
            "'stderr': r.stderr, 'sandbox_dir': r.sandbox_dir}))\n"
        )
        proc = subprocess.run(
            [sys.executable, "-c", source],
            capture_output=True,
            text=True,
            timeout=300,
            cwd=str(REPO),
            env=_child_env(None),
        )
        assert proc.returncode == 0, proc.stderr
        out = json.loads(proc.stdout)
        assert out["status"] == "ExecutionStatus.ERROR", out
        assert out["stderr"].startswith("refused: unqualified runtime"), out
        # a refusal that starts nothing leaves no sandbox behind
        assert out["sandbox_dir"] is None, out

    def test_doctor_surfaces_a_disabled_gate(self):
        """GIVEN the hatch is set WHEN the operator asks for a diagnosis THEN the
        report says the gate is off, whatever the engine's own verdict is."""
        proc = _plain("doctor", "--json", env={HATCH: "1"})
        doc = json.loads(proc.stdout[proc.stdout.index("{") :])
        by_name = {c["name"]: c for c in doc["checks"]}
        detail = by_name["runtime-floor"]["detail"]
        assert "EPHEMORA_ALLOW_UNQUALIFIED_RUNTIME" in detail, detail
        assert "NOT covered" in detail, detail


class TestAMissingRuntimeIsADiagnosisNotACrash:
    """B02 / L1: the first thing a broken install should do is tell the truth."""

    def test_doctor_names_the_missing_runtime_and_exits_one(self):
        proc = _cli(PROLOGUE_NO_RUNTIME, "doctor")
        assert proc.returncode == 1, (proc.returncode, proc.stdout, proc.stderr)
        assert "Traceback" not in proc.stderr, proc.stderr
        assert "runtime-import" in proc.stdout, proc.stdout
        assert "wasmtime is not importable" in proc.stdout, proc.stdout

    def test_doctor_json_stays_schema_valid_without_the_runtime(self):
        proc = _cli(PROLOGUE_NO_RUNTIME, "doctor", "--json")
        assert proc.returncode == 1, proc.stderr
        doc = json.loads(proc.stdout[proc.stdout.index("{") :])
        assert doc["schema"] == "ephemora-cell/doctor/1", doc
        assert doc["summary"]["fail"] >= 1, doc
        by_name = {c["name"]: c for c in doc["checks"]}
        assert by_name["runtime-import"]["status"] == "fail", by_name

    def test_run_reports_the_missing_runtime_instead_of_import_noise(self):
        proc = _cli(PROLOGUE_NO_RUNTIME, "run", str(FIXTURES / "hello02.wasm"))
        assert proc.returncode == 4, (proc.returncode, proc.stdout, proc.stderr)
        assert "Traceback" not in proc.stderr, proc.stderr
        assert "wasmtime" in proc.stderr.lower(), proc.stderr


class TestAGuestThatNeverRanAttestsNothing:
    """Fidelity describes the guest's exit, not the ABI label.

    These legs are about the exit CHANNEL, so they need the run to actually happen
    on whatever engine the developer's venv carries — hence the documented hatch on
    each call. Which engine may run a guest at all is the refusal class' subject
    (:class:`TestAnUnqualifiedEngineIsRefused`), measured without the hatch there.
    """

    def test_a_load_rejected_before_the_guest_reports_none(self):
        proc = _plain(
            "run",
            str(FIXTURES / "hello02.wasm"),
            "--abi",
            "preview1",
            "--json",
            env={HATCH: "1"},
        )
        assert proc.returncode != 0, (proc.returncode, proc.stdout, proc.stderr)
        doc = _json_document(proc.stdout)
        assert doc["status"] == "error", doc
        assert doc["exit_status_fidelity"] == "none", doc

    def test_a_real_guest_exit_still_keeps_its_channel_claim(self):
        # the contrast leg: a component that DOES exit keeps non_zero_only, so the
        # fix above is not a blanket downgrade that hides the real measurement
        proc = _plain(
            "run", str(FIXTURES / "exit3_02.wasm"), "--json", env={HATCH: "1"}
        )
        doc = _json_document(proc.stdout)
        assert (doc["status"], doc["exit_status_fidelity"]) == (
            "error",
            "non_zero_only",
        )

    def test_a_preview1_guest_number_still_arrives_exactly(self, tmp_path):
        wat = (
            b"(module\n"
            b'  (import "wasi_snapshot_preview1" "proc_exit" '
            b"(func $exit (param i32)))\n"
            b'  (memory (export "memory") 1)\n'
            b'  (func (export "_start") i32.const 7 call $exit))\n'
        )
        import wasmtime

        module = tmp_path / "exit7.wasm"
        module.write_bytes(wasmtime.wat2wasm(wat))
        proc = _plain("run", str(module), "--json", env={HATCH: "1"})
        assert proc.returncode == 7, (proc.returncode, proc.stderr)
        doc = _json_document(proc.stdout)
        assert doc["exit_status_fidelity"] == "exact", doc


@pytest.fixture(scope="module")
def keypair(tmp_path_factory):
    """A real Ed25519 pair through the shipped helpers (``tools-signing`` extra).

    A bare checkout without the extra SKIPS these legs; CI installs it, so the
    attestation paths run for real there and are never green-by-skip.
    """
    pytest.importorskip("cryptography")
    from cryptography.hazmat.primitives import serialization
    from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

    from ephemora_cell_mcp import tool_registry

    directory = tmp_path_factory.mktemp("b10keys")
    key = Ed25519PrivateKey.generate()
    private_pem = directory / "host.pem"
    public_pem = directory / "host.pub"
    private_pem.write_bytes(
        key.private_bytes(
            serialization.Encoding.PEM,
            serialization.PrivateFormat.PKCS8,
            serialization.NoEncryption(),
        )
    )
    public_pem.write_bytes(
        key.public_key().public_bytes(
            serialization.Encoding.PEM,
            serialization.PublicFormat.SubjectPublicKeyInfo,
        )
    )
    return (
        tool_registry.ed25519_signer_from_pem(str(private_pem)),
        tool_registry.ed25519_verifier_from_pem(str(public_pem)),
    )


class TestTheFidelityClaimIsInsideTheRecord:
    """What is attested must be separable from what is merely reported.

    ``exit_status_fidelity`` is a HOST statement about a run, so it belongs inside
    the payload the signature covers: an audit record that says ``exit_code: 1``
    without saying whether that number came from the guest can be read as a guest
    verdict later by someone with no way to check. One derivation, used by every
    place the claim appears (CLI document, signed record, MCP ``_meta``).
    """

    @pytest.mark.parametrize(
        "abi,observed,expected",
        [
            ("preview1", True, "exact"),
            ("component", True, "non_zero_only"),
            ("preview1", False, "none"),
            ("component", False, "none"),
            (None, False, "none"),
            (None, True, "exact"),
        ],
    )
    def test_one_derivation_decides_the_claim(self, abi, observed, expected):
        from ephemora_cell.execution_report import exit_status_fidelity

        assert exit_status_fidelity(abi=abi, guest_exit_observed=observed) == expected

    def test_a_signed_record_carries_the_claim(self, keypair):
        from ephemora_cell import ExecutionReport
        from ephemora_cell.execution_report import exit_status_fidelity

        signer, verifier = keypair
        report = ExecutionReport(
            status="error",
            exit_code=1,
            elapsed_ms=3.0,
            exit_status_fidelity=exit_status_fidelity(
                abi="component", guest_exit_observed=True
            ),
        )
        signed = report.sign(signer, alg="EdDSA")
        assert signed["exit_status_fidelity"] == "non_zero_only", signed
        assert ExecutionReport.verify(signed, verifier) is True

    def test_rewriting_the_word_in_a_signed_record_is_caught(self, keypair):
        from ephemora_cell import ExecutionReport

        signer, verifier = keypair
        signed = ExecutionReport(
            status="success", exit_code=0, elapsed_ms=1.0, exit_status_fidelity="none"
        ).sign(signer, alg="EdDSA")
        # the falsification: a report that quietly upgrades its own caveat
        signed["exit_status_fidelity"] = "exact"
        assert ExecutionReport.verify(signed, verifier) is False

    def test_a_report_that_never_sets_the_claim_keeps_its_old_bytes(self):
        """Compatibility: the key is absent, not null — the record a caller built
        before this field exists serializes exactly as it did."""
        from ephemora_cell import ExecutionReport

        payload = ExecutionReport(
            status="success", exit_code=0, elapsed_ms=1.0
        ).to_dict()
        assert "exit_status_fidelity" not in payload, sorted(payload)

    def test_the_agent_meta_reports_the_same_fact(self):
        """Field parity: an agent reading MCP ``_meta`` gets the identical
        claim, derived identically — not a field only the CLI knows."""
        from ephemora_cell import WASIConfig
        from ephemora_cell.execution_report import ExecutionReport
        from ephemora_cell.wasi_runtime import ExecutionResult, ExecutionStatus
        from ephemora_cell_mcp.engine import build_report

        result = ExecutionResult(
            status=ExecutionStatus.ERROR,
            exit_code=1,
            abi="component",
            guest_exit_observed=True,
        )
        report = build_report(result, WASIConfig())
        assert isinstance(report, ExecutionReport)
        assert report.to_dict()["exit_status_fidelity"] == "non_zero_only", report

        refused = ExecutionResult(status=ExecutionStatus.ERROR, exit_code=1)
        assert (
            build_report(refused, WASIConfig()).to_dict()["exit_status_fidelity"]
            == "none"
        )


class TestTheQualificationDecisionItself:
    """The rule the gate applies, tested as a decision and not as a string."""

    @pytest.mark.parametrize(
        "version,qualified",
        [
            ("49.0.3.post2+git.1d21c90f", True),
            ("49.0.3", True),
            ("49.1.0", True),
            ("49.0.0", False),
            ("49.0.2", False),
            ("50.0.0", False),
            ("48.0.1", False),
            ("unknown", False),
            ("", False),
        ],
    )
    def test_the_controlled_line_decides(self, version, qualified):
        from ephemora_cell.doctor import runtime_line_ok

        assert runtime_line_ok(version) is qualified, version

    def test_the_decision_never_raises_for_the_running_environment(self):
        from ephemora_cell.doctor import runtime_qualification

        ok, reason = runtime_qualification()
        assert isinstance(ok, bool)
        assert isinstance(reason, str) and reason, reason


class TestTheNewAttestationsCanBeFalsified:
    """A control that cannot be shown to fail is a slogan.

    Two things changed in this slice: the env surface moved INSIDE the signed
    baseline, and a tenant book/cap without an account now refuses before any
    sandbox exists. Each gets the negative test — tamper it, or prove nothing was
    created — not just the positive one.
    """

    def test_the_env_surface_is_inside_the_signed_record(self, keypair):
        from ephemora_cell import ExecutionReport, WASIConfig

        signer, verifier = keypair
        report = ExecutionReport(status="success", exit_code=0, elapsed_ms=1.0)
        report.apply_config(
            WASIConfig(
                allow_env=(("DEPLOY_TOKEN", "s3cr3t-value"), ("RUST_LOG", "info"))
            )
        )
        signed = report.sign(signer, alg="EdDSA")
        assert signed["security_baseline"]["allow_env_names"] == [
            "DEPLOY_TOKEN",
            "RUST_LOG",
        ], signed["security_baseline"]
        assert ExecutionReport.verify(signed, verifier) is True

    def test_the_values_stay_out_of_what_is_signed(self, keypair):
        """Names are policy, values are secrets: the signature must not carry one."""
        from ephemora_cell import ExecutionReport, WASIConfig

        signer, verifier = keypair
        report = ExecutionReport(status="success", exit_code=0, elapsed_ms=1.0)
        report.apply_config(WASIConfig(allow_env=(("DEPLOY_TOKEN", "s3cr3t-value"),)))
        signed = report.sign(signer, alg="EdDSA")
        payload = json.dumps(signed, sort_keys=True)
        assert "s3cr3t-value" not in payload
        assert "DEPLOY_TOKEN" in payload
        # excluding the value is not a signature bug: the record still verifies
        assert ExecutionReport.verify(signed, verifier) is True

    def test_adding_an_environment_variable_to_a_signed_record_is_caught(self, keypair):
        from ephemora_cell import ExecutionReport, WASIConfig

        signer, verifier = keypair
        signed = ExecutionReport(
            status="success", exit_code=0, elapsed_ms=1.0
        ).apply_config(WASIConfig(allow_env=(("RUST_LOG", "info"),)))
        signed = signed.sign(signer, alg="EdDSA")
        # the falsification: a record whose grant list grew after signing
        signed["security_baseline"]["allow_env_names"].append("AWS_SECRET_ACCESS_KEY")
        assert ExecutionReport.verify(signed, verifier) is False

    def test_dropping_the_env_surface_from_a_signed_record_is_caught(self, keypair):
        """Absence must not read as "no environment was granted"."""
        from ephemora_cell import ExecutionReport, WASIConfig

        signer, verifier = keypair
        signed = (
            ExecutionReport(status="success", exit_code=0, elapsed_ms=1.0)
            .apply_config(WASIConfig())
            .sign(signer, alg="EdDSA")
        )
        assert signed["security_baseline"]["allow_env_names"] == []
        del signed["security_baseline"]["allow_env_names"]
        assert ExecutionReport.verify(signed, verifier) is False

    def test_a_refused_tenant_call_creates_no_book(self, tmp_path):
        """The refusal is decided before the store exists: no file, no record.

        Which class refuses depends on the machine: on an engine outside the
        qualified line the runtime gate answers first (environment, `4`) — the
        call's own defect is real but nothing runs to find out more. Both are
        refusals, and both leave the book unwritten.
        """
        book = tmp_path / "book.jsonl"
        proc = _plain(
            "run",
            str(FIXTURES / "hello02.wasm"),
            "--tenant-book",
            str(book),
        )
        expected = 2 if QUALIFIED_ENGINE_ACTIVE else 4
        assert proc.returncode == expected, (proc.stdout, proc.stderr)
        assert not book.exists(), "a refused call still wrote the accounting book"

    def test_a_refused_tenant_call_reports_the_class_in_json(self, tmp_path):
        book = tmp_path / "book.jsonl"
        proc = _plain(
            "run",
            str(FIXTURES / "hello02.wasm"),
            "--json",
            "--tenant-max-runs",
            "5",
        )
        expected = 2 if QUALIFIED_ENGINE_ACTIVE else 4
        assert proc.returncode == expected, (proc.stdout, proc.stderr)
        assert not book.exists()
        if expected == 2:
            # no report to classify: the caller error is named on stderr, not in a
            # document that would imply a run happened
            assert "refusing instead of ignoring" in proc.stderr
            assert '"status"' not in proc.stdout
        else:
            # the gate's own refusal is a document, and it says nothing ran
            assert _json_document(proc.stdout)["error_class"] == "environment"


class TestTheGateDecidesBeforeTheCallIsJudged:
    """Precedence is part of the contract, on every route.

    Two refusals can be true of one command at once: the engine is outside the
    qualified line, and the arguments could not have been honoured either. The
    operator has to be sent to the machine first — fixing the flags would still
    leave a run on an unpatched engine — so the same order must hold for a module
    run and for a language run, not just for whichever one was written first.
    """

    def test_a_module_run_answers_the_environment_class_first(self, tmp_path):
        script = tmp_path / "s.py"
        script.write_text("print(1)\n")
        proc = _cli(
            PROLOGUE_UNQUALIFIED,
            "run",
            str(FIXTURES / "hello02.wasm"),
            "--json",
            "--tenant-book",
            str(tmp_path / "book.jsonl"),
        )
        assert proc.returncode == 4, (proc.stdout, proc.stderr)
        assert _json_document(proc.stdout)["error_class"] == "environment"

    def test_the_language_route_applies_the_same_precedence(self, tmp_path):
        script = tmp_path / "s.py"
        script.write_text("print(1)\n")
        # `--tenant` is a flag this route refuses outright, so both refusals are
        # true at once; the engine has to win
        proc = _cli(
            PROLOGUE_UNQUALIFIED,
            "run",
            str(script),
            "--language",
            "python",
            "--json",
            "--tenant",
            "acme",
        )
        assert proc.returncode == 4, (proc.stdout, proc.stderr)
        doc = _json_document(proc.stdout)
        assert doc["error_class"] == "environment", doc
        # the reason is its own field, so a consumer never parses prose to learn
        # which engine was rejected; it names the line or the exact digest
        assert any(
            marker in doc["runtime_qualification"]
            for marker in QUALIFIED_REFERENCE_MARKERS
        ), doc

    def test_the_caller_class_still_wins_when_the_engine_is_qualified(self, tmp_path):
        script = tmp_path / "s.py"
        script.write_text("print(1)\n")
        proc = _plain(
            "run",
            str(script),
            "--language",
            "python",
            "--json",
            "--tenant",
            "acme",
        )
        # on the audited engine the flag refusal is reached and answers `caller`
        # (2); off it, the engine answers first (4). Both are refusals, neither is 0.
        assert proc.returncode in (2, 4), (proc.stdout, proc.stderr)
        assert proc.returncode != 0


class TestTheLowLevelPrimitiveIsNotABackDoor:
    """A published primitive must not be a route around the runtime line.

    `ComponentSandbox` is documented as the low-level in-process primitive, and it
    is reachable from the package surface — so the engine decision belongs there
    too. Process isolation remains the facade's business; running a guest on an
    unqualified engine is nobody's.
    """

    PROLOGUE = (
        UNQUALIFIED_METADATA + "from ephemora_cell.wasi_02 import ComponentSandbox\n"
        "from ephemora_cell import WASIConfig\n"
        "sandbox = ComponentSandbox(config=WASIConfig())\n"
        "result = sandbox.run('tests/fixtures/hello02.wasm')\n"
        "print('STATUS', result.status.value)\n"
        "print('STDERR', result.stderr[:60])\n"
        "print('FUEL', result.fuel_consumed)\n"
    )

    def test_the_primitive_refuses_before_reading_the_module(self):
        proc = _cli(self.PROLOGUE)
        assert proc.returncode == 0, proc.stderr
        assert "STATUS error" in proc.stdout, proc.stdout
        assert "refused: unqualified runtime" in proc.stdout, proc.stdout

    @QUALIFIED_ENGINE
    def test_the_primitive_still_runs_on_the_audited_engine(self):
        plain = subprocess.run(
            [sys.executable, "-c", self.PROLOGUE.replace(UNQUALIFIED_METADATA, "")],
            capture_output=True,
            text=True,
            timeout=300,
            cwd=str(REPO),
            env=_child_env(None),
        )
        assert "STATUS success" in plain.stdout, (plain.stdout, plain.stderr)


class TestTheEscapeHatchTravelsWithTheRecord:
    """The most consequential operator option must be visible on every surface.

    The hatch lets guest code run on an engine the release does not qualify. The
    CLI stamped it; an agent reading MCP ``_meta`` did not see it, and a signed
    record dropped it. The field now lives on the record itself, so the stamp
    survives signing and reaches ``tools/call`` the same way it reaches a terminal.
    """

    def test_mcp_meta_carries_the_stamp_when_the_hatch_is_open(self, monkeypatch):
        from ephemora_cell import WASIConfig
        from ephemora_cell.wasi_runtime import ExecutionResult, ExecutionStatus
        from ephemora_cell_mcp.engine import build_report

        monkeypatch.setenv("EPHEMORA_ALLOW_UNQUALIFIED_RUNTIME", "1")
        report = build_report(
            ExecutionResult(status=ExecutionStatus.SUCCESS, exit_code=0),
            WASIConfig(),
        )
        assert (
            report.to_dict().get("unqualified_runtime_allowed") is True
        ), report.to_dict()

    def test_an_ordinary_record_does_not_carry_the_key(self, monkeypatch):
        """Byte-compatibility: absence is the normal case, not `false`."""
        from ephemora_cell import WASIConfig
        from ephemora_cell.wasi_runtime import ExecutionResult, ExecutionStatus
        from ephemora_cell_mcp.engine import build_report

        monkeypatch.delenv("EPHEMORA_ALLOW_UNQUALIFIED_RUNTIME", raising=False)
        payload = build_report(
            ExecutionResult(status=ExecutionStatus.SUCCESS, exit_code=0),
            WASIConfig(),
        ).to_dict()
        assert "unqualified_runtime_allowed" not in payload, payload


class TestADiscardedGrantIsNamedWhereTheCallerReads:
    """The no-flag-that-lies rule applies to a tool sidecar too.

    A host-signed manifest can only narrow a profile's grants — measured on the
    release build, a sidecar asking for `/etc` runs with `preopens=["/sandbox"]`.
    The refusal itself was right; the silence was not. The drop now shows up in
    the record's own `warnings`, which is what `tools/call` hands back.
    """

    class _StubSandbox:
        def __init__(self, *args, **kwargs):
            pass

        def run(self, path, **kwargs):
            from ephemora_cell.wasi_runtime import ExecutionResult, ExecutionStatus

            return ExecutionResult(status=ExecutionStatus.SUCCESS, exit_code=0)

        def cleanup(self):
            pass

    def _execute_with_wide_sidecar(self, monkeypatch, tmp_path):
        from ephemora_cell_mcp import engine as engine_mod
        from ephemora_cell_mcp.tool_registry import ToolSpec

        monkeypatch.setattr(engine_mod, "WASISandbox", self._StubSandbox)
        wasm = tmp_path / "tool.wasm"
        wasm.write_bytes(b"\x00asm\x0d\x00\x01\x00")
        spec = ToolSpec(
            name="wide",
            wasm_path=str(wasm),
            description="",
            profile="llm",
            allow_dirs=("/etc",),
        )
        return engine_mod.CellToolEngine().execute(spec, {})

    def test_the_run_warns_about_the_grant_it_did_not_get(self, monkeypatch, tmp_path):
        outcome = self._execute_with_wide_sidecar(monkeypatch, tmp_path)
        warnings = outcome.report.to_dict()["warnings"]
        assert any("/etc" in w for w in warnings), warnings
        assert any("intersection" in w for w in warnings), warnings

    def test_a_sidecar_that_as_for_nothing_warns_nothing(self, monkeypatch, tmp_path):
        from ephemora_cell_mcp import engine as engine_mod
        from ephemora_cell_mcp.tool_registry import ToolSpec

        monkeypatch.setattr(engine_mod, "WASISandbox", self._StubSandbox)
        wasm = tmp_path / "quiet.wasm"
        wasm.write_bytes(b"\x00asm\x0d\x00\x01\x00")
        outcome = engine_mod.CellToolEngine().execute(
            ToolSpec(name="quiet", wasm_path=str(wasm), description="", profile="llm"),
            {},
        )
        assert outcome.report.to_dict()["warnings"] == []
