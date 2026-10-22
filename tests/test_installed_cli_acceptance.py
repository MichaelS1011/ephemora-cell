"""Acceptance tests for the CLI as a user invokes it — not as a library import.

Every other CLI test in this suite drives `ephemora_cell.cli.main` in-process,
which proves the argument handling but not that the installed console script is
wired, that the JSON on stdout is the documented shape, or that a refused
execution leaves with a non-zero exit status. Those are the three things a user
meets first, so they are measured here through a real subprocess.

The command is taken from PATH when the package is installed (CI installs it);
otherwise the same `main()` is reached through `python -c`, and the mode is part
of every failure message so a reader can tell which wiring was exercised.
"""

from __future__ import annotations

import json
import shutil
import subprocess
import sys
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[1]
HELLO = ROOT / "examples" / "hello.wasm"
FUEL_BOMB = ROOT / "examples" / "fuel_bomb.wasm"


def _prefix() -> tuple[list[str], str]:
    # The environment running this test comes FIRST: a borrowed `ephemora` from
    # PATH may belong to another interpreter, and then the document it prints
    # names an engine this test never installed (the version assertion below
    # would be measuring a foreign venv). In CI the two are the same file.
    sibling = Path(sys.executable).with_name("ephemora")
    if sibling.exists():
        return [str(sibling)], "installed entry point (sibling of the interpreter)"
    exe = shutil.which("ephemora")
    if exe:
        return [exe], "installed entry point (from PATH)"
    return (
        [
            sys.executable,
            "-c",
            "from ephemora_cell.cli import main; raise SystemExit(main())",
        ],
        "python -c fallback (console script not installed)",
    )


PREFIX, MODE = _prefix()


def cli(*args: str, cwd: Path | None = None) -> subprocess.CompletedProcess[str]:
    proc = subprocess.run(
        [*PREFIX, *args],
        cwd=str(cwd or ROOT),
        capture_output=True,
        text=True,
        timeout=180,
    )
    proc.mode = MODE  # type: ignore[attr-defined]
    return proc


def json_stdout(proc: subprocess.CompletedProcess[str]) -> dict:
    assert proc.returncode == 0, (
        f"[{MODE}] rc={proc.returncode}\nstdout={proc.stdout[-800:]}\n"
        f"stderr={proc.stderr[-800:]}"
    )
    try:
        return json.loads(proc.stdout)
    except json.JSONDecodeError as exc:  # pragma: no cover - failure path
        raise AssertionError(
            f"[{MODE}] stdout is not JSON: {exc}\n{proc.stdout[-800:]}"
        ) from exc


def test_run_executes_a_real_module_and_names_the_runtime():
    """The report must name the engine that is actually installed under it.

    Pinning `49.0.3` here would have been the wrong assertion, measured on
    2026-10-20: on a development venv carrying the unpatched 49.0.0 *with* the
    documented escape hatch, the same tree runs guest code and truthfully
    reports `49.0.0` — the run happened, the runtime was named, and only a
    version literal made the leg red. The version claim is the runtime-floor
    check's job (tests/test_doctor.py); this test's job is that the document a
    user reads names the engine it ran on.
    """
    import importlib.metadata as md

    report = json_stdout(cli("run", str(HELLO), "--json"))
    assert report["status"] == "success", report
    assert report["exit_code"] == 0
    assert report["stdout_bytes"] > 0
    baseline = report["security_baseline"]
    assert baseline["wasmtime_version"] == md.version("wasmtime"), (
        f"the report names {baseline['wasmtime_version']!r} but this environment "
        f"carries {md.version('wasmtime')!r}"
    )
    assert baseline["fuel"] > 0
    assert report.get("exit_status_fidelity") in {"exact", "non_zero_only", "none"}


def test_a_refused_run_leaves_non_zero_and_is_never_reported_as_success():
    """A budget stop must be visible in both channels a caller checks."""
    proc = cli("run", str(FUEL_BOMB), "--fuel", "100", "--json")
    assert (
        proc.returncode != 0
    ), f"[{MODE}] a fuel-exhausted run exited 0:\n{proc.stdout[-600:]}"
    report = json.loads(proc.stdout)
    assert report["status"] == "fuel_exhausted", report
    assert report["fuel_consumed"] == report["fuel_budget"] == 100


def test_inspect_reports_the_module_shape():
    info = json_stdout(cli("inspect", str(HELLO), "--json"))
    assert info["raw_size"] > 0
    assert info["wasi_dependent"] is True
    assert any(i["module"].startswith("wasi_") for i in info["imports"])


def test_benchmark_measures_cold_and_warm_runs():
    result = json_stdout(cli("benchmark", str(HELLO), "--n", "2", "--json"))
    for phase in ("cold", "warm"):
        assert result[phase]["n"] >= 1
        assert result[phase]["median"] >= 0
    assert result["fuel"]["mean"] > 0


def test_policy_check_states_the_effective_policy_before_a_run():
    view = json_stdout(cli("policy", "check", "--json"))
    assert view["schema"] == "ephemora-cell/policy-check/1"
    budgets = view["budgets"]
    assert budgets["max_memory_mb"] > 0
    assert budgets["max_fuel"] > 0
    assert budgets["memory64"] is False


def test_doctor_json_is_internally_consistent():
    proc = cli("doctor", "--json", cwd=Path("/tmp"))
    report = json.loads(proc.stdout)
    summary = report["summary"]
    assert summary["fail"] >= 0 and summary["ok"] >= 0
    assert report["ok"] is (summary["fail"] == 0)
    assert proc.returncode == (0 if summary["fail"] == 0 else 1)
    ids = {check.get("id") or check.get("name") for check in report["checks"]}
    for required in ("python", "platform", "runtime-floor", "smoke-run"):
        assert required in ids, f"{required} missing from doctor: {sorted(ids)}"


def test_verify_refuses_a_document_it_cannot_classify(tmp_path):
    """A refusal must be a non-zero exit, not a green report about nothing."""
    target = tmp_path / "not-evidence.json"
    target.write_text('{"hello": 1}', encoding="utf-8")
    proc = cli("verify", str(target), "--json")
    assert proc.returncode != 0, f"[{MODE}] unverifiable evidence exited 0"
    report = json.loads(proc.stdout)
    assert report["verified"] is False
    assert report["kind"] == "unknown"
    assert report["errors"], "a refusal without a stated reason"
    assert report["details"]["key_supplied"] is False


@pytest.mark.parametrize(
    "command",
    [
        "run",
        "inspect",
        "benchmark",
        "build",
        "ledger",
        "doctor",
        "verify",
        "policy",
    ],
)
def test_every_advertised_command_is_reachable_from_the_installed_entry_point(command):
    """All eight commands, not the six the first version of this test listed.

    The inventory is the CLI's own: run, inspect, benchmark, build, ledger,
    doctor, verify, policy. Two of them (`build`, `ledger`) were covered only by
    import-level tests, so a console-script wiring defect for them would not
    have shown up here.
    """
    proc = cli(command, "--help")
    assert (
        proc.returncode == 0
    ), f"[{MODE}] `{command} --help` failed: {proc.stderr[-400:]}"
    assert command in proc.stdout
