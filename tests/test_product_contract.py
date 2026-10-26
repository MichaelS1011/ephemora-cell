"""The published product contract must stay true to the code.

`product_contract.json` is the single place that says which capability is
`supported`, `experimental`, `unavailable` or `unqualified`, and it is what
`docs/product_contract.md` describes. A contract that drifts is worse than no
contract: it turns "supported" into a word that once appeared in a file. So this
module checks the five ways it can rot:

1. **Version drift** — the contract names a version that neither `pyproject.toml`
   nor the package reports.
2. **Unclassified capability** — an entry without a status, or a non-supported
   entry without a stated reason.
3. **Proof drift** — a `supported` capability whose acceptance test was renamed,
   deleted or now collects nothing.
4. **Gate drift** — a capability proven only where an optional dependency exists
   (the MCP SDK) must name the CI job that installs it, and that job must still
   run the file. Otherwise "supported" would rest on a test nothing executes.
5. **Support drift** — a platform or Python version declared qualified although
   nothing measured it, or a doctor verdict that contradicts the matrix.

The acceptance check runs `pytest --collect-only` on each referenced node prefix
once per file, so it proves the reference is executable rather than trusting the
string. It deliberately does not run the tests themselves: the suite already
runs them, and a contract guard that re-runs everything would be a second CI.
"""

from __future__ import annotations

import json
import platform
import re
import subprocess
import sys
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[1]
STATUSES = {"supported", "experimental", "unavailable", "unqualified"}

#: JSON, not TOML: the package supports Python 3.10, where `tomllib` does not
#: exist, and the project's convention is to avoid a tomli dependency for tests.
CONTRACT = json.loads((ROOT / "product_contract.json").read_text(encoding="utf-8"))

#: file -> collected node ids, filled once per test session.
_collected: dict[str, list[str]] = {}


def _host_key() -> str:
    """The same naming the contract uses: ``darwin-arm64``, ``linux-x86_64``."""
    system = platform.system().lower()
    aliases = {"darwin": "darwin", "linux": "linux", "windows": "windows"}
    return f"{aliases.get(system, system)}-{platform.machine().lower()}"


def _collect(path: str) -> list[str]:
    if path not in _collected:
        proc = subprocess.run(
            [
                sys.executable,
                "-m",
                "pytest",
                path,
                "--collect-only",
                "-q",
                "-p",
                "no:cacheprovider",
            ],
            cwd=ROOT,
            capture_output=True,
            text=True,
        )
        assert (
            proc.returncode == 0
        ), f"{path} does not collect: {proc.stdout[-400:]}{proc.stderr[-400:]}"
        _collected[path] = [
            line.strip() for line in proc.stdout.splitlines() if "::" in line
        ]
    return _collected[path]


def test_the_contract_version_is_the_version_the_package_reports():
    """A contract for 1.2.0rc2 that ships inside 1.2.0 would be silently wrong."""
    import ephemora_cell

    # Regex, not tomllib: Python 3.10 has no tomllib and the project does not
    # take a tomli dependency for tests (same rule as test_policy_agreement.py).
    pyproject = (ROOT / "pyproject.toml").read_text(encoding="utf-8")
    declared = re.search(r'(?m)^version\s*=\s*"([^"]+)"', pyproject)
    assert declared is not None, "pyproject.toml carries no project version"
    assert CONTRACT["schema"] == 1
    assert CONTRACT["version"] == ephemora_cell.__version__
    assert declared.group(1) == ephemora_cell.__version__


def test_every_capability_is_classified_and_carries_its_own_evidence():
    seen: set[str] = set()
    for cap in CONTRACT["capability"]:
        assert cap["id"] not in seen, f"duplicate capability id: {cap['id']}"
        seen.add(cap["id"])
        assert cap["status"] in STATUSES, f"{cap['id']}: {cap['status']}"
        assert cap["surface"], f"{cap['id']}: no surface"
        if cap["status"] == "supported":
            assert cap.get(
                "acceptance"
            ), f"{cap['id']} is supported without an acceptance test"
        else:
            # experimental/unavailable/unqualified each owe the reader a reason;
            # an experimental entry may legitimately have no acceptance test yet,
            # and that absence is exactly what the reason has to state.
            assert cap.get("reason"), f"{cap['id']} must say why it is {cap['status']}"


def _ci_workflow() -> str:
    return (ROOT / ".github" / "workflows" / "ci.yml").read_text(encoding="utf-8")


def _collects_locally(path: str) -> bool:
    """Whether this environment can collect the file at all.

    The MCP E2E needs an optional dependency the default dev extra does not
    install, so its module-level ``importorskip`` skips at collection time. That
    is a fact about the environment, not about the evidence — the gate check
    below is what keeps it honest.
    """
    proc = subprocess.run(
        [
            sys.executable,
            "-m",
            "pytest",
            path,
            "--collect-only",
            "-q",
            "-p",
            "no:cacheprovider",
        ],
        cwd=ROOT,
        capture_output=True,
        text=True,
    )
    return proc.returncode == 0 and any(
        "::" in line for line in proc.stdout.splitlines()
    )


@pytest.mark.parametrize(
    "capability",
    [c for c in CONTRACT["capability"] if c["status"] == "supported"],
    ids=lambda c: c["id"],
)
def test_a_supported_capability_keeps_an_executable_acceptance_test(capability):
    """Every supported capability is executable SOMEWHERE that actually runs.

    Default: the file must collect here, and the node must exist in it.
    CI-gated (``gate``): the named workflow job must exist in ``ci.yml`` and must
    still invoke the file — and when this environment can collect the file, the
    node check applies as well.
    """
    gate = capability.get("gate")
    if gate:
        ci = _ci_workflow()
        assert f"\n  {gate}:" in ci, (
            f"{capability['id']}: the contract names CI job {gate!r}, "
            "which ci.yml does not define"
        )
        for node in capability["acceptance"]:
            path = node.split("::", 1)[0]
            assert (ROOT / path).exists(), f"{capability['id']}: {path} is gone"
            assert (
                path in ci
            ), f"{capability['id']}: {path} exists but job {gate} does not run it"

    for node in capability["acceptance"]:
        path = node.split("::", 1)[0]
        assert (ROOT / path).exists(), f"{capability['id']}: {path} is gone"
        if gate and not _collects_locally(path):
            continue  # the gate check above is the proof for this environment
        collected = _collect(path)
        matched = [
            test
            for test in collected
            if test == node
            or test.startswith(node + "::")
            or test.split("[")[0] == node
        ]
        assert matched, (
            f"{capability['id']}: {node} collects nothing; "
            f"{path} currently holds {len(collected)} tests"
        )


def test_the_platform_matrix_agrees_with_doctor():
    """`supported` must mean doctor says ok — and `unqualified` must not."""
    from ephemora_cell.doctor import _check_platform

    host = _host_key()
    check = _check_platform()
    qualified = CONTRACT["platforms"]["qualified"]
    unqualified = CONTRACT["platforms"]["unqualified"]

    assert qualified, "the contract must name at least one qualified platform"
    assert not set(qualified) & set(unqualified), "a platform cannot be both"

    if host in qualified:
        assert (
            check.status == "ok"
        ), f"{host} is declared qualified but doctor says {check.status}: {check.detail}"
    else:
        assert check.status == "warn", (
            f"{host} is not qualified, so doctor must warn; it said {check.status}: "
            f"{check.detail}"
        )
        assert host in unqualified or host not in qualified


def test_no_python_version_is_qualified_before_it_was_measured():
    """The CI matrix declares versions; only a run qualifies one."""
    python = CONTRACT["python"]
    qualified = set(python["qualified"])
    pending = set(python["pending"])
    exercised = set(python["exercised"])

    assert qualified, "at least one version must carry the measured claim"
    assert not qualified & pending, "a version cannot be qualified and pending"
    assert not qualified & exercised, "an exercised-only venv is not a qualification"
    assert qualified <= {"3.10", "3.11", "3.12", "3.13"}

    current = f"{sys.version_info.major}.{sys.version_info.minor}"
    if current in pending:
        pytest.skip(
            f"this interpreter ({current}) is declared pending; "
            "the contract does not yet claim it"
        )
    assert current in qualified or current in exercised, (
        f"this interpreter ({current}) is neither qualified, pending nor exercised; "
        "state what the contract claims about it"
    )
