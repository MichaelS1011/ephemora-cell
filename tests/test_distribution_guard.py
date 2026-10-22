"""Tests for the distribution guard (scripts/distribution_guard.py).

The guard covers the two surfaces the tree-level public-content guard cannot
see: git HISTORY reachable from a ref, and the built wheel/sdist. These tests
run the detection logic against synthetic artifacts and a synthetic git repo.

The shipped distribution is scanned as CI steps (``Distribution guard`` in the
security job); these tests prove the detectors fire, including the mandatory
negative control: a deliberately planted internal document must fail the guard
in BOTH an artifact and a history.

Secret fixtures are built by concatenation so the literal leak patterns never
appear as one token in this file.
"""

from __future__ import annotations

import base64
import hashlib
import importlib.util
import json
import subprocess
import sys
import tarfile
import zipfile
from pathlib import Path

import pytest

_ROOT = Path(__file__).resolve().parents[1]
_spec = importlib.util.spec_from_file_location(
    "distribution_guard", _ROOT / "scripts" / "distribution_guard.py"
)
assert _spec and _spec.loader
guard = importlib.util.module_from_spec(_spec)
sys.modules["distribution_guard"] = guard
_spec.loader.exec_module(guard)

CONFIG = json.loads((_ROOT / "scripts" / "public_content_guard.json").read_text())

_GHP = "ghp_" + "A1" * 18  # assembled, never a literal token in this file


# --------------------------------------------------------------------------- #
# artifacts mode
# --------------------------------------------------------------------------- #


def _make_wheel(path: Path, members: dict[str, str]) -> None:
    with zipfile.ZipFile(path, "w") as zf:
        for name, text in members.items():
            zf.writestr(name, text)


def _make_sdist(path: Path, root: str, members: dict[str, str]) -> None:
    with tarfile.open(path, "w:gz") as tf:
        for name, text in members.items():
            data = text.encode()
            info = tarfile.TarInfo(f"{root}/{name}")
            info.size = len(data)
            import io

            tf.addfile(info, io.BytesIO(data))


def test_clean_wheel_has_no_findings(tmp_path: Path) -> None:
    whl = tmp_path / "pkg-1.0-py3-none-any.whl"
    _make_wheel(
        whl,
        {"pkg/__init__.py": "VALUE = 1\n", "pkg-1.0.dist-info/METADATA": "Name: pkg\n"},
    )
    findings, _ = guard.scan_artifact(whl, CONFIG, inventory=False)
    assert findings == []


def test_internal_doc_inside_wheel_is_caught(tmp_path: Path) -> None:
    whl = tmp_path / "pkg-1.0-py3-none-any.whl"
    _make_wheel(
        whl, {"pkg/__init__.py": "ok\n", "docs/program/secret.md": "internal\n"}
    )
    findings, _ = guard.scan_artifact(whl, CONFIG, inventory=False)
    assert any(f.rule == "artifact-internal-path" for f in findings)


def test_workplan_at_sdist_root_is_caught_after_stripping(tmp_path: Path) -> None:
    sdist = tmp_path / "pkg-1.0.tar.gz"
    # sdist members carry a top-level dir; forbidden patterns are root-relative.
    _make_sdist(sdist, "pkg-1.0", {"WORKPLAN_2027.md": "planning only\n"})
    findings, _ = guard.scan_artifact(sdist, CONFIG, inventory=False)
    rules = {f.rule for f in findings}
    assert "artifact-internal-path" in rules


def test_credential_body_inside_artifact_is_caught(tmp_path: Path) -> None:
    whl = tmp_path / "pkg-1.0-py3-none-any.whl"
    _make_wheel(whl, {"pkg/leak.py": f'TOKEN = "{_GHP}"\n'})
    findings, _ = guard.scan_artifact(whl, CONFIG, inventory=False)
    assert any(f.rule == "secret-github-token" for f in findings)


def test_personal_path_inside_binary_artifact_member_is_caught(tmp_path: Path) -> None:
    """A binary payload is content too: path-shaped ASCII strings inside it leak."""
    whl = tmp_path / "pkg-1.0-py3-none-any.whl"
    _make_wheel(
        whl,
        {
            "pkg/__init__.py": "ok\n",
            "pkg/guest.wasm": "\x00binary prefix /Users/lab.reference/private/suffix\x00",
        },
    )
    findings, _ = guard.scan_artifact(whl, CONFIG, inventory=False)
    assert any(
        f.rule == "personal-home-path" and f.detail == "lab.reference" for f in findings
    )


def test_distinfo_metadata_body_is_exempt_from_content(tmp_path: Path) -> None:
    whl = tmp_path / "pkg-1.0-py3-none-any.whl"
    # governance word in generated metadata must not false-trip the body scan
    _make_wheel(whl, {"pkg-1.0.dist-info/METADATA": "summary approved by the CTO\n"})
    findings, _ = guard.scan_artifact(whl, CONFIG, inventory=False)
    assert findings == []


# --------------------------------------------------------------------------- #
# history mode
# --------------------------------------------------------------------------- #


def _git(repo: Path, *args: str) -> None:
    subprocess.run(["git", *args], cwd=repo, check=True, capture_output=True, text=True)


@pytest.fixture()
def history_repo(tmp_path: Path) -> Path:
    """Repo where an internal file is committed then deleted from the tree:
    the tree tip is clean, but the blob stays reachable in history."""
    repo = tmp_path / "repo"
    repo.mkdir()
    _git(repo, "init", "-q")
    _git(repo, "config", "user.email", "t@example.invalid")
    _git(repo, "config", "user.name", "Test")
    (repo / "README.md").write_text("clean\n", encoding="utf-8")
    (repo / "docs").mkdir()
    (repo / "docs" / "program").mkdir()
    (repo / "docs" / "program" / "internal.md").write_text(
        "internal plan\n", encoding="utf-8"
    )
    _git(repo, "add", ".")
    _git(repo, "commit", "-q", "-m", "add internal by mistake")
    _git(repo, "rm", "-q", "docs/program/internal.md")
    _git(repo, "commit", "-q", "-m", "remove from tree")
    return repo


def test_history_detects_committed_then_deleted_path(history_repo: Path) -> None:
    findings = guard.scan_history(history_repo, ["HEAD"], CONFIG, content=False)
    assert any(
        f.rule == "history-internal-path" and "docs/program" in f.location
        for f in findings
    )


def test_history_content_detects_removed_secret(tmp_path: Path) -> None:
    repo = tmp_path / "r2"
    repo.mkdir()
    _git(repo, "init", "-q")
    _git(repo, "config", "user.email", "t@example.invalid")
    _git(repo, "config", "user.name", "Test")
    (repo / "config.py").write_text(f'TOKEN = "{_GHP}"\n', encoding="utf-8")
    _git(repo, "add", ".")
    _git(repo, "commit", "-q", "-m", "commit secret")
    (repo / "config.py").write_text('TOKEN = ""\n', encoding="utf-8")
    _git(repo, "add", ".")
    _git(repo, "commit", "-q", "-m", "scrub from tree")
    findings = guard.scan_history(repo, ["HEAD"], CONFIG, content=True)
    assert any(f.rule == "secret-github-token" for f in findings)


def test_history_clean_repo_has_no_findings(tmp_path: Path) -> None:
    repo = tmp_path / "r3"
    repo.mkdir()
    _git(repo, "init", "-q")
    _git(repo, "config", "user.email", "t@example.invalid")
    _git(repo, "config", "user.name", "Test")
    (repo / "README.md").write_text("all good\n", encoding="utf-8")
    _git(repo, "add", ".")
    _git(repo, "commit", "-q", "-m", "init")
    assert guard.scan_history(repo, ["HEAD"], CONFIG, content=True) == []


def _repo_with(tmp_path: Path, name: str, files: dict[str, str]) -> Path:
    repo = tmp_path / name
    repo.mkdir()
    _git(repo, "init", "-q")
    _git(repo, "config", "user.email", "t@example.invalid")
    _git(repo, "config", "user.name", "Test")
    for rel, text in files.items():
        p = repo / rel
        p.parent.mkdir(parents=True, exist_ok=True)
        p.write_text(text, encoding="utf-8")
    _git(repo, "add", ".")
    _git(repo, "commit", "-q", "-m", "init")
    return repo


def test_history_content_ignores_contextual_governance_words(tmp_path: Path) -> None:
    """ADRs/CHANGELOG legitimately carry governance words; the FULL-history blob
    sweep runs only universal secret/home-path rules, so a public doc that says
    'approved by the CTO / follow the PDCA loop' must NOT be flagged.

    The other half of the same contract is asserted too: with ``strict_ids`` the
    contextual rules DO run, because that mode is what a range of commits that
    is new to a push is scanned with. A flag that changed nothing would be a
    silent gate.
    """
    repo = _repo_with(
        tmp_path,
        "pubdoc",
        {"docs/decisions/ADR-001.md": "approved by the CTO, follow the PDCA loop\n"},
    )
    assert guard.scan_history(repo, ["HEAD"], CONFIG, content=True) == []
    strict = guard.scan_history(repo, ["HEAD"], CONFIG, content=True, strict_ids=True)
    assert {f.rule for f in strict} == {"governance-role-ref", "internal-process-ref"}


def test_history_strict_ids_on_a_new_range_flags_only_the_new_commit(
    tmp_path: Path,
) -> None:
    """Pre-push requirement: content-check the COMMITS A PUSH INTRODUCES.

    A base commit carries a clean doc; the new commit adds a work-package id.
    Scanning only ``base..head`` with ``strict_ids`` must name the new blob and
    nothing else — that is what makes the check affordable enough to run in CI,
    where scanning all of history with contextual rules would be noise.
    """
    repo = tmp_path / "range"
    repo.mkdir()
    _git(repo, "init", "-q")
    _git(repo, "config", "user.email", "t@example.invalid")
    _git(repo, "config", "user.name", "Test")
    (repo / "docs").mkdir()
    (repo / "docs" / "a.md").write_text("clean text\n", encoding="utf-8")
    _git(repo, "add", ".")
    _git(repo, "commit", "-q", "-m", "base")
    base = subprocess.run(
        ["git", "rev-parse", "HEAD"], cwd=repo, capture_output=True, text=True
    ).stdout.strip()
    (repo / "docs" / "b.md").write_text(
        "landed under Entscheidung 9 and WP-DEMO-02\n", encoding="utf-8"
    )
    _git(repo, "add", ".")
    _git(repo, "commit", "-q", "-m", "new work")

    default = guard.scan_history(
        repo, [f"{base}..HEAD"], CONFIG, content=True, strict_ids=False
    )
    assert default == [], [f.render() for f in default]
    strict = guard.scan_history(
        repo, [f"{base}..HEAD"], CONFIG, content=True, strict_ids=True
    )
    rules = {f.rule for f in strict}
    assert rules == {"internal-decision-label-ref", "internal-id-ref"}, rules
    assert all("docs/b.md" in f.location for f in strict)


def test_history_strict_ids_without_content_flag_does_no_extra_work(
    tmp_path: Path,
) -> None:
    """``--strict-ids`` narrows WHICH rules run, not whether blobs are read."""
    repo = _repo_with(
        tmp_path,
        "nocontent",
        {"docs/a.md": "landed under Entscheidung 9\n"},
    )
    assert guard.scan_history(repo, ["HEAD"], CONFIG, content=False) == []
    assert (
        guard.scan_history(repo, ["HEAD"], CONFIG, content=False, strict_ids=True) == []
    )


def test_history_content_flags_personal_path(tmp_path: Path) -> None:
    repo = _repo_with(
        tmp_path,
        "homepath",
        {"assets/make.py": "out = /Users" + "/haralan.operator/x\n"},
    )
    findings = guard.scan_history(repo, ["HEAD"], CONFIG, content=True)
    assert any(f.rule == "personal-home-path" for f in findings)


def test_history_content_honours_allow_files(tmp_path: Path) -> None:
    """The guard's own rule/test files embed leak shapes on purpose; content mode
    must skip allow-listed paths instead of self-flagging."""
    repo = _repo_with(
        tmp_path, "allowf", {"scripts/check_public_content.py": f'X = "{_GHP}"\n'}
    )
    # same token in a non-allow-listed path IS flagged
    leaky = _repo_with(tmp_path, "allowf2", {"src/tool.py": f'X = "{_GHP}"\n'})
    assert guard.scan_history(repo, ["HEAD"], CONFIG, content=True) == []
    assert any(
        f.rule == "secret-github-token"
        for f in guard.scan_history(leaky, ["HEAD"], CONFIG, content=True)
    )


# --------------------------------------------------------------------------- #
# NEGATIVE CONTROL (mandatory): a planted internal document must fail the guard
# end to end, in BOTH an artifact and a history, via main() returning 1.
# --------------------------------------------------------------------------- #


def test_negative_control_planted_doc_fails_artifact_guard(
    tmp_path: Path, capsys
) -> None:
    dist = tmp_path / "dist"
    dist.mkdir()
    # A real-looking wheel plus one with a planted internal research doc.
    _make_wheel(dist / "good-1.0-py3-none-any.whl", {"pkg/__init__.py": "ok\n"})
    _make_wheel(
        dist / "bad-1.0-py3-none-any.whl",
        {
            "pkg/__init__.py": "ok\n",
            "docs/program/PLANTED_research.md": "confidential\n",
        },
    )
    rc = guard.main(["artifacts", str(dist / "*.whl")])
    assert rc == 1
    out = capsys.readouterr().out
    assert "artifact-internal-path" in out


def test_negative_control_planted_doc_fails_history_guard(history_repo: Path) -> None:
    rc = guard.main(["--root", str(history_repo), "history", "--ref", "HEAD"])
    assert rc == 1


def test_history_guard_fails_closed_on_an_empty_range(
    history_repo: Path, capsys
) -> None:
    """A refspec that selects no objects must not be mistaken for confirmation."""
    head = subprocess.run(
        ["git", "rev-parse", "HEAD"],
        cwd=history_repo,
        capture_output=True,
        text=True,
        check=True,
    ).stdout.strip()
    rc = guard.main(
        ["--root", str(history_repo), "history", "--ref", f"{head}..{head}"]
    )
    assert rc == 1
    assert "history-empty-scan" in capsys.readouterr().out


def test_clean_shipped_distribution_is_scannable() -> None:
    """The real built wheel/sdist in dist/ (when present) must pass the guard.

    Skipped when the artifacts have not been built in this checkout."""
    artifacts = sorted((_ROOT / "dist").glob("ephemora_cell-*.whl"))
    if not artifacts:
        pytest.skip("dist/ wheel not built in this checkout")
    for whl in artifacts:
        findings, _ = guard.scan_artifact(whl, CONFIG, inventory=False)
        assert findings == [], f"shipped wheel leaked: {findings}"


# --------------------------------------------------------------------------- #
# completeness + integrity of a BUILT artifact (the distribution guard rules)
# --------------------------------------------------------------------------- #

_RC2_WHEEL = "ephemora_cell-1.2.0rc2-py3-none-any.whl"
_EP = "[console_scripts]\nephemora = ephemora_cell.cli:main\nephemora-cell = ephemora_cell.cli:main\nephemora-cell-mcp = ephemora_cell_mcp.__main__:main\n"


def _full_rc2_members() -> dict[str, str]:
    """A wheel that carries exactly what a >=1.2.0rc2 artifact must carry."""
    members = {
        f"ephemora_cell/{m.split('/')[-1]}": "# module\n"
        for m in guard._REQUIRED_MODULES
    }
    members["ephemora_cell_mcp/__main__.py"] = "# mcp\n"
    members["ephemora_cell-1.2.0rc2.dist-info/METADATA"] = (
        "Metadata-Version: 2.1\nName: ephemora-cell\nVersion: 1.2.0rc2\n"
    )
    members["ephemora_cell-1.2.0rc2.dist-info/entry_points.txt"] = _EP
    return members


def _with_record(members: dict[str, str]) -> dict[str, str]:
    """Add a RECORD whose digests match the bytes written below it."""
    rows = []
    for name, text in members.items():
        data = text.encode()
        digest = (
            base64.urlsafe_b64encode(hashlib.sha256(data).digest())
            .rstrip(b"=")
            .decode()
        )
        rows.append(f"{name},sha256={digest},{len(data)}")
    members = dict(members)
    members["ephemora_cell-1.2.0rc2.dist-info/RECORD"] = "\n".join(rows) + "\n"
    return members


def test_complete_rc2_wheel_raises_no_completeness_finding(tmp_path) -> None:
    wheel = tmp_path / _RC2_WHEEL
    _make_wheel(wheel, _with_record(_full_rc2_members()))
    findings, _ = guard.scan_artifact(wheel, CONFIG, inventory=False)
    assert [f.rule for f in findings if f.rule.startswith("artifact-")] == []


def test_missing_cli_module_is_a_completeness_finding(tmp_path) -> None:
    members = _full_rc2_members()
    del members["ephemora_cell/doctor.py"]
    wheel = tmp_path / _RC2_WHEEL
    _make_wheel(wheel, _with_record(members))
    findings, _ = guard.scan_artifact(wheel, CONFIG, inventory=False)
    rules = {f.rule for f in findings}
    assert "artifact-missing-module" in rules
    assert any("doctor.py" in f.detail for f in findings)


def test_missing_console_script_is_a_completeness_finding(tmp_path) -> None:
    members = _full_rc2_members()
    members["ephemora_cell-1.2.0rc2.dist-info/entry_points.txt"] = (
        "[console_scripts]\nephemora-cell = ephemora_cell.cli:main\n"
        "ephemora-cell-mcp = ephemora_cell_mcp.__main__:main\n"
    )
    wheel = tmp_path / _RC2_WHEEL
    _make_wheel(wheel, _with_record(members))
    findings, _ = guard.scan_artifact(wheel, CONFIG, inventory=False)
    assert any(f.rule == "artifact-missing-console-script" for f in findings)


def test_stale_member_content_fails_the_record_digest(tmp_path) -> None:
    """An artifact from an older commit that HAS the members is still not this build."""
    members = _full_rc2_members()
    record = _with_record(members)["ephemora_cell-1.2.0rc2.dist-info/RECORD"]
    members["ephemora_cell-1.2.0rc2.dist-info/RECORD"] = record
    members["ephemora_cell/doctor.py"] = "# silently replaced content\n"
    wheel = tmp_path / _RC2_WHEEL
    _make_wheel(wheel, members)
    findings, _ = guard.scan_artifact(wheel, CONFIG, inventory=False)
    assert any(f.rule == "artifact-record-mismatch" for f in findings), [
        f.rule for f in findings
    ]


def test_wheel_without_record_is_refused_not_ignored(tmp_path) -> None:
    wheel = tmp_path / _RC2_WHEEL
    _make_wheel(wheel, _full_rc2_members())  # no RECORD at all
    findings, _ = guard.scan_artifact(wheel, CONFIG, inventory=False)
    assert any(f.rule == "artifact-record-missing" for f in findings)
