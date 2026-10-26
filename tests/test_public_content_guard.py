"""Tests for the public-content guard (scripts/check_public_content.py).

The guard protects the separation between the public product surface and
internal governance / private environment detail. These tests exercise the
detection logic against synthetic files — the shipped tree itself is scanned
as a CI step (`Public-content guard` in the security job).

Secret fixtures are built by concatenation so the literal leak patterns never
appear as a single token in this file: the guard stays green on the tests even
if the allowlist for this file were removed.
"""

from __future__ import annotations

import importlib.util
import json
import os
import re
import subprocess
import sys
from pathlib import Path

import pytest

_ROOT = Path(__file__).resolve().parents[1]
_spec = importlib.util.spec_from_file_location(
    "check_public_content", _ROOT / "scripts" / "check_public_content.py"
)
assert _spec and _spec.loader
guard = importlib.util.module_from_spec(_spec)
# Register before exec_module: the guard's @dataclass resolves its (deferred)
# annotations via sys.modules[cls.__module__], which importlib does not populate
# on its own.
sys.modules["check_public_content"] = guard
_spec.loader.exec_module(guard)

CONFIG = json.loads((_ROOT / "scripts" / "public_content_guard.json").read_text())


def _scan(tmp_path: Path, files: dict[str, str]) -> list[guard.Finding]:
    for rel, text in files.items():
        p = tmp_path / rel
        p.parent.mkdir(parents=True, exist_ok=True)
        p.write_text(text, encoding="utf-8")
    return guard.scan_tree(tmp_path, list(files), CONFIG)


def test_shipped_rules_compile() -> None:
    for rule in CONFIG["content_rules"]:
        re.compile(rule["regex"])
    for pattern in CONFIG["forbidden_tracked_paths"] + CONFIG["allow_files"]:
        re.compile(pattern)


def test_detects_personal_home_path(tmp_path: Path) -> None:
    findings = _scan(
        tmp_path, {"docs/a.md": "run it under /Users/harlan.operator/cache now\n"}
    )
    assert [f.rule for f in findings] == ["personal-home-path"]


def test_benign_system_users_are_not_flagged(tmp_path: Path) -> None:
    findings = _scan(
        tmp_path,
        {
            "evidence.json": (
                "panicked at /Users/runner/.rustup/toolchains:\n"
                "loaded from /home/username/app/main.py\n"
            )
        },
    )
    assert findings == []


def test_the_generic_service_account_name_is_not_pretrusted(
    tmp_path: Path,
) -> None:
    """``operator`` reads like a CI service account, and a real reference host
    ran under exactly that name.

    Pre-allowlisting it silenced that host's build paths in committed evidence.
    The tightening is asserted against the configuration itself rather than by
    publishing a plausible path under that account: a name that generic cannot
    be treated as structurally benign.
    """
    rule = next(r for r in CONFIG["content_rules"] if r["id"] == "personal-home-path")
    assert "operator" not in rule["benign_users"], rule["benign_users"]
    # and an account name outside the benign list is still reported
    findings = _scan(tmp_path, {"evidence.txt": "binds /home/lab.reference/x\n"})
    assert [f.rule for f in findings] == ["personal-home-path"]


def test_detects_credential_shapes(tmp_path: Path) -> None:
    pem = "-----BEGIN " + "RSA PRIVATE KEY-----"
    token = "ghp_" + "A1" * 18
    findings = _scan(
        tmp_path,
        {"config.sh": f"export K={pem}\nexport T={token}\n"},
    )
    rules = {f.rule for f in findings}
    assert "secret-private-key" in rules
    assert "secret-github-token" in rules


def test_detects_governance_references(tmp_path: Path) -> None:
    findings = _scan(
        tmp_path,
        {
            "README.md": (
                "approved by the CTO in the plan\n"
                "package WP-AA-01 shipped\n"
                "follow the PDCA loop\n"
            )
        },
    )
    rules = {f.rule for f in findings}
    assert {"governance-role-ref", "internal-id-ref", "internal-process-ref"} <= rules


def test_detects_management_wording_families(tmp_path: Path) -> None:
    findings = _scan(
        tmp_path,
        {
            "docs/x.md": (
                "granted by decision D7 on 2026-09-12\n"
                "shipped as a separate work package\n"
                "fixed after audit F3 in a regression test\n"
                "lands with the M2 engine upgrade\n"
                "tracked as defect P1 #12 and OODA-4\n"
            )
        },
    )
    assert len(findings) == 5  # one finding per rule and line
    assert {f.rule for f in findings} == {"internal-process-ref", "internal-id-ref"}


def test_detects_the_identifier_shapes_found_by_the_release_sweep(
    tmp_path: Path,
) -> None:
    """Every marker class the 1.2.0 pre-push sweep actually found, as samples.

    The rules covering this family were written for the hyphenated form
    (``WP-AA-01``) and missed the shapes the tree really carried: ``WP99``,
    ``WP97-WP98``, ``WP-DEMO-02`` and the lower-case file-name form
    ``wp99_freeze_evidence.json``. Each line below is a shape taken from the
    tree before it was scrubbed, so a rule that only matches the old form fails
    here instead of passing on a toy example.
    """
    findings = _scan(
        tmp_path,
        {
            "docs/y.md": (
                "see WP99 and WP97-WP98 for the rule\n"
                "added by WP-DEMO-02 during the pass\n"
                "evidence in wp99_freeze_evidence.json\n"
                "recorded under the 1.2.0 mandate Entscheidung 9\n"
                "measured in gate9z/sim and rerun at gate8y\n"
                "classified under MS99 and the MP99 finding\n"
                "closed as P0-QQ1-01 after Blocker #3\n"
                "integrity of the record (WP99/Q9) is unchanged\n"
            )
        },
    )
    rules = {f.rule for f in findings}
    assert {
        "internal-id-ref",
        "internal-decision-label-ref",
        "internal-gate-ref",
        "internal-milestone-ref",
        "internal-finding-ref",
        "internal-review-round-ref",
    } <= rules, rules


def test_detects_the_environment_labels_found_in_pre_release_evidence(
    tmp_path: Path,
) -> None:
    """The second sanitisation pass found a family the identifier rules miss.

    Raw capture files carried the *environment* names of the machine they were
    taken on: an internal work-branch value, a lab host name, a build-tree
    directory named after a gate number, an image tag naming that gate and a
    container named after a milestone. None of those shapes matched an existing
    rule, so the tree scanned clean around them.
    """
    findings = _scan(
        tmp_path,
        {
            "benchmarks/results/evidence.json": (
                '  "branch": "wp-aa99-topic-branch",\n'
                '  "host": "some-lab-host",\n'
                '  "bind": "/home/uid/build-ref-99gate/x.py",\n'
                '  "image": "product-ref:9.9.9-gate.abc123",\n'
                '  "names": "cell-mp99",\n'
            )
        },
    )
    rules = {f.rule for f in findings}
    assert {
        "internal-branch-ref",
        "internal-build-label-ref",
        "internal-artifact-label-ref",
    } <= rules, rules


def test_detects_internal_workstream_labels(tmp_path: Path) -> None:
    """Two test module docstrings opened with the internal work-stream label.

    ``Arbeitsstrang B (2026-10-15)`` names a private planning item; nothing in
    the rule set matched the word, so the tree scanned clean around it.
    """
    findings = _scan(
        tmp_path,
        {"docs/z.md": "Arbeitsstrang B (2026-10-15): the adapter detects ABI\n"},
    )
    assert [f.rule for f in findings] == ["internal-workstream-ref"], findings


def test_quarter_labels_are_not_research_question_refs(tmp_path: Path) -> None:
    """``/Q9`` is a research-question ref; ``Q3/2027`` is a roadmap quarter.

    A pattern that flagged the SECURITY.md review date would be a false
    positive the next release would either silence with an allow marker or learn
    to ignore, so the distinction is pinned instead.
    """
    findings = _scan(tmp_path, {"SECURITY.md": "Next LTS review: **Q3/2027**\n"})
    assert findings == []


def test_every_configured_rule_can_fire() -> None:
    """Non-vacuity: no content rule ships that nothing could ever match.

    A rule with no positive fixture is indistinguishable from a dead rule, and
    this guard's own contract is that absence is an error rather than a pass.
    The fixture lines below are the same shapes the two detection tests use,
    matched against the SHIPPED configuration.
    """
    fixture_lines = [
        "run it under /Users/harlan.operator/cache now",
        "host at build-node.ts.net",
        "-----BEGIN RSA PRIVATE KEY-----",
        "export T=ghp_" + "A1" * 18,
        "xoxb-" + "1234567890-1234567890",
        "AKIA" + "0A1B2C3D4E5F6G7H",
        "approved by the CTO in the plan",
        "granted by decision D7 on 2026-09-12",
        "shipped as a separate work package",
        "fixed after audit F3 in a regression test",
        "lands with the M2 engine upgrade",
        "tracked as defect P1 #12 and OODA-4",
        "follow the PDCA loop",
        "see WP99 and WP97-WP98 for the rule",
        "added by WP-DEMO-02 during the pass",
        "evidence in wp99_freeze_evidence.json",
        "recorded under the 1.2.0 mandate Entscheidung 9",
        "measured in gate9z/sim and rerun at gate8y",
        "classified under MS99 and the MP99 finding",
        "closed as P0-QQ1-01 after Blocker #3",
        "integrity of the record (WP99/Q9) is unchanged",
        '  "branch": "wp-aa99-topic-branch",',
        "host some-lab-host uptime 12d",
        "bind /home/uid/build-ref-99gate/x.py",
        "image product-ref:9.9.9-gate.abc123",
        "names=cell-mp99",
        "Arbeitsstrang C (2026-10-15): the adapter detects the ABI",
    ]
    firing: set[str] = set()
    for line in fixture_lines:
        for rule in CONFIG["content_rules"]:
            if re.search(rule["regex"], line):
                firing.add(rule["id"])
    shipped = {rule["id"] for rule in CONFIG["content_rules"]}
    assert (
        shipped - firing == set()
    ), f"rules with no fixture that can fire: {sorted(shipped - firing)}"


#: Work-item identifier shapes in the families this release actually scrubbed.
#: The guard's own implementation and tests are exempt from scanning (its rule
#: regexes would self-match), so that exemption is exactly where a real internal
#: identifier could hide unseen. It is bounded instead of blanket: an identifier
#: fixture in one of those files must be demonstrably synthetic - a placeholder
#: word group, or a number inside the reserved 90+ demonstration range.
_SYNTHETIC_FLOOR = 90
_SYNTHETIC_WORDS = frozenset({"DEMO", "AA", "XX", "QQ", "NN", "LAB", "SYNTH"})
_ITEM_NUMBER = re.compile(r"\b(?:WP|MP|MS|wp|mp|ms)[-_]?(\d{1,3})\b")
_ITEM_WORD = re.compile(r"\bWP-([A-Z]{2,})-\d+\b")
_FINDING_CODE = re.compile(r"\bP\d-([A-Z]{2,})\d*-\d+\b")


def _guard_own_files() -> list[str]:
    """The files ``allow_files`` can legitimately point at: the guard itself, its
    tests and the ignore files that name its private working paths. A new exempt
    path outside these directories is a design change, not an oversight."""
    candidates = [
        *sorted((_ROOT / "scripts").glob("*.py")),
        *sorted((_ROOT / "scripts").glob("*.json")),
        *sorted((_ROOT / "tests").glob("test_*.py")),
        *[_ROOT / ".gitignore", _ROOT / ".dockerignore"],
    ]
    exempt = [re.compile(pattern) for pattern in CONFIG["allow_files"]]
    out = []
    for path in candidates:
        if not path.is_file():
            continue
        rel = str(path.relative_to(_ROOT)).replace(os.sep, "/")
        if any(pattern.search(rel) for pattern in exempt):
            out.append(rel)
    return out


def test_guard_exempt_files_carry_only_synthetic_identifiers() -> None:
    """The self-exemption is bounded, so it cannot become a hiding place."""
    own = _guard_own_files()
    assert {
        "scripts/public_content_guard.json",
        "tests/test_public_content_guard.py",
    } <= {p for p in own}, own
    offenders: list[str] = []
    for rel in own:
        text = (_ROOT / rel).read_text(encoding="utf-8", errors="replace")
        for lineno, line in enumerate(text.splitlines(), start=1):
            for match in _ITEM_NUMBER.finditer(line):
                if int(match.group(1)) < _SYNTHETIC_FLOOR:
                    offenders.append(f"{rel}:{lineno} {match.group(0)}")
            for match in _ITEM_WORD.finditer(line):
                if match.group(1) not in _SYNTHETIC_WORDS:
                    offenders.append(f"{rel}:{lineno} {match.group(0)}")
            for match in _FINDING_CODE.finditer(line):
                if match.group(1) not in _SYNTHETIC_WORDS:
                    offenders.append(f"{rel}:{lineno} {match.group(0)}")
    assert (
        offenders == []
    ), f"non-synthetic work-item ids in guard-owned files: {offenders}"


def test_allow_marker_suppresses_line(tmp_path: Path) -> None:
    marker = CONFIG["allow_marker"]
    findings = _scan(
        tmp_path,
        {
            "tool.py": (
                f"# deliberate fixture, reviewed /Users/anita.dev/tools {marker}\n"
                "# unreviewed /Users/anita.dev/tools\n"
            )
        },
    )
    assert len(findings) == 1


def test_forbidden_internal_paths_are_flagged(tmp_path: Path) -> None:
    findings = _scan(
        tmp_path,
        {
            "social/post.md": "public-safe text\n",
            "WORKPLAN_2026.md": "public-safe text\n",
        },
    )
    assert {f.path for f in findings} == {"social/post.md", "WORKPLAN_2026.md"}
    assert all(f.rule == "tracked-internal-path" for f in findings)


def test_allowlisted_guard_files_are_exempt_from_content_scan(tmp_path: Path) -> None:
    findings = _scan(
        tmp_path,
        {
            "scripts/check_public_content.py": "the CTO pattern lives here on purpose\n",
            "docs/other.md": "the CTO pattern lives here too\n",
        },
    )
    paths = {f.path for f in findings if f.rule == "governance-role-ref"}
    assert paths == {"docs/other.md"}


def test_overlay_findings_never_carry_snippets(tmp_path: Path) -> None:
    private_word = "sensitive-partner-name"
    (tmp_path / "leak.md").write_text(
        f"talked to {private_word} today\n", encoding="utf-8"
    )
    findings = guard._scan_overlay(
        ["leak.md"],
        tmp_path,
        [{"id": "private-contact", "regex": private_word}],
    )
    assert len(findings) == 1
    assert findings[0].rule == "private-contact"
    assert private_word not in findings[0].render()


# ---------------------------------------------------------------------------
# --include-untracked: the window a plain `git add -A` would open
# ---------------------------------------------------------------------------


def _git(repo: Path, *args: str) -> None:
    subprocess.run(["git", *args], cwd=repo, check=True, capture_output=True, text=True)


@pytest.fixture()
def fresh_repo(tmp_path: Path) -> Path:
    """A real git repo: one tracked clean file, one gitignored leak, one
    untracked leak (the set a commit would newly add)."""
    repo = tmp_path / "repo"
    repo.mkdir()
    _git(repo, "init", "-q")
    _git(repo, "config", "user.email", "t@example.invalid")
    _git(repo, "config", "user.name", "Test")
    (repo / ".gitignore").write_text("ignored/\n", encoding="utf-8")
    (repo / "README.md").write_text("clean tracked text\n", encoding="utf-8")
    _git(repo, "add", ".gitignore", "README.md")
    _git(repo, "commit", "-q", "-m", "init")
    leak = "/Users" + "/haralan.operator/evidence.txt\n"
    (repo / "ignored").mkdir()
    (repo / "ignored" / "raw.txt").write_text(leak, encoding="utf-8")
    (repo / "benchmarks").mkdir()
    (repo / "benchmarks" / "new_measurement.txt").write_text(leak, encoding="utf-8")
    return repo


def test_untracked_leak_is_invisible_without_the_flag(fresh_repo: Path, capsys) -> None:
    """Green guard + unstaged leak: exactly the false comfort the flag exists to
    remove. Tracked-only scanning cannot see what the next commit would add."""
    assert guard.main(["--root", str(fresh_repo)]) == 0
    assert "clean" in capsys.readouterr().out


def test_untracked_leak_is_caught_before_staging(fresh_repo: Path, capsys) -> None:
    rc = guard.main(["--root", str(fresh_repo), "--include-untracked"])
    out = capsys.readouterr().out
    assert rc == 1
    assert "personal-home-path: benchmarks/new_measurement.txt:1" in out
    # gitignored files cannot be committed, so they cannot leak publicly: the
    # flag must not turn them into findings (or the signal drowns in noise).
    assert "ignored/raw.txt" not in out


def test_untracked_internal_path_is_caught(fresh_repo: Path, capsys) -> None:
    (fresh_repo / "WORKPLAN_2027.md").write_text("public-safe text\n", encoding="utf-8")
    assert guard.main(["--root", str(fresh_repo), "--include-untracked"]) == 1
    assert "tracked-internal-path: WORKPLAN_2027.md" in capsys.readouterr().out
