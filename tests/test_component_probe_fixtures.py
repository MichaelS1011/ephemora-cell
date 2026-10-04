# SPDX-License-Identifier: BUSL-1.1
# Copyright 2026 Michael Soppa
"""Component probe fixtures: cited evidence must name bytes that exist somewhere.

The four WASI 0.2 probe binaries are cited by SECURITY.md and CHANGELOG.md as the
fixture of dated measurements, and they are deliberately NOT committed
(``.gitignore``: ``*.wasm``, no exception for this directory). That is only honest
as long as three things stay true, and this file is the gate that keeps them true:

* every cited fixture is identified by a sha256 in
  ``benchmarks/component_probes/fixtures.json``;
* when the bytes are present on a machine, they ARE the pinned bytes;
* no document or script claims the binaries are committed.

Read as: the manifest is an identity pin for what was measured, not a
reproducibility promise — a rebuild on another toolchain may legitimately differ,
and then the measurement has to be re-run rather than the hash quietly replaced.
"""

from __future__ import annotations

import hashlib
import json
import re
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))

PROBES = ROOT / "benchmarks" / "component_probes"
MANIFEST = PROBES / "fixtures.json"
GITIGNORE = ROOT / ".gitignore"
REBUILD = PROBES / "rebuild.sh"


def _manifest() -> dict:
    return json.loads(MANIFEST.read_text(encoding="utf-8"))


def test_manifest_exists_and_names_every_fixture():
    doc = _manifest()
    fixtures = doc["fixtures"]
    assert doc["manifest_version"] == "component-probe-fixtures.v1"
    assert set(fixtures) == {
        "fs_probe.wasm",
        "net_probe.wasm",
        "times_probe.wasm",
        "sync_probe.wasm",
    }, "the manifest must cover the probes the evidence cites, and only those"
    for name, entry in fixtures.items():
        assert re.fullmatch(r"[0-9a-f]{64}", entry["sha256"]), name
        assert int(entry["size_bytes"]) > 0, name
        assert (PROBES / entry["source"]).is_dir(), f"{name}: source crate missing"


def test_present_bytes_match_the_pinned_hashes():
    """The real check, whenever a machine has the artifacts. A fresh clone has
    none — that is the documented state, and this test says so instead of
    quietly passing on an empty loop."""
    present = sorted(p.name for p in PROBES.glob("*.wasm"))
    if not present:
        # Not a skip: the absence IS the policy, and the policy text must be
        # in the manifest for the absence to be explainable.
        assert any(
            "not committed" in line for line in _manifest()["policy"]
        ), "artifacts absent without a stated policy is an unexplained hole"
        return
    fixtures = _manifest()["fixtures"]
    for name in present:
        digest = hashlib.sha256((PROBES / name).read_bytes()).hexdigest()
        assert (
            digest == fixtures[name]["sha256"]
        ), f"{name} on disk is not the byte sequence the dated evidence ran on"
        assert (PROBES / name).stat().st_size == int(fixtures[name]["size_bytes"])


def test_cited_fixtures_are_all_hash_identified():
    """Every ``benchmarks/component_probes/<x>.wasm`` mention in the shipped
    documentation must be covered by the manifest — otherwise a cited binary is
    an anonymous file."""
    cited: set[str] = set()
    for doc in (ROOT / "SECURITY.md", ROOT / "CHANGELOG.md", ROOT / "README.md"):
        text = doc.read_text(encoding="utf-8")
        cited.update(
            m.group(1) + ".wasm"
            for m in re.finditer(
                r"benchmarks/component_probes/([a-z0-9_]+)\.wasm", text
            )
        )
    assert cited, "the docs are expected to cite at least one probe fixture"
    missing = cited - set(_manifest()["fixtures"])
    assert not missing, f"cited without a hash pin: {sorted(missing)}"


def test_no_document_or_script_claims_the_binaries_are_committed():
    """The wording this replaces: rebuild.sh used to assert 'the committed .wasm
    binaries are the evidence'. They are not committed, and a script that says
    otherwise is how a repository drifts from its own evidence.

    A document MAY narrate that removal — quoting the old claim to explain the
    fix is what a changelog is for — so an assertion is only an offence when
    nothing around it negates it."""
    texts = {
        "rebuild.sh": REBUILD.read_text(encoding="utf-8"),
        "SECURITY.md": (ROOT / "SECURITY.md").read_text(encoding="utf-8"),
        "CHANGELOG.md": (ROOT / "CHANGELOG.md").read_text(encoding="utf-8"),
    }
    assertion = re.compile(
        r"committed\s+\.?wasm\s+binaries" r"|\.wasm[^.\n]{0,40}is committed",
        re.IGNORECASE,
    )
    negation = re.compile(r"\bnot\b|\bnever\b|\bno longer\b|\bclaim", re.IGNORECASE)
    for name, text in texts.items():
        lines = text.splitlines()
        for match in assertion.finditer(text):
            start = text.count("\n", 0, match.start())
            end = text.count("\n", 0, match.end())
            clause = "\n".join(lines[start : end + 1])
            msg = f"{name} asserts a probe binary is committed: {clause.strip()!r}"
            assert negation.search(clause), msg


def test_gitignore_policy_is_what_the_manifest_states():
    ignore = GITIGNORE.read_text(encoding="utf-8")
    assert "*.wasm" in ignore, "the artifacts are excluded by this rule"
    assert not any(
        line.startswith("!") and "component_probes" in line
        for line in ignore.splitlines()
    ), "an un-ignore exception would silently change the fixture policy"


def test_rebuild_script_covers_exactly_the_manifested_probes():
    script = REBUILD.read_text(encoding="utf-8")
    loop = re.search(r"for crate in ([^;]+); do", script)
    assert loop, "rebuild.sh must list its crates in one loop"
    crates = set(loop.group(1).split())
    expected = {
        entry["source"].split("/")[-1] for entry in _manifest()["fixtures"].values()
    }
    assert (
        crates == expected
    ), f"rebuild.sh builds {sorted(crates)} but the manifest pins {sorted(expected)}"


def test_rebuild_script_verifies_against_the_manifest():
    """The script's whole purpose is to catch drift, so it has to read the pin."""
    script = REBUILD.read_text(encoding="utf-8")
    assert "fixtures.json" in script, "rebuild.sh does not consult the manifest"
    assert "sha256" in script, "rebuild.sh does not hash what it builds"


def test_rebuild_does_not_overwrite_the_evidence_by_default():
    """The pinned bytes exist only on the machine that measured with them, so a
    bare rebuild must not be able to destroy the evidence; installing is opt-in."""
    script = REBUILD.read_text(encoding="utf-8")
    assert "--install" in script
    assert not re.search(r"-o\s+\"\$HERE/\$crate\.wasm\"", script), (
        "rebuild.sh strips straight onto the working fixture — the default run "
        "would overwrite bytes the dated evidence names"
    )


def test_ci_claim_about_rebuilding_is_true():
    """rebuild.sh says CI does not rebuild these. That is only honest while the
    workflow really lacks the wasm32-wasip2 target the probes need."""
    workflow = (ROOT / ".github" / "workflows" / "ci.yml").read_text(encoding="utf-8")
    assert "wasm32-wasip2" not in workflow, (
        "CI now installs wasm32-wasip2 — the manifest and rebuild.sh claim it cannot "
        "rebuild the component probes, so add the hash verification step instead"
    )
    assert "wasm32-wasip1" in workflow
