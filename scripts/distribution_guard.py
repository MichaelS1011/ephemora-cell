#!/usr/bin/env python3
"""Distribution guard — allowlist enforcement over the two public surfaces the
tree-level public-content guard cannot see:

1. git HISTORY reachable from a ref, and
2. the built DISTRIBUTION ARTIFACTS (wheel + sdist).

Why this exists: an internal document can be gone from the tracked tree and
still be public. It leaks either through history (committed, then deleted —
the blob stays reachable through a branch/tag/orphaned pull-request ref, the
commit-then-delete class) or through a wheel/sdist that a working-tree scan never opens.
Both expose confidential research, internal governance and private paths while
``check_public_content.py`` reports green, because it only reads the current
tree.

This is a fail-closed gate, not a sanitizer: it flags, a human classifies. It
reuses ``scripts/public_content_guard.json`` so the path and content rules live
in exactly one place. Rules are structural and generic; project-private
specifics stay in the optional local overlay (``EPHEMORA_PUBLIC_GUARD_RULES``)
that never reaches the repository.

Modes
-----
  history   Scan objects reachable from refs (default: HEAD) for internal paths
            that were committed at any point in that history. ``--content``
            adds the universal secret/home-path rules to the blob bodies; with
            ``--strict-ids`` the contextual internal-id rules run too, which is
            what a range of commits new to a push should be scanned with
  artifacts Open each wheel (.zip) and sdist (.tar.gz/.tgz/.zip), print the
            member inventory, and fail if any member path is a forbidden
            internal path or any member body trips a content rule. It ALSO
            fails when an artifact is INCOMPLETE: from 1.2.0rc2 upward every
            ephemora-cell artifact must carry the CLI modules the public docs
            advertise (cli/doctor/verify_cli/policy_cli) and all three console
            scripts in its entry_points.txt. A leak scan alone cannot see a
            stale build - a wheel produced before that surface landed is
            leak-free and unusable at the same time.

Usage
-----
  python scripts/distribution_guard.py history
  python scripts/distribution_guard.py history --ref origin/main..HEAD --content
  python scripts/distribution_guard.py history --all
  python scripts/distribution_guard.py artifacts "dist/*"
  python scripts/distribution_guard.py artifacts --inventory "dist/*.whl"
"""

from __future__ import annotations

import argparse
import base64
import glob
import hashlib
import json
import os
import re
import subprocess
import sys
import tarfile
import zipfile
from dataclasses import dataclass
from pathlib import Path

CONFIG_PATH = Path(__file__).with_name("public_content_guard.json")
# Text suffixes carried inside artifacts that are worth a content scan.
_ARTIFACT_TEXT_SUFFIXES = {
    ".py",
    ".md",
    ".txt",
    ".json",
    ".toml",
    ".yaml",
    ".yml",
    ".cfg",
    ".ini",
    ".sh",
}
# Executable/container payloads are not text files, but their embedded path
# strings still disclose build machines. Universal secret/home rules only:
# ordinary binary noise must not turn contextual word lists into false alarms.
_ARTIFACT_BINARY_SCAN_SUFFIXES = {
    ".wasm",
    ".dylib",
    ".so",
    ".dll",
}
# Packaging-generated members: skip their body from content rules (a metadata
# body echoes the project description and can trip generic words legitimately).
# Forbidden-PATH checking still applies to every member without exemption.
_METADATA_MEMBERS = re.compile(
    r"(^|/)(PKG-INFO|METADATA|RECORD|WHEEL|entry_points\.txt)$"
)

# --------------------------------------------------------------------------- #
# Completeness and self-consistency rules for built artefacts (2026-10-17).
#
# The leak rules above answer "what must NOT be inside an artifact". They are
# structurally blind to the opposite question, and that blindness shipped a
# stale rc2: a wheel built before doctor/verify/policy landed, whose
# entry_points.txt did not carry the `ephemora` console script that pyproject
# declares. It passed every leak rule because nothing sensitive was in it -
# what was missing was the product.
#
# So the artifact is also checked against what its OWN version and metadata
# promise. This is an artifact-content assertion, read out of the opened
# wheel/sdist; the source tree is not consulted and cannot satisfy it.
# --------------------------------------------------------------------------- #
_PROJECT_DIST_NAMES = {"ephemora-cell", "ephemora_cell", "ephemoracell"}
# First version whose public CLI surface must be present. PEP 440 ordering is
# used, so 1.2.0, 1.2.0rc2 and 1.2.1 are all subject to it while 1.2.0rc1 is not.
_COMPLETENESS_SINCE = "1.2.0rc2"
# Modules (repo-relative, sdist root stripped) that must be members.
_REQUIRED_MODULES = (
    "ephemora_cell/cli.py",
    "ephemora_cell/doctor.py",
    "ephemora_cell/verify_cli.py",
    "ephemora_cell/policy_cli.py",
)
# Console-script names that must appear in the artifact's entry_points.txt.
_REQUIRED_CONSOLE_SCRIPTS = ("ephemora", "ephemora-cell", "ephemora-cell-mcp")
_ENTRY_POINTS_RE = re.compile(r"(^|/)[^/]*\.(dist|egg)-info/entry_points\.txt$")
_VERSION_RE = re.compile(
    r"^v?(?P<rel>[0-9]+(?:\.[0-9]+)*)(?P<rest>.*?)(?:\+(?P<local>.*))?$",
    re.IGNORECASE,
)
_PRE_RE = re.compile(
    r"^\.?(?P<kind>rc|pre|preview|alpha|beta|a|b)(?P<num>[0-9]+)", re.IGNORECASE
)
_POST_RE = re.compile(r"^\.?(?:post|rev|r)(?P<num>[0-9]+)", re.IGNORECASE)


@dataclass(frozen=True)
class Finding:
    rule: str
    location: str
    detail: str = ""

    def render(self) -> str:
        return f"{self.rule}: {self.location}  {self.detail}".rstrip()


def _load_config() -> dict:
    return json.loads(CONFIG_PATH.read_text(encoding="utf-8"))


def _forbidden_patterns(config: dict) -> list[re.Pattern]:
    return [re.compile(p) for p in config.get("forbidden_tracked_paths", [])]


def _content_rules(config: dict) -> list[dict]:
    return config.get("content_rules", [])


def _allow_files(config: dict) -> list[re.Pattern]:
    return [re.compile(p) for p in config.get("allow_files", [])]


def _scan_body(
    location: str,
    text: str,
    rules: list[dict],
    marker: str,
    report_snippets: bool,
) -> list[Finding]:
    findings: list[Finding] = []
    for lineno, line in enumerate(text.splitlines(), start=1):
        if marker and marker in line:
            continue
        for rule in rules:
            match = re.search(rule["regex"], line)
            if not match:
                continue
            detail = ""
            if rule["id"] == "personal-home-path":
                user = match.group("user")
                if user in rule.get("benign_users", []):
                    continue
                detail = user
            elif report_snippets:
                detail = line.strip()[:80]
            findings.append(Finding(rule["id"], f"{location}:{lineno}", detail))
    return findings


# --------------------------------------------------------------------------- #
# history mode
# --------------------------------------------------------------------------- #


def _git(root: Path, *args: str) -> str:
    return subprocess.run(
        ["git", *args], cwd=root, check=True, capture_output=True, text=True
    ).stdout


def _reachable_objects(root: Path, refs: list[str]) -> list[tuple[str, str]]:
    """Return (oid, path) pairs for objects reachable from ``refs``.

    ``git rev-list --objects`` lists every object with its path when the object
    was introduced at a path; commits/trees carry no useful path and are dropped
    by keeping only lines with a path field.
    """
    out = _git(root, "rev-list", "--objects", *refs)
    pairs: list[tuple[str, str]] = []
    for line in out.splitlines():
        parts = line.split(" ", 1)
        if len(parts) == 2 and parts[1]:
            pairs.append((parts[0], parts[1]))
    return pairs


def _is_universal_secret_rule(rule_id: str) -> bool:
    """Rules whose match is a leak in ANY file, regardless of context.

    In history content mode these are the DEFAULT rules: credential shapes and
    personal home paths are unsafe anywhere. The governance / internal-id /
    internal-process word rules are CONTEXTUAL — public engineering docs (ADRs,
    CHANGELOG, SECURITY.md) intentionally carry words like those — so they do
    not belong to a sweep over all of history, where they would only bury a real
    secret under noise.

    They DO belong to a scan of a commit range that is new to this push, which
    is what ``scan_history(..., strict_ids=True)`` selects: only blobs that no
    public ref has ever carried are examined there, so a contextual rule can
    only name content this push would disclose for the first time.
    """
    return rule_id.startswith("secret-") or rule_id == "personal-home-path"


def scan_history(
    root: Path,
    refs: list[str],
    config: dict,
    content: bool,
    strict_ids: bool = False,
) -> list[Finding]:
    forbidden = _forbidden_patterns(config)
    allow = _allow_files(config)
    all_rules = _content_rules(config)
    rules = (
        all_rules
        if strict_ids
        else [r for r in all_rules if _is_universal_secret_rule(r["id"])]
    )
    marker = config.get("allow_marker", "")
    findings: list[Finding] = []
    seen_content: set[str] = set()
    reachable = _reachable_objects(root, refs)
    if not reachable:
        # An empty range is not a verified range. Failing here keeps an
        # accidentally collapsed refspec from reporting success over zero work.
        return [
            Finding(
                "history-empty-scan",
                ",".join(refs),
                "no reachable objects were selected for the history scan",
            )
        ]
    for oid, path in reachable:
        posix = path.replace(os.sep, "/")
        if any(pat.search(posix) for pat in forbidden):
            findings.append(
                Finding("history-internal-path", posix, "committed in history")
            )
            # path leak is enough; no need to also read this blob body
            continue
        if not content:
            continue
        # the guard's own rule/test files legitimately embed leak shapes.
        if any(pat.search(posix) for pat in allow):
            continue
        suffix = Path(posix).suffix.lower()
        if suffix not in _ARTIFACT_TEXT_SUFFIXES or oid in seen_content:
            continue
        seen_content.add(oid)
        body = subprocess.run(
            ["git", "cat-file", "blob", oid],
            cwd=root,
            capture_output=True,
            text=True,
            errors="replace",
        ).stdout
        findings.extend(_scan_body(f"history:{oid} {posix}", body, rules, marker, True))
    return findings


# --------------------------------------------------------------------------- #
# artifacts mode
# --------------------------------------------------------------------------- #


def _read_tar(path: Path) -> list[tuple[str, int]]:
    with tarfile.open(path) as tf:
        return [(m.name, m.size) for m in tf.getmembers() if m.isfile()]


def _tar_body(tf: tarfile.TarFile, name: str) -> bytes:
    handle = tf.extractfile(name)
    return handle.read() if handle else b""


def _artifact_kind(path: Path) -> str:
    if path.name.endswith(".whl"):
        return "wheel"
    if path.name.endswith(".zip"):
        return "zip"
    if path.name.endswith((".tar.gz", ".tgz", ".tar")):
        return "tar"
    raise ValueError(f"unsupported artifact type: {path.name}")


def _strip_sdist_root(member: str) -> str:
    """`ephemora-cell-1.2.0/docs/program/x.md` -> `docs/program/x.md`."""
    parts = member.split("/", 1)
    return parts[1] if len(parts) == 2 else member


def scan_artifact(
    path: Path,
    config: dict,
    inventory: bool,
) -> tuple[list[Finding], int]:
    forbidden = _forbidden_patterns(config)
    allow = _allow_files(config)
    rules = _content_rules(config)
    marker = config.get("allow_marker", "")
    findings: list[Finding] = []

    kind = _artifact_kind(path)
    # Read every member once: name, size, and the bodies we may scan.
    members: list[tuple[str, int]] = []
    bodies: dict[str, bytes] = {}
    binary_bodies: dict[str, bytes] = {}
    if kind in ("wheel", "zip"):
        with zipfile.ZipFile(path) as zf:
            for info in zf.infolist():
                if info.is_dir():
                    continue
                members.append((info.filename, info.file_size))
                suffix = Path(info.filename).suffix.lower()
                if suffix in _ARTIFACT_TEXT_SUFFIXES:
                    bodies[info.filename] = zf.read(info.filename)
                elif suffix in _ARTIFACT_BINARY_SCAN_SUFFIXES:
                    binary_bodies[info.filename] = zf.read(info.filename)
    else:
        with tarfile.open(path) as tf:
            members = _read_tar(path)
            for name, _size in members:
                suffix = Path(name).suffix.lower()
                if suffix in _ARTIFACT_TEXT_SUFFIXES:
                    bodies[name] = _tar_body(tf, name)
                elif suffix in _ARTIFACT_BINARY_SCAN_SUFFIXES:
                    binary_bodies[name] = _tar_body(tf, name)
    total_bytes = sum(size for _, size in members)

    if inventory:
        print(f"\n== inventory: {path.name} ({len(members)} members) ==")
        for member, size in sorted(members):
            print(f"  {size:>10}  {member}")

    # 1. forbidden member PATHS (no exemption) — an internal doc/test/research
    #    path inside the distribution is always a failure.
    for member, _size in members:
        candidates = {member, _strip_sdist_root(member)}
        if any(pat.search(c) for pat in forbidden for c in candidates):
            findings.append(
                Finding(
                    "artifact-internal-path",
                    f"{path.name}!{member}",
                    "member must not ship",
                )
            )

    # 2. content rules over text bodies (allow-listed members are skipped).
    for member, body in bodies.items():
        tail = _strip_sdist_root(member)
        if any(pat.search(member) or pat.search(tail) for pat in allow):
            continue
        if _METADATA_MEMBERS.search(member):
            continue
        if Path(tail).suffix.lower() not in _ARTIFACT_TEXT_SUFFIXES:
            continue
        try:
            text = body.decode("utf-8")
        except UnicodeDecodeError:
            continue
        findings.extend(_scan_body(f"{path.name}!{tail}", text, rules, marker, True))

    # 2b. universal credential/home-path rules over binary payloads. The full
    # contextual vocabulary is deliberately not applied here: arbitrary machine
    # code is not prose and would drown real secrets in noise.
    universal_rules = [rule for rule in rules if _is_universal_secret_rule(rule["id"])]
    for member, body in binary_bodies.items():
        tail = _strip_sdist_root(member)
        if any(pat.search(member) or pat.search(tail) for pat in allow):
            continue
        if _METADATA_MEMBERS.search(member):
            continue
        text = body.decode("utf-8", errors="ignore")
        findings.extend(
            _scan_body(f"{path.name}!{tail}", text, universal_rules, marker, False)
        )

    # 3. completeness (hard): the artifact must carry what its version promises.
    findings.extend(check_completeness(path, [name for name, _ in members], bodies))

    # 4. self-consistency (hard): a wheel's own RECORD must match the bytes it
    #    ships. Presence-only completeness cannot see an artifact that carries
    #    the right NAMES but the wrong CONTENT — e.g. a wheel from an earlier
    #    commit whose modules were already there.
    findings.extend(check_record_integrity(path))

    return findings, total_bytes


def check_record_integrity(path: Path) -> list[Finding]:
    """Verify a wheel's RECORD digests and sizes against its own members.

    RECORD is the wheel's own statement about its contents (PEP 427). Checking
    it costs one pass over the archive and turns "the artifact contains the
    modules" into "the artifact contains THESE bytes", which is what a release
    identity has to mean. A missing RECORD, an unparsable line, or any mismatch
    is a finding: the check never degrades to silence.
    """
    if not path.name.endswith(".whl"):
        return []
    try:
        dist_name, _version = _dist_name_version(path)
    except ValueError:
        return []
    if dist_name.lower().replace("-", "_") not in _PROJECT_DIST_NAMES:
        return []  # a foreign wheel is not this project's release surface
    findings: list[Finding] = []
    with zipfile.ZipFile(path) as zf:
        names = {info.filename for info in zf.infolist() if not info.is_dir()}
        record_name = next((n for n in names if n.endswith(".dist-info/RECORD")), None)
        if record_name is None:
            return [
                Finding(
                    "artifact-record-missing",
                    path.name,
                    "no .dist-info/RECORD member — the artifact cannot prove "
                    "its own contents",
                )
            ]
        lines = zf.read(record_name).decode("utf-8", errors="replace").splitlines()
        checked = 0
        for line in lines:
            row = line.strip()
            if not row:
                continue
            parts = row.split(",")
            if len(parts) < 3:
                findings.append(
                    Finding(
                        "artifact-record-mismatch",
                        path.name,
                        f"unparsable RECORD row: {row[:80]}",
                    )
                )
                continue
            member, digest_field, size_field = parts[0], parts[1], parts[2]
            if member == record_name:
                continue  # RECORD does not hash itself
            if member not in names:
                findings.append(
                    Finding(
                        "artifact-record-mismatch",
                        path.name,
                        f"{member} listed in RECORD but absent from the archive",
                    )
                )
                continue
            if not digest_field.startswith("sha256="):
                continue  # a wheel may legitimately list no hash for some entries
            try:
                expected_size = int(size_field)
            except ValueError:
                findings.append(
                    Finding(
                        "artifact-record-mismatch",
                        path.name,
                        f"{member}: bad size field",
                    )
                )
                continue
            data = zf.read(member)
            actual_digest = (
                base64.urlsafe_b64encode(hashlib.sha256(data).digest())
                .rstrip(b"=")
                .decode()
            )
            if digest_field != f"sha256={actual_digest}" or len(data) != expected_size:
                findings.append(
                    Finding(
                        "artifact-record-mismatch",
                        path.name,
                        f"{member}: RECORD says {digest_field[:20]}…/{expected_size} B, "
                        f"bytes are sha256={actual_digest[:20]}…/{len(data)} B",
                    )
                )
            checked += 1
        if checked == 0:
            findings.append(
                Finding(
                    "artifact-record-mismatch",
                    path.name,
                    "RECORD lists no verifiable member",
                )
            )
    return findings


# --------------------------------------------------------------------------- #
# completeness of a built artifact
# --------------------------------------------------------------------------- #


def _dist_name_version(path: Path) -> tuple[str, str]:
    """`(name, version)` claimed by the artifact FILENAME (PEP 427 / sdist)."""
    name = path.name
    if name.endswith(".whl"):
        parts = name[: -len(".whl")].split("-")
        if len(parts) < 5:
            raise ValueError(f"not a PEP 427 wheel name: {name}")
        return parts[0], parts[1]
    for ext in (".tar.gz", ".tgz", ".tar", ".zip"):
        if name.endswith(ext):
            stem = name[: -len(ext)]
            base, _, version = stem.rpartition("-")
            if not base:
                raise ValueError(f"cannot split name-version: {name}")
            return base, version
    raise ValueError(f"unhandled artifact name: {name}")


def _version_key(version: str) -> tuple[tuple[int, ...], int, int, int]:
    """Ordering key sufficient for the freeze comparison (release vs rc/post).

    Deliberately local: no `packaging` import, because this guard must run in a
    bare CI venv. It understands the forms this project uses (1.2.0, 1.2.0rc2,
    1.2.0.post3+git.abc); anything else is refused by the caller (fail closed).
    """
    match = _VERSION_RE.match(version.strip())
    if not match:
        raise ValueError(f"unparsable version: {version!r}")
    release = tuple(int(p) for p in match.group("rel").split("."))
    release = release + (0,) * (4 - len(release))
    rest = match.group("rest") or ""
    post = _POST_RE.match(rest)
    postnum = int(post.group("num")) if post else 0
    pre = _PRE_RE.match(rest)
    if pre:
        # a pre-release sorts BELOW the release it precedes
        return release, 0, int(pre.group("num")), postnum
    return release, 1, 0, postnum


def _console_scripts(text: str) -> set[str]:
    """Names declared under [console_scripts] of an entry_points.txt body."""
    section: str | None = None
    names: set[str] = set()
    for raw in text.splitlines():
        line = raw.strip()
        if not line or line.startswith(("#", ";")):
            continue
        if line.startswith("[") and line.endswith("]"):
            section = line[1:-1].strip().lower()
            continue
        if section == "console_scripts" and "=" in line:
            names.add(line.split("=", 1)[0].strip())
    return names


def check_completeness(
    path: Path, members: list[str], bodies: dict[str, bytes]
) -> list[Finding]:
    """Assert what the artifact MUST contain, from the artifact itself."""
    findings: list[Finding] = []
    try:
        dist_name, version = _dist_name_version(path)
    except ValueError as exc:
        return [Finding("artifact-name-unparsable", path.name, str(exc))]
    if dist_name.lower().replace("-", "_") not in _PROJECT_DIST_NAMES:
        return findings  # a foreign wheel (e.g. wasmtime) is not our product surface
    try:
        if _version_key(version) < _version_key(_COMPLETENESS_SINCE):
            return findings
    except ValueError as exc:
        return [Finding("artifact-version-unparsable", path.name, str(exc))]

    # A wheel has no root prefix; an sdist does. Match BOTH spellings, so the
    # root-strip that an sdist needs cannot erase a wheel's first directory.
    tails = {m: _strip_sdist_root(m) for m in members}
    for required in _REQUIRED_MODULES:
        if not any(m == required or tail == required for m, tail in tails.items()):
            findings.append(
                Finding(
                    "artifact-missing-module",
                    path.name,
                    f"{required} absent (version {version} must ship it)",
                )
            )
    entry_members = [
        m
        for m, tail in tails.items()
        if _ENTRY_POINTS_RE.search(m) or _ENTRY_POINTS_RE.search(tail)
    ]
    if not entry_members:
        findings.append(
            Finding(
                "artifact-missing-entry-points", path.name, "no entry_points.txt member"
            )
        )
        return findings
    declared: set[str] = set()
    for member in entry_members:
        body = bodies.get(member)
        if body is None:
            try:
                if _artifact_kind(path) == "tar":
                    with tarfile.open(path) as tf:
                        body = _tar_body(tf, member)
                else:
                    with zipfile.ZipFile(path) as zf:
                        body = zf.read(member)
            except Exception as exc:  # unreadable -> fail closed
                findings.append(
                    Finding("artifact-entry-points-unreadable", path.name, str(exc))
                )
                continue
        try:
            declared |= _console_scripts(body.decode("utf-8"))
        except UnicodeDecodeError as exc:
            findings.append(
                Finding("artifact-entry-points-unreadable", path.name, str(exc))
            )
    for script in _REQUIRED_CONSOLE_SCRIPTS:
        if script not in declared:
            findings.append(
                Finding(
                    "artifact-missing-console-script",
                    path.name,
                    f"[console_scripts] {script} = ... absent (version {version} must expose it)",
                )
            )
    return findings


# --------------------------------------------------------------------------- #
# CLI
# --------------------------------------------------------------------------- #


def _resolve_artifacts(patterns: list[str]) -> list[Path]:
    matched: list[Path] = []
    for pat in patterns:
        for p in sorted(glob.glob(pat)):
            path = Path(p)
            if path.is_file() and path.name.endswith(
                (".whl", ".zip", ".tar.gz", ".tgz", ".tar")
            ):
                matched.append(path)
    return matched


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(
        description="Git-history and distribution-artifact guard."
    )
    parser.add_argument("--root", default=".", help="repository root (default: cwd)")
    sub = parser.add_subparsers(dest="mode", required=True)

    h = sub.add_parser("history", help="scan reachable history for internal paths")
    h.add_argument("--ref", action="append", default=[], help="ref/range (repeatable)")
    h.add_argument("--all", action="store_true", help="scan all local refs")
    h.add_argument(
        "--content", action="store_true", help="also run secret rules on blobs"
    )
    h.add_argument(
        "--strict-ids",
        action="store_true",
        help="with --content, also run the contextual internal-id / governance "
        "rules; intended for a ref RANGE that is new to this push",
    )

    a = sub.add_parser("artifacts", help="scan built wheel + sdist contents")
    a.add_argument("patterns", nargs="*", default=["dist/*"], help="artifact globs")
    a.add_argument("--inventory", action="store_true", help="print member inventory")

    args = parser.parse_args(argv)
    root = Path(args.root).resolve()
    config = _load_config()

    findings: list[Finding] = []
    if args.mode == "history":
        refs = ["--all"] if args.all else (args.ref or ["HEAD"])
        if args.all:
            refs = _git(root, "for-each-ref", "--format=%(refname)").split() or ["HEAD"]
        try:
            findings.extend(
                scan_history(root, refs, config, args.content, args.strict_ids)
            )
        except subprocess.CalledProcessError as exc:  # bad ref -> fail closed
            print(f"::error::history scan failed: {exc}")
            return 1
    elif args.mode == "artifacts":
        artifacts = _resolve_artifacts(args.patterns)
        if not artifacts:
            print(f"::error::no artifacts matched {args.patterns} (fail closed)")
            return 1
        for path in artifacts:
            f, _ = scan_artifact(path, config, args.inventory)
            findings.extend(f)

    if findings:
        by_rule: dict[str, int] = {}
        for f in findings:
            by_rule[f.rule] = by_rule.get(f.rule, 0) + 1
        print(
            f"::error::distribution-guard: {len(findings)} finding(s) across "
            f"{len(by_rule)} rule(s): {', '.join(sorted(by_rule))}"
        )
        for f in sorted(findings, key=lambda x: (x.rule, x.location)):
            print("  " + f.render())
        return 1

    print("distribution-guard: clean")
    return 0


if __name__ == "__main__":
    sys.exit(main())
