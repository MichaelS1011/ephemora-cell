"""Regression tests for the two High-severity CodeQL findings that were real.

Local CodeQL 2.27.2 (`codeql/python-queries@1.8.12`, the CI default suite) on the
release candidate reported, among others:

  * ``py/insecure-temporary-file`` (CWE-377, security-severity 7.0) — twice:
    ``benchmarks/poll_oneoff_wall_hostcall_probe.py`` and
    ``benchmarks/stdio_overflow_output_alloc_probe.py`` called the deprecated
    ``tempfile.mktemp()``, which only *names* a path: another process can win the
    race to it between the guess and the open.
  * ``py/incomplete-url-substring-sanitization`` (CWE-20, security-severity 7.8)
    — ``scripts/metrics_snapshot.py`` chose the GitHub request shape with a
    prefix test on the raw URL string. A prefix test on a URL is not a host
    check: ``https://api.github.com.evil.test`` passes it, and a substring test
    would also let ``http://evil.test/?u=https://api.github.com`` through.

Neither file ships in the wheel and neither is reachable from guest code, but
both are published, both are High on the scale GitHub code scanning shows, and a
High finding here is either fixed or refuted with reproducible evidence — never
closed by writing about it.

The hygiene rule is written against the **syntax tree**, not a line regex, and
carries its own positive control. That is deliberate: an independent review
measured that a textual rule stays green for ``from tempfile import mktemp``,
for an aliased import, for a call split across lines and for ``getattr`` — four
ways back in that the original regex would not have seen. Scanning the same files
git would publish (``git ls-files``) keeps local and CI verdicts identical.
"""

from __future__ import annotations

import ast
import importlib.util
import subprocess
import sys
from pathlib import Path

import pytest

_ROOT = Path(__file__).resolve().parents[1]

#: Directories that are never repository source. Only used as the fallback scan
#: basis when no git metadata exists (a `git archive` export, an sdist).
_SKIP_DIRS = {
    ".git",
    ".venv",
    ".tmp_gate",
    "tmp_probe_dir",
    "build",
    "dist",
    "node_modules",
    "__pycache__",
}


# --------------------------------------------------------------------------
# the rule itself, as a function under test
# --------------------------------------------------------------------------


def _mktemp_hits(source: str) -> int:
    """Count calls that reach the deprecated ``tempfile.mktemp``.

    Resolved through the syntax tree, so an alias, a from-import, a call split
    over lines or a ``getattr`` lookup all count, while prose that merely names
    the function does not.
    """
    tree = ast.parse(source)
    modules: set[str] = set()  # names bound to the `tempfile` module
    direct: set[str] = set()  # names bound to `tempfile.mktemp` itself
    hits = 0
    for node in ast.walk(tree):
        if isinstance(node, ast.Import):
            for alias in node.names:
                if alias.name == "tempfile":
                    modules.add(alias.asname or "tempfile")
        elif isinstance(node, ast.ImportFrom) and node.module == "tempfile":
            for alias in node.names:
                if alias.name == "mktemp":
                    direct.add(alias.asname or "mktemp")
        elif isinstance(node, ast.Call):
            func = node.func
            if (
                isinstance(func, ast.Attribute)
                and func.attr == "mktemp"
                and isinstance(func.value, ast.Name)
                and func.value.id in modules
            ):
                hits += 1
            elif isinstance(func, ast.Name) and func.id in direct:
                hits += 1
            elif (
                isinstance(func, ast.Name)
                and func.id == "getattr"
                and len(node.args) >= 2
                and isinstance(node.args[1], ast.Constant)
                and node.args[1].value == "mktemp"
            ):
                hits += 1
    return hits


def _scan_basis() -> list[Path]:
    """The files a push would carry, or — without git metadata — the tree itself."""
    proc = subprocess.run(
        ["git", "ls-files", "-z", "*.py"],
        cwd=str(_ROOT),
        capture_output=True,
        text=True,
    )
    if proc.returncode == 0 and proc.stdout.strip("\x00"):
        return [_ROOT / name for name in proc.stdout.split("\x00") if name]
    found = [
        path
        for path in _ROOT.rglob("*.py")
        if not any(
            part in _SKIP_DIRS or part.endswith(".egg-info")
            for part in path.relative_to(_ROOT).parts
        )
    ]
    assert found, "no repository sources found to scan — the check would be vacuous"
    return found


#: Every spelling that must be caught. Each is a way back in that a line-based
#: regex measured blind during the pre-push review.
_MKTEMP_FORMS = [
    "import tempfile\nx = tempfile.mktemp()\n",
    "import tempfile as tf\nx = tf.mktemp()\n",
    "import tempfile\nx = tempfile.mktemp ()\n",
    "import tempfile\nx = (tempfile.mktemp)()\n",
    "from tempfile import mktemp\nx = mktemp()\n",
    "from tempfile import mktemp as mt\nx = mt()\n",
    "import tempfile\nx = getattr(tempfile, 'mktemp')()\n",
]

#: Stated limit of the rule, as a test so it cannot be mistaken for completeness:
#: a reference stored in a name and called later is a data-flow fact, not a call
#: shape, and this hygiene gate does not see it. The rule's purpose is to stop
#: the deprecated call coming back in any of its written forms, not to replace
#: the CodeQL run that reported it.
_UNDETECTED_BY_DESIGN = "import tempfile\nf = tempfile.mktemp\nx = f()\n"

#: Prose that mentions the function must not fail the build — otherwise the rule
#: gets routed around instead of obeyed.
_NOT_A_CALL = [
    '"""This module avoids tempfile.mktemp."""\n',
    "# tempfile.mktemp() is deprecated\nx = 1\n",
]


@pytest.mark.parametrize("source", _MKTEMP_FORMS)
def test_the_rule_detects_every_spelling_of_the_deprecated_call(source):
    """Positive control: the detector can detect, on every form found in review."""
    assert _mktemp_hits(source) == 1


@pytest.mark.parametrize("source", _NOT_A_CALL)
def test_the_rule_does_not_fire_on_prose(source):
    assert _mktemp_hits(source) == 0


def test_the_rule_states_its_own_limit():
    """A stored reference is not a call shape — and the test says so out loud.

    Without this the file would read as if it made the deprecated call
    impossible; it makes the written forms impossible to reintroduce.
    """
    assert _mktemp_hits(_UNDETECTED_BY_DESIGN) == 0


def test_no_repository_source_uses_the_deprecated_tempfile_mktemp():
    """CWE-377: a temp NAME is not a temp FILE; mkstemp creates it atomically."""
    offenders = []
    for path in _scan_basis():
        try:
            count = _mktemp_hits(path.read_text(encoding="utf-8"))
        except (UnicodeDecodeError, SyntaxError):
            # a file the scanner cannot read is not a clean file
            offenders.append(f"{path.relative_to(_ROOT)}: unreadable/unparsable")
            continue
        if count:
            offenders.append(f"{path.relative_to(_ROOT)}: {count} call(s)")
    assert offenders == [], f"deprecated mktemp usage remains: {offenders}"


def test_the_scan_basis_is_not_empty_and_covers_the_fixed_probes():
    """The rule must actually see the files it was written for."""
    names = {str(p.relative_to(_ROOT)) for p in _scan_basis()}
    assert names, "empty scan basis"
    for expected in (
        "benchmarks/poll_oneoff_wall_hostcall_probe.py",
        "benchmarks/stdio_overflow_output_alloc_probe.py",
        "scripts/metrics_snapshot.py",
    ):
        assert expected in names, f"{expected} is outside the scanned basis"


# --------------------------------------------------------------------------
# the URL/host finding
# --------------------------------------------------------------------------


@pytest.fixture(scope="module")
def metrics_snapshot():
    spec = importlib.util.spec_from_file_location(
        "metrics_snapshot", _ROOT / "scripts" / "metrics_snapshot.py"
    )
    assert spec and spec.loader
    module = importlib.util.module_from_spec(spec)
    sys.modules["metrics_snapshot"] = module
    spec.loader.exec_module(module)
    return module


@pytest.mark.parametrize(
    "url, scheme, host",
    [
        ("https://api.github.com/repos/x/stargazers", "https", "api.github.com"),
        ("https://pypistats.org/api/packages/x/recent", "https", "pypistats.org"),
        # a host that merely STARTS with the allowlisted one is a different host
        ("https://api.github.com.evil.test/x", "https", "api.github.com.evil.test"),
        # userinfo and port must not be able to shift what counts as the host
        ("https://user:pw@api.github.com/z", "https", "api.github.com"),
        ("https://user:pw@evil.test/api.github.com@/z", "https", "evil.test"),
        ("https://API.GitHub.com:443/z", "https", "api.github.com"),
        # cleartext stays cleartext whatever the string contains
        ("http://api.github.com/z", "http", "api.github.com"),
        # a trailing dot is DNS-equivalent to the real host but is NOT the string
        # this script allows, so it is parsed as what it is and refused below
        ("https://api.github.com./x", "https", "api.github.com."),
    ],
)
def test_host_identity_is_parsed_not_prefix_matched(
    metrics_snapshot, url, scheme, host
):
    assert metrics_snapshot._host(url) == (scheme, host)


@pytest.mark.parametrize(
    "url",
    [
        "https://api.github.com.evil.test/repos/x",
        "https://api.github.com./repos/x",
        "https://[::1]/repos/x",
        "http://api.github.com/repos/x",
        "https://evil.test/?redirect=https://api.github.com/repos/x",
    ],
)
def test_get_refuses_every_host_that_is_not_on_the_allowlist(metrics_snapshot, url):
    """Refused before a request object exists — the allowlist is a check."""
    with pytest.raises(ValueError):
        metrics_snapshot._get(url)


def test_github_request_carries_the_github_accept_header(metrics_snapshot, monkeypatch):
    """The behaviour the CodeQL finding was about, executed rather than declared."""
    seen: dict = {}

    class _Resp:
        def read(self):
            return b'{"ok": 1}'

        def __enter__(self):
            return self

        def __exit__(self, *exc):
            return False

    def fake_urlopen(request, timeout=None):
        seen["headers"] = dict(request.headers)
        seen["url"] = request.full_url
        return _Resp()

    monkeypatch.setattr(metrics_snapshot.urllib.request, "urlopen", fake_urlopen)
    assert metrics_snapshot._get(
        "https://api.github.com/repos/x/stargazers", token="t"
    ) == {"ok": 1}
    assert seen["headers"]["Accept"] == "application/vnd.github+json"
    assert seen["headers"]["Authorization"] == "Bearer t"
    # parsed, not substring-tested: a substring check on a URL is the very shape
    # CodeQL flags, and the host is what the production code decides on
    assert metrics_snapshot._host(seen["url"]) == ("https", "api.github.com")


def test_pypistats_request_carries_the_json_accept_header(
    metrics_snapshot, monkeypatch
):
    seen: dict = {}

    class _Resp:
        def read(self):
            return b'{"package": "x"}'

        def __enter__(self):
            return self

        def __exit__(self, *exc):
            return False

    def fake_urlopen(request, timeout=None):
        seen["headers"] = dict(request.headers)
        return _Resp()

    monkeypatch.setattr(metrics_snapshot.urllib.request, "urlopen", fake_urlopen)
    metrics_snapshot._get("https://pypistats.org/api/packages/x/recent")
    assert seen["headers"]["Accept"] == "application/json"
    assert "Authorization" not in seen["headers"]
