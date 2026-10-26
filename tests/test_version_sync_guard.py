"""Tests for the version-sync guard (scripts/check_version_sync.py).

The guard is the machine check behind the repo's single-source versioning. Its
release-candidate contract is what these tests pin: a PEP 440 label (`rc1`,
`+gate.<sha>`) must be *understood* — a labelled build is the only mechanism that
keeps a locally produced artifact from being mistaken for the published one —
while a version that is not a version, or one that sits behind the newest tag,
must still fail hard.

`verdict()` and `_split_version()` are pure; the git-dependent half of the
script is exercised by CI itself (`python scripts/check_version_sync.py`).
"""

from __future__ import annotations

import importlib.util
from pathlib import Path

_ROOT = Path(__file__).resolve().parents[1]
_spec = importlib.util.spec_from_file_location(
    "check_version_sync", _ROOT / "scripts" / "check_version_sync.py"
)
assert _spec and _spec.loader
guard = importlib.util.module_from_spec(_spec)
_spec.loader.exec_module(guard)


def test_plain_release_equal_to_tag_is_ok() -> None:
    message, code = guard.verdict("1.1.0", "1.1.0")
    assert code == 0
    assert message.startswith("OK")


def test_release_in_progress_stays_a_warning() -> None:
    # bump -> gate -> CI -> tag: the bump commit is by definition ahead.
    _, code = guard.verdict("1.2.0", "1.1.0")
    assert code == 0
    # The final version of the line an rc tag points toward is also in progress;
    # it must not read as "older than its own release".
    message, code = guard.verdict("1.2.0", "1.2.0rc1")
    assert code == 0
    assert "release in progress" in message


def test_prerelease_label_is_parsed_and_marked_non_publishable() -> None:
    release, label = guard._split_version("1.2.0rc1")
    assert release == (1, 2, 0)
    assert label == "rc1"
    message, code = guard.verdict("1.2.0rc1", "1.1.0")
    assert code == 0
    assert "must not be published as one" in message


def test_local_label_is_parsed_and_keeps_the_release_part_separate() -> None:
    release, label = guard._split_version("1.2.0rc1+gate.7303274")
    assert release == (1, 2, 0)
    assert label == "rc1+gate.7303274"
    # A gate label on the ALREADY released line is still distinguishable by
    # name, so it is a warning with an explicit upload ban — not a fail, and not
    # silently equal to the published artifact.
    message, code = guard.verdict("1.1.0+gate.7303274", "1.1.0")
    assert code == 0
    assert "must never be uploaded as one" in message


def test_version_below_the_newest_tag_fails() -> None:
    _, code = guard.verdict("1.0.4", "1.1.0")
    assert code == 1


def test_non_pep440_string_fails_rather_than_comparing_as_equal() -> None:
    # "1.2.0.beta" is not a PEP 440 version; silently treating it as one would
    # let a typo'd identity through the release gate.
    assert guard._split_version("1.2.0.beta") is None
    _, code = guard.verdict("1.2.0.beta", "1.1.0")
    assert code == 1


def test_shipped_sources_are_in_sync_and_label_free() -> None:
    # Reads the real tree: if a bump touches only some of the four sources, this
    # fails before the release can be tagged.
    sources = {
        guard._pyproject_version(),
        guard._module_version("ephemora_cell/__init__.py"),
        guard._module_version("ephemora_cell_mcp/_version.py"),
        *guard._server_json_versions(),
    }
    assert len(sources) == 1
    version = sources.pop()
    assert guard._split_version(version) is not None
    # No gate/RC label may survive into the tracked tree of a released line.
    assert "+" not in version
