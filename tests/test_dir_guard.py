"""WP-B1 regression: ONE dir-guard denylist policy on BOTH ABI paths.

The Preview1 sandbox (``WASISandbox._filter_dangerous_dirs``) splits
``host::guest`` mapping entries FIRST and applies the canonical allowlist +
string denylist to the HOST part. The component path
(``ComponentSandbox._filter_dangerous_dirs``) used to re-implement the
filter over the RAW entry string without splitting, so a mapping-style
entry whose HOST part was dangerous (``/etc::guest-etc``) bypassed the
string-denylist layer on the component path (denylist drift between ABI
paths, verified 2026-09-29). Both paths now delegate to the one shared
implementation in ``ephemora_cell/_sandbox_common.py`` — these tests pin
parity.

Note: sandbox construction (``__init__``) already rejects entries whose
HOST part canonicalizes into a forbidden location on both paths, so the
filter layer is exercised directly — construct a default sandbox (no
allow_dirs) and call ``_filter_dangerous_dirs`` (the same technique
tests/test_security.py uses; the filter is the run-time defense-in-depth
layer behind config validation).
"""

from __future__ import annotations

import os
import shutil
import sys
import tempfile
from pathlib import Path

import pytest

sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))

from ephemora_cell import ComponentSandbox, WASISandbox
from ephemora_cell._sandbox_common import DANGEROUS_DIRS

# A real _DANGEROUS_DIRS entry as the HOST part of a mapping entry —
# exactly the shape that drifted (the raw string "/etc::guest-etc" matches
# no denylist prefix, the split host "/etc" does).
DANGEROUS_MAPPING_ENTRY = "/etc::guest-etc"


def _both_sandboxes():
    """Fresh sandboxes for both ABI paths (no allow_dirs configured)."""
    return (WASISandbox(), ComponentSandbox())


def test_dangerous_dirs_fixture_is_real_policy():
    """Guard the guard: the probe entry below uses a real denylist entry."""
    assert "/etc" in DANGEROUS_DIRS


def test_mapping_entry_with_dangerous_host_filtered_on_both_paths():
    """THE drift regression: a ``host::guest`` entry whose HOST part is a
    real _DANGEROUS_DIRS entry must be filtered on BOTH paths.

    Pre-fix the component path checked the RAW string and KEPT the entry —
    this test failed there while passing on Preview1.
    """
    for sandbox in _both_sandboxes():
        assert sandbox._filter_dangerous_dirs((DANGEROUS_MAPPING_ENTRY,)) == (), type(
            sandbox
        ).__name__


def test_mapping_entry_dangerous_host_subpath_filtered_on_both_paths():
    """Prefix form: host under a dangerous dir, mapped to a guest name."""
    for sandbox in _both_sandboxes():
        assert sandbox._filter_dangerous_dirs(("/etc/passwd::shadow",)) == (), type(
            sandbox
        ).__name__


def test_plain_entries_filtered_or_kept_identically_on_both_paths():
    """Plain (non-mapping) entries: identical filter results on both paths
    — dangerous dropped, ordinary kept, verbatim."""
    for sandbox in _both_sandboxes():
        assert sandbox._filter_dangerous_dirs(("/etc",)) == ()
        assert sandbox._filter_dangerous_dirs(("/usr/local",)) == ()
        assert sandbox._filter_dangerous_dirs(("/data",)) == ("/data",)
        assert sandbox._filter_dangerous_dirs(("/data/ghost",)) == ("/data/ghost",)
        assert sandbox._filter_dangerous_dirs(()) == ()


def test_both_paths_agree_on_every_probe():
    """Parity probe: for a mixed batch, both ABI paths return the SAME
    filtered tuple (the canonical check is the authority; the mapping split
    happens before every check)."""
    probes = (
        "/etc",
        DANGEROUS_MAPPING_ENTRY,
        "/proc/self::g",
        "/data",
        "/usr/local::u",
        "/private/etc::p",
        "/tmp-ish/../etc",
    )
    preview1 = WASISandbox()._filter_dangerous_dirs(probes)
    component = ComponentSandbox()._filter_dangerous_dirs(probes)
    assert preview1 == component == ("/data",)


def test_mapping_entry_with_safe_host_kept_verbatim_on_both_paths():
    """A safe mapping entry survives verbatim (the ORIGINAL entry string is
    kept; only the checks apply to the host side) on both paths."""
    target = Path.home() / f".ephemora_dir_guard_{os.getpid()}"
    target.mkdir(parents=True, exist_ok=True)
    try:
        entry = f"{target}::/"
        for sandbox in _both_sandboxes():
            assert sandbox._filter_dangerous_dirs((entry,)) == (entry,)
    finally:
        shutil.rmtree(target, ignore_errors=True)


@pytest.mark.skipif(
    sys.platform != "darwin", reason="macOS temp-root exception (/private)"
)
def test_macos_temp_root_exception_honored_on_both_paths():
    """The _under_canonical_exception carve-out survives on both paths:
    macOS temp roots stay allowed as plain entries AND as the HOST part of
    a mapping entry (pre-fix the component path dropped the mapping form:
    the raw string starts with /private/ and the exception never saw the
    split host)."""
    d = tempfile.mkdtemp(prefix="ephemora_dir_guard_")
    try:
        canon = str(Path(d).resolve())
        assert canon.startswith("/private/")
        for sandbox in _both_sandboxes():
            assert sandbox._filter_dangerous_dirs((d,)) == (d,), type(sandbox).__name__
            assert sandbox._filter_dangerous_dirs((canon,)) == (canon,), type(
                sandbox
            ).__name__
            assert sandbox._filter_dangerous_dirs((f"{canon}::/",)) == (
                f"{canon}::/",
            ), type(sandbox).__name__
    finally:
        shutil.rmtree(d, ignore_errors=True)


def test_denylist_policy_is_single_sourced():
    """Structural: both sandbox classes expose the SAME denylist objects —
    the shared policy from _sandbox_common, not two copies that can drift."""
    from ephemora_cell import wasi_02, wasi_runtime

    assert wasi_runtime.WASISandbox._DANGEROUS_DIRS is DANGEROUS_DIRS
    assert wasi_02.ComponentSandbox._DANGEROUS_DIRS is DANGEROUS_DIRS
    assert (
        wasi_runtime.WASISandbox._forbidden_canonical_match("/private/etc")
        == "/private"
    )
    assert wasi_02.ComponentSandbox._forbidden_canonical_match("/private/etc") == (
        "/private"
    )


def test_case_variant_of_a_denied_path_is_denied_on_both_paths():
    """Measured, not assumed: `realpath` is what closes case tricks, on APFS.

    A reviewer asked whether ``/ETC`` slips past a textual denylist on a
    case-insensitive filesystem. It does not, because the filter compares the
    CANONICAL path, and ``realpath("/ETC")`` returns the stored case
    (``/private/etc``) — so the denylist sees ``/etc`` whatever the caller typed.
    The counter-case that proves the comparison is not a naive lowercase match:
    ``/TMP`` stays allowed because it canonicalizes into the explicitly excepted
    ``/private/tmp``, not because of any case rule.
    """
    for sandbox in _both_sandboxes():
        name = type(sandbox).__name__
        assert sandbox._filter_dangerous_dirs(("/ETC::g",)) == (), name
        assert sandbox._filter_dangerous_dirs(("/eTc/passwd::shadow",)) == (), name
        assert sandbox._filter_dangerous_dirs(("/VAR/LOG::g",)) == (), name
        assert sandbox._filter_dangerous_dirs(("/TMP::g",)) == ("/TMP::g",), name
