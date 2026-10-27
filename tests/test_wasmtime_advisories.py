"""Range evaluation for the advisory watcher, pinned to real advisory ranges."""

from __future__ import annotations

import importlib.util
import sys
from pathlib import Path

import pytest

_ROOT = Path(__file__).resolve().parents[1]
_spec = importlib.util.spec_from_file_location(
    "check_wasmtime_advisories", _ROOT / "scripts" / "check_wasmtime_advisories.py"
)
assert _spec and _spec.loader
watch = importlib.util.module_from_spec(_spec)
sys.modules["check_wasmtime_advisories"] = watch
_spec.loader.exec_module(watch)

#: GHSA-mghf-wjfp-p5xm, the 2026-10 aarch64 br_table escape.
BR_TABLE = "<36.0.19, >=37.0.0, <48.0.7, >=49.0.0, <49.0.4"
#: GHSA-m9f7-9w4p-gv38, the macOS filesystem escape, patched in 49.0.3.
RENAME_ESCAPE = "<=36.0.17, >=37.0.0, <=48.0.5, >=49.0.0, <=49.0.2"
#: GHSA-9pvw-hwfg-92h5, component stream type confusion, patched in 49.0.4.
STREAM_PANIC = ">=46.0.0, <48.0.7, >=49.0.0, <49.0.4"


def test_qualified_version_parses_through_post_and_local_segments():
    assert watch.release_tuple("49.0.4.post1+git.2c2970205f") == (49, 0, 4)


@pytest.mark.parametrize(
    "version,affected",
    [
        ("49.0.3", True),
        ("49.0.3.post2+git.1d21c90f", True),
        ("49.0.4", False),
        ("49.0.4.post1+git.2c2970205f", False),
        ("50.0.0", False),
        ("37.0.0", True),
        ("36.0.19", False),
        ("36.0.18", True),
    ],
)
def test_br_table_range(version, affected):
    assert watch.is_affected(version, [BR_TABLE]) is affected


@pytest.mark.parametrize(
    "version,affected",
    [("49.0.2", True), ("49.0.3", False), ("49.0.4", False), ("48.0.5", True)],
)
def test_rename_escape_range(version, affected):
    assert watch.is_affected(version, [RENAME_ESCAPE]) is affected


def test_stream_panic_range_is_closed_by_49_0_4():
    assert watch.is_affected("49.0.3", [STREAM_PANIC]) is True
    assert watch.is_affected("49.0.4", [STREAM_PANIC]) is False


def test_every_range_in_a_list_is_evaluated():
    assert watch.is_affected("49.0.3", ["<40.0.0", STREAM_PANIC]) is True
    assert watch.is_affected("49.0.4", ["<40.0.0", STREAM_PANIC]) is False


def test_unknown_constraint_fails_closed():
    with pytest.raises(ValueError):
        watch.parse_range("~> 49.0")


def test_historical_advisory_ranges_are_out_of_line():
    assert watch.concerns_line(["<= 0.38.1, >=0.37.0"]) is False
    assert watch.concerns_line([BR_TABLE]) is True


def test_exact_version_range_matches_only_that_version():
    assert watch.is_affected("49.0.0", ["49.0.0"]) is True
    assert watch.is_affected("49.0.4", ["49.0.0"]) is False


#: GHSA-j2g9-4prp-pf6h (wasmtime-wasi datetime overflow) and
#: GHSA-c9gc-w9vx-w86p (wasi-http body DoS), as published on 2026-10-21.
#: The final bare 49.0.0 is a single affected version, not an open lower bound.
J2G9_C9GC = "< 36.0.16, >= 37.0.0, >= 47.0.0, < 48.0.3, 49.0.0"


@pytest.mark.parametrize(
    "version,affected",
    [
        ("36.0.15", True),
        ("36.0.16", False),
        ("48.0.2", True),
        ("48.0.3", False),
        ("49.0.0", True),
        ("49.0.1", False),
        ("49.0.4.post1+git.2c2970205f", False),
    ],
)
def test_consecutive_lower_bounds_do_not_open_an_unbounded_range(version, affected):
    assert watch.is_affected(version, [J2G9_C9GC]) is affected


def test_exact_version_after_a_closed_interval_is_a_separate_union_member():
    assert watch.is_affected("49.0.0", [J2G9_C9GC]) is True
    assert watch.is_affected("49.0.4", [J2G9_C9GC]) is False


def test_wasi_crate_advisories_are_not_filtered_out():
    advisory = {
        "vulnerabilities": [
            {
                "package": {"name": "wasmtime-wasi"},
                "vulnerable_version_range": ">=49.0.0, <49.0.4",
            }
        ]
    }
    assert len(watch.relevant_vulnerabilities(advisory)) == 1


def test_unrelated_package_advisories_are_ignored():
    advisory = {
        "vulnerabilities": [
            {
                "package": {"name": "some-other-crate"},
                "vulnerable_version_range": ">=1.0.0",
            }
        ]
    }
    assert watch.relevant_vulnerabilities(advisory) == []


def test_unreadable_feed_is_reported_as_not_verified(monkeypatch, capsys):
    def offline():
        raise watch.urllib.error.URLError("feed offline")

    monkeypatch.setattr(watch, "fetch_advisories", offline)
    assert watch.main() == 2
    captured = capsys.readouterr()
    assert "NOT VERIFIED" in captured.err
    assert "grants no security verdict" in captured.err
