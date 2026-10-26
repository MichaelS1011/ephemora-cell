# SPDX-License-Identifier: BUSL-1.1
# Copyright 2026 Michael Soppa

"""Fail-closed behaviour on the CLI product paths (v1.2).

"Nicht vertrauenswürdiger Code wird niemals ungeschützt als Fallback ausgeführt."
These cases pin the *style* of the refusal too: an unusable guard must produce a
clean caller error, never a host traceback and never a run that proceeds
unguarded.
"""

from __future__ import annotations

import os
import subprocess
import sys
from pathlib import Path

sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))


REPO = Path(__file__).resolve().parent.parent
ECHO_WASM = REPO / "ephemora_cell_mcp" / "tools" / "echo.wasm"


def _run(*args):
    return subprocess.run(
        [sys.executable, "-m", "ephemora_cell.cli", *args],
        capture_output=True,
        text=True,
        timeout=180,
        cwd=str(REPO),
    )


def _assert_clean_refusal(result, *, expected_code=2):
    joined = result.stdout + result.stderr
    assert result.returncode == expected_code, joined
    assert "Traceback" not in joined, joined
    assert "error:" in result.stderr


# --- an unusable admission book must refuse, cleanly -----------------------


def test_a_missing_book_directory_is_a_clean_refusal(tmp_path):
    book = tmp_path / "nope" / "book.jsonl"
    _assert_clean_refusal(
        _run("run", str(ECHO_WASM), "--tenant", "t", "--tenant-book", str(book))
    )


def test_a_directory_as_book_path_is_a_clean_refusal(tmp_path):
    _assert_clean_refusal(
        _run("run", str(ECHO_WASM), "--tenant", "t", "--tenant-book", str(tmp_path))
    )


def test_a_corrupted_book_is_a_clean_refusal(tmp_path):
    book = tmp_path / "book.jsonl"
    book.write_text("{not json}\n", encoding="utf-8")
    _assert_clean_refusal(
        _run("run", str(ECHO_WASM), "--tenant", "t", "--tenant-book", str(book))
    )


def test_a_tenant_without_a_book_is_refused(tmp_path):
    _assert_clean_refusal(_run("run", str(ECHO_WASM), "--tenant", "t"))


def test_a_cap_without_an_account_is_refused(tmp_path):
    book = tmp_path / "book.jsonl"
    result = _run(
        "run", str(ECHO_WASM), "--tenant-book", str(book), "--tenant-max-runs", "1"
    )
    _assert_clean_refusal(result)
    assert not book.exists()  # nothing ran, nothing was billed


# --- the ledger chain report refuses an unusable path the same way ----------


def test_ledger_on_a_missing_directory_is_a_clean_refusal(tmp_path):
    path = tmp_path / "nope" / "l.jsonl"
    result = _run("ledger", str(path))
    assert result.returncode == 1
    assert "Traceback" not in (result.stdout + result.stderr)
    assert "error: cannot read ledger" in result.stderr


def test_ledger_on_a_directory_is_a_clean_refusal(tmp_path):
    result = _run("ledger", str(tmp_path))
    assert result.returncode == 1
    assert "Traceback" not in (result.stdout + result.stderr)
    assert "error: cannot read ledger" in result.stderr


# --- positive control: a usable book runs and the cap is enforced ----------


def test_a_valid_book_runs_and_the_cap_is_enforced(tmp_path):
    book = tmp_path / "book.jsonl"
    first = _run(
        "run",
        str(ECHO_WASM),
        "--tenant",
        "t",
        "--tenant-book",
        str(book),
        "--tenant-max-runs",
        "1",
    )
    assert first.returncode == 0, first.stdout + first.stderr
    assert book.exists()

    second = _run(
        "run",
        str(ECHO_WASM),
        "--tenant",
        "t",
        "--tenant-book",
        str(book),
        "--tenant-max-runs",
        "1",
    )
    assert second.returncode != 0
    assert "budget exhausted" in (second.stdout + second.stderr)
    assert "Traceback" not in (second.stdout + second.stderr)
