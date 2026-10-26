# SPDX-License-Identifier: BUSL-1.1
# Copyright 2026 Michael Soppa

"""v1.2 — host book files refuse symlinks and group-/world-writable modes.

The tenant book and the ledgers are the running account behind the budget: a
book anyone can write is a budget anyone can inflate, and a book that is a
symlink can be swapped for a fresh one to reset the account. Both must fail
closed at construction, not silently at the first admit.
"""

from __future__ import annotations

import os
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

import pytest

from ephemora_cell.tenant import Charge, TenantStore


def test_a_world_writable_book_is_refused(tmp_path):
    book = tmp_path / "book.jsonl"
    book.write_text("")
    os.chmod(book, 0o666)
    with pytest.raises(PermissionError):
        TenantStore(book)


def test_a_group_writable_book_is_refused(tmp_path):
    book = tmp_path / "book.jsonl"
    book.write_text("")
    os.chmod(book, 0o664)
    with pytest.raises(PermissionError):
        TenantStore(book)


def test_an_owner_only_writable_book_is_accepted(tmp_path):
    book = tmp_path / "book.jsonl"
    book.write_text("")
    os.chmod(book, 0o644)
    store = TenantStore(book)
    admission = store.admit("t", reserve=Charge())
    assert admission.allowed


def test_a_symlinked_book_is_refused(tmp_path):
    target = tmp_path / "real.jsonl"
    target.write_text("")
    link = tmp_path / "book.jsonl"
    link.symlink_to(target)
    with pytest.raises(OSError):
        TenantStore(link)


def test_a_fresh_book_is_created_and_admits(tmp_path):
    store = TenantStore(tmp_path / "new.jsonl")
    assert store.admit("t", reserve=Charge()).allowed
