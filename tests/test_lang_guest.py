# SPDX-License-Identifier: BUSL-1.1
# Copyright 2026 Michael Soppa

"""Guest-resolution contract of the 1.2.0 language decision.

These are resolver-level tests only: none of them instantiates a sandbox or
spawns a worker, so they run fast and prove the *delivery* contract the release
decision makes binding — after install there is no manual guest hunting, an
uninstalled guest fails closed with the install command, and nothing is ever
downloaded or executed on the host.
"""

from __future__ import annotations

import hashlib

import pytest

from ephemora_cell import lang_guest
from ephemora_cell.lang import run_language
from ephemora_cell.lang_guest import GuestArtifact, GuestNotInstalled, resolve_guest

_BYO_VARS = [
    "EPHEMORA_BYO_PYTHON_GUEST",
    "EPHEMORA_BYO_PYTHON_STDLIB",
    "EPHEMORA_BYO_PYTHON_SHA256",
    "EPHEMORA_BYO_JS_GUEST",
    "EPHEMORA_BYO_JS_SHA256",
]


@pytest.fixture(autouse=True)
def _clean_env(monkeypatch):
    for var in _BYO_VARS:
        monkeypatch.delenv(var, raising=False)


def _write(tmp_path, name="guest.wasm", data=b"\x00asm\x01\x00\x00\x00"):
    p = tmp_path / name
    p.write_bytes(data)
    return str(p)


class TestFailClosed:
    # Each leg below asks what the resolver does where NO packaged guest exists,
    # which is a statement about the machine: the `no_packaged_guest` fixture
    # (tests/conftest.py) steps them aside with a reason on a host that carries
    # one, instead of failing on the environment.

    def test_uninstalled_python_fails_closed_with_install_command(
        self, no_packaged_guest
    ):
        with pytest.raises(GuestNotInstalled) as exc:
            resolve_guest("python")
        msg = str(exc.value)
        assert 'pip install "ephemora-cell[python]"' in msg
        # the decision is explicit that no silent runtime download happens
        assert "download" in msg.lower()

    def test_uninstalled_javascript_fails_closed(self, no_packaged_guest):
        with pytest.raises(GuestNotInstalled):
            resolve_guest("javascript")

    def test_unknown_language_has_no_mechanism(self):
        with pytest.raises(GuestNotInstalled):
            resolve_guest("ruby")

    def test_dispatcher_propagates_fail_closed_without_running(self, no_packaged_guest):
        # No explicit path + no installed guest -> the resolver refuses BEFORE
        # any adapter/sandbox exists (a FileNotFoundError, not a silent run).
        with pytest.raises(GuestNotInstalled):
            run_language("javascript", input_json={})


class TestByoPath:
    def test_byo_env_pin_resolves_explicit_guest(self, tmp_path, monkeypatch):
        wasm = _write(tmp_path)
        monkeypatch.setenv("EPHEMORA_BYO_JS_GUEST", wasm)
        guest = resolve_guest("javascript")
        assert isinstance(guest, GuestArtifact)
        assert guest.wasm_path == wasm
        assert guest.source.startswith("byo:")

    def test_byo_python_carries_stdlib_pin(self, tmp_path, monkeypatch):
        wasm = _write(tmp_path)
        monkeypatch.setenv("EPHEMORA_BYO_PYTHON_GUEST", wasm)
        monkeypatch.setenv("EPHEMORA_BYO_PYTHON_STDLIB", str(tmp_path))
        guest = resolve_guest("python")
        assert guest.stdlib_dir == str(tmp_path)

    def test_byo_missing_file_fails_closed(self, monkeypatch):
        monkeypatch.setenv("EPHEMORA_BYO_JS_GUEST", "/nope/absent.wasm")
        with pytest.raises(GuestNotInstalled):
            resolve_guest("javascript")

    def test_byo_digest_mismatch_refuses(self, tmp_path, monkeypatch):
        wasm = _write(tmp_path)
        monkeypatch.setenv("EPHEMORA_BYO_JS_GUEST", wasm)
        monkeypatch.setenv("EPHEMORA_BYO_JS_SHA256", "deadbeef" * 8)
        with pytest.raises(GuestNotInstalled, match="digest mismatch"):
            resolve_guest("javascript")

    def test_byo_digest_match_passes(self, tmp_path, monkeypatch):
        wasm = _write(tmp_path)
        digest = hashlib.sha256(open(wasm, "rb").read()).hexdigest()
        monkeypatch.setenv("EPHEMORA_BYO_JS_GUEST", wasm)
        monkeypatch.setenv("EPHEMORA_BYO_JS_SHA256", digest)
        assert resolve_guest("javascript").expected_sha256 == digest


class _FakeEP:
    def __init__(self, group, name, factory, dist=None):
        self._group = group
        self.name = name
        self.value = f"pkg:{name}"
        self._factory = factory
        self.dist = dist

    def load(self):
        return self._factory


class _FakeDist:
    def __init__(self, name):
        self.metadata = {"Name": name}


class TestPackageEntryPoint:
    def _patch_ep(self, monkeypatch, ep):
        # emulate importlib.metadata.entry_points(group=...) -> matching EPs
        monkeypatch.setattr(
            lang_guest.metadata,
            "entry_points",
            lambda group=None: [e for e in (ep,) if e._group == group],
        )

    def test_installed_package_guest_resolves(self, tmp_path, monkeypatch):
        wasm = _write(tmp_path)
        factory = lambda: {  # noqa: E731 (test stand-in for an entry point)
            "wasm_path": wasm,
            "stdlib_dir": None,
            "expected_sha256": None,
            "version": "3.14.0",
        }
        dist = _FakeDist("ephemora-cell-javascript-guest")
        ep = _FakeEP(
            lang_guest.GUEST_ENTRY_POINT_GROUP, "javascript", factory, dist=dist
        )
        self._patch_ep(monkeypatch, ep)
        guest = resolve_guest("javascript")
        assert guest.wasm_path == wasm
        assert guest.version == "3.14.0"
        assert guest.source == "package:ephemora-cell-javascript-guest"

    def test_package_guest_digest_mismatch_refuses(self, tmp_path, monkeypatch):
        wasm = _write(tmp_path)
        factory = lambda: {  # noqa: E731
            "wasm_path": wasm,
            "expected_sha256": "0" * 64,
            "version": "1",
        }
        dist = _FakeDist("ephemora-cell-python-guest")
        ep = _FakeEP(lang_guest.GUEST_ENTRY_POINT_GROUP, "python", factory, dist=dist)
        self._patch_ep(monkeypatch, ep)
        with pytest.raises(GuestNotInstalled, match="digest mismatch"):
            resolve_guest("python")

    def test_byo_takes_precedence_over_package(self, tmp_path, monkeypatch):
        byo = _write(tmp_path, name="byo.wasm", data=b"\x00asm\x02\x00\x00\x00")
        pkg = _write(tmp_path, name="pkg.wasm")
        monkeypatch.setenv("EPHEMORA_BYO_PYTHON_GUEST", byo)
        factory = lambda: {"wasm_path": pkg, "version": "9"}  # noqa: E731
        dist = _FakeDist("ephemora-cell-python-guest")
        ep = _FakeEP(lang_guest.GUEST_ENTRY_POINT_GROUP, "python", factory, dist=dist)
        self._patch_ep(monkeypatch, ep)
        assert resolve_guest("python").wasm_path == byo


def test_sha256_file_matches_hashlib(tmp_path):
    path = _write(tmp_path, data=b"abcdef")
    assert lang_guest._sha256_file(path) == hashlib.sha256(b"abcdef").hexdigest()
