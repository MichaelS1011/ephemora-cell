"""Regression tests for the CI runtime bootstrap's platform gate.

The first public `macos-15` run failed before any test executed:
`qualified runtime requires a macOS arm64 platform tag, got
'macosx-10.13-universal2'`. The runner's python.org interpreter is universal2:
it runs natively on arm64 but reports its deployment target (10.13) as the
platform tag, not the host version. The gate therefore accepts an arm64 or
universal2 interpreter on arm64 hardware and takes the macOS 11.0 floor from
the running host; these tests pin that acceptance and the refusals around it.
"""

from __future__ import annotations

import importlib.util
import sys
from pathlib import Path

import pytest

_ROOT = Path(__file__).resolve().parents[1]
_spec = importlib.util.spec_from_file_location(
    "ci_runtime_bootstrap", _ROOT / "scripts" / "ci_runtime_bootstrap.py"
)
assert _spec and _spec.loader
bootstrap = importlib.util.module_from_spec(_spec)
sys.modules["ci_runtime_bootstrap"] = bootstrap
_spec.loader.exec_module(bootstrap)


def _gate(monkeypatch, *, machine: str, tag: str, release: str) -> str:
    monkeypatch.setattr(bootstrap.platform, "machine", lambda: machine)
    monkeypatch.setattr(bootstrap.sysconfig, "get_platform", lambda: tag)
    monkeypatch.setattr(bootstrap.platform, "mac_ver", lambda: (release, "", ""))
    return bootstrap._platform_gate()


def test_universal2_interpreter_on_apple_silicon_is_accepted(monkeypatch):
    tag = _gate(
        monkeypatch,
        machine="arm64",
        tag="macosx-10.13-universal2",
        release="15.6.1",
    )
    assert tag == "macosx-10.13-universal2"


def test_native_arm64_interpreter_is_accepted(monkeypatch):
    tag = _gate(monkeypatch, machine="arm64", tag="macosx-11.0-arm64", release="14.5")
    assert tag == "macosx-11.0-arm64"


def test_x64_interpreter_is_refused(monkeypatch):
    with pytest.raises(bootstrap.BootstrapError, match="requires arm64"):
        _gate(
            monkeypatch,
            machine="x86_64",
            tag="macosx-15.0-x86_64",
            release="15.6.1",
        )


def test_non_macos_platform_tag_is_refused(monkeypatch):
    with pytest.raises(bootstrap.BootstrapError, match="arm64 or universal2"):
        _gate(
            monkeypatch,
            machine="arm64",
            tag="linux-aarch64",
            release="15.6.1",
        )


def test_host_older_than_macos_11_is_refused(monkeypatch):
    with pytest.raises(bootstrap.BootstrapError, match=r"11\.0"):
        _gate(
            monkeypatch,
            machine="arm64",
            tag="macosx-10.15-universal2",
            release="10.15.7",
        )


def test_unreadable_host_version_fails_closed(monkeypatch):
    with pytest.raises(bootstrap.BootstrapError, match="cannot read"):
        _gate(monkeypatch, machine="arm64", tag="macosx-11.0-arm64", release="")


@pytest.mark.parametrize(
    "url",
    [
        "http://github.com/x.whl",
        "https://user:pass@github.com/x.whl",
        "https://example.com/x.whl",
    ],
)
def test_download_url_must_be_credential_free_https_on_an_asset_host(url):
    with pytest.raises(bootstrap.BootstrapError):
        bootstrap._require_https(url)


def test_wheel_name_is_checked_before_the_bytes(tmp_path):
    with pytest.raises(bootstrap.BootstrapError, match="wheel name"):
        bootstrap._verify_wheel(
            tmp_path / "wasmtime-49.0.4.post1+git.2c2970205f-py3-none-any.whl"
        )
