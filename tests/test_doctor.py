# SPDX-License-Identifier: BUSL-1.1
# Copyright 2026 Michael Soppa
"""Tests for ephemora_cell.doctor — the local health-check surface."""

from __future__ import annotations

import json
from pathlib import Path
from typing import ClassVar

from ephemora_cell import doctor
from ephemora_cell.runtime_qualification import (
    QUALIFIED_ENGINE_SHA256,
    NativeEngineIdentity,
    runtime_line_ok,
    version_tuple,
)


class TestVersionTuple:
    def test_release_fields(self):
        assert version_tuple("49.0.3") == (49, 0, 3)

    def test_post_and_local_suffix_dropped(self):
        assert version_tuple("49.0.4.post1+git.2c2970205f") == (49, 0, 4)

    def test_zero_micro(self):
        assert version_tuple("49.0.0") == (49, 0, 0)


class TestRuntimeFloor:
    """The line rule the gate and this diagnosis share (one source)."""

    def test_below_floor_fails(self):
        assert runtime_line_ok("49.0.3") is False

    def test_floor_ok(self):
        assert runtime_line_ok("49.0.4") is True

    def test_qualified_build_ok(self):
        assert runtime_line_ok("49.0.4.post1+git.2c2970205f") is True

    def test_zero_build_fails(self):
        assert runtime_line_ok("49.0.0") is False

    def test_next_major_fails(self):
        assert runtime_line_ok("50.0.0") is False


class TestExitCode:
    def test_empty_is_zero(self):
        assert doctor.exit_code([]) == 0

    def test_ok_and_warn_are_zero(self):
        checks = [
            doctor.CheckResult("a", "ok", "d", {}),
            doctor.CheckResult("b", "warn", "d", {}),
        ]
        assert doctor.exit_code(checks) == 0

    def test_fail_is_one(self):
        assert doctor.exit_code([doctor.CheckResult("a", "fail", "d", {})]) == 1


class TestToJson:
    def test_schema_and_summary(self):
        checks = [
            doctor.CheckResult("a", "ok", "d", {}),
            doctor.CheckResult("b", "warn", "d", {}),
            doctor.CheckResult("c", "fail", "d", {"k": 1}),
        ]
        payload = doctor.to_json(checks)
        assert payload["schema"] == "ephemora-cell/doctor/1"
        assert payload["summary"] == {"ok": 1, "warn": 1, "fail": 1}
        assert payload["ok"] is False
        assert [c["name"] for c in payload["checks"]] == ["a", "b", "c"]

    def test_no_fail_means_ok(self):
        assert doctor.to_json([doctor.CheckResult("a", "warn", "d", {})])["ok"] is True

    def test_json_roundtrip(self):
        payload = doctor.to_json([doctor.CheckResult("a", "ok", "d", {"n": 1})])
        assert json.loads(json.dumps(payload)) == payload


class TestRunChecks:
    NAMES: ClassVar[list[str]] = [
        "python",
        "platform",
        "package",
        "runtime-import",
        "runtime-floor",
        "runtime-identity",
        "language-guests",
        "cli-entrypoints",
        "smoke-run",
    ]

    def test_all_names_in_order(self):
        assert [c.name for c in doctor.run_checks()] == self.NAMES

    def test_statuses_are_known(self):
        for check in doctor.run_checks():
            assert check.status in {"ok", "warn", "fail"}

    def test_never_raises_and_is_serializable(self):
        checks = doctor.run_checks()
        json.dumps(doctor.to_json(checks))
        assert doctor.exit_code(checks) in (0, 1)

    def test_floor_check_matches_logic(self):
        import importlib.metadata as md

        floor = {c.name: c for c in doctor.run_checks()}["runtime-floor"]
        try:
            version = md.version("wasmtime")
        except Exception:
            return
        assert (floor.status == "ok") is runtime_line_ok(version)


class TestPlatformCheck:
    def test_darwin_arm64_ok(self, monkeypatch):
        monkeypatch.setattr(doctor._platform, "system", lambda: "Darwin")
        monkeypatch.setattr(doctor._platform, "machine", lambda: "arm64")
        assert doctor._check_platform().status == "ok"

    def test_other_platform_warns(self, monkeypatch):
        monkeypatch.setattr(doctor._platform, "system", lambda: "Linux")
        monkeypatch.setattr(doctor._platform, "machine", lambda: "x86_64")
        result = doctor._check_platform()
        assert result.status == "warn"
        assert "NOT QUALIFIED" in result.detail


class TestRuntimeIdentity:
    @staticmethod
    def _stub(
        monkeypatch,
        *,
        match,
        path=Path("/tmp/_libwasmtime.dylib"),
        sha256=QUALIFIED_ENGINE_SHA256,
        qualified=True,
    ):
        monkeypatch.setattr(doctor, "qualified_platform", lambda: qualified)
        monkeypatch.setattr(
            doctor,
            "native_engine_identity",
            lambda: NativeEngineIdentity(path, sha256, match, "test reason"),
        )
        monkeypatch.setattr(doctor, "_engine_artifacts", lambda: [])

    def test_matching_exact_artifact_is_ok(self, monkeypatch):
        self._stub(monkeypatch, match=True)
        result = doctor._check_runtime_identity()
        assert result.status == "ok"
        assert result.data["match"] is True
        assert result.data["exact_artifact"] == "/tmp/_libwasmtime.dylib"

    def test_mismatch_on_the_qualified_platform_fails(self, monkeypatch):
        """The verdict follows the file the loader uses, not any backup copy."""
        self._stub(monkeypatch, match=False, sha256="0" * 64)
        monkeypatch.setattr(
            doctor,
            "_engine_artifacts",
            lambda: [
                {
                    "artifact": "wasmtime/_libwasmtime.dylib.bak",
                    "bytes": 10,
                    "sha256": QUALIFIED_ENGINE_SHA256,
                }
            ],
        )
        result = doctor._check_runtime_identity()
        assert result.status == "fail"
        assert result.data["match"] is False
        assert doctor.exit_code([result]) == 1

    def test_mismatch_off_the_qualified_platform_warns(self, monkeypatch):
        """Elsewhere there is no reference build to match, so it stays a warning."""
        self._stub(
            monkeypatch,
            match=None,
            path=Path("/tmp/_libwasmtime.so"),
            sha256="0" * 64,
            qualified=False,
        )
        result = doctor._check_runtime_identity()
        assert result.status == "warn"
        assert "NOT QUALIFIED" in result.detail
        assert result.data["match"] is None

    def test_missing_artifact_off_the_qualified_platform_warns(self, monkeypatch):
        self._stub(monkeypatch, match=None, path=None, sha256=None, qualified=False)
        assert doctor._check_runtime_identity().status == "warn"

    def test_missing_exact_artifact_on_the_qualified_platform_fails(self, monkeypatch):
        self._stub(monkeypatch, match=False, path=None, sha256=None)
        result = doctor._check_runtime_identity()
        assert result.status == "fail"
        assert result.data["match"] is False


class TestFormatReport:
    def test_lines_and_summary(self):
        report = doctor.format_report(
            [
                doctor.CheckResult("python", "ok", "fine", {}),
                doctor.CheckResult("runtime-floor", "fail", "bad", {}),
            ]
        )
        lines = report.splitlines()
        assert lines[0].startswith("PASS") and "python" in lines[0]
        assert lines[1].startswith("FAIL")
        assert "1 ok" in lines[2] and "1 fail" in lines[2]


class TestCliEntrypoints:
    """`cli-entrypoints` must describe the INSTALL, not the shell's PATH luck.

    Measured on the clean-room wheel install: `ephemora` was present beside the
    interpreter and the check still said "not on PATH: ephemora" — a WARN in a
    correctly installed environment is a false alarm, and a false alarm teaches
    the operator to ignore the WARN that would catch a broken install.
    """

    def _make_env(self, tmp_path, names, shebang=None):
        bin_dir = tmp_path / "venv" / "bin"
        bin_dir.mkdir(parents=True, exist_ok=True)
        for name in names:
            head = f"#!{shebang}\n" if shebang else "#!/bin/sh\n"
            (bin_dir / name).write_text(head)
        return bin_dir

    def test_scripts_beside_the_interpreter_are_ok_even_off_path(
        self, monkeypatch, tmp_path
    ):
        bin_dir = self._make_env(tmp_path, ["ephemora", "ephemora-cell"])
        monkeypatch.setattr(doctor.shutil, "which", lambda name: None)
        monkeypatch.setattr(doctor.sys, "executable", str(bin_dir / "python"))
        result = doctor._check_cli_entrypoints()
        assert result.status == "ok", result.detail
        assert result.data["paths"]["ephemora"] == str(bin_dir / "ephemora")
        # the invocation caveat stays visible, it just is not a failure
        assert "not on PATH" in result.detail

    def test_scripts_on_path_win_and_need_no_caveat(self, monkeypatch, tmp_path):
        """PATH hit from THIS environment: ok, and no "not on PATH" advice.

        Both halves are asserted — a test that only checks the status would stay
        green if the PATH preference were dropped.
        """
        bin_dir = self._make_env(tmp_path, ["ephemora", "ephemora-cell"])
        python = str(bin_dir / "python")
        monkeypatch.setattr(doctor.sys, "executable", python)
        monkeypatch.setattr(
            doctor.shutil,
            "which",
            lambda name: str(bin_dir / name),
        )
        result = doctor._check_cli_entrypoints()
        assert result.status == "ok", result.detail
        assert "not on PATH" not in result.detail
        assert result.data["paths"]["ephemora"] == str(bin_dir / "ephemora")

    def test_a_foreign_install_on_path_is_not_this_install(self, monkeypatch, tmp_path):
        """A script whose shebang names ANOTHER interpreter proves nothing here.

        Measured on the release machine: Homebrew carried an `ephemora-cell` from
        an older release, and `doctor` reported it as the entry point of the
        environment under test. Here the environment owns `ephemora-cell` only,
        and the bare name `ephemora` resolves to a foreign interpreter — so the
        release's own entry point is still missing, and saying so is the point.
        """
        bin_dir = self._make_env(tmp_path, ["ephemora-cell"])
        foreign = self._make_env(
            tmp_path / "other", ["ephemora"], shebang="/opt/homebrew/bin/python3.14"
        )
        monkeypatch.setattr(doctor.sys, "executable", str(bin_dir / "python"))
        monkeypatch.setattr(
            doctor.shutil,
            "which",
            lambda name: str(foreign / name) if name == "ephemora" else None,
        )
        result = doctor._check_cli_entrypoints()
        assert result.status == "warn", result.detail
        assert "another installation" in result.detail
        assert result.data["paths"]["ephemora"] is None

    def test_found_nowhere_is_the_warning(self, monkeypatch, tmp_path):
        # an interpreter whose script directory holds neither console script:
        # this is the broken installation the WARN exists to catch
        empty_bin = tmp_path / "bare"
        empty_bin.mkdir()
        monkeypatch.setattr(doctor.shutil, "which", lambda name: None)
        monkeypatch.setattr(doctor.sys, "executable", str(empty_bin / "python"))
        result = doctor._check_cli_entrypoints()
        assert result.status == "warn"
        assert "ephemora" in result.detail
        assert "nowhere" in result.detail
        assert str(empty_bin) in result.detail
