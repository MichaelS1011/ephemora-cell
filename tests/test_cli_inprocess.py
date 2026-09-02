"""In-process CLI tests — makes cmd_run/cmd_inspect/cmd_build/main measurable.

Characterization tests: the same surface the subprocess tests in test_cli.py
cover externally, called directly so coverage counts it. capsys/monkeypatch
isolate stdout/stderr/argv; SystemExit is asserted via pytest.raises.
"""

from __future__ import annotations

import json
import sys

sys.path.insert(0, __file__.rsplit("/", 2)[0])

from test_cli import OOB_WAT, PRINTING_WAT, _write_module

from ephemora_cell import cli


def _run(monkeypatch, capsys, argv, stdin_text=""):
    monkeypatch.setattr(sys, "argv", ["ephemora-cell", *argv])
    monkeypatch.setattr(
        sys,
        "stdin",
        type(
            "FakeStdin",
            (),
            {
                "read": lambda self: stdin_text,
                "isatty": lambda self: True,
            },
        )(),
    )
    try:
        cli.main()
        return None, capsys.readouterr()  # success paths return without SystemExit
    except SystemExit as exc:
        return exc.code, capsys.readouterr()


class TestRunInProcess:
    def test_prints_guest_stdout_exit_0(self, monkeypatch, capsys, tmp_path):
        wasm = _write_module(tmp_path, PRINTING_WAT)
        code, out = _run(monkeypatch, capsys, ["run", str(wasm)])
        assert code == 0
        assert "HELLO-CLI-STDOUT" in out.out

    def test_json_mode_stdout_is_pure_json(self, monkeypatch, capsys, tmp_path):
        wasm = _write_module(tmp_path, PRINTING_WAT)
        code, out = _run(monkeypatch, capsys, ["run", str(wasm), "--json"])
        assert code == 0
        doc = json.loads(out.out)
        assert doc["status"] == "success"
        assert "security_baseline" in doc

    def test_missing_module_clean_error(self, monkeypatch, capsys, tmp_path):
        code, out = _run(monkeypatch, capsys, ["run", str(tmp_path / "nope.wasm")])
        assert code == 1
        assert "not found" in out.err
        assert "Traceback" not in out.err

    def test_oob_maps_to_memory_error_exit(self, monkeypatch, capsys, tmp_path):
        wasm = _write_module(tmp_path, OOB_WAT)
        code, out = _run(monkeypatch, capsys, ["run", str(wasm), "--json"])
        assert code == 1
        assert json.loads(out.out)["status"] == "memory_exceeded"

    def test_malformed_allow_env_rejected(self, monkeypatch, capsys, tmp_path):
        wasm = _write_module(tmp_path, PRINTING_WAT)
        code, out = _run(monkeypatch, capsys, ["run", str(wasm), "--allow-env", "BAD"])
        # SystemExit carries the message string; the interpreter turns it into rc 1
        assert "NAME=VALUE" in str(code)
        assert "Traceback" not in out.err


class TestInspectInProcess:
    def test_core_module_summary(self, monkeypatch, capsys, tmp_path):
        wasm = _write_module(tmp_path, PRINTING_WAT)
        code, out = _run(monkeypatch, capsys, ["inspect", str(wasm)])
        assert code is None  # success returns without SystemExit
        assert str(wasm.name) in out.out or "module" in out.out.lower()

    def test_json_output(self, monkeypatch, capsys, tmp_path):
        wasm = _write_module(tmp_path, PRINTING_WAT)
        code, out = _run(monkeypatch, capsys, ["inspect", str(wasm), "--json"])
        assert code is None
        assert isinstance(json.loads(out.out), dict)


class TestBuildGuidanceInProcess:
    def test_python_source_gives_guidance_rc2(self, monkeypatch, capsys, tmp_path):
        src = tmp_path / "tool.py"
        src.write_text("print('hi')\n")
        code, out = _run(monkeypatch, capsys, ["build", str(src)])
        assert code == 2
        assert "guidance:" in out.err

    def test_unknown_extension_error_rc2(self, monkeypatch, capsys, tmp_path):
        src = tmp_path / "tool.txt"
        src.write_text("x\n")
        code, out = _run(monkeypatch, capsys, ["build", str(src)])
        assert code == 2
        assert "no WASM build recipe" in out.err

    def test_missing_source_error_rc1(self, monkeypatch, capsys, tmp_path):
        code, out = _run(monkeypatch, capsys, ["build", str(tmp_path / "gone.rs")])
        assert code == 1
        assert "source not found" in out.err


class TestBenchmarkInProcess:
    def test_two_runs_text_output(self, monkeypatch, capsys, tmp_path):
        wasm = _write_module(tmp_path, PRINTING_WAT)
        code, out = _run(monkeypatch, capsys, ["benchmark", str(wasm), "--n", "2"])
        assert code is None
        assert "cold_start" in out.out

    def test_json_report(self, monkeypatch, capsys, tmp_path):
        wasm = _write_module(tmp_path, PRINTING_WAT)
        code, out = _run(
            monkeypatch, capsys, ["benchmark", str(wasm), "--n", "2", "--json"]
        )
        assert code is None
        doc = json.loads(out.out)
        assert doc["warm"]["n"] == 1


class TestMainNoCommand:
    def test_no_subcommand_prints_help_rc1(self, monkeypatch, capsys):
        code, out = _run(monkeypatch, capsys, [])
        assert code == 1
        assert "usage" in out.out.lower()
