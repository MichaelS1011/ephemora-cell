"""In-process tests for process_worker main() and _build_report.

Characterization tests (coverage gap: worker body ran only in spawned
subprocesses, invisible to coverage). _apply_rlimits is stubbed — its
hard RLIMIT_NOFILE=256 cannot be restored inside the pytest process.
"""

from __future__ import annotations

import io
import json
import sys

import wasmtime

sys.path.insert(0, __file__.rsplit("/", 2)[0])

import ephemora_cell.process_worker as pw
from test_cli import PRINTING_WAT, _write_module
from ephemora_cell.wasi_runtime import ExecutionResult, ExecutionStatus


def _main(monkeypatch, capsys, argv, stdin_text=""):
    monkeypatch.setattr(pw, "_apply_rlimits", lambda cfg: None)
    monkeypatch.setattr(sys, "stdin", io.StringIO(stdin_text))
    rc = pw.main(argv)
    return rc, capsys.readouterr()


def _payload(config=None, args=None, stdin=None):
    p = {}
    if config is not None:
        p["config"] = config
    if args is not None:
        p["args"] = args
    if stdin is not None:
        p["stdin"] = stdin
    return json.dumps(p)


class TestWorkerMainPayload:
    def test_valid_payload_runs_and_prints_json(self, monkeypatch, capsys, tmp_path):
        wasm = _write_module(tmp_path, PRINTING_WAT)
        rc, out = _main(
            monkeypatch,
            capsys,
            ["--wasm", str(wasm), "--payload-stdin"],
            _payload(args=["a"], stdin="hi"),
        )
        assert rc == 0
        report = json.loads(out.out)
        assert report["status"] == "success"
        assert report["exit_code"] == 0

    def test_malformed_json_crashes_cleanly(self, monkeypatch, capsys, tmp_path):
        wasm = _write_module(tmp_path, PRINTING_WAT)
        rc, out = _main(
            monkeypatch, capsys, ["--wasm", str(wasm), "--payload-stdin"], "{not json"
        )
        assert rc == 1
        assert "worker crashed" in out.err

    def test_non_object_payload_rejected(self, monkeypatch, capsys, tmp_path):
        wasm = _write_module(tmp_path, PRINTING_WAT)
        rc, out = _main(
            monkeypatch, capsys, ["--wasm", str(wasm), "--payload-stdin"], "[1,2]"
        )
        assert rc == 1
        assert "must be a JSON object" in out.err

    def test_non_string_args_rejected(self, monkeypatch, capsys, tmp_path):
        wasm = _write_module(tmp_path, PRINTING_WAT)
        rc, out = _main(
            monkeypatch,
            capsys,
            ["--wasm", str(wasm), "--payload-stdin"],
            _payload(args=["ok", 42]),
        )
        assert rc == 1
        assert "args must be a list of strings" in out.err

    def test_non_string_stdin_rejected(self, monkeypatch, capsys, tmp_path):
        wasm = _write_module(tmp_path, PRINTING_WAT)
        rc, out = _main(
            monkeypatch,
            capsys,
            ["--wasm", str(wasm), "--payload-stdin"],
            _payload(stdin=42),
        )
        assert rc == 1
        assert "stdin must be a string or null" in out.err

    def test_missing_wasm_reports_error_not_crash(self, monkeypatch, capsys, tmp_path):
        rc, out = _main(
            monkeypatch,
            capsys,
            ["--wasm", str(tmp_path / "nope.wasm"), "--payload-stdin"],
            _payload(),
        )
        assert rc == 0  # error is a report, not a crash
        report = json.loads(out.out)
        assert report["status"] == "error"
        assert "not found" in report["stderr"]

    def test_defaults_without_payload_stdin(self, monkeypatch, capsys, tmp_path):
        wasm = _write_module(tmp_path, PRINTING_WAT)
        rc, out = _main(monkeypatch, capsys, ["--wasm", str(wasm)])
        assert rc == 0
        assert json.loads(out.out)["status"] == "success"


class TestBuildReport:
    def test_success_fields(self):
        result = ExecutionResult(
            status=ExecutionStatus.SUCCESS,
            exit_code=0,
            stdout="hi",
            elapsed_ms=12.5,
            effective_preopens=("/tmp/a",),
            io_bytes_written=7,
        )
        r = pw._build_report(result, 3.0, pw.WASIConfig())
        assert r["status"] == "success"
        assert r["exit_code"] == 0
        assert r["effective_preopens"] == ["/tmp/a"]
        assert r["baseline_ms"] == 3.0
        assert r["io_budget_exceeded"] is False

    def test_timeout_status_and_override(self):
        result = ExecutionResult(
            status=ExecutionStatus.TIMEOUT, exit_code=-1, stderr="fuel"
        )
        r = pw._build_report(result, 1.0, pw.WASIConfig(), io_budget_exceeded=True)
        assert r["status"] == "timeout"
        assert r["exit_code"] == -1
        assert r["io_budget_exceeded"] is True
