# SPDX-License-Identifier: BUSL-1.1
# Copyright 2026 Michael Soppa
"""S5 controls for the eight-vector classification harness.

The harness must distinguish an enforced policy block from a structural
refusal. These assertions pin the corrections the older "8/8 blocked" summary
got wrong:

* vectors 1-3 are proven by instantiating a real module through
  ``WASISandbox`` (unknown import), not by scanning a vanilla linker;
* vector 7 is a validation refusal (``wasm_threads=False``), classified
  REJECTED AS UNSUPPORTED, while a threads-enabled engine compiles and
  instantiates the very same shared-memory + atomics bytes;
* vectors 4/5/8 carry positive controls that actually pass;
* a parse/unknown-import refusal is never counted as BLOCKED BY POLICY;
* the harness exits 0 only when no vector is VULNERABLE, NOT VERIFIED, or
  INVALID TEST.

The harness runs in a subprocess from a neutral working directory. That is
deliberate: the 1.2.0 isolation mandate runs guest code in a disposable worker
whose bootstrap removes the caller's cwd from ``sys.path``. Keeping the repo
root on ``PYTHONPATH`` (instead of relying on cwd) makes the worker import the
tree under test, not an installed copy.
"""

from __future__ import annotations

import json
import os
import subprocess
import sys
import time
from pathlib import Path

import pytest

from ephemora_cell.runtime_qualification import (
    UNQUALIFIED_RUNTIME_ENV,
    runtime_qualification,
)

REPO = Path(__file__).resolve().parents[1]
HARNESS = REPO / "benchmarks" / "verify_8_vectors.py"

VECTOR_KEYS = {
    "shell_access",
    "fork",
    "network",
    "fsync",
    "host_fs",
    "symlink",
    "threading",
    "env",
}


@pytest.fixture(scope="module")
def s5_report(tmp_path_factory: pytest.TempPathFactory):
    workdir = tmp_path_factory.mktemp("s5_verify")
    report_path = workdir / "report.json"
    env = os.environ.copy()
    env["PYTHONPATH"] = os.pathsep.join(
        part for part in (str(REPO), env.get("PYTHONPATH", "")) if part
    )
    qualified, _why = runtime_qualification()
    if not qualified:
        # The classification assertions are about the sandbox guards, not the
        # runtime-identity gate. On a development venv the documented hatch is
        # the only way a guest runs at all; the report records that it was used.
        env[UNQUALIFIED_RUNTIME_ENV] = "1"

    started = time.monotonic()
    proc = subprocess.run(
        [sys.executable, str(HARNESS), "--json", str(report_path)],
        cwd=str(workdir),
        env=env,
        capture_output=True,
        text=True,
        timeout=90,
    )
    elapsed = time.monotonic() - started

    assert report_path.is_file(), (proc.stdout, proc.stderr)
    report = json.loads(report_path.read_text(encoding="utf-8"))
    return proc, report, elapsed


def test_harness_reports_technical_classifications(s5_report):
    proc, report, elapsed = s5_report
    assert proc.returncode == 0, (
        "harness did not pass:",
        proc.stdout[-4000:],
        proc.stderr[-2000:],
    )
    assert elapsed < 60, f"harness took {elapsed:.1f}s, expected <60s"

    vectors = {v["key"]: v for v in report["vectors"]}
    assert set(vectors) == VECTOR_KEYS
    for vector in report["vectors"]:
        assert {"classification", "reached_guard", "controls"} <= set(vector)

    # Running on a dev venv is allowed only through the documented hatch, and
    # the report must say so; the runtime gate itself is never silently bypassed.
    if not report["runtime"]["qualified"]:
        assert report["runtime"]["unqualified_allowed"] is True
    assert report["summary"]["runtime_gate_refused"] is False

    # 1-3: real instantiation through the product, refused as unknown imports.
    for key in ("shell_access", "fork", "network"):
        vector = vectors[key]
        assert vector["classification"] == "REJECTED AS UNSUPPORTED", vector
        assert "unknown import" in vector["reached_guard"].lower(), vector
        assert (
            vector["controls"]["benign_preview1_import_instantiates_and_runs"] is True
        ), vector
        assert vector["evidence"]["imports_present"] == [], vector
        probes = vector["evidence"]["probes"]
        assert probes, vector
        assert all(p["outcome"] == "absent" for p in probes.values()), probes
        assert any(
            "unknown import" in p["stderr"].lower() for p in probes.values()
        ), probes

    # 7: a parser/validation refusal, never a policy block, and independently
    # proven valid on a threads-enabled engine with the same bytes.
    threading = vectors["threading"]
    assert threading["classification"] == "REJECTED AS UNSUPPORTED", threading
    assert "validation" in threading["reached_guard"].lower(), threading
    assert threading["controls"]["threads_enabled_engine_compiles"] is True
    assert threading["controls"]["threads_enabled_engine_instantiates"] is True
    assert threading["controls"]["atomic_rmw_result"] == 0
    assert len(threading["controls"]["same_bytes_sha256"]) == 64
    assert threading["evidence"]["product_refusal"]["status"] == "error"

    # 4/5/8: positive controls must actually exercise the granted capability.
    fsync_controls = vectors["fsync"]["controls"]
    assert fsync_controls["allow_fsync_releases_sync_calls"] is True
    assert fsync_controls["allow_fsync_fd_sync"]["status"] == "success"
    assert fsync_controls["allow_fsync_fd_datasync"]["status"] == "success"
    assert vectors["fsync"]["classification"] == "BLOCKED BY POLICY"

    host_fs_control = vectors["host_fs"]["controls"]["read_file_in_preopen"]
    assert host_fs_control["status"] == "success", host_fs_control
    assert host_fs_control["exit_code"] == 0, host_fs_control
    assert vectors["host_fs"]["classification"] == "BLOCKED BY POLICY"

    env_control = vectors["env"]["controls"]["allow_env_one_variable"]
    assert env_control["status"] == "success", env_control
    assert env_control["exit_code"] == 0, env_control
    assert vectors["env"]["controls"]["one_variable_visible"] is True
    assert vectors["env"]["classification"] == "BLOCKED BY POLICY"

    # 6 keeps its granted-preopen control.
    assert vectors["symlink"]["classification"] == "BLOCKED BY POLICY"
    assert vectors["symlink"]["controls"]["read_file_in_preopen"]["status"] == "success"

    # The overall count must separate the two refusal kinds and never promote
    # a parse/unknown-import refusal into a block.
    summary = report["summary"]
    assert summary["total"] == 8
    assert summary["blocked_by_policy"] == 4, summary
    assert summary["rejected_as_unsupported"] == 4, summary
    assert summary["vulnerable"] == 0, summary
    assert summary["not_verified"] == 0, summary
    assert summary["invalid_test"] == 0, summary
    assert summary["disposition"] == "PASS", summary
    for vector in report["vectors"]:
        if vector["classification"] == "BLOCKED BY POLICY":
            assert "parse" not in vector["reached_guard"].lower(), vector
