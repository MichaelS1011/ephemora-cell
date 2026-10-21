"""Tests for the conformance harnesses that produce the committed evidence.

`conformance/run_core_spec.py` writes `conformance/results/core_spec_*.json`, and
those files are the public proof behind the conformance claim in README and
`conformance/README.md`. Two defects in that harness were measured on 2026-10-19
while the release candidate's CI scope was reproduced locally:

1. The suite checkout used `git clone --depth 1`. A shallow clone carries only
   the branch tip, so `git checkout <pin>` fails with `pathspec '<pin>' did not
   match any file(s) known to git` as soon as upstream moves past the pin;
   GitHub also refuses `fetch --depth 1 <sha>` (`couldn't find remote ref`). The
   measured consequence: the core-spec job could not run at all from a cold
   cache.

2. Per-file results are cached under `.conformance_cache/core-testsuite/gen/`
   and reused whenever the file exists ("resume"). The cache carried no identity
   of the runtime or engine configuration that produced it, so a run under a
   different engine inherited numbers from an older one. Measured: the published
   `core_spec_2026-10-12.json` (labelled `wasmtime: 49.0.0`, `measured: true`)
   contains the `data`, `global` and `imports` records of the 2026-09-19 cache,
   which was produced under `wasmtime 47.0.1` and BEFORE the proposal lockdown
   of GHSA-m63x-6p34-q65x entered `ENGINE_KWARGS`.

Both are evidence-integrity defects, not softening: nothing here changes how a
command is judged, only whether a number may be attributed to a configuration.

BDD acceptance (the scenario the release claim depends on):

  Given a cold conformance cache on a machine that never ran the suite
  When  the core-spec harness prepares the suite
  Then  it checks out the pinned revision and refuses to measure any other
  And   a per-file result is only reused when it was produced by the same
        runtime version and the same engine configuration.
"""

from __future__ import annotations

import importlib.util
import json
import subprocess
import sys
import types
from datetime import datetime, timezone
from pathlib import Path

import pytest

_ROOT = Path(__file__).resolve().parents[1]


def _load(name: str, rel: str):
    spec = importlib.util.spec_from_file_location(name, _ROOT / rel)
    assert spec and spec.loader
    module = importlib.util.module_from_spec(spec)
    sys.modules[name] = module
    spec.loader.exec_module(module)
    return module


core_spec = _load("run_core_spec", "conformance/run_core_spec.py")


class _Recorder:
    """Stand-in for the module's `subprocess`, recording the git commands."""

    def __init__(self, head_sha: str, pin_known: bool = True) -> None:
        self.calls: list[list[str]] = []
        self._head = head_sha
        self._pin_known = pin_known
        self.TimeoutExpired = subprocess.TimeoutExpired
        self.CalledProcessError = subprocess.CalledProcessError

    def run(self, cmd, *args, **kwargs):
        self.calls.append(list(cmd))
        text = kwargs.get("text") or kwargs.get("encoding")
        out = ""
        code = 0
        if "rev-parse" in cmd:
            out = self._head
        elif "cat-file" in cmd:
            code = 0 if self._pin_known else 1
        elif "--version" in cmd:
            # the identity asks the suite compiler who it is; answer without git
            out = "1.0.42\n"
        return subprocess.CompletedProcess(
            cmd, code, stdout=out if text else out.encode()
        )


@pytest.fixture()
def cold_cache(tmp_path, monkeypatch):
    """Point the harness at an empty cache location inside tmp_path."""
    cache = tmp_path / ".conformance_cache" / "core-testsuite"
    monkeypatch.setattr(core_spec, "CACHE", cache)
    return cache


# --------------------------------------------------------------------------
# defect 1: the pinned revision must be reachable from a cold cache
# --------------------------------------------------------------------------


def test_core_spec_clone_is_not_shallow_and_checks_out_the_pin(cold_cache, monkeypatch):
    """Given a cold cache, the clone must be complete and the pin checked out."""
    full = core_spec.PINNED_COMMIT + "0" * (40 - len(core_spec.PINNED_COMMIT))
    rec = _Recorder(full)
    monkeypatch.setattr(core_spec, "subprocess", rec)

    core_spec.ensure_suite()

    clones = [c for c in rec.calls if "clone" in c]
    assert clones, f"no clone was issued at all: {rec.calls}"
    assert (
        "--depth" not in clones[0]
    ), f"a shallow clone cannot reach the pinned commit: {clones[0]}"
    checkouts = [c for c in rec.calls if "checkout" in c]
    assert (
        checkouts and core_spec.PINNED_COMMIT in checkouts[0]
    ), f"the pinned revision was never checked out: {rec.calls}"


def test_core_spec_refuses_to_measure_a_foreign_revision(cold_cache, monkeypatch):
    """The claim is pinned: a cache that cannot reach the pin must abort, not run."""
    foreign = "0123456789abcdef" + "0" * 26
    (cold_cache / ".git").mkdir(parents=True)
    rec = _Recorder(foreign)
    monkeypatch.setattr(core_spec, "subprocess", rec)

    with pytest.raises(SystemExit) as exc:
        core_spec.ensure_suite()

    assert "FAIL" in str(exc.value)
    assert foreign[:12] in str(exc.value) or foreign in str(exc.value)


def test_core_spec_at_pin_is_accepted_without_recloning(cold_cache, monkeypatch):
    """A warm cache already at the pin must be used as-is (no clone, no fetch churn)."""
    full = core_spec.PINNED_COMMIT + "0" * (40 - len(core_spec.PINNED_COMMIT))
    (cold_cache / ".git").mkdir(parents=True)
    rec = _Recorder(full)
    monkeypatch.setattr(core_spec, "subprocess", rec)

    core_spec.ensure_suite()

    churn = [
        c for c in rec.calls if any(w in c for w in ("clone", "fetch", "checkout"))
    ]
    assert churn == [], f"an in-place cache must not be re-fetched: {churn}"


# --------------------------------------------------------------------------
# defect 2: a cached per-file result belongs to one runtime configuration
# --------------------------------------------------------------------------


def test_core_spec_result_identity_names_runtime_and_engine():
    """The identity a cached result is stamped with is runtime + engine config."""
    ident = core_spec._identity()
    assert ident["wasmtime"]
    assert ident["engine_config"] == core_spec.ENGINE_KWARGS
    assert ident["pinned_commit"] == core_spec.PINNED_COMMIT
    assert core_spec._result_is_current({"identity": ident}) is True


def test_core_spec_stale_result_is_not_current():
    """A pre-identity cache entry, or one from another config, must not be reused."""
    ident = core_spec._identity()
    assert core_spec._result_is_current({}) is False
    assert core_spec._result_is_current({"identity": None}) is False

    other_runtime = dict(ident, wasmtime=ident["wasmtime"] + "+other")
    assert core_spec._result_is_current({"identity": other_runtime}) is False

    # GHSA-m63x-6p34-q65x posture is part of the identity: a result measured
    # with exceptions enabled says nothing about the shipped, locked-down engine.
    relaxed = dict(core_spec.ENGINE_KWARGS, wasm_exceptions=True)
    other_engine = dict(ident, engine_config=relaxed)
    assert core_spec._result_is_current({"identity": other_engine}) is False


def test_core_spec_resume_refuses_a_foreign_runtime_result(cold_cache, monkeypatch):
    """Given a cached result from another configuration, the file is re-measured."""
    stem = "address"
    gen = cold_cache / "gen" / stem
    gen.mkdir(parents=True)
    stale = gen / "result.json"
    stale.write_text(
        json.dumps(
            {
                "outcomes": {"pass": 999, "xfail": 0, "fail": 0, "skipped": 0},
                "failures": [],
                "identity": {
                    "wasmtime": "0.0.0",
                    "engine_config": {},
                    "pinned_commit": "x",
                },
            }
        )
    )

    fresh = {
        "outcomes": {"pass": 259, "xfail": 0, "fail": 1, "skipped": 1},
        "failures": [],
        "identity": core_spec._identity(),
    }
    calls: list[list[str]] = []

    class _Runner:
        TimeoutExpired = subprocess.TimeoutExpired
        CalledProcessError = subprocess.CalledProcessError

        def run(self, cmd, *a, **kw):
            if "--version" in cmd:
                return subprocess.CompletedProcess(cmd, 0, stdout="1.0.42\n")
            calls.append(list(cmd))
            (gen / "result.json").write_text(json.dumps(fresh))
            return subprocess.CompletedProcess(cmd, 0)

    monkeypatch.setattr(core_spec, "subprocess", _Runner())

    result = core_spec._run_isolated(Path(f"{stem}.wast"))

    assert calls, "the foreign-configuration result was reused without re-measuring"
    assert result["outcomes"] == fresh["outcomes"]
    assert result["outcomes"]["pass"] != 999


def test_core_spec_worker_stamps_the_identity_it_measured_with(cold_cache, monkeypatch):
    """Every cached per-file result carries the configuration it was measured under."""
    stem = "address"
    gen = cold_cache / "gen" / stem
    gen.mkdir(parents=True)

    monkeypatch.setattr(core_spec, "_wast2json", lambda wast, out: gen / "x.json")

    class _Runner:
        def __init__(self):
            self.runner = None

        def __call__(self, *a, **kw):
            return {
                "outcomes": {"pass": 1, "xfail": 0, "fail": 0, "skipped": 0},
                "failures": [],
            }

    monkeypatch.setattr(core_spec, "run_file", _Runner())
    monkeypatch.setattr(core_spec.SpecRunner, "stop", lambda self: None, raising=True)

    core_spec._worker_run(gen / f"{stem}.wast")

    payload = json.loads((gen / "result.json").read_text())
    assert payload["identity"] == core_spec._identity()
    assert core_spec._result_is_current(payload) is True


# --------------------------------------------------------------------------
# the identity must contain things that cannot be typed into a dict
# --------------------------------------------------------------------------


def test_identity_carries_observed_facts_and_not_only_declared_ones():
    """Runtime library digest, harness digest and compiler version are observed.

    A declared dict can say anything; these three fields describe the toolchain
    that produced the number. They make a bumped wabt, a different native library
    or an edited harness invalidate the cache instead of inheriting a predecessor's
    results — the exact failure mode that produced the mislabelled 2026-10-12
    evidence.
    """
    ident = core_spec._identity()
    for key in (
        "wasmtime",
        "engine_config",
        "pinned_commit",
        "runtime_library_sha256",
        "harness_sha256",
        "wast2json_version",
    ):
        assert key in ident, f"identity lost {key}"
    assert len(ident["harness_sha256"]) == 64, "harness digest is not a sha256"
    assert (
        len(ident["runtime_library_sha256"]) == 64
        or ident["runtime_library_sha256"] == "missing"
    ), ident["runtime_library_sha256"]
    assert ident["wast2json_version"] in {"missing", "error"} or "wast2json" in str(
        ident["wast2json_version"]
    ), ident["wast2json_version"]


def test_identity_changes_when_the_engine_configuration_changes():
    """An engine dict that differs is a different measurement, by definition."""
    base = core_spec._identity()
    other = dict(base, engine_config=dict(base["engine_config"], wasm_gc=True))
    assert core_spec._result_is_current(other) is False


def test_abort_result_is_stamped_like_every_other_result(cold_cache, monkeypatch):
    """A file that died is still a statement about THIS configuration.

    The synthetic abort entries used to be written without any identity, so a
    later run inherited them — and a suite in which every file aborted reported
    zero unexpected failures with a green-looking document.
    """
    import subprocess as _sp

    def boom(cmd, *args, **kwargs):
        if "--version" in cmd:
            return subprocess.CompletedProcess(cmd, 0, stdout="1.0.42\n")
        raise _sp.CalledProcessError(1, cmd)

    monkeypatch.setattr(
        core_spec,
        "subprocess",
        types.SimpleNamespace(
            run=boom,
            CalledProcessError=_sp.CalledProcessError,
            TimeoutExpired=_sp.TimeoutExpired,
        ),
    )

    result = core_spec._run_isolated(Path("relaxed_if_gt_u.wast"))
    assert result["status"] == "aborted"
    assert result["identity"] == core_spec._identity()
    assert core_spec._result_is_current(result) is True


def test_a_run_in_which_every_file_aborted_has_measured_nothing():
    """`measured` is provenance: no measurement, no flag, whatever the counts say."""
    total = {"pass": 0, "xfail": 3, "fail": 0, "skipped": 0}
    files = [{"status": "aborted"}, {"status": "aborted"}]
    assert core_spec._is_measured(files, total, aborted=2) is False
    assert core_spec._is_measured([], total, aborted=0) is False

    measured_total = {"pass": 100, "xfail": 2, "fail": 0, "skipped": 0}
    mixed = [{"status": "aborted"}, {"outcomes": measured_total}]
    assert core_spec._is_measured(mixed, measured_total, aborted=1) is True


# --------------------------------------------------------------------------
# the second published evidence file: the wasi-testsuite harness
# --------------------------------------------------------------------------


@pytest.fixture(scope="module")
def wasi_harness():
    return _load("run_wasi_testsuite", "conformance/run_wasi_testsuite.py")


def test_wasi_harness_refuses_a_cache_at_another_revision(
    tmp_path, monkeypatch, wasi_harness
):
    """The claim is pinned: a checkout on another commit must not produce evidence.

    This harness used to write `pinned_commit` into its summary as a constant and
    never compare it with the checkout — the same defect class that was closed in
    `run_core_spec.py`. Measured during the pre-push review.
    """
    cache = tmp_path / ".conformance_cache" / "wasi-testsuite"
    (cache / ".git").mkdir(parents=True)
    monkeypatch.setattr(wasi_harness, "CACHE", cache)
    foreign = "0123456789abcdef0123456789abcdef01234567"

    def fake_run(cmd, *args, **kwargs):
        out = foreign if "rev-parse" in cmd else ""
        return subprocess.CompletedProcess(cmd, 0, stdout=out, stderr="")

    monkeypatch.setattr(
        wasi_harness,
        "subprocess",
        types.SimpleNamespace(
            run=fake_run, CalledProcessError=subprocess.CalledProcessError
        ),
    )

    with pytest.raises(SystemExit) as exc:
        wasi_harness.ensure_suite()
    assert "FAIL" in str(exc.value)
    assert foreign[:12] in str(exc.value)


def test_wasi_harness_summary_records_the_commit_it_observed(
    tmp_path, monkeypatch, wasi_harness
):
    """Declared pin and observed revision sit side by side in the summary."""
    cache = tmp_path / ".conformance_cache" / "wasi-testsuite"
    (cache / ".git").mkdir(parents=True)
    results = tmp_path / "results"
    results.mkdir()
    monkeypatch.setattr(wasi_harness, "CACHE", cache)
    monkeypatch.setattr(wasi_harness, "RESULTS", results)
    monkeypatch.setenv("CELL_RETRY_LOG", str(tmp_path / "no-retries.jsonl"))

    observed = wasi_harness.PINNED_COMMIT
    monkeypatch.setattr(wasi_harness, "observed_commit", lambda: observed)
    raw = tmp_path / "raw.json"
    raw.write_text(
        json.dumps(
            {
                "results": [
                    {
                        "name": "WASI C tests [wasm32-wasip1]",
                        "runtime": {"name": "ephemora-cell"},
                        "passed": 14,
                        "xfailed": 1,
                        "xpassed": 0,
                        "failed": 0,
                        "skipped": 0,
                    }
                ]
            }
        )
    )

    wasi_harness.summarize(raw, "unit-test", datetime.now(timezone.utc))
    summary = json.loads((results / "summary-unit-test.json").read_text())
    assert summary["pinned_commit"] == wasi_harness.PINNED_COMMIT
    assert summary["observed_commit"] == observed
    assert "runtime_identity" in summary
    ident = summary["runtime_identity"]
    for key in ("python", "wasmtime", "ephemora-cell", "adapter_cli"):
        assert key in ident, f"runtime identity lost {key}"


def test_wasi_harness_observed_commit_is_honest_about_a_missing_cache(
    tmp_path, monkeypatch, wasi_harness
):
    monkeypatch.setattr(wasi_harness, "CACHE", tmp_path / "absent")
    assert wasi_harness.observed_commit() == "missing"


def test_summary_counts_per_test_outcomes_not_the_suite_header(
    tmp_path, monkeypatch, wasi_harness
):
    """An expected failure must not be counted twice.

    Measured on the 2026-10-20 run: the runner's C-suite header says
    `passed: 14, xfailed: 1` while its 14 entries are 13 pass + 1 xfail. Copying
    the header published "72 pass / 1 xfail" for 72 executed tests — 73 results
    out of 72 runs. The summary now counts the entries and keeps the diverging
    header in the document instead of quietly reconciling it.
    """
    results = tmp_path / "results"
    results.mkdir()
    monkeypatch.setattr(wasi_harness, "RESULTS", results)
    monkeypatch.setenv("CELL_RETRY_LOG", str(tmp_path / "none.jsonl"))
    raw = tmp_path / "raw.json"
    raw.write_text(
        json.dumps(
            {
                "results": [
                    {
                        "name": "WASI C tests [wasm32-wasip1]",
                        "runtime": {"name": "ephemora-cell"},
                        "passed": 14,
                        "xfailed": 1,
                        "xpassed": 0,
                        "failed": 0,
                        "skipped": 0,
                        "tests": (
                            [{"name": f"t{i}", "outcome": "pass"} for i in range(13)]
                            + [{"name": "sock_shutdown", "outcome": "xfail"}]
                        ),
                    }
                ]
            }
        )
    )

    wasi_harness.summarize(raw, "counting", datetime.now(timezone.utc))
    summary = json.loads((results / "summary-counting.json").read_text())
    assert summary["totals"]["pass"] == 13
    assert summary["totals"]["expected_fail"] == 1
    assert summary["totals"]["fail"] == 0
    assert sum(summary["totals"].values()) == 14, "each entry counted exactly once"
    # the diverging header is disclosed, not hidden
    assert summary["runner_headers"], "the header difference vanished"
    assert (
        summary["runner_headers"]["WASI C tests [wasm32-wasip1] [ephemora-cell]"][
            "pass"
        ]
        == 14
    )
    assert "counting_note" in summary


def test_an_unknown_outcome_is_counted_as_a_failure_not_dropped(
    tmp_path, monkeypatch, wasi_harness
):
    results = tmp_path / "results"
    results.mkdir()
    monkeypatch.setattr(wasi_harness, "RESULTS", results)
    monkeypatch.setenv("CELL_RETRY_LOG", str(tmp_path / "none.jsonl"))
    raw = tmp_path / "raw.json"
    raw.write_text(
        json.dumps(
            {
                "results": [
                    {
                        "name": "S",
                        "runtime": {"name": "ephemora-cell"},
                        "passed": 2,
                        "tests": [
                            {"name": "a", "outcome": "pass"},
                            {"name": "b", "outcome": "exploded"},
                        ],
                    }
                ]
            }
        )
    )
    counts, unknown = wasi_harness.count_outcomes(
        json.loads(raw.read_text())["results"][0]
    )
    assert counts["fail"] == 1, counts
    assert unknown == ["b:exploded"]
