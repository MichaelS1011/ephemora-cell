"""Regression tests for what the benchmark guard is allowed to conclude.

The guard is a blocking CI step (`Benchmark guard` in the `test` job of
ci.yml). Reproduced on the release candidate with the qualified runtime, it
failed:

    pooled_wall_median_ms: 127.967 ms (limit 5.0) [FAIL]
    default_wall_median_ms: 126.607 ms (limit 20.0) [FAIL]

Not because the engine got 100x slower — it did not — but because the guard
called `sandbox.run()` with no posture and no isolation argument, and the
default posture since ADR-015 routes an untrusted Preview1 run through the
disposable worker. So the guard was measuring a process spawn against
thresholds calibrated on a pooled in-process execution (~0.5 ms guest, ~1.6 ms
wall measured 2026-10-20 on macOS arm64). A check must state the route it
measures, or its number means nothing.

An independent review then measured what that restatement did NOT yet guarantee,
and those are the legs this file now carries:

  * a route whose runs are all REFUSED still produced a median (0.08 ms on an
    unqualified runtime) and reported "pass" — a measurement that never happened;
  * a route could claim the in-process path while the host recorded the worker
    path, because nothing compared the label with `ExecutionResult.execution_mode`;
  * the declared budget could be inflated to `1_000_000_000` ms and every test
    stayed green, since the only bound was "not too tight";
  * the sandbox could be handed a different config than the route declared,
    because the spy threw the config argument away.

Nothing here weakens a threshold: the in-process budgets are the ones the guard
has always documented, and the worker route carries its own, spawn-inclusive
calibration.
"""

from __future__ import annotations

import importlib.util
import sys
from pathlib import Path
from typing import ClassVar

import pytest

_ROOT = Path(__file__).resolve().parents[1]
_spec = importlib.util.spec_from_file_location(
    "benchmark_guard", _ROOT / "benchmarks" / "benchmark_guard.py"
)
assert _spec and _spec.loader
guard = importlib.util.module_from_spec(_spec)
sys.modules["benchmark_guard"] = guard
_spec.loader.exec_module(guard)

#: A wall-clock limit below this is a claim about a pooled in-process execution.
#: The worker route includes a full process spawn, so it cannot be judged by it.
MS_SCALE_ROUTE_CEILING_MS = 500.0


def _routes():
    routes = getattr(guard, "ROUTES", None)
    assert routes, "the guard must declare its measured routes as ROUTES"
    return list(routes)


class _Result:
    """A stand-in ExecutionResult with the fields the guard is required to read."""

    def __init__(
        self, elapsed_ms=0.5, status=None, execution_mode="in_process", stderr=""
    ):
        self.elapsed_ms = elapsed_ms
        self.status = status if status is not None else guard.ExecutionStatus.SUCCESS
        self.execution_mode = execution_mode
        self.stderr = stderr


class _Sandbox:
    """Sandbox double that records every call and answers with a set sample.

    `template` is what a run returns. The guard is required to read the sample's
    status and `execution_mode`, so a test that wants to claim "this route ran"
    has to say so here — which is also how a route that refuses, or lands on the
    other path, becomes visible instead of median-of-zero.
    """

    created: ClassVar[list[_Sandbox]] = []
    template: ClassVar[_Result | None] = None

    def __init__(self, config):
        self.config = config
        self.calls: list[dict] = []

    def run(self, path, **kwargs):
        assert _Sandbox.template is not None, "test forgot to give the double a sample"
        self.calls.append(kwargs)
        return _Sandbox.template

    def cleanup(self):
        pass


@pytest.fixture()
def sandbox_double(monkeypatch):
    _Sandbox.created = []
    _Sandbox.template = _Result()

    def _factory(config):
        spy = _Sandbox(config)
        _Sandbox.created.append(spy)
        return spy

    monkeypatch.setattr(guard, "WASISandbox", _factory)
    return _Sandbox


# --------------------------------------------------------------------------
# the table itself
# --------------------------------------------------------------------------


def test_every_route_names_its_isolation_path_and_its_own_limits():
    """Each check states which execution route it measures and how it judges it."""
    declared = set()
    for route in _routes():
        assert route.name, "a measured route needs a name for the report"
        assert route.route in (
            guard.IN_PROCESS,
            guard.WORKER,
        ), f"{route.name}: route must be in-process or worker, got {route.route!r}"
        assert route.limits, f"{route.name}: declares no threshold at all"
        assert set(route.limits) <= {
            "wall",
            "guest",
        }, f"{route.name}: unknown metric in {sorted(route.limits)}"
        assert (
            route.calibration
        ), f"{route.name}: a limit without a calibration is a guess"
        assert route.name not in declared, f"duplicate check name {route.name}"
        declared.add(route.name)
        # every route must be able to say which path it expects to observe
        assert route.expected_mode in ("in_process", "subprocess")


def test_both_routes_are_measured_and_the_default_posture_is_not_dropped():
    """Silently dropping the worker leg would make the guard blind, not green.

    The worker route is what an ordinary caller gets, so it has to stay in the
    table — measured on its own scale rather than removed.
    """
    routes = _routes()
    assert {r.route for r in routes} == {
        guard.IN_PROCESS,
        guard.WORKER,
    }, "the guard must measure the pooled in-process route AND the worker route"
    workers = [r for r in routes if r.route == guard.WORKER]
    assert all(
        r.run_kwargs.get("trust") != guard.TRUST_TRUSTED for r in workers
    ), "a worker-route leg asserts a trusted posture: that run goes in-process"


def test_ms_scale_limits_belong_only_to_the_in_process_route():
    """The measured defect: a process spawn was judged by an in-process budget."""
    for route in _routes():
        if route.route != guard.WORKER:
            continue
        for metric, limit in route.limits.items():
            assert limit >= MS_SCALE_ROUTE_CEILING_MS, (
                f"{route.name}.{metric}: limit {limit} ms is an in-process budget "
                "applied to a route that includes a process spawn"
            )


def test_in_process_limits_keep_the_documented_budgets():
    """The in-process thresholds are the 2026-10-23 runner calibration."""
    in_process = [r for r in _routes() if r.route == guard.IN_PROCESS]
    assert in_process, "the pooled in-process route must stay measured"
    pooled = [r for r in in_process if "pooled" in r.name]
    assert pooled, "the pooling regression check (io_budget_bytes=None) must stay"
    limits = {m: lim for r in pooled for m, lim in r.limits.items()}
    assert limits["wall"] <= 50.0, f"pooled wall budget drifted: {limits['wall']}"
    assert limits["guest"] <= 5.0, f"pooled guest budget drifted: {limits['guest']}"
    default = [r for r in in_process if "pooled" not in r.name]
    assert default, "the default-configuration in-process leg must stay"
    assert all(lim <= 50.0 for r in default for lim in r.limits.values())


def test_no_limit_is_softer_than_the_guard_is_allowed_to_be(monkeypatch, capsys):
    """Negative control on the gate's own design: an advisory limit fails it.

    Measured during review: nothing stopped a budget being raised to
    1_000_000_000 ms while every structural test stayed green.
    """
    blown = guard.Route(
        name="pooled_inprocess",
        route=guard.IN_PROCESS,
        config=guard.WASIConfig(io_budget_bytes=None),
        run_kwargs={"use_subprocess": False, "trust": guard.TRUST_TRUSTED},
        limits={"wall": 1_000_000_000.0},
        calibration="absurd",
    )
    monkeypatch.setattr(guard, "ROUTES", (blown,))
    monkeypatch.setattr(guard, "fuel_invariance", lambda: (True, "fake"))
    monkeypatch.setattr(guard, "slow_control", lambda: (True, "fake"))

    assert guard.main() == 1
    out = capsys.readouterr().out
    assert "advisory" in out, out


# --------------------------------------------------------------------------
# the measurement, not just the table
# --------------------------------------------------------------------------


def test_route_kwargs_and_config_are_the_ones_the_route_declares(sandbox_double):
    """The label cannot drift from the call: kwargs AND the sandbox config."""
    for route in _routes():
        sandbox_double.created.clear()
        # the double answers with the mode the route claims; the next two legs
        # show that a different answer is a failure, not a number
        sandbox_double.template = _Result(execution_mode=route.expected_mode)
        guard.measure(route, runs=2, warmup=1)
        assert sandbox_double.created, f"{route.name}: nothing was executed"
        sandbox = sandbox_double.created[0]
        assert vars(sandbox.config) == vars(
            route.config
        ), f"{route.name}: the sandbox got a different config than declared"
        for call in sandbox.calls:
            if route.route == guard.IN_PROCESS:
                assert (
                    call.get("use_subprocess") is False
                ), f"{route.name}: declared in-process, called with {call}"
                assert (
                    call.get("trust") == guard.TRUST_TRUSTED
                ), f"{route.name}: an in-process run needs the trusted posture, got {call}"
            else:
                assert (
                    call.get("use_subprocess") is not False
                ), f"{route.name}: declared worker, called with {call}"


def test_a_refused_run_is_not_a_timing_sample(sandbox_double):
    """A machine where every run is refused must fail, not report 0.08 ms.

    Measured during review on an unqualified runtime: all three routes "passed"
    their budgets because a refusal still produces a number.
    """
    sandbox_double.template = _Result(
        elapsed_ms=0.0,
        status=guard.ExecutionStatus.ERROR,
        stderr="refused: unqualified runtime",
    )
    with pytest.raises(guard.RouteNotMeasured) as exc:
        guard.measure(_routes()[0], runs=2, warmup=0)
    assert "refusal is not a timing sample" in str(exc.value)


def test_the_observed_execution_mode_must_match_the_declared_route(sandbox_double):
    """Claiming in-process while the host recorded the worker is a failure."""
    sandbox_double.template = _Result(execution_mode="subprocess")
    in_process = next(r for r in _routes() if r.route == guard.IN_PROCESS)
    with pytest.raises(guard.RouteNotMeasured) as exc:
        guard.measure(in_process, runs=2, warmup=0)
    assert "execution_mode" in str(exc.value)


def test_a_route_that_measures_nothing_cannot_report_a_median(sandbox_double):
    with pytest.raises(guard.RouteNotMeasured):
        guard.measure(_routes()[0], runs=0, warmup=0)


def test_guard_reports_not_measured_routes_as_failure(
    sandbox_double, monkeypatch, capsys
):
    """`main()` must not turn a missing measurement into a green step."""
    monkeypatch.setattr(guard, "fuel_invariance", lambda: (True, "fake"))
    monkeypatch.setattr(guard, "slow_control", lambda: (True, "fake"))

    def refuse(route, runs=1, warmup=0):
        raise guard.RouteNotMeasured(f"{route.name}: refused")

    monkeypatch.setattr(guard, "measure", refuse)
    assert guard.main() == 1
    out = capsys.readouterr().out
    assert "NOT MEASURED" in out, out


# --------------------------------------------------------------------------
# the rest of the gate
# --------------------------------------------------------------------------


def test_guard_still_checks_fuel_invariance_within_the_run(monkeypatch, capsys):
    """The fuel assertion stays invariance, never an absolute per-platform count."""
    seen = {}

    def fake_invariance():
        seen["called"] = True
        return True, "fuel run1=1 run2=1 (fake)"

    monkeypatch.setattr(guard, "fuel_invariance", fake_invariance)
    monkeypatch.setattr(guard, "slow_control", lambda: (True, "fake"))
    monkeypatch.setattr(
        guard,
        "measure",
        lambda route, runs=1, warmup=0: guard.SampleStats(0.0, 0.0, 0.0, 0.0),
    )

    assert guard.main() == 0
    assert seen.get("called"), "the fuel-invariance leg disappeared from the guard"
    out = capsys.readouterr().out
    assert "fuel_invariance" in out
    for route in _routes():
        assert route.name in out, f"{route.name} is not reported"


def test_guard_fails_loudly_when_a_route_breaks_its_budget(monkeypatch, capsys):
    """Negative control: a breached limit must exit non-zero, never read as green."""
    monkeypatch.setattr(guard, "fuel_invariance", lambda: (True, "fake"))
    monkeypatch.setattr(guard, "slow_control", lambda: (True, "fake"))

    limits = {r.name: r.limits for r in _routes()}

    def fake_measure(route, runs=1, warmup=0):
        worst = max(limits[route.name].values()) * 10.0
        return guard.SampleStats(worst, worst, worst, worst)

    monkeypatch.setattr(guard, "measure", fake_measure)

    assert guard.main() == 1
    out = capsys.readouterr().out
    assert "FAIL" in out and "benchmark-guard" in out


def test_guard_fails_if_the_slow_control_is_not_detected(monkeypatch, capsys):
    """If a recalibration makes the guard blind to a stall, the guard fails."""
    monkeypatch.setattr(guard, "fuel_invariance", lambda: (True, "fake"))
    monkeypatch.setattr(
        guard,
        "measure",
        lambda route, runs=1, warmup=0: guard.SampleStats(0.0, 0.0, 0.0, 0.0),
    )
    monkeypatch.setattr(guard, "slow_control", lambda: (False, "stall not seen"))

    assert guard.main() == 1
    out = capsys.readouterr().out
    assert "slow_control" in out and "FAIL" in out
