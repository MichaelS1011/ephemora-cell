"""Benchmark guard — order-of-magnitude regression check for CI.

Deliberately LOOSE thresholds: this guards against a ~100x-scale
regression (engine pooling broken, fuel/epoch accidentally enabled on
every run), NOT against platform noise. Timing on shared CI runners is
far too volatile for tight gates, and fuel counts are per-platform
(see SECURITY.md) — so the only fuel assertion is INVARIANCE within a
single run: same module, same runner -> identical fuel_consumed.

Every measured route names the execution path it belongs to, because the
two paths legitimately differ by two orders of magnitude: since ADR-015 an
untrusted Preview1 run goes through the disposable worker, so its wall clock
contains a full process spawn. Measured 2026-10-20 on macOS arm64 with the
qualified runtime (wasmtime 49.0.3.post2+git.1d21c90f), 20 warmup + 200 timed
runs of examples/hello.wasm, median:

    pooled in-process        wall  1.61 ms   guest  0.44 ms
    default in-process       wall  2.16 ms   guest  1.12 ms
    worker (default posture) wall 114.6 ms   guest  3.12 ms

Before this was stated, the guard applied the in-process budgets to the worker
route and reported `pooled_wall_median_ms: 127.967 ms (limit 5.0) [FAIL]` on a
healthy engine — a red CI step that described the guard, not the runtime.

Checks (each bound to the route printed with it):
  1. pooled_inprocess_wall_median_ms   < 5 ms
  2. pooled_inprocess_guest_median_ms  < 5 ms
  3. default_inprocess_wall_median_ms  < 20 ms
  4. worker_default_posture_wall_median_ms < 1500 ms — one order of magnitude
     above the measured median, so a pathological spawn is caught while normal
     runner noise is not
  5. fuel invariance: two identical runs consume identical fuel

Metrics measured without a threshold are still reported, never dropped.
Exit code 0 = pass; 1 = a route broke its own budget.
"""

from __future__ import annotations

import sys
import time
from dataclasses import dataclass, field
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

import wasmtime

from ephemora_cell import ExecutionStatus, WASIConfig, WASISandbox

WASM = Path(__file__).resolve().parents[1] / "examples" / "hello.wasm"

N = 200
WARMUP = 20

#: The two execution paths a run can take, named exactly as SECURITY.md names them.
IN_PROCESS = "in-process"
WORKER = "worker"
TRUST_TRUSTED = "trusted"

#: The execution mode each route must actually report. A route label is a claim
#: about which path ran, and `ExecutionResult.execution_mode` is the host's own
#: record of that path — so the claim is checked against a fact, not against the
#: kwargs the guard passed.
MODE_OF_ROUTE = {IN_PROCESS: "in_process", WORKER: "subprocess"}

#: Softening this guard past here is itself a failure. The limits below are
#: deliberately loose (this is a ~100x regression detector), but "loose" is a
#: design decision with a bound: an independent review measured that nothing in
#: the file stopped a limit being raised to 1_000_000_000 ms, which would keep the
#: step green while measuring nothing. So the bound is asserted at run time.
MAX_PLAUSIBLE_LIMIT_MS = 2500.0


@dataclass(frozen=True)
class Route:
    """One measured execution path, its budget, and where the budget came from."""

    name: str
    route: str
    config: WASIConfig
    run_kwargs: dict = field(default_factory=dict)
    limits: dict = field(default_factory=dict)
    calibration: str = ""

    @property
    def expected_mode(self) -> str:
        """The execution mode a sample on this route must report."""
        return MODE_OF_ROUTE[self.route]


ROUTES = (
    Route(
        name="pooled_inprocess",
        route=IN_PROCESS,
        config=WASIConfig(io_budget_bytes=None),
        run_kwargs={"use_subprocess": False, "trust": TRUST_TRUSTED},
        limits={"wall": 5.0, "guest": 5.0},
        calibration="median 1.61 ms wall / 0.44 ms guest, 2026-10-20, macOS arm64",
    ),
    Route(
        name="default_inprocess",
        route=IN_PROCESS,
        config=WASIConfig(),
        run_kwargs={"use_subprocess": False, "trust": TRUST_TRUSTED},
        limits={"wall": 20.0},
        calibration="median 2.16 ms wall, 2026-10-20, macOS arm64",
    ),
    Route(
        # The documented default posture: no caller assertion, so the run is
        # routed through the disposable worker. This is what an ordinary
        # integration sees, so it stays measured — on its own scale.
        name="worker_default_posture",
        route=WORKER,
        config=WASIConfig(),
        run_kwargs={},
        limits={"wall": 1500.0},
        calibration="median 114.6-134.0 ms wall incl. process spawn, "
        "2026-10-20, macOS arm64",
    ),
)


def median(xs: list[float]) -> float:
    xs = sorted(xs)
    return xs[len(xs) // 2]


class RouteNotMeasured(RuntimeError):
    """A route produced no valid timing sample.

    Named for what it means: the guard did not measure the thing it claims to
    measure. It is a failure, never a skip and never a zero.
    """


def measure(route: Route, runs: int = N, warmup: int = WARMUP) -> tuple[float, float]:
    """Median wall and guest-reported milliseconds for one declared route.

    Raises `RouteNotMeasured` when a run on the route did not execute the guest,
    or executed it on a different path than the route claims. Without that, a
    machine on which every run is refused (an unqualified runtime, for instance)
    still produces a median — of 0.08 ms — and the guard reports "pass" for a
    measurement that never happened. Measured during the pre-push review.
    """
    sandbox = WASISandbox(config=route.config)
    try:
        for _ in range(warmup):
            sample = sandbox.run(str(WASM), **route.run_kwargs)
            _check_sample(route, sample)
        walls: list[float] = []
        guests: list[float] = []
        for _ in range(runs):
            t0 = time.perf_counter()
            result = sandbox.run(str(WASM), **route.run_kwargs)
            walls.append((time.perf_counter() - t0) * 1000)
            guests.append(result.elapsed_ms)
            _check_sample(route, result)
        if not walls:
            raise RouteNotMeasured(f"{route.name}: no timed runs were performed")
        return median(walls), median(guests)
    finally:
        sandbox.cleanup()


def _check_sample(route: Route, sample) -> None:
    if sample.status is not ExecutionStatus.SUCCESS:
        raise RouteNotMeasured(
            f"{route.name}: run did not execute the guest "
            f"(status={getattr(sample.status, 'value', sample.status)}, "
            f"stderr={sample.stderr[:120]!r}) — a refusal is not a timing sample"
        )
    mode = getattr(sample, "execution_mode", None)
    if mode != route.expected_mode:
        raise RouteNotMeasured(
            f"{route.name}: declared the {route.route} route but the host "
            f"recorded execution_mode={mode!r} — the label no longer describes "
            "what is being timed"
        )


def fuel_invariance() -> tuple[bool, str]:
    """Same module + same runner twice -> identical fuel_consumed."""
    wat = """
    (module
      (func (export "_start")
        (local $i i32)
        i32.const 0 (local.set $i)
        (loop $l
          local.get $i i32.const 1 i32.add (local.set $i)
          local.get $i i32.const 1000 i32.lt_s if (br $l) end
        )
      )
    )
    """
    wasm_bytes = bytes(wasmtime.wat2wasm(wat))
    tmp = WASM.parent / "_fuel_guard_tmp.wasm"
    tmp.write_bytes(wasm_bytes)
    try:
        fuels = []
        for _ in range(2):
            sandbox = WASISandbox(config=WASIConfig(max_fuel=1_000_000))
            try:
                result = sandbox.run(str(tmp))
                if result.status != ExecutionStatus.SUCCESS:
                    return False, f"guard module failed: {result.status.value}"
                fuels.append(result.fuel_consumed)
            finally:
                sandbox.cleanup()
        ok = fuels[0] == fuels[1] and fuels[0] is not None
        return ok, f"fuel run1={fuels[0]} run2={fuels[1]}"
    finally:
        tmp.unlink(missing_ok=True)


def main() -> int:
    failures = []

    # The guard checks its own softness first: a budget so loose that it cannot
    # fail is a disabled gate wearing the shape of a test.
    for route in ROUTES:
        for metric, limit in route.limits.items():
            if not 0 < limit <= MAX_PLAUSIBLE_LIMIT_MS:
                failures.append(
                    f"{route.name}_{metric}: limit {limit} ms is outside "
                    f"0..{MAX_PLAUSIBLE_LIMIT_MS} — the gate would be advisory"
                )
    if failures:
        for line in failures:
            print(f"{line} [FAIL]")
        print(f"benchmark-guard: {len(failures)} failure(s)")
        return 1

    for route in ROUTES:
        try:
            wall, guest = measure(route)
        except RouteNotMeasured as exc:
            print(f"{route.name}: NOT MEASURED — {exc} [FAIL]")
            failures.append(f"{route.name}: not measured")
            continue
        values = {"wall": wall, "guest": guest}
        for metric in ("wall", "guest"):
            name = f"{route.name}_{metric}_median_ms"
            value = values[metric]
            limit = route.limits.get(metric)
            if limit is None:
                print(
                    f"{name}: {value:.3f} ms [reported, no threshold — {route.route}]"
                )
                continue
            status = "ok" if value < limit else "FAIL"
            print(f"{name}: {value:.3f} ms (limit {limit}) [{status}]")
            if value >= limit:
                failures.append(f"{name}={value:.3f} >= {limit} ({route.route})")

    ok, detail = fuel_invariance()
    print(f"fuel_invariance: {detail} [{'ok' if ok else 'FAIL'}]")
    if not ok:
        failures.append(f"fuel_invariance: {detail}")

    if failures:
        print(f"benchmark-guard: {len(failures)} failure(s)")
        return 1
    print("benchmark-guard: pass")
    return 0


if __name__ == "__main__":
    sys.exit(main())
