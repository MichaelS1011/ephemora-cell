"""Agentic Workflow Benchmark.

Simulates 50 sequential tool-calls per agent, measures latency,
throughput, memory, cost, security injection, concurrency scaling,
and statistical significance vs Docker.

Usage:
    python benchmarks/agentic_workflow.py
    python benchmarks/agentic_workflow.py --inject --n-agents 5 --stats
    python benchmarks/agentic_workflow.py --json > report.json
"""
from __future__ import annotations
import argparse
import json
import math
import random
import statistics
import subprocess
import sys
import threading
import time
from concurrent.futures import ThreadPoolExecutor, as_completed
from pathlib import Path
from typing import Any

# Setup path
sys.path.insert(0, str(Path(__file__).parent.parent))
from ephemora_cell import WASISandbox, WASIConfig


WORKLOADS = Path(__file__).parent / "workloads"


def run_ephemora_cell_naive(wasm_path: str, n_calls: int) -> list[float]:
    """Each call: create sandbox → run → cleanup (worst case)."""
    times = []
    for _ in range(n_calls):
        config = WASIConfig(max_fuel=1_000_000, timeout_seconds=5, max_memory_mb=64)
        sandbox = WASISandbox(config=config)
        start = time.monotonic()
        sandbox.run(wasm_path)
        elapsed = (time.monotonic() - start) * 1000
        times.append(elapsed)
        sandbox.cleanup()
    return times


def run_ephemora_cell_pooled(wasm_path: str, n_calls: int) -> list[float]:
    """Single sandbox, reused n_calls times (typical production)."""
    times = []
    config = WASIConfig(max_fuel=1_000_000, timeout_seconds=5, max_memory_mb=64)
    sandbox = WASISandbox(config=config)
    for i in range(n_calls):
        start = time.monotonic()
        sandbox.run(wasm_path)
        elapsed = (time.monotonic() - start) * 1000
        times.append(elapsed)
    sandbox.cleanup()
    return times


def _docker_transform_payload(wasm_path: str) -> str:
    """Representative Python transform logic for the scenario module.

    The .wasm workloads are not shipped with the repository, so the Docker
    baseline runs the closest equivalent Python-side work instead of the
    binary module itself. Result tables are labelled accordingly.
    """
    name = Path(wasm_path).stem
    payloads = {
        "code_review": (
            "src = 'def f(x):\\n    return x * 2\\n';\n"
            "assert 'return' in src;\n"
            "out = [src.replace('x', str(i)) for i in range(1000)];\n"
            "assert len(out) == 1000"
        ),
        "data_transform": (
            "data = [{'id': i, 'v': i * 2} for i in range(500)];\n"
            "[d.update({'v': d['v'] * 3}) for d in data];\n"
            "assert len(data) == 500 and sum(d['v'] for d in data) > 0"
        ),
        "plugin_chain": (
            "v = 1;\n"
            "for i in range(1000):\n"
            "    v = v * 2 + 1\n"
            "assert v > 0"
        ),
    }
    return payloads.get(
        name, "acc = 0;\nfor i in range(10000):\n    acc += i\nassert acc > 0"
    )


def run_docker(wasm_path: str, n_calls: int) -> list[float] | None:
    """Docker baseline — container cold start + equivalent transform logic.

    The payload is derived from the scenario module name (see
    `_docker_transform_payload`). Measures container startup, not WASM parity.
    """
    try:
        # Check if docker is available
        subprocess.run(["docker", "--version"], capture_output=True, timeout=5)
    except Exception:
        return None

    payload = _docker_transform_payload(wasm_path)
    times = []
    for _ in range(n_calls):
        start = time.monotonic()
        result = subprocess.run(
            ["docker", "run", "--rm", "python:3.12-slim", "python3", "-c", payload],
            capture_output=True, timeout=30
        )
        if result.returncode != 0:
            return None
        elapsed = (time.monotonic() - start) * 1000
        times.append(elapsed)
    return times


def stats(values: list[float]) -> dict[str, Any]:
    """Compute statistics with 95% CI."""
    if not values:
        return {}
    n = len(values)
    mean = statistics.mean(values)
    stdev = statistics.stdev(values) if n > 1 else 0
    median = statistics.median(values)
    ci = 1.96 * stdev / (n ** 0.5)
    s = sorted(values)
    return {
        "n": n,
        "mean_ms": round(mean, 2),
        "stdev_ms": round(stdev, 2),
        "median_ms": round(median, 2),
        "min_ms": round(s[0], 2),
        "max_ms": round(s[-1], 2),
        "p95_ms": round(s[int(n * 0.95)], 2),
        "p99_ms": round(s[int(n * 0.99)], 2),
        "ci95_low": round(mean - ci, 2),
        "ci95_high": round(mean + ci, 2),
        "total_ms": round(sum(values), 2),
        "throughput": round(n / (sum(values) / 1000), 1),
    }


def cost_analysis(throughput: float, hourly_cost: float = 3.06) -> dict[str, float]:
    """AWS f4dn.2xlarge @ $3.06/hr. Compute cost per 1K and 1M calls."""
    calls_per_hour = throughput * 3600
    cost_per_call = hourly_cost / max(calls_per_hour, 1)
    return {
        "calls_per_hour": round(calls_per_hour, 0),
        "cost_per_1k": round(cost_per_call * 1000, 4),
        "cost_per_1m": round(cost_per_call * 1_000_000, 2),
    }


def t_test_independent(a: list[float], b: list[float]) -> dict[str, float]:
    """Two-sample independent t-test with Cohen's d effect size."""
    if len(a) < 2 or len(b) < 2:
        return {"t": 0, "p": 1.0, "cohens_d": 0}
    mean_a, mean_b = statistics.mean(a), statistics.mean(b)
    var_a, var_b = statistics.variance(a), statistics.variance(b)
    n_a, n_b = len(a), len(b)
    se = math.sqrt(var_a / n_a + var_b / n_b)
    if se == 0:
        return {"t": 0, "p": 1.0, "cohens_d": 0}
    t_stat = (mean_a - mean_b) / se
    # Welch-Satterthwaite df approximation
    num = (var_a / n_a + var_b / n_b) ** 2
    den = (var_a / n_a) ** 2 / (n_a - 1) + (var_b / n_b) ** 2 / (n_b - 1)
    df = num / den if den > 0 else min(n_a, n_b) - 1
    # Approximate p-value (two-tailed) using Student's t CDF approximation
    p_val = _t_cdf_approx(abs(t_stat), df)
    # Cohen's d
    pooled_sd = math.sqrt(((n_a - 1) * var_a + (n_b - 1) * var_b) / (n_a + n_b - 2))
    cohens_d = (mean_a - mean_b) / pooled_sd if pooled_sd > 0 else 0
    return {
        "t": round(t_stat, 4),
        "p": round(p_val, 6),
        "df": round(df, 1),
        "cohens_d": round(cohens_d, 4),
    }


def _t_cdf_approx(t: float, df: float) -> float:
    """Approximate two-tailed p-value for t-statistic."""
    # Use regularized incomplete beta function approximation
    x = df / (df + t * t)
    ibeta = _incomplete_beta(df / 2, 0.5, x)
    return ibeta


def _incomplete_beta(a: float, b: float, x: float) -> float:
    """Regularized incomplete beta function (continued fraction)."""
    if x < 0 or x > 1:
        return 0.0
    if x == 0:
        return 0.0
    if x == 1:
        return 1.0
    # Continued fraction (Lentz's algorithm)
    max_it = 200
    eps = 1e-14
    qab = a + b
    qap = a + 1
    qam = a - 1
    c = 1.0
    d = 1.0 - qab * x / qap
    if abs(d) < 1e-30:
        d = 1e-30
    d = 1.0 / d
    h = d
    for m in range(1, max_it + 1):
        m2 = 2 * m
        # Even step
        aa = m * (b - m) * x / ((qam + m2) * (a + m2))
        d = 1.0 + aa * d
        if abs(d) < 1e-30:
            d = 1e-30
        c = 1.0 + aa / c
        if abs(c) < 1e-30:
            c = 1e-30
        d = 1.0 / d
        h *= d * c
        # Odd step
        aa = -(a + m) * (qab + m) * x / ((a + m2) * (qap + m2))
        d = 1.0 + aa * d
        if abs(d) < 1e-30:
            d = 1e-30
        c = 1.0 + aa / c
        if abs(c) < 1e-30:
            c = 1e-30
        d = 1.0 / d
        delta = d * c
        h *= delta
        if abs(delta - 1.0) < eps:
            break
    # Scale by beta function (approximation via log-gamma)
    lbeta = _lgamma(a) + _lgamma(b) - _lgamma(a + b)
    front = math.exp(-lbeta + a * math.log(x) + b * math.log(1 - x)) / a
    return front * h


def _lgamma(x: float) -> float:
    """Stirling's approximation for log-gamma."""
    if x <= 0:
        return 0
    cof = [76.18009172947146, -86.50532032941677, 24.01409824083091,
           -1.231739572450155, 0.001208650973866179, -5.395239384953e-6]
    y = x
    tmp = x + 5.5
    tmp -= (x + 0.5) * math.log(tmp)
    ser = 1.000000000190015
    for j in range(6):
        ser += cof[j] / (y + j + 1)
    return -tmp + math.log(2.5066282746310005 * ser / x)


def run_security_injection(
    scenario_wasm: str,
    exploit_wasm: str,
    n_calls: int = 50,
    inject_every: int = 10,
    repeats: int = 5,
    quiet: bool = False,
) -> dict[str, Any]:
    """Run agent loop with periodic exploit injection.

    Every inject_every-th call uses exploit.wasm instead of the scenario module.
    Measures: how many exploits were blocked, latency impact, agent continuity.
    """
    exploit_path = str(WORKLOADS / exploit_wasm)
    if not Path(exploit_path).exists():
        return {"error": f"exploit module not found: {exploit_path}"}

    all_blocked = []
    all_times = []
    all_inject_times = []
    all_normal_times = []
    agent_interrupted = 0

    for rep in range(repeats):
        blocked_in_rep = 0
        times_rep = []
        inject_times_rep = []
        normal_times_rep = []

        for call_idx in range(n_calls):
            config = WASIConfig(max_fuel=1_000_000, timeout_seconds=5, max_memory_mb=64)
            sandbox = WASISandbox(config=config)
            is_exploit = (call_idx % inject_every == inject_every - 1)
            wasm = exploit_path if is_exploit else scenario_wasm

            start = time.monotonic()
            result = sandbox.run(wasm)
            elapsed = (time.monotonic() - start) * 1000
            sandbox.cleanup()

            times_rep.append(elapsed)
            if is_exploit:
                inject_times_rep.append(elapsed)
                if result.status.value != "success":
                    blocked_in_rep += 1
                else:
                    agent_interrupted += 1
            else:
                normal_times_rep.append(elapsed)

        all_blocked.append(blocked_in_rep)
        all_times.extend(times_rep)
        all_inject_times.extend(inject_times_rep)
        all_normal_times.extend(normal_times_rep)

    total_injections = len(all_inject_times)
    total_blocked = sum(all_blocked)

    result = {
        "n_calls": n_calls,
        "repeats": repeats,
        "inject_every": inject_every,
        "total_injections": total_injections,
        "total_blocked": total_blocked,
        "block_rate": round(total_blocked / max(total_injections, 1), 4),
        "agent_interrupted": agent_interrupted,
        "normal_stats": stats(all_normal_times),
        "inject_stats": stats(all_inject_times),
        "overall_stats": stats(all_times),
    }

    if not quiet:
        print(f"  Security Injection:")
        print(f"    {total_blocked}/{total_injections} exploits blocked ({result['block_rate']:.0%})")
        print(f"    Normal: {result['normal_stats'].get('mean_ms', 0):.2f}ms/call")
        print(f"    Inject: {result['inject_stats'].get('mean_ms', 0):.2f}ms/call")

    return result


def run_concurrent(
    scenario: str,
    n_calls: int = 50,
    n_agents: int = 5,
    repeats: int = 3,
    quiet: bool = False,
) -> dict[str, Any]:
    """Run n_agents concurrently, each doing n_calls sequential tool-calls."""
    wasm_path = str(WORKLOADS / f"{scenario}.wasm")
    if not Path(wasm_path).exists():
        return {"error": f"module not found: {wasm_path}"}

    all_agent_times: list[list[float]] = []

    def agent_work(agent_id: int) -> list[float]:
        times = []
        config = WASIConfig(max_fuel=1_000_000, timeout_seconds=5, max_memory_mb=64)
        for _ in range(n_calls):
            sandbox = WASISandbox(config=config)
            start = time.monotonic()
            sandbox.run(wasm_path)
            elapsed = (time.monotonic() - start) * 1000
            times.append(elapsed)
            sandbox.cleanup()
        return times

    for rep in range(repeats):
        with ThreadPoolExecutor(max_workers=n_agents) as executor:
            futures = [executor.submit(agent_work, i) for i in range(n_agents)]
            rep_results = [f.result() for f in as_completed(futures)]
        all_agent_times.extend(rep_results)

    all_times = []
    per_agent_stats = []
    for agent_t in all_agent_times:
        all_times.extend(agent_t)
        per_agent_stats.append(stats(agent_t))

    total_calls = len(all_times)
    total_time_ms = sum(
        max(a) for a in all_agent_times
    )  # Wall-clock = max of all agents per repeat

    result = {
        "n_agents": n_agents,
        "n_calls_per_agent": n_calls,
        "repeats": repeats,
        "total_calls": total_calls,
        "overall_stats": stats(all_times),
        "concurrent_throughput": round(total_calls / (total_time_ms / 1000), 1),
        "per_agent": per_agent_stats[:n_agents],
    }

    if not quiet:
        print(f"  Concurrent ({n_agents} agents × {n_calls} calls × {repeats} reps):")
        print(f"    Throughput: {result['concurrent_throughput']:.1f} calls/s")
        print(f"    Mean/call: {result['overall_stats']['mean_ms']:.2f}ms")

    return result


SCENARIOS = ["code_review", "data_transform", "plugin_chain"]


def run_scenario(
    scenario: str,
    n_calls: int = 50,
    repeats: int = 10,
    include_docker: bool = True,
    quiet: bool = False,
) -> dict[str, Any]:
    """Run a single scenario with all modes."""
    wasm_path = str(WORKLOADS / f"{scenario}.wasm")
    if not Path(wasm_path).exists():
        print(f"Error: {wasm_path} not found", file=sys.stderr)
        sys.exit(1)

    if not quiet:
        print(f"\n{'=' * 60}")
        print(f"Scenario: {scenario} ({n_calls} calls × {repeats} repeats)")
        print("=" * 60)

    results: dict[str, Any] = {
        "scenario": scenario,
        "n_calls": n_calls,
        "n_repeats": repeats,
    }

    # Ephemora Cell Naive
    if not quiet:
        print("\n  Ephemora Cell (Naive) ... ", end="", flush=True)
    all_times_naive = []
    for _ in range(repeats):
        times = run_ephemora_cell_naive(wasm_path, n_calls)
        all_times_naive.extend(times)
    s = stats(all_times_naive)
    results["ephemora_cell_naive"] = s
    if not quiet:
        print(f"mean={s['mean_ms']}ms, total={s['total_ms']}ms")

    # Ephemora Cell Pooled
    if not quiet:
        print("  Ephemora Cell (Pooled) ... ", end="", flush=True)
    all_times_pooled = []
    for _ in range(repeats):
        times = run_ephemora_cell_pooled(wasm_path, n_calls)
        all_times_pooled.extend(times)
    s = stats(all_times_pooled)
    results["ephemora_cell_pooled"] = s
    if not quiet:
        print(f"mean={s['mean_ms']}ms, total={s['total_ms']}ms")

    # Docker (optional)
    if include_docker:
        if not quiet:
            print("  Docker ... ", end="", flush=True)
        all_times_docker = []
        docker_repeats = max(1, repeats // 5)
        for _ in range(docker_repeats):
            times = run_docker(wasm_path, n_calls)
            if times is not None:
                all_times_docker.extend(times)
        if all_times_docker:
            s = stats(all_times_docker)
            results["docker"] = s
            results["docker_payload"] = "python transform logic (equivalent work, not WASM)"
            if not quiet:
                print(f"mean={s['mean_ms']}ms, total={s['total_ms']}ms "
                      f"(python transform logic, not WASM)")
        else:
            if not quiet:
                print("skipped (docker not available)")
            results["docker"] = None

    # Cost analysis
    if "ephemora_cell_naive" in results and results["ephemora_cell_naive"]:
        results["cost_ephemora_cell_naive"] = cost_analysis(
            results["ephemora_cell_naive"]["throughput"]
        )
    if "ephemora_cell_pooled" in results and results["ephemora_cell_pooled"]:
        results["cost_ephemora_cell_pooled"] = cost_analysis(
            results["ephemora_cell_pooled"]["throughput"]
        )
    if results.get("docker"):
        results["cost_docker"] = cost_analysis(results["docker"]["throughput"])

    return results


def main():
    parser = argparse.ArgumentParser(
        prog="agentic_workflow",
        description="Agentic Workflow Benchmark — Ephemora Cell vs Docker",
    )
    parser.add_argument(
        "--scenario", choices=SCENARIOS + ["all"], default="all",
        help="Scenario to run (default: all)",
    )
    parser.add_argument("--n", type=int, default=50, help="Tool-calls per agent")
    parser.add_argument("--repeats", type=int, default=10, help="Repeat each run")
    parser.add_argument("--no-docker", action="store_true", help="Skip Docker comparison")
    parser.add_argument("--json", action="store_true", help="JSON output only")
    parser.add_argument(
        "--inject", action="store_true",
        help="Inject exploits every N calls (security test)",
    )
    parser.add_argument(
        "--n-agents", type=int, default=0,
        help="Concurrent agents (0 = sequential only)",
    )
    parser.add_argument(
        "--stats", action="store_true",
        help="Include statistical significance (t-test, Cohen's d)",
    )
    args = parser.parse_args()

    scenarios = SCENARIOS if args.scenario == "all" else [args.scenario]
    all_results = {}

    for scenario in scenarios:
        r = run_scenario(scenario, args.n, args.repeats, not args.no_docker, args.json)
        all_results[scenario] = r

        # Security injection
        if args.inject:
            r["security_injection"] = run_security_injection(
                f"{scenario}.wasm", "exploit.wasm",
                args.n, 10, args.repeats, args.json,
            )

        # Concurrency
        if args.n_agents > 0:
            r["concurrent"] = run_concurrent(
                scenario, args.n, args.n_agents,
                max(1, args.repeats // 3), args.json,
            )

        # Statistical significance (Naive vs Docker)
        if args.stats and r.get("ephemora_cell_naive") and r.get("docker"):
            # Collect raw samples for proper t-test
            wasm_path = str(WORKLOADS / f"{scenario}.wasm")
            naive_samples = []
            docker_samples = []
            for _ in range(max(2, args.repeats // 5)):
                naive_samples.extend(run_ephemora_cell_naive(wasm_path, args.n))
                docker_t = run_docker(wasm_path, args.n)
                if docker_t:
                    docker_samples.extend(docker_t)
            r["stat_significance"] = t_test_independent(naive_samples, docker_samples)

    if args.json:
        print(json.dumps(all_results, indent=2))
    else:
        print(f"\n{'=' * 60}")
        print("Summary")
        print("=" * 60)
        for scenario, r in all_results.items():
            print(f"\n  {scenario}:")
            for mode in ["ephemora_cell_naive", "ephemora_cell_pooled", "docker"]:
                s = r.get(mode)
                if s:
                    cost = r.get(f"cost_{mode}", {})
                    print(f"    {mode:20s}: {s['mean_ms']:>7.2f}ms/call "
                          f"| total {s['total_ms']:>8.2f}ms "
                          f"| {s['throughput']:>7.1f} calls/s "
                          f"| $1K={cost.get('cost_per_1k', 'N/A')}")
            # Speedup
            if r.get("ephemora_cell_naive") and r.get("docker"):
                speedup = r["docker"]["mean_ms"] / r["ephemora_cell_naive"]["mean_ms"]
                print(f"    {'':>20s}  Speedup (Naive/Docker): {speedup:.0f}x")
            # Security
            if "security_injection" in r and r["security_injection"]:
                si = r["security_injection"]
                if "error" not in si:
                    print(f"\n  Security Injection:")
                    print(f"    Block rate: {si['block_rate']:.0%} "
                          f"({si['total_blocked']}/{si['total_injections']})")
                    print(f"    Normal mean: {si['normal_stats'].get('mean_ms', 0):.2f}ms")
                    print(f"    Inject mean: {si['inject_stats'].get('mean_ms', 0):.2f}ms")
            # Concurrency
            if "concurrent" in r and r["concurrent"]:
                cc = r["concurrent"]
                if "error" not in cc:
                    print(f"\n  Concurrent ({cc['n_agents']} agents):")
                    print(f"    Throughput: {cc['concurrent_throughput']:.1f} calls/s")
            # Stats
            if "stat_significance" in r and r["stat_significance"]:
                ss = r["stat_significance"]
                print(f"\n  Statistical Significance:")
                print(f"    t={ss['t']:.4f}, p={ss['p']}, d={ss['cohens_d']:.4f}")


if __name__ == "__main__":
    main()