#!/usr/bin/env python3
"""Generate extended statistics for pov_benchmark.py output.

Produces: median, std, CI (95%), min/max, boxplot (terminal Unicode).
Usage:
    python benchmarks/pov_benchmark.py
    python benchmarks/stats_summary.py /tmp/ephemora_cell-benchmarks-mac.json
"""
import sys
import json
import math
from pathlib import Path


def load_data(path: str | Path) -> dict:
    return json.loads(Path(path).read_text())


def stats(values: list[float]) -> dict:
    n = len(values)
    s = sorted(values)
    mean = sum(s) / n
    variance = sum((x - mean) ** 2 for x in s) / max(n - 1, 1)
    std = math.sqrt(variance)
    ci = 1.96 * std / math.sqrt(max(n, 1))
    median = s[n // 2] if n % 2 else (s[n // 2 - 1] + s[n // 2]) / 2
    return {
        "n": n, "mean": mean, "median": median, "std": std,
        "min": s[0], "max": s[-1],
        "p50": s[n * 50 // 100], "p95": s[n * 95 // 100],
        "p99": s[n * 99 // 100],
        "ci95": ci,
    }


def boxplot(values: list[float], label: str, width: int = 40):
    s = stats(values)
    quartiles = [s["min"], s["p50"], s["median"], s["p95"], s["p99"], s["max"]]
    lo, hi = s["min"], s["max"]
    if hi - lo == 0:
        hi = lo + 1
    def bar(v):
        pos = int((v - lo) / (hi - lo) * width)
        return " " * pos + "█"
    lines = []
    lines.append(f"  {label}")
    lines.append(f"  min  {bar(quartiles[0])} {s['min']:.2f}ms")
    lines.append(f"  p50  {bar(quartiles[1])} {s['p50']:.2f}ms")
    lines.append(f"  med  {bar(quartiles[2])} {s['median']:.2f}ms")
    lines.append(f"  p95  {bar(quartiles[3])} {s['p95']:.2f}ms")
    lines.append(f"  p99  {bar(quartiles[4])} {s['p99']:.2f}ms")
    lines.append(f"  max  {bar(quartiles[5])} {s['max']:.2f}ms")
    return "\n".join(lines)


def main():
    if len(sys.argv) < 2:
        print(f"Usage: {sys.argv[0]} <bench_json>")
        sys.exit(1)

    data = load_data(sys.argv[1])
    print("Extended Benchmark Statistics")
    print("=" * 60)

    if isinstance(data, dict) and "cold_start_raw" in data:
        platform = data.get("platform", "unknown")
        cold = data.get("cold_start_raw") or []
        warm = data.get("warm_start_raw") or []
        if cold:
            print(f"\n{platform} (Cold Start, {len(cold)} runs):")
            cs = stats(cold)
            print(f"  Mean: {cs['mean']:.2f}ms ± {cs['std']:.2f}ms")
            print(f"  Median: {cs['median']:.2f}ms")
            print(f"  P95: {cs['p95']:.2f}ms  P99: {cs['p99']:.2f}ms")
            print(f"  95% CI: [{cs['mean'] - cs['ci95']:.2f}, {cs['mean'] + cs['ci95']:.2f}]")
            print(f"  Range: {cs['min']:.2f} — {cs['max']:.2f}ms")
            print()
            print(boxplot(cold, f"  {platform} Cold"))
        if warm:
            print(f"\n{platform} (Warm Start, {len(warm)} runs):")
            ws = stats(warm)
            print(f"  Mean: {ws['mean']:.2f}ms ± {ws['std']:.2f}ms")
            print(f"  Median: {ws['median']:.2f}ms")
            print(f"  95% CI: [{ws['mean'] - ws['ci95']:.2f}, {ws['mean'] + ws['ci95']:.2f}]")
        return

    for platform, runs in data.items():
        if not isinstance(runs, list):
            continue
        cold = [r["cold_start_ms"] for r in runs if isinstance(r, dict) and "cold_start_ms" in r]
        warm = [r["warm_start_ms"] for r in runs if isinstance(r, dict) and "warm_start_ms" in r]

        if cold:
            print(f"\n{platform} (Cold Start, {len(cold)} runs):")
            cs = stats(cold)
            print(f"  Mean: {cs['mean']:.2f}ms ± {cs['std']:.2f}ms")
            print(f"  Median: {cs['median']:.2f}ms")
            print(f"  P95: {cs['p95']:.2f}ms  P99: {cs['p99']:.2f}ms")
            print(f"  95% CI: [{cs['mean'] - cs['ci95']:.2f}, {cs['mean'] + cs['ci95']:.2f}]")
            print(f"  Range: {cs['min']:.2f} — {cs['max']:.2f}ms")
            print()
            print(boxplot(cold, f"  {platform} Cold"))

        if warm:
            print(f"\n{platform} (Warm Start, {len(warm)} runs):")
            ws = stats(warm)
            print(f"  Mean: {ws['mean']:.2f}ms ± {ws['std']:.2f}ms")
            print(f"  Median: {ws['median']:.2f}ms")
            print(f"  95% CI: [{ws['mean'] - ws['ci95']:.2f}, {ws['mean'] + ws['ci95']:.2f}]")


if __name__ == "__main__":
    main()