#!/usr/bin/env python3
"""Performance evidence & fair comparison (measurement only).

Separates the THREE execution modes and never lets the fastest stand in for
the security architecture:

  * in_process          — technical baseline / microbenchmark (NOT representative
                          of the protected posture).
  * protected_worker    — the ADR-015 forced process isolation (use_subprocess).
  * linux_reference /   — NOT TESTED on a darwin lab host; needs the pilot VM
    pilot_vm              (NOT TESTED). No substitute value is invented.

Reuses existing workloads by digest; historical benchmark files are never
touched (new evidence lands under benchmarks/results/<date>/).

Pure measurement: no product-code change, no security-config change to win a
number, no runtime optimisation. Sign/verify overhead uses the optional
`cryptography` extra; if absent it is marked NOT MEASURED, not guessed.

Run:
    python benchmarks/perf_evidence.py
"""

from __future__ import annotations

import hashlib
import json
import os
import platform
import resource
import subprocess
import sys
import time
from concurrent.futures import ThreadPoolExecutor
from datetime import date
from importlib.metadata import version as _pkg_version
from pathlib import Path

REPO = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(REPO))

from ephemora_cell import WASIConfig, WASISandbox

HELLO = REPO / "examples" / "hello.wasm"
COREMARK = REPO / "benchmarks" / "workloads" / "coremark.wasm"
OUT_DIR = REPO / "benchmarks" / "results" / date.today().isoformat()


def sha256(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


def percentile(samples: list[float], p: float) -> float | None:
    """Nearest-rank percentile on a sorted copy; None on empty input."""
    if not samples:
        return None
    s = sorted(samples)
    k = max(0, min(len(s) - 1, round((p / 100.0) * (len(s) - 1))))
    return s[k]


def distribution(samples: list[float]) -> dict:
    if not samples:
        return {"n": 0}
    s = sorted(samples)
    return {
        "n": len(s),
        "min_ms": round(s[0], 3),
        "p50_ms": round(percentile(s, 50), 3),
        "p95_ms": round(percentile(s, 95), 3),
        "p99_ms": round(percentile(s, 99), 3),
        "max_ms": round(s[-1], 3),
        "mean_ms": round(sum(s) / len(s), 3),
    }


def one_run(sandbox: WASISandbox, wasm: Path, **kw) -> float:
    """Wall time (ms) of a single sandbox.run; returns elapsed by our clock."""
    t0 = time.perf_counter()
    sandbox.run(str(wasm), **kw)
    return (time.perf_counter() - t0) * 1000.0


def measure_latency(config: WASIConfig, wasm: Path, *, n: int, warmup: int, **kw):
    """Return (distributions, all_samples). Warm-up runs are discarded."""
    sandbox = WASISandbox(config=config)
    try:
        for _ in range(warmup):
            one_run(sandbox, wasm, **kw)
        samples = [one_run(sandbox, wasm, **kw) for _ in range(n)]
    finally:
        sandbox.cleanup()
    return distribution(samples), samples


def measure_throughput(config: WASIConfig, wasm: Path, *, seconds: float, **kw):
    """How many completed runs in a wall-clock window (concurrency=1)."""
    sandbox = WASISandbox(config=config)
    count = 0
    t0 = time.perf_counter()
    try:
        while (time.perf_counter() - t0) < seconds:
            one_run(sandbox, wasm, **kw)
            count += 1
    finally:
        sandbox.cleanup()
    wall = time.perf_counter() - t0
    return {
        "concurrency": 1,
        "completed": count,
        "wall_s": round(wall, 3),
        "exec_per_s": round(count / wall, 2) if wall else None,
    }


def measure_throughput_concurrent(
    config: WASIConfig, wasm: Path, *, conc: int, total: int, **kw
):
    """Concurrency via independent per-thread sandbox instances (the guest
    itself stays single-thread: max_threads=1). One sandbox per worker."""

    def _worker():
        sb = WASISandbox(config=config)
        try:
            one_run(sb, wasm, **kw)
        finally:
            sb.cleanup()

    t0 = time.perf_counter()
    with ThreadPoolExecutor(max_workers=conc) as pool:
        list(pool.map(lambda _: _worker(), range(total)))
    wall = time.perf_counter() - t0
    return {
        "concurrency": conc,
        "completed": total,
        "wall_s": round(wall, 3),
        "exec_per_s": round(total / wall, 2) if wall else None,
    }


def host_rss_probe(fn) -> dict:
    """ru_maxrss around fn. NOTE: on darwin ru_maxrss is in BYTES and is a
    HIGH-WATER MARK (never decreases), so a self delta is meaningful only when
    the run actually grows the process peak (e.g. a memory-heavy workload) and
    reads 0 for a warm repeat; children peak captures a worker subprocess.
    """
    self_before = resource.getrusage(resource.RUSAGE_SELF).ru_maxrss
    child_before = resource.getrusage(resource.RUSAGE_CHILDREN).ru_maxrss
    fn()
    self_after = resource.getrusage(resource.RUSAGE_SELF).ru_maxrss
    child_after = resource.getrusage(resource.RUSAGE_CHILDREN).ru_maxrss
    return {
        "host_self_peak_bytes": int(self_after),
        "host_self_delta_bytes": int(self_after - self_before),
        "children_peak_bytes": int(child_after),
        "children_delta_bytes": int(child_after - child_before),
        "unit_note": "bytes on darwin; ru_maxrss is a high-water mark",
    }


def record_overhead(config: WASIConfig, wasm: Path, *, reps: int) -> dict:
    """Isolate record build / canonicalize / sign / verify from the run.

    Uses one real run result to populate a record, then times only the record
    operations. sign/verify need the optional `cryptography` extra; when absent
    those two are NOT MEASURED (never fabricated).
    """
    from ephemora_cell import ExecutionReport

    sandbox = WASISandbox(config=config)
    try:
        result = sandbox.run(str(wasm))
    finally:
        sandbox.cleanup()

    def build():
        return ExecutionReport(
            status=result.status.value,
            exit_code=result.exit_code,
            elapsed_ms=result.elapsed_ms,
            fuel_consumed=result.fuel_consumed,
            fuel_budget=config.max_fuel,
            stdout_bytes=len(result.stdout.encode("utf-8")),
            stderr_bytes=len(result.stderr.encode("utf-8")),
        ).apply_config(
            config,
            effective_preopens=result.effective_preopens,
            execution_mode=result.execution_mode,
            abi=result.abi,
        )

    t0 = time.perf_counter()
    for _ in range(reps):
        build()
    build_ms = (time.perf_counter() - t0) * 1000.0 / reps

    from ephemora_cell.execution_report import canonical_bytes

    rep = build()
    payload = rep.to_dict()
    t0 = time.perf_counter()
    for _ in range(reps):
        canonical_bytes(payload)
    serial_ms = (time.perf_counter() - t0) * 1000.0 / reps

    out = {
        "build_apply_config_ms_per_record": round(build_ms, 4),
        "canonicalize_ms_per_record": round(serial_ms, 4),
        "sign_ms_per_record": None,
        "verify_ms_per_record": None,
        "signing_status": "NOT MEASURED",
    }

    try:
        from cryptography.exceptions import InvalidSignature
        from cryptography.hazmat.primitives.asymmetric.ed25519 import (
            Ed25519PrivateKey,
        )
    except ImportError:
        return out  # cryptography extra absent -> sign/verify stay NOT MEASURED

    key = Ed25519PrivateKey.generate()
    public = key.public_key()

    def verifier(canonical: bytes, sig: bytes) -> bool:
        try:
            public.verify(sig, canonical)
            return True
        except InvalidSignature:
            return False

    signed = rep.sign(key.sign, alg="EdDSA")
    t0 = time.perf_counter()
    for _ in range(reps):
        rep.sign(key.sign, alg="EdDSA")
    sign_ms = (time.perf_counter() - t0) * 1000.0 / reps

    t0 = time.perf_counter()
    for _ in range(reps):
        ExecutionReport.verify(signed, verifier)
    verify_ms = (time.perf_counter() - t0) * 1000.0 / reps

    out.update(
        {
            "sign_ms_per_record": round(sign_ms, 4),
            "verify_ms_per_record": round(verify_ms, 4),
            "signing_status": "MEASURED (Ed25519/EdDSA)",
        }
    )
    return out


def artifact_metadata(config: WASIConfig, workload_digests: dict) -> dict:
    def git(*a):
        try:
            return subprocess.run(
                ["git", *a], cwd=REPO, capture_output=True, text=True, timeout=5
            ).stdout.strip()
        except Exception:
            return None

    native = None
    try:
        import wasmtime

        native = getattr(getattr(wasmtime, "_native", None), "__version__", None)
    except Exception:
        pass

    return {
        "source_commit": git("rev-parse", "HEAD"),
        "branch": git("rev-parse", "--abbrev-ref", "HEAD"),
        "security_freeze_ref": "284b577",
        "python": platform.python_version(),
        "wasmtime_py_version": _pkg_version("wasmtime"),
        "native_runtime_digest": native,  # engine-internal digest not exposed -> None
        "architecture": platform.machine(),
        "os": f"{platform.system()} {platform.release()}",
        "cpu_limits": {
            "max_fuel": config.max_fuel,
            "max_threads": config.max_threads,
            "timeout_seconds": config.timeout_seconds,
            "io_cpu_seconds": config.io_cpu_seconds,
        },
        "memory_limits": {"max_memory_mb": config.max_memory_mb},
        "isolation": {
            "protected_worker": "use_subprocess=True (ADR-015)",
            "engine_pool_warm": "use_engine_pool=True",
            "engine_cold": "use_engine_pool=False",
        },
        "workload_digests_sha256": workload_digests,
        "host_redaction": os.path.expanduser("~"),
    }


def main() -> None:
    hello_cfg = WASIConfig(max_fuel=1_000_000, max_memory_mb=128, timeout_seconds=30)
    # CoreMark is compute-heavy: fuel metering OFF so it runs to completion
    # (matches the existing cell_sandbox posture in coremark_wasi.py).
    core_cfg = WASIConfig(max_fuel=None, max_memory_mb=256, timeout_seconds=120)
    digests = {"hello.wasm": sha256(HELLO), "coremark.wasm": sha256(COREMARK)}

    results: dict = {
        "title": "Performance evidence — three execution modes, separated",
        "measured": True,
        "fairness_rule": "the in-process warm number is NOT presented as the "
        "representative figure for the security architecture",
        "artifact_binding": artifact_metadata(hello_cfg, digests),
        "method": {
            "timing": "time.perf_counter around sandbox.run (wall latency)",
            "warmup_discarded": True,
            "percentile": "nearest-rank on sorted samples",
            "concurrency": "independent per-thread WASISandbox instances; "
            "guest stays single-thread (max_threads=1)",
        },
    }

    # ---- in-process (cold engine, warm engine pool) ----
    cold, _ = measure_latency(hello_cfg, HELLO, n=150, warmup=20, use_engine_pool=False)
    warm, _ = measure_latency(hello_cfg, HELLO, n=300, warmup=30, use_engine_pool=True)
    results["in_process"] = {
        "label": "BASELINE ONLY — not representative of protected posture",
        "cold_engine": cold,
        "warm_engine_pool": warm,
    }

    # ---- protected worker (forced process isolation) ----
    worker, _ = measure_latency(hello_cfg, HELLO, n=60, warmup=5, use_subprocess=True)
    results["protected_worker"] = {
        "label": "ADR-015 process isolation (use_subprocess=True), fresh worker per run",
        "latency": worker,
        "worker_start_cost_note": "each run spawns python -m ephemora_cell.process_worker; "
        "the delta vs warm in-process is the isolation tax",
    }

    # ---- latency already captured above per mode ----
    results["latency_distribution"] = {
        "in_process_warm_p50_p95_p99": [
            warm.get("p50_ms"),
            warm.get("p95_ms"),
            warm.get("p99_ms"),
        ],
        "protected_worker_p50_p95_p99": [
            worker.get("p50_ms"),
            worker.get("p95_ms"),
            worker.get("p99_ms"),
        ],
    }

    # ---- throughput ----
    results["throughput"] = {
        "in_process_conc1": measure_throughput(
            hello_cfg, HELLO, seconds=3.0, use_engine_pool=True
        ),
        "in_process_conc4": measure_throughput_concurrent(
            hello_cfg, HELLO, conc=4, total=120, use_engine_pool=True
        ),
        "protected_worker_conc1": measure_throughput(
            hello_cfg, HELLO, seconds=4.0, use_subprocess=True
        ),
    }

    # ---- memory ----
    results["memory"] = {
        "enforced_ceiling_max_memory_mb": hello_cfg.max_memory_mb,
        "in_process_hello_rss_delta": host_rss_probe(
            lambda: one_run(WASISandbox(config=hello_cfg), HELLO, use_engine_pool=True)
        ),
        "protected_worker_hello_rss_delta": host_rss_probe(
            lambda: one_run(WASISandbox(config=hello_cfg), HELLO, use_subprocess=True)
        ),
        "coremark_in_process_rss_peak": host_rss_probe(
            lambda: one_run(
                WASISandbox(config=core_cfg), COREMARK, use_engine_pool=True
            )
        ),
        "guest_internal_peak_note": "wasmtime guest-internal peak is not exposed on "
        "ExecutionResult; host RSS + enforced ceiling are "
        "reported instead (NOT measured separately).",
    }

    # ---- execution-record overhead ----
    results["record_overhead"] = record_overhead(hello_cfg, HELLO, reps=2000)

    # ---- linux reference profile ----
    results["linux_reference_profile"] = {
        "status": "NOT TESTED",
        "reason": "lab host is darwin; a genuine Linux reference profile with OS "
        "isolation mechanisms needs the pilot VM (NOT TESTED). Docker "
        "cold-start numbers are a different security/start model and are "
        "classified as a separate cold-start measurement, not reused as a Linux substitute.",
        "deviation_vs_pilot_vm": "unknown until measured on the pilot VM",
    }

    # ---- pilot VM ----
    results["pilot_vm"] = {
        "status": "BLOCKED — PILOT VM NOT PROVISIONED",
        "prepared_method": "same three modes, same workload digests, run natively "
        "on the provisioned Linux pilot VM; compare in-process "
        "vs protected worker vs hardened OS-isolation. No "
        "substitute value inserted.",
    }

    # ---- external alternatives ----
    results["external_comparison"] = {
        "status": "NOT TESTED",
        "reason": "no local competitor with an EQUIVALENT model (capability-bound "
        "in-process WASM + forced process isolation + signed execution "
        "attestation). wasmer/wasm3 (coremark_wasi.py) are engine-context "
        "columns, not equal-security competitors. gVisor/hardened-docker "
        "are different security boundaries — comparing them as like-for-like "
        "would be an unfair claim.",
    }

    # ---- docker cold-start classification ----
    results["docker_cold_start"] = {
        "classification": "Docker/gVisor/hardened-container numbers already in the repo "
        "(gvisor_docker_probe.py, hardened_docker_probe.py, "
        "BENCHMARK_RESULTS.md) are CONTAINER cold-start vs WASM warm "
        "runs. Different start condition AND different security model.",
        "rule": "no single 'Nx faster' factor may be claimed across those boundaries; "
        "only like-for-like (same workload, same start condition, same active "
        "security boundary) comparisons are valid — which the pilot VM will "
        "provide, not the current lab host.",
    }

    OUT_DIR.mkdir(parents=True, exist_ok=True)
    out_path = OUT_DIR / "perf_evidence.json"
    # redact home prefix for committed evidence
    home = os.path.expanduser("~")
    blob = json.dumps(results, indent=2, sort_keys=True).replace(home, "$HOME")
    out_path.write_text(blob + "\n")
    print(f"wrote {out_path.relative_to(REPO)}")
    print(
        json.dumps(
            {
                "in_process_warm_p50": warm.get("p50_ms"),
                "protected_worker_p50": worker.get("p50_ms"),
                "worker_vs_inprocess_p50_ratio": round(
                    (worker.get("p50_ms") or 0) / (warm.get("p50_ms") or 1), 1
                ),
                "record_sign_ms": results["record_overhead"]["sign_ms_per_record"],
                "not_tested_legs": "NOT TESTED / BLOCKED (see JSON)",
            },
            indent=2,
        )
    )


if __name__ == "__main__":
    main()
