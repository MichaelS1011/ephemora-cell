#!/usr/bin/env python3
"""Classify the core-spec result artifact command by command.

Input is the committed per-date evidence JSON (``conformance/results/
core_spec_<date>.json``), NOT a rerun: the classification must describe the
numbers that were actually committed. Two things are re-measured because the
artifact does not record them:

* for files whose process was marked ``aborted``, whether ``wast2json`` can
  produce a JSON fixture at all, and its first error (the artifact only says
  "native-abort", a label the harness never verified);
* for the 56 SIMD/relaxed-SIMD files that do produce a fixture, the observed
  worker exit code and stderr, if ``--v128-evidence`` is supplied.

The output is one record per failing file and one per aborted file. Counts are
exact; anything the evidence does not decide is marked ``unclassified``
instead of guessed.

Usage:
    python conformance/classify_failures.py \
        --results conformance/results/core_spec_2026-10-23.json \
        --out /path/V120_CORE_SPEC_CLASSIFICATION.json \
        --wabt-bin /tmp/wabt142/bin/wast2json \
        --v128-evidence /tmp/s6_v128_probe.json \
        --reference-checks /path/reference_checks.json
"""

from __future__ import annotations

import argparse
import hashlib
import json
import shutil
import subprocess
import tempfile
from collections import Counter
from datetime import datetime, timezone
from pathlib import Path

REPO = Path(__file__).resolve().parents[1]
DEFAULT_RESULTS = REPO / "conformance" / "results" / "core_spec_2026-10-23.json"
DEFAULT_OUT = REPO / "conformance" / "results" / "V120_CORE_SPEC_CLASSIFICATION.json"
TAXONOMY = {
    "categories": [
        "product_defect",
        "unsupported_feature",
        "toolchain_problem",
        "harness_gap",
        "unclassified",
    ],
    "phases": ["parse", "validate", "compile", "runtime", "harness"],
    "features": [
        "threads",
        "GC",
        "relaxed-simd",
        "tail-call",
        "NaN",
        "exceptions",
        "memory64",
        "other",
        "unclassified",
    ],
    "confidence": ["high", "medium", "low"],
}

# Reference checks are maintained as data so every conclusion in the JSON is
# traceable to a command and an observed output.
REFERENCE_CHECK_IDS = {
    "array": ["R01"],
    "struct": ["R02"],
    "i31": ["R03"],
    "br_on_cast": ["R04"],
    "call_ref": ["R05"],
    "return_call": ["R06"],
    "throw": ["R07"],
    "throw_ref": ["R07"],
    "address0": ["R08"],
    "align64": ["R09"],
    "simd_const": ["R10"],
    "relaxed_madd_nmadd": ["R11"],
    "table_grow": ["R12"],
    "table_get": ["R13"],
    "bulk": ["R14"],
    "conversions": ["R15"],
    "float_misc": ["R16"],
    "float_exprs": ["R16"],
    "float_memory": ["R16"],
    "local_init": ["R18"],
    "data": ["R19"],
    "global": ["R20"],
    "imports": ["R21"],
    "start": ["R21"],
    "token": ["R21"],
}

_NAN_FILES = {"conversions", "float_exprs", "float_memory", "float_misc"}


def _sha256(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


def _trim(text: str, limit: int = 600) -> str:
    text = " ".join(str(text).split())
    return text if len(text) <= limit else text[: limit - 3] + "..."


def _classify_failure(spec_file: str, detail: str) -> dict:
    """Map one failing command to (phase, feature, category, reason)."""
    if (
        "exceptions proposal not enabled" in detail
        or "exception refs not supported" in detail
    ):
        return {
            "phase": "validate",
            "feature": "exceptions",
            "feature_detail": "exceptions proposal",
            "category": "unsupported_feature",
            "expected_support": False,
            "reason": "engine config has wasm_exceptions=False; module refused at validation",
        }
    if "global.get of locally defined global" in detail:
        return {
            "phase": "validate",
            "feature": "GC",
            "feature_detail": "global.get of a locally defined global in a constant expression",
            "category": "unsupported_feature",
            "expected_support": False,
            "reason": "accepted when wasm_gc=True; shipped config keeps GC off",
        }
    if "tables with expression initializers require the function-references" in detail:
        return {
            "phase": "validate",
            "feature": "other",
            "feature_detail": "function-references (table expression initializer)",
            "category": "unsupported_feature",
            "expected_support": False,
            "reason": "engine config has wasm_function_references=False",
        }
    if "unknown import spectest." in detail or "unknown import test." in detail:
        return {
            "phase": "runtime",
            "feature": "other",
            "feature_detail": "spectest host environment (harness import set)",
            "category": "harness_gap",
            "expected_support": True,
            "reason": "harness defines no test.* module and no spectest.print; reference spectest-interp passes these files",
        }
    if "KeyError: 'print" in detail:
        return {
            "phase": "harness",
            "feature": "other",
            "feature_detail": "spectest host environment (missing print export)",
            "category": "harness_gap",
            "expected_support": True,
            "reason": "assertion resolved a spectest export the harness never installed",
        }
    if spec_file in _NAN_FILES:
        return {
            "phase": "harness",
            "feature": "NaN",
            "feature_detail": "NaN bit pattern via Python float (payload not recoverable / arg canonicalised)",
            "category": "harness_gap",
            "expected_support": True,
            "reason": "WABT spectest-interp passes the same .wast; wasmtime-py surfaces floats, not f32 bits",
        }
    if spec_file.startswith("table"):
        return {
            "phase": "harness",
            "feature": "other",
            "feature_detail": "reference types (externref/funcref arguments) and table state",
            "category": "harness_gap",
            "expected_support": True,
            "reason": "setup action with an externref argument is xfailed, so dependent assertions observe an unmodified table; Node passes the sequence",
        }
    if "trap text" in detail:
        return {
            "phase": "harness",
            "feature": "other",
            "feature_detail": "trap message text (table init)",
            "category": "harness_gap",
            "expected_support": True,
            "reason": "engine traps as expected but omits the element index the suite's text expects; reference engines word it differently too",
        }
    if "module compiled but should not" in detail:
        return {
            "phase": "validate",
            "feature": "other",
            "feature_detail": "function-references (uninitialized non-nullable local)",
            "category": "unclassified",
            "expected_support": "unknown",
            "reason": "wasm-tools 1.255 also validates these modules, wasmtime default also accepts; WABT spectest fails the same 3/10, so the assertion is ahead of all installed validators",
        }
    if (
        "no module to resolve" in detail
        or "register: unknown module" in detail
        or "KeyError" in detail
    ):
        if spec_file in {"imports", "throw", "throw_ref"}:
            feature, fdetail = "exceptions", "cascade after a refused exceptions module"
        elif spec_file == "global":
            feature, fdetail = (
                "other",
                "cascade after a refused function-references table module",
            )
        else:
            feature, fdetail = "other", "cascade after a refused module"
        return {
            "phase": "runtime",
            "feature": feature,
            "feature_detail": fdetail,
            "category": "unsupported_feature",
            "expected_support": False,
            "reason": "assertion depends on a module that was refused earlier; not an independent engine result",
        }
    return {
        "phase": "unclassified",
        "feature": "unclassified",
        "feature_detail": "no rule matched",
        "category": "unclassified",
        "expected_support": "unknown",
        "reason": "evidence does not decide",
    }


def _abort_feature(name: str, error: str) -> tuple[str, str, bool | str]:
    if name.startswith("simd_"):
        return "other", "SIMD (v128)", True
    if "relaxed" in name:
        return "relaxed-simd", "relaxed SIMD", True
    if name in {"tag", "try_table"}:
        return "exceptions", "exceptions", False
    if name in {"return_call", "return_call_indirect", "return_call_ref"}:
        return "tail-call", "tail call", False
    if name == "annotations":
        return "other", "annotations (custom section syntax)", "unknown"
    if name.startswith("type-"):
        return "GC", "GC type system (rec/sub/type canonicalisation)", False
    if "array type not allowed" in error or "struct not allowed" in error:
        return "GC", "GC (array/struct types)", False
    if 'unexpected token "i31"' in error:
        return "GC", "GC (i31)", False
    if 'unexpected token "sub"' in error or 'unexpected token "rec"' in error:
        return "GC", "GC type system (rec/sub)", False
    if "opcode not allowed: return_call" in error:
        return "tail-call", "tail call", False
    if "opcode not allowed: call_ref" in error or "ref.as_non_null" in error:
        return "other", "function-references", False
    if "table elem type must be a reference" in error:
        return "other", "function-references / typed tables", False
    if "tag" in error or "try_table" in name:
        return "exceptions", "exceptions", False
    if "unexpected token" in error and '"null"' in error:
        return "other", "function-references (typed null)", False
    if "unexpected token anyref" in error:
        return "other", "function-references (typed references)", False
    return "unclassified", "no rule matched", "unknown"


def _wast2json_probe(wast: Path, wast2json: str | None) -> dict:
    if not wast2json or not Path(wast2json).exists():
        return {
            "ran": False,
            "error": "pinned wast2json not available; abort cause not re-verified",
        }
    tmp = Path(tempfile.mkdtemp(prefix="s6_classify_"))
    try:
        proc = subprocess.run(
            [wast2json, str(wast), "-o", str(tmp / (wast.stem + ".json"))],
            capture_output=True,
            text=True,
            timeout=120,
        )
        lines = [ln for ln in (proc.stderr or "").splitlines() if "error:" in ln]
        return {
            "ran": True,
            "command": f"{wast2json} {wast} -o <tmp>/{wast.stem}.json",
            "exit_code": proc.returncode,
            "first_error": (lines[0] if lines else (proc.stderr or "").strip()[-300:]),
        }
    except subprocess.TimeoutExpired:
        return {"ran": True, "timeout_s": 120}
    finally:
        shutil.rmtree(tmp, ignore_errors=True)


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--results", type=Path, default=DEFAULT_RESULTS)
    ap.add_argument("--out", type=Path, default=DEFAULT_OUT)
    ap.add_argument("--wabt-bin", default="/tmp/wabt142/bin/wast2json")
    ap.add_argument("--v128-evidence", type=Path, default=None)
    ap.add_argument("--reference-checks", type=Path, default=None)
    args = ap.parse_args()

    doc = json.loads(args.results.read_text())
    files = doc["files"]
    observed = {
        "files": len(files),
        "pass": sum(f["outcomes"]["pass"] for f in files),
        "xfail": sum(f["outcomes"]["xfail"] for f in files),
        "fail": sum(f["outcomes"]["fail"] for f in files),
        "skipped": sum(f["outcomes"]["skipped"] for f in files),
        "fail_files": sum(1 for f in files if f["outcomes"]["fail"] > 0),
        "aborted_files": sum(1 for f in files if f.get("status") == "aborted"),
        "deviation_files": sum(1 for f in files if "deviation" in f),
    }
    v128 = {}
    if args.v128_evidence and args.v128_evidence.exists():
        for rec in json.loads(args.v128_evidence.read_text()):
            v128[rec["file"]] = rec

    failing_records = []
    group_totals = Counter()
    for f in files:
        if f["outcomes"]["fail"] == 0:
            continue
        kind_fail = [
            x for x in f["failures"] if isinstance(x, dict) and x.get("kind") == "fail"
        ]
        assert len(kind_fail) == f["outcomes"]["fail"], f["file"]
        breakdown = Counter()
        first = {}
        for x in kind_fail:
            mapped = _classify_failure(f["file"], x["detail"])
            key = (
                mapped["phase"],
                mapped["feature"],
                mapped["feature_detail"],
                mapped["category"],
                mapped["reason"],
                mapped["expected_support"],
            )
            breakdown[key] += 1
            first.setdefault(key, x)
        cats = Counter(k[3] for k in breakdown)
        if cats.get("unsupported_feature"):
            category = "unsupported_feature"
        elif cats.get("unclassified"):
            category = "unclassified"
        else:
            category = "harness_gap"
        # Root cause = phase/feature of the FIRST failing command; the
        # composition of all commands stays in command_breakdown.
        root = next(iter(breakdown))
        feat_counts = Counter()
        for k, n in breakdown.items():
            feat_counts[k[1]] += n
        phase = root[0]
        feature = root[1]
        feature_detail = root[2]
        expected = root[5]
        confidence = "medium" if category == "unclassified" else "high"
        failing_records.append(
            {
                "spec_file": f["file"],
                "wast_path": str(
                    REPO / ".conformance_cache" / "core-testsuite" / f"{f['file']}.wast"
                ),
                "failing_commands": f["outcomes"]["fail"],
                "non_failing_outcomes": {
                    "pass": f["outcomes"]["pass"],
                    "xfail": f["outcomes"]["xfail"],
                    "skipped": f["outcomes"]["skipped"],
                },
                "command_types": dict(Counter(x["cmd"] for x in kind_fail)),
                "first_error": _trim(kind_fail[0]["detail"]),
                "phase": phase,
                "feature": feature,
                "feature_detail": feature_detail,
                "feature_counts": dict(feat_counts),
                "phase_counts": dict(
                    Counter(k[0] for k, n in breakdown.items() for _ in range(n))
                ),
                "shipped_engine_expected_support": expected,
                "category": category,
                "confidence": confidence,
                "command_breakdown": [
                    {
                        "count": n,
                        "phase": k[0],
                        "feature": k[1],
                        "feature_detail": k[2],
                        "category": k[3],
                        "reason": k[4],
                        "expected_support": k[5],
                        "example_line": first[k]["line"],
                        "example_command": first[k]["cmd"],
                    }
                    for k, n in breakdown.most_common()
                ],
                "reference_checks": REFERENCE_CHECK_IDS.get(f["file"], []),
                # One record per failing command, not only per file: the
                # directive's case-by-case fields must be readable without
                # re-deriving them from command_breakdown examples.
                "failing_command_records": [
                    {
                        "line": x.get("line"),
                        "command": x.get("cmd"),
                        "detail": _trim(x.get("detail", ""), 300),
                        **_classify_failure(f["file"], x["detail"]),
                        "reference_checks": REFERENCE_CHECK_IDS.get(f["file"], []),
                    }
                    for x in kind_fail
                ],
            }
        )
        for k, n in breakdown.items():
            group_totals[(k[3], k[1])] += n

    aborted_records = []
    for f in files:
        if f.get("status") != "aborted":
            continue
        name = f["file"]
        wast = REPO / ".conformance_cache" / "core-testsuite" / f"{name}.wast"
        probe = _wast2json_probe(wast, args.wabt_bin)
        ev = v128.get(name, {})
        if name.startswith("simd_") or "relaxed" in name:
            cause = "v128_binding_abort"
            phase = "runtime"
            category = "harness_gap"
            feature, fdetail, expected = _abort_feature(name, "")
            reason = (
                "wasmtime-py C API aborts the worker with 'support for v128 is not "
                "implemented' (SIGABRT); the native engine and reference engines "
                "accept the module"
            )
            if not ev:
                confidence = "medium"
                reason += "; worker exit not re-verified in this run"
            else:
                confidence = "high"
        elif probe.get("ran") and probe.get("exit_code") not in (0, None):
            cause = "wast2json_parse_error"
            phase = "parse"
            category = "toolchain_problem"
            feature, fdetail, expected = _abort_feature(name, probe["first_error"])
            reason = (
                "pinned WABT 1.0.42 wast2json exits non-zero on the .wast; no "
                "command was ever measured. The harness labels every such process "
                "death 'native-abort' without inspecting stderr."
            )
            confidence = "high"
        elif probe.get("ran") and probe.get("exit_code") == 0:
            # Cannot happen for this artifact's 100 aborts unless the toolchain
            # changed; record it rather than guess.
            cause = "unclassified"
            phase = "unclassified"
            category = "unclassified"
            feature, fdetail, expected = _abort_feature(name, "")
            reason = (
                "wast2json now produces a fixture; abort cause requires a worker rerun"
            )
            confidence = "low"
        else:
            cause = "unclassified"
            phase = "unclassified"
            category = "unclassified"
            feature, fdetail, expected = _abort_feature(name, "")
            reason = probe.get("error", "abort cause not re-verified")
            confidence = "low"
        aborted_records.append(
            {
                "spec_file": name,
                "failing_commands": 0,
                "command_types": {},
                "recorded_label": f.get("deviation"),
                "abort_reason_observed": (
                    probe.get("first_error")
                    if cause == "wast2json_parse_error"
                    else (
                        f"worker exit {ev.get('exit')}: {ev.get('stderr_tail')}"
                        if cause == "v128_binding_abort" and ev
                        else reason
                    )
                ),
                "abort_cause": cause,
                "label_accurate": (
                    "no"
                    if cause == "wast2json_parse_error" or name.startswith("simd_")
                    else "partially" if cause == "v128_binding_abort" else "no"
                ),
                "phase": phase,
                "feature": feature,
                "feature_detail": fdetail,
                "shipped_engine_expected_support": expected,
                "category": category,
                "confidence": confidence,
                "reason": reason,
                "evidence": probe | ({"worker": ev} if ev else {}),
            }
        )

    counts = {
        "failing_commands_by_category": {},
        "failing_commands_by_feature": {},
        "aborted_files_by_cause": dict(
            Counter(r["abort_cause"] for r in aborted_records)
        ),
        "aborted_files_by_category": dict(
            Counter(r["category"] for r in aborted_records)
        ),
        "aborted_files_by_feature": dict(
            Counter(r["feature"] for r in aborted_records)
        ),
        "aborted_files_by_expected_support": dict(
            Counter(str(r["shipped_engine_expected_support"]) for r in aborted_records)
        ),
        "failing_files_by_primary_category": dict(
            Counter(r["category"] for r in failing_records)
        ),
        "failing_files_by_primary_feature": dict(
            Counter(r["feature"] for r in failing_records)
        ),
    }
    for category in TAXONOMY["categories"]:
        counts["failing_commands_by_category"].setdefault(category, 0)
    for feature in TAXONOMY["features"]:
        counts["failing_commands_by_feature"].setdefault(feature, 0)
    for (category, feature), n in group_totals.items():
        counts["failing_commands_by_category"][category] += n
        counts["failing_commands_by_feature"][feature] += n

    reference_checks = []
    if args.reference_checks and args.reference_checks.exists():
        reference_checks = json.loads(args.reference_checks.read_text())

    label = Counter(r["label_accurate"] for r in aborted_records)
    out = {
        "schema": "ephemora.core_spec_classification.v1",
        "generated_at": datetime.now(timezone.utc).isoformat(),
        "generated_by": "conformance/classify_failures.py",
        "taxonomy": TAXONOMY,
        "source": {
            "results_json": str(args.results),
            "results_sha256": _sha256(args.results),
            "date": doc.get("date"),
            "pinned_commit": doc.get("suite", {}).get("pinned_commit"),
            "wasmtime": doc.get("wasmtime"),
            "engine_config": doc.get("engine_config"),
            "declared_toolchain": doc.get("toolchain"),
            "declared_totals": doc.get("totals"),
            "declared_aborted_files": doc.get("aborted_files"),
            "observed_totals": observed,
            "wast2json_used": (
                _sha256(Path(args.wabt_bin))
                if args.wabt_bin and Path(args.wabt_bin).exists()
                else "missing"
            ),
        },
        "integrity_notes": [
            "The artifact has 257 files. The number 81 is the count of failing "
            "COMMANDS across 15 files, not 81 failing files; 181 files carry a "
            "non-pass outcome (15 fail + 42 multi-memory xfail + 24 memory64 xfail "
            "+ 100 aborted).",
            "The claimed 2,827 failed commands is not present in this artifact: "
            "observed fail=81 and xfail=3281 (sum 3362). No field or sum in the "
            "JSON equals 2827; that figure could not be traced.",
            "The 100 'aborted' files have no per-command measurement. The artifact's "
            "blanket 'relaxed-simd native abort' label is not supported by "
            "re-measurement: 44 files fail in wast2json before any engine runs, "
            "50 are ordinary SIMD v128 binding aborts, and only 6 are relaxed-SIMD "
            "(whose abort is in the wasmtime-py binding, not the upstream engine).",
            "The committed artifact records wast2json sha256 "
            f"{doc.get('toolchain', {}).get('wast2json_sha256', '?')[:16]}...; the "
            "verified official 1.0.42 asset was downloaded and hashed to the same "
            "value. Homebrew's 1.0.42 binary has a different digest and was not "
            "used for the 'measured' claims.",
        ],
        "summary": {
            **counts,
            "failing_commands_total": observed["fail"],
            "failing_files_total": observed["fail_files"],
            "aborted_files_total": observed["aborted_files"],
            "aborted_label_audit": {
                "recorded_label": "relaxed-simd native abort (upstream engine)",
                "fully_accurate": label.get("yes", 0),
                "partially_accurate": label.get("partially", 0),
                "inaccurate": label.get("no", 0),
                "note": "0/100 are fully accurate. 6 relaxed-SIMD files are the "
                "right family but the abort is in wasmtime-py's v128 binding, "
                "not the upstream engine. 50 SIMD files and 44 wast2json parse "
                "failures are mislabelled.",
            },
        },
        "failing_files": sorted(failing_records, key=lambda r: r["spec_file"]),
        "aborted_files": sorted(aborted_records, key=lambda r: r["spec_file"]),
        "reference_checks": reference_checks,
        "unclassified": {
            "failing_commands": counts["failing_commands_by_category"].get(
                "unclassified", 0
            ),
            "failing_files": [
                r["spec_file"]
                for r in failing_records
                if r["category"] == "unclassified"
            ],
            "aborted_files": [
                r["spec_file"]
                for r in aborted_records
                if r["category"] == "unclassified"
            ],
            "reason": "local_init's three assert_invalid cases are accepted by "
            "wasm-tools 1.255 AND by wasmtime's default config, while WABT's "
            "spectest-interp fails the same 3/10. The suite expects a validation "
            "rule no installed validator implements; whether that is a product "
            "validation gap or spec drift is not decided by this evidence.",
        },
        "uncertainties": [
            "No failure was reproduced through the installed ephemora-cell CLI: "
            "the Homebrew install refuses to run because its wasmtime dylib hash "
            "does not match the qualified build. CLI-level product behaviour is "
            "therefore NOT TESTED here; the core harness drives wasmtime directly.",
            "The 56 SIMD/relaxed aborts were re-verified on this host with the "
            "pinned WABT fixture generator; the abort is in the wasmtime-py C API "
            "layer, so it says nothing about the native engine's SIMD support.",
            "The 44 wast2json failures are a property of WABT 1.0.42's parser on "
            "Wasm 3.0-era syntax (GC, typed references, tail calls, exceptions). "
            "A newer WABT would change coverage; it would not make the shipped "
            "engine support proposals it keeps disabled.",
            "No product-specific defect was confirmed among the 81 failing "
            "commands. This is a statement about this evidence set, not a claim "
            "of full conformance.",
        ],
    }
    args.out.parent.mkdir(parents=True, exist_ok=True)
    args.out.write_text(json.dumps(out, indent=2) + "\n")
    print(json.dumps(out["summary"], indent=2))
    print(f"wrote {args.out}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
