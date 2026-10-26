#!/usr/bin/env python3
"""Repeatable differential fuzzing for core WASM (Wasmtime vs Node/V8 vs wasm-interp).

The generator emits valid MVP modules with a deterministic seed, executes each
case in three independent engines, and compares the i32 result or the trap
verdict. Compiler crashes, trap disagreements and value mismatches are archived
with their WAT, bytes and metadata. Components are mutated separately and run
through the product's component guard; that path has no differential oracle.

Examples:
    python scripts/fuzz_wasm_diff.py --cases 500 --seed 20261022
    python scripts/fuzz_wasm_diff.py --duration 600 --out /tmp/ephemora_fuzz
    python scripts/fuzz_wasm_diff.py --predicate case.wasm --input 7

`wasm-tools shrink` can consume the predicate mode:
    wasm-tools shrink "python scripts/fuzz_wasm_diff.py --predicate" case.wasm
"""

from __future__ import annotations

import argparse
import json
import random
import re
import shutil
import subprocess
import sys
import time
from pathlib import Path

import wasmtime

NODE = shutil.which("node") or ""
WASM_INTERP = shutil.which("wasm-interp") or ""
WASM_TOOLS = shutil.which("wasm-tools") or ""
ROOT = Path(__file__).resolve().parent.parent
COMPONENT_SEED = ROOT / "tests" / "fixtures" / "hello02.wasm"

NODE_RUNNER = r"""
const fs = require("fs");
const entries = JSON.parse(fs.readFileSync(process.argv[2], "utf8"));
(async () => {
  const out = [];
  for (const e of entries) {
    try {
      const {instance} = await WebAssembly.instantiate(fs.readFileSync(e.path));
      const value = instance.exports.main(e.input);
      out.push({id: e.id, result: Number(value), kind: "value"});
    } catch (err) {
      const kind = err instanceof WebAssembly.CompileError ? "error" : "trap";
      out.push({id: e.id, result: kind, kind: kind, error: String(err)});
    }
  }
  console.log(JSON.stringify(out));
})();
"""


def _expr(rng: random.Random, depth: int = 0) -> str:
    if depth >= 3 or rng.random() < 0.35:
        return rng.choice(
            [
                f"i32.const {rng.randint(-1000, 1000)}",
                "local.get 0",
                f"i32.const {rng.randint(1, 31)}",
            ]
        )
    op = rng.choice(["i32.add", "i32.sub", "i32.mul", "i32.xor", "i32.and", "i32.or"])
    left = _expr(rng, depth + 1)
    right = _expr(rng, depth + 1)
    return f"({op} {left} {right})"


def make_case(rng: random.Random, family: str) -> tuple[str, int]:
    """Return (WAT, input) for one valid core module exporting main(i32)->i32."""
    if family == "arithmetic":
        expr = _expr(rng)
        wat = f"""(module
          (func (export "main") (param i32) (result i32)
            {expr}))
        """
        return wat, rng.randint(-1000, 1000)

    if family == "control":
        n = rng.randint(2, 5)
        labels = " ".join(f"$b{i}" for i in range(n))
        blocks = "\n".join(f"block $b{i}" for i in range(n))
        ends = "\n".join("end" for _ in range(n))
        wat = f"""(module
          (func (export "main") (param i32) (result i32) (local $x i32)
            local.get 0
            local.set $x
            {blocks}
              local.get $x
              i32.const {rng.randint(0, n + 2)}
              i32.and
              br_table {labels}
            {ends}
            local.get $x
            i32.const {rng.randint(1, 9)}
            i32.add))
        """
        return wat, rng.randint(-1000, 1000)

    if family == "memory":
        offset = rng.choice([0, 4, 8, 12, 16, 32, 64])
        delta = rng.randint(-50, 50)
        wat = f"""(module
          (memory 1)
          (data (i32.const 0) "\\01\\02\\03\\04\\05\\06\\07\\08\\09\\0a\\0b\\0c\\0d\\0e\\0f")
          (func (export "main") (param i32) (result i32)
            i32.const {offset}
            local.get 0
            i32.const 3
            i32.and
            i32.add
            i32.load8_u
            i32.const {delta}
            i32.add
            i32.const 255
            i32.and))
        """
        return wat, rng.randint(0, 200)

    if family == "table":
        idx = rng.randint(0, 3)
        wat = f"""(module
          (type $t (func (param i32) (result i32)))
          (table {4 + rng.randint(0, 8)} funcref)
          (elem (i32.const 0) $f0 $f1 $f2 $f3)
          (func $f0 (param i32) (result i32) local.get 0 i32.const 1 i32.add)
          (func $f1 (param i32) (result i32) local.get 0 i32.const 7 i32.mul)
          (func $f2 (param i32) (result i32) local.get 0 i32.const 3 i32.xor)
          (func $f3 (param i32) (result i32) local.get 0 i32.const 11 i32.sub)
          (func (export "main") (param i32) (result i32)
            local.get 0
            local.get 0
            i32.const 3
            i32.and
            call_indirect (type $t)))
        """
        return wat, idx

    if family == "recursion":
        depth = rng.randint(2, 5)
        wat = f"""(module
          (func $sum (param i32) (result i32)
            local.get 0
            i32.eqz
            if (result i32)
              i32.const 0
            else
              local.get 0
              local.get 0
              i32.const 1
              i32.sub
              call $sum
              i32.add
            end)
          (func (export "main") (param i32) (result i32)
            local.get 0
            i32.const {depth}
            i32.and
            call $sum))
        """
        return wat, rng.randint(0, 31)

    if family == "global_select":
        init = rng.randint(-1000, 1000)
        wat = f"""(module
          (global $g (mut i32) (i32.const {init}))
          (func (export "main") (param i32) (result i32)
            global.get $g
            local.get 0
            local.get 0
            i32.const 0
            i32.gt_s
            select
            i32.const {rng.randint(1, 31)}
            i32.xor))
        """
        return wat, rng.randint(-1000, 1000)

    if family == "division":
        divisor = rng.choice([0, 1, 2, 3, 7, -1])
        op = rng.choice(["i32.div_s", "i32.rem_s"])
        wat = f"""(module
          (func (export "main") (param i32) (result i32)
            local.get 0
            i32.const {divisor}
            {op}
            i32.const {rng.randint(1, 31)}
            i32.add))
        """
        return wat, rng.randint(-1000, 1000)

    if family == "sign_extension":
        wat = f"""(module
          (func (export "main") (param i32) (result i32)
            local.get 0
            i32.extend8_s
            i32.const {rng.randint(1, 31)}
            i32.and))
        """
        return wat, rng.randint(-1000, 1000)

    raise ValueError(family)


FAMILIES = (
    "arithmetic",
    "control",
    "memory",
    "table",
    "recursion",
    "global_select",
    "division",
    "sign_extension",
)


def wasmtime_worker(entries_path: Path) -> int:
    entries = json.loads(entries_path.read_text())
    engine = wasmtime.Engine()
    out = []
    for entry in entries:
        try:
            module = wasmtime.Module.from_file(engine, entry["path"])
            store = wasmtime.Store(engine)
            instance = wasmtime.Instance(store, module, [])
            value = instance.exports(store)["main"](store, int(entry["input"]))
            out.append(
                {"id": entry["id"], "result": _norm_i32(int(value)), "kind": "value"}
            )
        except Exception as exc:  # trap vs API/validation error
            kind = "trap" if "trap" in type(exc).__name__.lower() else "error"
            out.append(
                {
                    "id": entry["id"],
                    "result": kind,
                    "kind": kind,
                    "error": str(exc)[:300],
                }
            )
    print(json.dumps(out))
    return 0


def component_worker(paths_path: Path) -> int:
    from ephemora_cell.component_guard import ComponentGuardError, guard_component_bytes

    out = []
    for path in json.loads(paths_path.read_text()):
        data = Path(path).read_bytes()
        try:
            guard_component_bytes(data)
            out.append({"path": path, "guard": "accepted"})
        except ComponentGuardError as exc:
            out.append({"path": path, "guard": "refused", "reason": str(exc)[:200]})
        except Exception as exc:  # a parser crash is not a clean refusal
            out.append({"path": path, "guard": "error", "reason": repr(exc)[:200]})
    print(json.dumps(out))
    return 0


def run_wasmtime(entries: list[dict], out_dir: Path) -> dict[str, dict]:
    batch = out_dir / "wasmtime_batch.json"
    batch.write_text(json.dumps(entries))
    proc = subprocess.run(
        [sys.executable, __file__, "--wasmtime-worker", str(batch)],
        capture_output=True,
        text=True,
        timeout=max(20, len(entries) * 2),
    )
    if proc.returncode != 0:
        return {
            e["id"]: {"result": "crash", "kind": "crash", "error": proc.stderr[-300:]}
            for e in entries
        }
    try:
        return {item["id"]: item for item in json.loads(proc.stdout)}
    except json.JSONDecodeError:
        return {
            e["id"]: {"result": "crash", "kind": "crash", "error": proc.stdout[-300:]}
            for e in entries
        }


def run_node(entries: list[dict], out_dir: Path) -> dict[str, dict]:
    if not NODE:
        return {
            e["id"]: {"result": "unavailable", "kind": "unavailable"} for e in entries
        }
    batch = out_dir / "node_batch.json"
    batch.write_text(json.dumps(entries))
    runner = out_dir / "node_runner.js"
    runner.write_text(NODE_RUNNER)
    proc = subprocess.run(
        [NODE, str(runner), str(batch)],
        capture_output=True,
        text=True,
        timeout=max(20, len(entries) * 2),
    )
    if proc.returncode != 0:
        return {
            e["id"]: {"result": "crash", "kind": "crash", "error": proc.stderr[-300:]}
            for e in entries
        }
    try:
        return {item["id"]: item for item in json.loads(proc.stdout)}
    except json.JSONDecodeError:
        return {
            e["id"]: {"result": "crash", "kind": "crash", "error": proc.stdout[-300:]}
            for e in entries
        }


def _norm_i32(value: int) -> int:
    value &= 0xFFFFFFFF
    return value - 0x100000000 if value >= 0x80000000 else value


def run_interp(path: str, input_value: int) -> dict:
    if not WASM_INTERP:
        return {"result": "unavailable", "kind": "unavailable"}
    unsigned = input_value & 0xFFFFFFFF
    proc = subprocess.run(
        [WASM_INTERP, path, "-r", "main", "-a", f"i32:{unsigned}"],
        capture_output=True,
        text=True,
        timeout=10,
    )
    match = re.search(r"=>\s*i32:(-?\d+)", proc.stdout)
    if proc.returncode == 0 and match:
        return {"result": _norm_i32(int(match.group(1))), "kind": "value"}
    detail = (proc.stderr or proc.stdout)[-200:]
    if "=> error:" in proc.stdout or "trap" in detail.lower():
        return {"result": "trap", "kind": "trap", "error": detail}
    return {"result": "error", "kind": "error", "error": detail}


def archive_finding(out_dir: Path, case: dict, engines: dict) -> Path:
    target = out_dir / "findings" / case["id"]
    target.mkdir(parents=True, exist_ok=True)
    (target / "case.wat").write_text(case["wat"])
    (target / "case.wasm").write_bytes(Path(case["path"]).read_bytes())
    (target / "meta.json").write_text(
        json.dumps({"case": case, "engines": engines}, indent=2, sort_keys=True)
    )
    return target


def run_component_mutations(out_dir: Path, count: int, rng: random.Random) -> dict:
    if not COMPONENT_SEED.exists():
        return {"seed": str(COMPONENT_SEED), "status": "missing"}
    seed = COMPONENT_SEED.read_bytes()
    mutants = out_dir / "components"
    mutants.mkdir(parents=True, exist_ok=True)
    paths = []
    for index in range(count):
        data = bytearray(seed)
        for _ in range(rng.randint(1, 8)):
            pos = rng.randrange(len(data))
            data[pos] ^= 1 << rng.randrange(8)
        path = mutants / f"mutant_{index:04d}.wasm"
        path.write_bytes(bytes(data))
        paths.append(str(path))
    list_path = out_dir / "component_paths.json"
    list_path.write_text(json.dumps(paths))
    proc = subprocess.run(
        [sys.executable, __file__, "--component-worker", str(list_path)],
        capture_output=True,
        text=True,
        timeout=max(20, count),
    )
    if proc.returncode != 0:
        return {"cases": count, "worker_crash": proc.stderr[-500:], "results": []}
    results = json.loads(proc.stdout)
    counts = {"accepted": 0, "refused": 0, "error": 0}
    for result in results:
        counts[result["guard"]] = counts.get(result["guard"], 0) + 1
    validator = {"accepted": 0, "rejected": 0, "unavailable": 0}
    disagreements = []
    if WASM_TOOLS:
        for result in results:
            checked = subprocess.run(
                [WASM_TOOLS, "validate", "--features", "all", result["path"]],
                capture_output=True,
                text=True,
                timeout=10,
            )
            validator_ok = checked.returncode == 0
            validator["accepted" if validator_ok else "rejected"] += 1
            guard_ok = result["guard"] == "accepted"
            if guard_ok != validator_ok:
                disagreements.append(
                    {
                        "path": result["path"],
                        "guard": result["guard"],
                        "validator": "accepted" if validator_ok else "rejected",
                        "validator_error": checked.stderr[-160:],
                    }
                )
    else:
        validator["unavailable"] = count
    return {
        "seed": str(COMPONENT_SEED),
        "cases": count,
        "counts": counts,
        "worker_crash": None,
        "independent_validator": WASM_TOOLS or None,
        "validator_counts": validator,
        "guard_validator_disagreements": disagreements[:10],
        "guard_validator_disagreement_count": len(disagreements),
        "differential_oracle": "none (component model has no second engine in this harness)",
        "error_examples": [r for r in results if r["guard"] == "error"][:5],
    }


def predicate(path: Path, input_value: int) -> int:
    entries = [{"id": "predicate", "path": str(path), "input": input_value}]
    with TemporaryDir() as tmp:
        wm = run_wasmtime(entries, tmp)
        node = run_node(entries, tmp)
        interp = {"predicate": run_interp(str(path), input_value)}
    results = [
        wm["predicate"]["result"],
        node["predicate"]["result"],
        interp["predicate"]["result"],
    ]
    interesting = len(set(map(str, results))) > 1 or "crash" in map(str, results)
    return 0 if interesting else 1


class TemporaryDir:
    def __enter__(self):
        import tempfile

        self.path = Path(tempfile.mkdtemp(prefix="ephemora_fuzz_pred_"))
        return self.path

    def __exit__(self, *exc):
        shutil.rmtree(self.path, ignore_errors=True)
        return False


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--cases", type=int, default=300)
    parser.add_argument("--duration", type=float, default=0.0)
    parser.add_argument("--seed", type=int, default=20261022)
    parser.add_argument("--out", type=Path, default=Path("/tmp/ephemora_fuzz_diff"))
    parser.add_argument("--batch", type=int, default=25)
    parser.add_argument("--components", type=int, default=100)
    parser.add_argument("--components-only", action="store_true")
    parser.add_argument("--wasmtime-worker", type=Path)
    parser.add_argument("--component-worker", type=Path)
    parser.add_argument("--predicate", type=Path)
    parser.add_argument("--input", type=int, default=7)
    args = parser.parse_args()

    if args.wasmtime_worker:
        return wasmtime_worker(args.wasmtime_worker)
    if args.component_worker:
        return component_worker(args.component_worker)
    if args.predicate:
        return predicate(args.predicate, args.input)

    out_dir = args.out.resolve()
    out_dir.mkdir(parents=True, exist_ok=True)
    rng = random.Random(args.seed)
    if args.components_only:
        report = run_component_mutations(out_dir, args.components, rng)
        (out_dir / "components_report.json").write_text(
            json.dumps(report, indent=2, sort_keys=True)
        )
        print(json.dumps(report, indent=2, sort_keys=True))
        return 0
    corpus = out_dir / "corpus"
    corpus.mkdir(exist_ok=True)
    start = time.monotonic()
    deadline = start + args.duration if args.duration > 0 else None
    case_id = 0
    executed = 0
    families_seen: dict[str, int] = {}
    findings = []
    corpus_bytes = 0

    while True:
        if deadline is not None and time.monotonic() >= deadline:
            break
        if deadline is None and case_id >= args.cases:
            break
        family = FAMILIES[case_id % len(FAMILIES)]
        wat, input_value = make_case(rng, family)
        path = corpus / f"case_{case_id:06d}.wasm"
        try:
            path.write_bytes(wasmtime.wat2wasm(wat))
        except Exception as exc:
            findings.append(
                {
                    "id": f"generator_{case_id:06d}",
                    "kind": "generator_error",
                    "error": repr(exc),
                }
            )
            case_id += 1
            continue
        case = {
            "id": f"case_{case_id:06d}",
            "family": family,
            "input": input_value,
            "path": str(path),
            "wat": wat,
            "bytes": path.stat().st_size,
        }
        entries = [{"id": case["id"], "path": case["path"], "input": input_value}]
        with TemporaryDir() as tmp:
            wm = run_wasmtime(entries, tmp)
            node = run_node(entries, tmp)
        interp = {"case": run_interp(case["path"], input_value)}
        engines = {
            "wasmtime": wm[case["id"]],
            "node": node[case["id"]],
            "wasm_interp": interp["case"],
        }
        results = {name: entry["result"] for name, entry in engines.items()}
        values = set(map(str, results.values()))
        crashed = any(entry["kind"] == "crash" for entry in engines.values())
        errored = any(entry["kind"] == "error" for entry in engines.values())
        if crashed or errored or len(values) > 1:
            case["engines"] = engines
            target = archive_finding(out_dir, case, engines)
            findings.append(
                {
                    "id": case["id"],
                    "kind": "crash" if crashed else "error" if errored else "mismatch",
                    "family": family,
                    "results": results,
                    "archive": str(target),
                }
            )
        executed += 1
        families_seen[family] = families_seen.get(family, 0) + 1
        corpus_bytes += case["bytes"]
        case_id += 1

    elapsed = time.monotonic() - start
    components = run_component_mutations(out_dir, args.components, rng)
    report = {
        "probe": "differential core-WASM fuzzing",
        "seed": args.seed,
        "campaign_seconds": round(elapsed, 2),
        "campaign_hours": round(elapsed / 3600, 5),
        "cases_generated": case_id,
        "cases_executed": executed,
        "corpus_files": executed,
        "corpus_bytes": corpus_bytes,
        "feature_families": families_seen,
        "coverage_note": (
            "families/cases executed, not engine-code coverage; every case ran "
            "Wasmtime, Node/V8 and wasm-interp when all three were available"
        ),
        "oracles": {
            "wasmtime": "primary",
            "node": NODE or "unavailable",
            "wasm_interp": WASM_INTERP or "unavailable",
        },
        "findings": findings,
        "components": components,
        "limits": [
            "MVP core modules with deterministic i32 input only",
            "no SIMD/threads/exceptions/GC/multi-memory in this generator",
            "components have a guard-only oracle, not differential execution",
            "wasm-tools shrink is available via --predicate but only exercised on a real finding",
        ],
    }
    (out_dir / "report.json").write_text(json.dumps(report, indent=2, sort_keys=True))
    print(json.dumps(report, indent=2, sort_keys=True))
    return 0 if not findings else 1


if __name__ == "__main__":
    raise SystemExit(main())
