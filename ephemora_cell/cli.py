"""Ephemora Cell CLI — run, inspect, benchmark subcommands."""

from __future__ import annotations

import argparse
import json
import sys
import time
from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from ephemora_cell import WASIConfig


def _parse_env_pairs(items: list[str]) -> list[tuple[str, str]]:
    """Parse --allow-env 'NAME=VALUE' items into WASIConfig env pairs.

    Rejects malformed input with a clean error instead of an unpack traceback
    .
    """
    pairs: list[tuple[str, str]] = []
    for item in items:
        if "=" not in item:
            raise SystemExit(f"error: --allow-env expects NAME=VALUE, got '{item}'")
        name, _, value = item.partition("=")
        if not name:
            raise SystemExit(
                f"error: --allow-env has an empty variable name in '{item}'"
            )
        if not value:
            # An empty value (e.g. NAME=) is a likely typo; warn
            # instead of silently passing a bogus env var to the guest.
            print(
                f"warning: --allow-env '{item}' has an empty value "
                f"(setting {name}='')",
                file=sys.stderr,
            )
        pairs.append((name, value))
    return pairs


def _resolve_config(args) -> WASIConfig:
    """Build the run config.

    Explicit CLI flags override the selected profile; profile values (or
    WASIConfig defaults) fill anything left at None. --memory64 is
    enable-only: when absent, the profile's own memory64 setting stands.
    """
    from ephemora_cell import WASIConfig, get_profile

    if args.profile:
        base = get_profile(args.profile)
    else:
        base = WASIConfig()

    allow_env = () if args.allow_env is None else _parse_env_pairs(args.allow_env)
    return WASIConfig(
        max_memory_mb=(
            args.memory_mb if args.memory_mb is not None else base.max_memory_mb
        ),
        max_fuel=args.fuel if args.fuel is not None else base.max_fuel,
        timeout_seconds=(
            args.timeout if args.timeout is not None else base.timeout_seconds
        ),
        allow_dirs=(
            tuple(args.allow_dirs)
            if args.allow_dirs not in (None, ())
            else base.allow_dirs
        ),
        allow_env=allow_env if allow_env else base.allow_env,
        memory64=True if args.memory64 else base.memory64,
    )


def _capture_cli_stdin(args) -> str | None:
    """stdin for the guest: explicit --stdin file, '-' for piped sys.stdin, or
    auto-capture when stdin is a pipe."""
    if args.stdin:
        if args.stdin == "-":
            return sys.stdin.read()
        with open(args.stdin) as f:
            return f.read()
    if not sys.stdin.isatty():
        return sys.stdin.read()
    return None


def _write_stderr(text: str) -> None:
    # Guest/host diagnostics may arrive without a trailing newline; without
    # this the message glues onto the next shell prompt. stdout is written
    # verbatim (it is programmatic output), stderr is for humans.
    sys.stderr.write(text if text.endswith("\n") else text + "\n")


def cmd_run(args):
    from ephemora_cell import (
        STDIN_MAX_BYTES,
        ExecutionReport,
        ExecutionStatus,
        WASISandbox,
    )

    config = _resolve_config(args)
    stdin_data = _capture_cli_stdin(args)

    sandbox = None
    try:
        sandbox = WASISandbox(config=config)
        result = sandbox.run(
            args.module,
            args=args.args or [],
            use_subprocess=args.isolated,
            abi=args.abi,
            stdin_data=stdin_data,
        )
    except ValueError as exc:
        # Clean rejection without Python traceback
        print(f"error: {exc}", file=sys.stderr)
        sys.exit(1)
    finally:
        if sandbox is not None:
            sandbox.cleanup()

    if args.json:
        # Machine-readable mode: guest output is NOT allowed to pollute
        # stdout — the JSON document must be the only thing on it.
        if result.stdout:
            sys.stderr.write(result.stdout)
        if result.stderr:
            _write_stderr(result.stderr)
        report = ExecutionReport(
            status=result.status.value,
            exit_code=result.exit_code,
            elapsed_ms=result.elapsed_ms,
            fuel_consumed=result.fuel_consumed,
        ).apply_config(config, effective_preopens=result.effective_preopens)
        print(
            json.dumps(
                {
                    "status": result.status.value,
                    "exit_code": result.exit_code,
                    "elapsed_ms": result.elapsed_ms,
                    "fuel_consumed": result.fuel_consumed,
                    "stdin_capped": (
                        len(stdin_data) > STDIN_MAX_BYTES if stdin_data else False
                    ),
                    "security_baseline": report.security_baseline,
                },
                indent=2,
            )
        )
    else:
        if result.stdout:
            sys.stdout.write(result.stdout)
        if result.stderr:
            _write_stderr(result.stderr)
        if stdin_data and len(stdin_data) > STDIN_MAX_BYTES:
            print(
                f"warning: stdin ({len(stdin_data)} bytes) exceeds the wasmtime "
                f"host cap of {STDIN_MAX_BYTES} bytes — wasmtime silently "
                "truncates larger stdin on fd 0; use a preopened file instead",
                file=sys.stderr,
            )

    sys.exit(0 if result.status == ExecutionStatus.SUCCESS else result.exit_code or 1)


def cmd_inspect(args):
    from ephemora_cell import inspect_module
    from ephemora_cell.wasi_02 import is_component_binary

    if is_component_binary(args.module):
        # Clean message instead of a WasmtimeError traceback
        print(
            "error: inspect supports core (preview1) modules only — the given "
            "file is a WASI 0.2 component; use 'run --abi component' to execute it",
            file=sys.stderr,
        )
        sys.exit(1)

    try:
        info = inspect_module(args.module)
    except Exception as exc:
        print(f"error: cannot inspect module: {exc}", file=sys.stderr)
        sys.exit(1)

    if args.json:
        print(json.dumps(info.to_dict(), indent=2))
    else:
        print(info.summary())


def cmd_benchmark(args):
    import statistics

    from ephemora_cell import WASIConfig, WASISandbox

    config = WASIConfig(
        max_memory_mb=args.memory_mb,
        max_fuel=args.fuel,
        timeout_seconds=args.timeout,
        allow_dirs=tuple(args.allow_dirs) if args.allow_dirs else (),
    )

    sandbox = WASISandbox(config=config)
    cold, warm, fuels = [], [], []

    for i in range(args.n):
        start = time.monotonic()
        result = sandbox.run(args.module, args=args.args or [])
        elapsed = (time.monotonic() - start) * 1000

        if i == 0:
            cold.append(elapsed)
        else:
            warm.append(elapsed)
        if result.fuel_consumed is not None:
            fuels.append(result.fuel_consumed)

    sandbox.cleanup()

    def stats_label(times, label):
        if not times:
            return {}
        s = sorted(times)
        return {
            "label": label,
            "mean": round(statistics.mean(times), 2),
            "median": round(statistics.median(times), 2),
            "stdev": round(statistics.stdev(times), 2) if len(times) > 1 else 0,
            "min": round(s[0], 2),
            "max": round(s[-1], 2),
            "p95": round(s[int(len(s) * 0.95)], 2),
            "n": len(times),
        }

    report = {
        "cold": stats_label(cold, "cold_start"),
        "warm": stats_label(warm, "warm_start"),
        "fuel": (
            {
                "mean": round(statistics.mean(fuels)) if fuels else 0,
                "stdev": round(statistics.stdev(fuels)) if len(fuels) > 1 else 0,
                "n": len(fuels),
            }
            if fuels
            else {}
        ),
    }

    if args.json:
        print(json.dumps(report, indent=2))
    else:
        print(f"Benchmark: {args.module} ({args.n} runs)")
        print("=" * 50)
        for key, s in report.items():
            if key == "fuel" and s:
                print(f"  Fuel (mean): {s['mean']:>8,} units")
            elif s:
                print(
                    f"  {s['label']:>8}: {s['mean']:>7.2f}ms ± {s['stdev']:.2f}ms  [min={s['min']}, p95={s['p95']}]"
                )


def cmd_build(args) -> None:
    """One-command WASM build with actionable error hints."""
    from pathlib import Path

    from ephemora_cell.builder import BuildGuidance, build, detect_recipe

    source = Path(args.source)
    if not source.is_file():
        print(f"error: source not found: {source}", file=sys.stderr)
        sys.exit(1)
    output = Path(args.out) if args.out else None
    try:
        recipe = detect_recipe(source, output)
    except BuildGuidance as guidance:
        print(f"guidance: {guidance}", file=sys.stderr)
        sys.exit(2)
    if recipe is None:
        print(
            f"error: no WASM build recipe for {source.suffix!r} "
            "(supported: .rs, .go, .c, .ts, .zig; guidance: .py)",
            file=sys.stderr,
        )
        sys.exit(2)
    result = build(recipe, timeout=args.timeout)
    if result.ok:
        print(f"built {result.language} -> {result.output_path} ({result.elapsed_s}s)")
        print(f"run it: ephemora-cell run {result.output_path}")
        return
    print(
        f"error: {result.language} build failed ({result.elapsed_s}s)", file=sys.stderr
    )
    if result.hint:
        print(f"hint: {result.hint}", file=sys.stderr)
    sys.exit(1)


def main():
    from ephemora_cell import __version__
    from ephemora_cell.profiles import list_profiles

    parser = argparse.ArgumentParser(
        prog="ephemora-cell", description="Ephemora Cell — Isolated WASM sandbox"
    )
    parser.add_argument(
        "--version", action="version", version=f"%(prog)s {__version__}"
    )
    sub = parser.add_subparsers(dest="command")

    p_run = sub.add_parser("run", help="Execute a WASM module")
    p_run.add_argument("module", help="Path to .wasm file")
    p_run.add_argument("--profile", choices=sorted(list_profiles()))
    p_run.add_argument(
        "--memory-mb",
        type=int,
        default=None,
        help="max guest memory in MiB (overrides --profile; default 128)",
    )
    p_run.add_argument(
        "--fuel",
        type=int,
        default=None,
        help="fuel budget (overrides --profile; default 1,000,000)",
    )
    p_run.add_argument(
        "--timeout",
        type=int,
        default=None,
        help="timeout in seconds (overrides --profile; default 30)",
    )
    p_run.add_argument("--allow-dirs", nargs="*", default=None)
    p_run.add_argument("--allow-env", nargs="*", default=None, metavar="NAME=VALUE")
    p_run.add_argument(
        "--stdin",
        metavar="FILE",
        help="guest stdin from FILE ('-' reads piped stdin; piped stdin is "
        "auto-captured when no --stdin is given)",
    )
    p_run.add_argument(
        "--memory64",
        action="store_true",
        help="enable Wasm 3.0 memory64 (64-bit address space) — opt-in",
    )
    p_run.add_argument(
        "--isolated",
        action="store_true",
        help="run in a disposable worker subprocess with OS-level limits",
    )
    p_run.add_argument(
        "--abi",
        choices=["auto", "preview1", "component"],
        default="auto",
        help="execution ABI (auto detects WASI 0.2 components by magic bytes)",
    )
    p_run.add_argument("--json", action="store_true")
    p_run.add_argument("args", nargs="*")
    p_run.set_defaults(func=cmd_run)

    p_inspect = sub.add_parser("inspect", help="Inspect a WASM module")
    p_inspect.add_argument("module", help="Path to .wasm file")
    p_inspect.add_argument("--json", action="store_true")
    p_inspect.set_defaults(func=cmd_inspect)

    p_bench = sub.add_parser("benchmark", help="Benchmark a WASM module")
    p_bench.add_argument("module", help="Path to .wasm file")
    p_bench.add_argument("--n", type=int, default=100)
    p_bench.add_argument("--memory-mb", type=int, default=128)
    p_bench.add_argument("--fuel", type=int, default=1_000_000)
    p_bench.add_argument("--timeout", type=int, default=30)
    p_bench.add_argument("--allow-dirs", nargs="*", default=[])
    p_bench.add_argument("--json", action="store_true")
    p_bench.add_argument("args", nargs="*")
    p_bench.set_defaults(func=cmd_benchmark)

    p_build = sub.add_parser(
        "build",
        help=(
            "Compile a tool source to WASM (recipes: rust/go/c/assemblyscript/"
            "zig; guidance: python)"
        ),
    )
    p_build.add_argument("source", help="Tool source file (.rs/.go/.c/.ts/.zig/.py)")
    p_build.add_argument(
        "--out",
        help="output .wasm path (default: <stem>.wasm next to the source)",
    )
    p_build.add_argument(
        "--timeout",
        type=float,
        default=600.0,
        help="build timeout in seconds (default 600)",
    )
    p_build.set_defaults(func=cmd_build)

    args = parser.parse_args()
    if not args.command:
        parser.print_help()
        sys.exit(1)
    args.func(args)


if __name__ == "__main__":
    main()
