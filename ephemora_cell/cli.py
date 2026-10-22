# SPDX-License-Identifier: BUSL-1.1
# Copyright 2026 Michael Soppa

"""Ephemora Cell CLI — run, inspect, benchmark, doctor, verify, policy subcommands."""

from __future__ import annotations

import argparse
import dataclasses
import json
import os
import sys
import time
from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from ephemora_cell import WASIConfig


#: The CLI's failure classes. A caller — often an agent that branches on the
#: process status without reading prose — must be able to classify a failure from
#: the exit code alone, so the classes are one code each, never overlapping, and
#: the whole table is published in docs/cli-errors.md.
EXIT_OK = 0
#: the guest ran and did not succeed (trap, timeout, budget stop, non-zero exit)
EXIT_EXECUTION = 1
#: the call cannot be honoured as stated (a flag whose value would be dropped, a
#: policy contradiction, an unreadable input) — nothing was executed
EXIT_CALLER = 2
#: evidence cannot be checked the way it reads (a signed artefact verified without
#: the key that would prove authorship)
EXIT_ATTESTATION = 3
#: this environment is not the audited execution configuration — the engine is
#: absent or outside the controlled line, so no guest code ran
EXIT_ENVIRONMENT = 4

ERROR_CLASSES = {
    EXIT_OK: "none",
    EXIT_EXECUTION: "execution",
    EXIT_CALLER: "caller",
    EXIT_ATTESTATION: "attestation",
    EXIT_ENVIRONMENT: "environment",
}


def _runtime_gate() -> tuple[bool, str, str]:
    """May this process run guest code here, and what does it have to say about it?

    Returns ``(allowed, refusal_reason, note)``. The library's own choke point
    refuses as well — this is the CLI's voice, so an operator gets the class, the
    reason and :data:`EXIT_ENVIRONMENT` instead of a traceback or a quiet run on
    an engine the release was never audited against.
    """
    from ephemora_cell.runtime_qualification import (
        UNQUALIFIED_RUNTIME_ENV,
        runtime_qualification,
        unqualified_runtime_allowed,
    )

    qualified, why = runtime_qualification()
    if qualified:
        return True, "", ""
    if unqualified_runtime_allowed():
        return (
            True,
            "",
            f"note: NOT the audited runtime — {why}. Proceeding because "
            f"{UNQUALIFIED_RUNTIME_ENV} is set; this run is not covered by the "
            "release's runtime qualification.",
        )
    return False, why, ""


def _refuse_unqualified_runtime(reason: str, *, json_mode: bool) -> None:
    """Report an environment refusal and leave — nothing ran, say exactly that."""
    if json_mode:
        print(
            json.dumps(
                {
                    "schema": "ephemora-cell/run-refusal/1",
                    "status": "error",
                    "error_class": ERROR_CLASSES[EXIT_ENVIRONMENT],
                    "exit_status_fidelity": "none",
                    "runtime_qualification": reason,
                },
                indent=2,
            )
        )
    print(f"error: unqualified runtime — {reason}", file=sys.stderr)
    sys.exit(EXIT_ENVIRONMENT)


def _refuse_caller(message: str) -> None:
    """Leave with the caller class after naming the problem.

    A flag the CLI cannot honour is decided before anything runs, so it must not
    share the status a guest's own failure produces — and it must never read as a
    success (docs/cli-errors.md).
    """
    print(f"error: {message}", file=sys.stderr)
    raise SystemExit(EXIT_CALLER)


def _parse_env_pairs(items: list[str]) -> list[tuple[str, str]]:
    """Parse --allow-env 'NAME=VALUE' items into WASIConfig env pairs.

    Rejects malformed input with a clean error instead of an unpack traceback.
    """
    pairs: list[tuple[str, str]] = []
    for item in items:
        if "=" not in item:
            _refuse_caller(f"--allow-env expects NAME=VALUE, got '{item}'")
        name, _, value = item.partition("=")
        if not name:
            _refuse_caller(f"--allow-env has an empty variable name in '{item}'")
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


#: CPython only learned to intermix a ``nargs="*"`` positional with optionals
#: in 3.12.5 (gh-61252). Before that, ``run target --json a b`` exited with
#: "unrecognized arguments: a b" and the guest never saw ``a b`` — measured on
#: 3.10.20 and 3.11.15 against this parser, working on 3.12.13/3.13.14. The
#: repair below is gated on this fact, so a 3.12+ interpreter keeps its own
#: parse and only the versions that cannot mix get the attach rule.
_ARGPARSE_INTERMIXES = sys.version_info >= (3, 12, 5)


def _parse_argv(parser: argparse.ArgumentParser) -> argparse.Namespace:
    """``parse_args``, with guest argv carried on pre-3.12.5 argparse.

    The documented spellings (``run s.py --json a b``, ``-- a b``,
    ``-- -x``) are one contract across the supported matrix, so on an
    interpreter whose argparse drops trailing positionals after an optional the
    leftovers are attached where 3.12+ attaches them: to the subcommand's
    ``args``. A leftover that looks like an option stays the error it is, and a
    ``--`` separator hands everything after it to the guest verbatim.

    One measured divergence, deliberately not smoothed over: on 3.10/3.11
    ``run s.py a b --json c`` carries ``c`` while 3.12+ refuses it, because the
    pre-3.12 parse has already closed the positional and cannot tell a late
    guest argument from a stray one. No documented spelling uses that order.
    """
    if _ARGPARSE_INTERMIXES:
        return parser.parse_args()
    namespace, extras = parser.parse_known_args()
    if not extras:
        return namespace
    if isinstance(getattr(namespace, "args", None), list):
        cut = extras.index("--") if "--" in extras else len(extras)
        head, tail = extras[:cut], extras[cut + 1 :]
        if not any(token.startswith("-") and token != "-" for token in head):
            namespace.args.extend(head + tail)
            return namespace
    parser.error(f"unrecognized arguments: {' '.join(extras)}")
    raise SystemExit(EXIT_CALLER)  # parser.error() exits; keeps the type honest


def _flatten(groups):
    """Flatten repeated nargs="*" flags ([["a=b"], ["b=c"]] -> ["a=b", "b=c"])."""
    if groups is None:
        return None
    flat = []
    for group in groups:
        flat.extend(group)
    return flat


def _resolve_config(args, default_profile: str | None = None) -> WASIConfig:
    """Build the run config.

    Explicit CLI flags override the selected profile; every profile value the
    CLI has no flag for (I/O budgets, GC-heap knob, sandbox base dir) carries
    through unchanged — rebuilding the config from scratch would silently
    reset those knobs to defaults. --memory64 is enable-only: when absent,
    the profile's own memory64 setting stands.

    ``default_profile`` is the base when the user passed no ``--profile``:
    plain runs start from WASIConfig defaults, language runs from the
    ``interpreter`` profile (their guests are 10-150 MB and boot a runtime
    before user code runs, so compiled-module budgets do not fit).
    """
    from ephemora_cell import WASIConfig, get_profile

    if args.profile:
        base = get_profile(args.profile)
    elif default_profile is not None:
        base = get_profile(default_profile)
    else:
        base = WASIConfig()

    allow_env = (
        () if args.allow_env is None else _parse_env_pairs(_flatten(args.allow_env))
    )
    overrides: dict = {}
    if args.memory_mb is not None:
        overrides["max_memory_mb"] = args.memory_mb
    if args.fuel is not None:
        overrides["max_fuel"] = args.fuel
    if args.timeout is not None:
        overrides["timeout_seconds"] = args.timeout
    allow_dirs_flat = _flatten(args.allow_dirs)
    if allow_dirs_flat:
        overrides["allow_dirs"] = tuple(allow_dirs_flat)
    if allow_env:
        overrides["allow_env"] = allow_env
    memory64 = getattr(args, "memory64", False)
    no_memory64 = getattr(args, "no_memory64", False)
    if memory64 and no_memory64:
        raise SystemExit("error: --memory64 and --no-memory64 are mutually exclusive")
    if memory64:
        overrides["memory64"] = True
    if no_memory64:
        overrides["memory64"] = False
    max_wasm_bytes = getattr(args, "max_wasm_bytes", None)
    if max_wasm_bytes is not None:
        overrides["max_wasm_bytes"] = max_wasm_bytes
    if getattr(args, "allow_fsync", False):
        overrides["allow_fsync"] = True
    if not overrides:
        return base
    return dataclasses.replace(base, **overrides)


def _capture_cli_stdin(args) -> str | None:
    """stdin for the guest: explicit --stdin file, '-' for piped sys.stdin, or
    auto-capture when stdin is a pipe."""
    if args.stdin:
        if args.stdin == "-":
            return sys.stdin.read()
        try:
            with open(args.stdin) as f:
                return f.read()
        except OSError as e:
            print(
                f"error: cannot read --stdin file {args.stdin!r}: "
                f"{e.strerror or e}",
                file=sys.stderr,
            )
            # The call cannot be honoured as stated and no guest ran: caller class.
            sys.exit(EXIT_CALLER)
    if not sys.stdin.isatty():
        return sys.stdin.read()
    return None


def _write_stderr(text: str) -> None:
    # Guest/host diagnostics may arrive without a trailing newline; without
    # this the message glues onto the next shell prompt. stdout is written
    # verbatim (it is programmatic output), stderr is for humans.
    sys.stderr.write(text if text.endswith("\n") else text + "\n")


def _cli_exit_status(failed: bool, exit_code: int | None) -> int:
    """The process exit code the CLI reports for a run.

    A guest's number only survives the shell if it fits in one byte: an
    exit_code of 256 (which a guest-reported status can carry, because the
    reporting channel is the guest's own) would leave ``sys.exit`` with status
    0 and read as a clean run although the document says ``error``. Any value
    that collapses to zero is therefore reported as 1, and a zero code that
    came with a failure keeps failing loudly.
    """
    if not failed:
        return 0
    return ((exit_code or 1) & 0xFF) or 1


def _detected_language(args) -> str:
    """The run language: explicit --language wins, else the file extension."""
    if args.language != "auto":
        return args.language
    module = args.module.lower()
    if module.endswith(".py"):
        return "python"
    if module.endswith(".js"):
        return "javascript"
    return "wasm"


def cmd_run_language(args, language: str) -> None:
    """Run Python/JavaScript source through the language adapters.

    One behaviour for all three languages: the same budget flags
    (--profile/--memory-mb/--fuel/--timeout) build the config, the guest is
    resolved fail-closed (never downloaded, never a host interpreter), and
    the host-observed status/exit_code — not the guest's self-report — decide
    the exit. Guest stdout/stderr behave exactly like a plain run's. Flags the
    adapters would discard (--allow-dirs, --stdin, the --tenant family, a
    contradicting --abi) are refused with exit 2 rather than swallowed, so
    ``policy check`` and ``run`` agree about which configurations exist at all.

    A route whose guest cannot report the script's own exit status is stated as
    such — in the JSON (``"exit_status_fidelity": "none"``) and as one stderr
    note in human mode — because the alternative is a silent ``success``.
    """
    from ephemora_cell.lang import run_language

    if args.args and language != "python":
        print(
            "error: positional args after the script are not supported for "
            "JavaScript runs (the QuickJS guest takes input via stdin only)",
            file=sys.stderr,
        )
        sys.exit(2)

    # A language run carries exactly three things from the CLI: the script, its
    # args and the budget config. Flags whose VALUE the adapters discard are
    # refused instead of swallowed — a silently replaced --allow-dirs reads as a
    # permission the guest never gets, --stdin never reaches these guests, and
    # the --tenant family (including the caps given without --tenant) would drop
    # quota attribution. (``--allow-env`` is NOT in that set: the adapters rebuild
    # only ``allow_dirs`` over the interpreter profile, so env pairs do carry
    # through.) Flags whose intent the adapter already satisfies —
    # ``--isolated``, a non-trusted ``--trust`` — are accepted.
    discarded = []
    if args.allow_dirs:
        discarded.append(
            "--allow-dirs (the adapter mounts its own grant set in its place — "
            "see 'policy check --language ...' for which directories survive)"
        )
    if args.stdin:
        discarded.append(
            "--stdin (a language guest reads input through the library's "
            "input_json, not the CLI's stdin)"
        )
    if any(
        getattr(args, name, None) is not None
        for name in (
            "tenant",
            "tenant_book",
            "tenant_max_runs",
            "tenant_max_fuel",
        )
    ):
        discarded.append(
            "--tenant/--tenant-book/--tenant-max-runs/--tenant-max-fuel "
            "(per-tenant quota is not attributed on this path)"
        )
    if _abi_contradicts_guest(language, args.abi):
        discarded.append(
            f"--abi {args.abi} (the {language} adapter does not take the ABI from "
            f"the caller: {_abi_source_short(language)})"
        )
    # One precedence rule on every route (docs/cli-errors.md): the machine is
    # checked before the call is judged. A refusal about this engine is a fact
    # that holds no matter what else is wrong with the arguments, and the two
    # classes lead an operator to different fixes — so the language path asks
    # the same question the module path asks, in the same order.
    gate_ok, refusal, gate_note = _runtime_gate()
    if not gate_ok:
        _refuse_unqualified_runtime(refusal, json_mode=args.json)

    if discarded:
        print(
            f"error: run --language {language} cannot carry these flags; refusing "
            "instead of ignoring them:",
            file=sys.stderr,
        )
        for item in discarded:
            print(f"  {item}", file=sys.stderr)
        print(
            "'ephemora policy check --language "
            f"{language} --json' shows what the run really grants.",
            file=sys.stderr,
        )
        # the reason is already on stderr above, line by line: leave with the
        # caller class without printing a second, blander "error:" header
        raise SystemExit(EXIT_CALLER)

    kwargs: dict = {"script_path": args.module}
    if args.args:
        kwargs["args"] = tuple(args.args)
    # Language guests need the interpreter budgets; explicit flags still win.
    kwargs["config"] = _resolve_config(args, default_profile="interpreter")

    try:
        result = run_language(language, **kwargs)
    except FileNotFoundError as exc:
        # GuestNotInstalled (a subclass) is the adapter saying the guest this
        # call needs is not on this machine, or is not the pinned artefact.
        from ephemora_cell.lang_guest import GuestNotInstalled

        if isinstance(exc, GuestNotInstalled):
            print(f"error: {exc}", file=sys.stderr)
            sys.exit(EXIT_ENVIRONMENT)
        print(f"error: {exc}", file=sys.stderr)
        sys.exit(EXIT_CALLER)
    except (ValueError, OSError) as exc:
        # LanguagePolicyError/AdapterPolicyError are ValueErrors: the call
        # contradicts itself or names a configuration the adapter does not
        # implement. Nothing ran, so this is not an execution failure.
        print(f"error: {exc}", file=sys.stderr)
        sys.exit(EXIT_CALLER)

    # The adapter shape carries the enum's str() ("ExecutionStatus.SUCCESS");
    # the CLI speaks the short status the rest of the reports use.
    short_status = str(result.get("status", "error")).rsplit(".", 1)[-1].lower()

    if args.json:
        if result.get("stdout"):
            sys.stderr.write(result["stdout"])
        if result.get("stderr"):
            _write_stderr(result["stderr"])
        payload = dict(result)
        # …and the JSON carries that short status too: the wasm branch reports
        # "success", so a language run must not hand a consumer
        # "ExecutionStatus.SUCCESS" under the same key. One report shape on
        # ``run --json``, whatever the guest.
        payload["status"] = short_status
        payload["language"] = language
        payload["script"] = args.module
        payload["error_class"] = ERROR_CLASSES[
            EXIT_OK if short_status == "success" else EXIT_EXECUTION
        ]
        if gate_note:
            payload["unqualified_runtime_allowed"] = True
        print(json.dumps(payload, indent=2))
    else:
        if result.get("stdout"):
            sys.stdout.write(result["stdout"])
        if result.get("stderr"):
            _write_stderr(result["stderr"])
        if result.get("exit_status_fidelity") == "none":
            # The status above is the HOST's observation of the guest export,
            # not the script's own exit: say so next to the output rather than
            # letting a ``sys.exit(3)`` script read as a clean run.
            print(
                f"note: the {language} guest does not report its script's exit "
                "status — status/exit_code attest the guest export, not the "
                "script (docs/languages.md)",
                file=sys.stderr,
            )

    if gate_note:
        print(gate_note, file=sys.stderr)

    sys.exit(_cli_exit_status(short_status != "success", result.get("exit_code")))


def cmd_run(args):
    language = _detected_language(args)
    if language != "wasm":
        cmd_run_language(args, language)
        return

    from ephemora_cell import (
        STDIN_MAX_BYTES,
        CumulativeBudget,
        ExecutionReport,
        ExecutionStatus,
        TenantStore,
        WASISandbox,
    )
    from ephemora_cell.execution_report import (
        exit_status_fidelity as derive_fidelity,
    )

    gate_ok, refusal, gate_note = _runtime_gate()
    if not gate_ok:
        _refuse_unqualified_runtime(refusal, json_mode=args.json)

    config = _resolve_config(args)
    stdin_data = _capture_cli_stdin(args)

    tenant_store = None
    tenant_budget = None
    if args.tenant:
        if not args.tenant_book:
            _refuse_caller(
                "--tenant needs --tenant-book PATH (the cumulative book this run "
                "is billed to)"
            )
        tenant_store = TenantStore(args.tenant_book)
        if args.tenant_max_runs or args.tenant_max_fuel:
            tenant_budget = CumulativeBudget(
                max_runs=args.tenant_max_runs,
                max_total_fuel=args.tenant_max_fuel,
            )
    elif args.tenant_book or args.tenant_max_runs or args.tenant_max_fuel:
        # The same decision the language route already makes (1.2.0rc2): a book
        # or a cap without an account is a number the operator believes something
        # is billed to, and nothing would be. Silently dropping it would report a
        # guard that does not exist — so this refuses instead of ignoring, on
        # every route, with the same class.
        dropped = [
            flag
            for flag, given in (
                ("--tenant-book", args.tenant_book),
                ("--tenant-max-runs", args.tenant_max_runs),
                ("--tenant-max-fuel", args.tenant_max_fuel),
            )
            if given
        ]
        _refuse_caller(
            f"{', '.join(dropped)} needs --tenant ID (there is no account to "
            "attribute this run to); refusing instead of ignoring them"
        )

    sandbox = None
    try:
        sandbox = WASISandbox(config=config)
        result = sandbox.run(
            args.module,
            args=args.args or [],
            use_subprocess=args.isolated,
            abi=args.abi,
            trust=args.trust,
            stdin_data=stdin_data,
            tenant=args.tenant,
            tenant_budget=tenant_budget,
            tenant_store=tenant_store,
        )
    except ValueError as exc:
        # Clean rejection without Python traceback: the sandbox refuses the
        # configuration before any guest starts, so the call — not the guest —
        # is at fault.
        print(f"error: {exc}", file=sys.stderr)
        sys.exit(EXIT_CALLER)
    finally:
        if sandbox is not None:
            sandbox.cleanup()

    cli_exit = _cli_exit_status(
        result.status != ExecutionStatus.SUCCESS, result.exit_code
    )

    if args.json:
        # Machine-readable mode: guest output is NOT allowed to pollute
        # stdout — the JSON document must be the only thing on it.
        if result.stdout:
            sys.stderr.write(result.stdout)
        if result.stderr:
            _write_stderr(result.stderr)
        # Schema = ExecutionReport.to_dict() (same shape machine readers get
        # from the library and the MCP _meta attachment) + stdin_capped.
        report = ExecutionReport(
            status=result.status.value,
            exit_code=result.exit_code,
            elapsed_ms=result.elapsed_ms,
            fuel_consumed=result.fuel_consumed,
            fuel_budget=config.max_fuel,
            stdout_bytes=len(result.stdout.encode("utf-8")),
            stderr_bytes=len(result.stderr.encode("utf-8")),
            # How much of the GUEST's own exit status this ABI actually delivered:
            # Preview1 proc_exit arrives as the run's code, a component leaving
            # through wasi:cli/exit arrives as "non-zero" only (measured: exit(3)
            # and exit(7) both surface to wasmtime as "exit status 1"), and a run
            # that never reached the guest — a load the loader rejected, a refusal
            # at the choke point, a host-imposed stop — carries no guest status at
            # all and says `none` rather than attesting a channel nothing travelled
            # through. One derivation (:func:`execution_report.exit_status_fidelity`)
            # for every place the claim is made, and it belongs to the record, so it
            # is inside the signature a verifier checks instead of decoration the CLI
            # adds after it.
            exit_status_fidelity=derive_fidelity(
                abi=result.abi, guest_exit_observed=result.guest_exit_observed
            ),
        ).apply_config(
            config,
            effective_preopens=result.effective_preopens,
            tenant=result.tenant,
            tenant_budget_ref=result.tenant_budget_ref,
            execution_mode=result.execution_mode,
            abi=result.abi,
        )
        # The hatch stamp goes ON the record, not beside it: whoever signs this
        # report later signs the fact that the engine was outside the qualified
        # line, so the escape hatch cannot be dropped by re-serialising.
        if gate_note:
            report.unqualified_runtime_allowed = True
        payload = report.to_dict()
        payload["stdin_capped"] = (
            len(stdin_data) > STDIN_MAX_BYTES if stdin_data else False
        )
        payload["error_class"] = ERROR_CLASSES[
            EXIT_OK if result.status == ExecutionStatus.SUCCESS else EXIT_EXECUTION
        ]
        print(json.dumps(payload, indent=2))
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

    if gate_note:
        print(gate_note, file=sys.stderr)

    sys.exit(cli_exit)


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
        allow_dirs=tuple(_flatten(args.allow_dirs) or ()),
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


def cmd_ledger(args):
    """Report a ledger chain's integrity — and say what integrity it can prove.

    The CLI holds no key, so this verifies LINKAGE (sequence plus prev_hash),
    not authorship. That distinction is printed rather than glossed: a chain can
    be intact and still have been written by someone else.
    """
    from ephemora_cell.ledger import Ledger, chain_break

    ledger = Ledger(args.path)
    try:
        entries = ledger.entries()
    except (OSError, ValueError) as exc:
        print(f"error: cannot read ledger: {exc}", file=sys.stderr)
        sys.exit(1)

    reason = chain_break(entries)
    if args.json:
        print(
            json.dumps(
                {
                    "path": str(args.path),
                    "entries": len(entries),
                    "head_sequence": (
                        entries[-1].get("sequence")
                        if reason is None and entries
                        else None
                    ),
                    "signed": bool(entries) and "signature" in entries[-1],
                    "intact": reason is None,
                    "break_reason": reason,
                    "proves": "linkage and order, not authorship (no key here)",
                    "cannot_see": (
                        "a chain truncated at the end — that needs an external "
                        "head anchor"
                    ),
                },
                indent=2,
            )
        )
    else:
        if reason is None:
            head = entries[-1]
            signed = "signed" if "signature" in head else "unsigned"
            print(
                f"ledger intact: {len(entries)} entries, head sequence "
                f"{head['sequence']} ({signed}, appended {head['appended_at']})"
            )
            print("  proved: order and linkage — no entry removed, moved or edited")
            print(
                "  not proved: authorship (this command holds no key), and a "
                "chain truncated at the end"
            )
        else:
            print(f"ledger BROKEN: {reason}", file=sys.stderr)
    sys.exit(0 if reason is None else 1)


def cmd_doctor(args):
    """Local health checks: installation, platform, runtime — offline.

    Exit 0 = no check failed (warnings allowed); 1 = at least one failure.
    """
    from ephemora_cell import doctor

    checks = doctor.run_checks()
    if args.json:
        print(json.dumps(doctor.to_json(checks), indent=2))
    else:
        print(doctor.format_report(checks))
    sys.exit(doctor.exit_code(checks))


def cmd_verify(args):
    """Verify an execution-evidence artefact with explicit trust boundaries.

    Exit 0 = verified (a ledger: intact linkage); 1 = broken/failed;
    3 = signed artefact without --key — nothing was actually checked, and the
    command refuses to imply otherwise.
    """
    from pathlib import Path

    from ephemora_cell import verify_cli

    path = Path(args.path)
    key_pem = None
    if args.key:
        try:
            key_pem = Path(args.key).read_text(encoding="utf-8")
        except (OSError, UnicodeDecodeError) as exc:
            print(f"error: cannot read --key file {args.key!r}: {exc}", file=sys.stderr)
            sys.exit(1)

    outcome = verify_cli.verify_path(path, key_pem)
    if args.json:
        print(
            json.dumps(
                verify_cli.to_json(outcome, path, key_supplied=key_pem is not None),
                indent=2,
            )
        )
    else:
        print(verify_cli.format_report(outcome, path))
    sys.exit(verify_cli.exit_code(outcome, key_pem is not None))


def _abi_contradicts_guest(language: str, abi: str) -> bool:
    """True when an explicit ``--abi`` is not the caller's to make here.

    ``auto`` is never contradicted — it means 'whatever the run decides'. A
    Python run's ABI comes from the guest bytes, so no concrete choice is the
    caller's to make; a JavaScript run is always preview1. The table in
    ``policy_cli.LANGUAGE_ABI`` is the single source for both facts.

    The reason stated to the user is about WHO decides, not about what a
    particular guest would have done: with a BYO legacy interpreter the run
    really would be preview1, and the flag is still refused because the caller
    did not choose it — the guest did.
    """
    from ephemora_cell import policy_cli

    if abi == policy_cli.ABI_AUTO:
        return False
    effective = policy_cli.LANGUAGE_ABI[language]
    return effective == policy_cli.ABI_AUTO or abi != effective


def _abi_source_short(language: str) -> str:
    """Where the ABI of a language run actually comes from, in one clause."""
    from ephemora_cell import policy_cli

    if policy_cli.LANGUAGE_ABI[language] == policy_cli.ABI_AUTO:
        return "it comes from the guest's own bytes"
    return "a javascript run is always the preview1 ABI"


def cmd_policy_check(args):
    """Show the effective permissions/isolation BEFORE a run.

    Computed from the same authoritative policy logic the run enforces, for the
    configuration the flags select — a language guest is viewed under the
    interpreter profile it actually runs with, and ``--isolated`` raises the
    view the way it raises the run. A requested directory the run would refuse
    makes the check exit non-zero (fail-closed), so ``policy check && run``
    cannot pass silently.
    """
    from ephemora_cell import policy_cli

    language = getattr(args, "language", "wasm")
    if language != policy_cli.LANGUAGE_WASM and _abi_contradicts_guest(
        language, args.abi
    ):
        effective = policy_cli.LANGUAGE_ABI[language]
        tail = (
            "so no ABI can be pinned for it before the guest is chosen"
            if effective == policy_cli.ABI_AUTO
            else f"so this view would be computed under '{effective}' either way"
        )
        print(
            f"error: --abi {args.abi} cannot be combined with --language {language}: "
            f"the {language} adapter does not take the ABI from the caller "
            f"({_abi_source_short(language)}), {tail}",
            file=sys.stderr,
        )
        sys.exit(2)
    guest_profile = "interpreter" if language in ("python", "javascript") else None
    try:
        snap = policy_cli.snapshot(
            _resolve_config(args, default_profile=guest_profile),
            trust=args.trust,
            abi=args.abi,
            profile_name=args.profile,
            isolated=bool(getattr(args, "isolated", False)),
            language=language,
        )
    except ValueError as exc:
        print(f"error: {exc}", file=sys.stderr)
        sys.exit(1)

    if args.json:
        print(json.dumps(policy_cli.to_json(snap), indent=2))
    else:
        print(policy_cli.format_report(snap))
    refused = snap.get("preopens", {}).get("refused", [])
    sys.exit(1 if refused else 0)


def _policy_check_flags(parser) -> None:
    """The run-flag subset that shapes a policy-checked configuration.

    Deliberately narrower than ``run``: only flags that change what the sandbox
    would grant or how it is isolated. ``--stdin`` and the ``--tenant`` quota
    flags carry no policy, so they are not accepted here — a view that took a
    flag it could not honour would describe a run that never happens.
    """
    from ephemora_cell.profiles import list_profiles

    parser.add_argument("--profile", choices=sorted(list_profiles()))
    parser.add_argument(
        "--language",
        choices=["wasm", "python", "javascript"],
        default="wasm",
        help="which guest the view describes; python/javascript start from the "
        "interpreter profile, exactly as 'run --language' does",
    )
    parser.add_argument(
        "--isolated",
        action="store_true",
        help="raise the run into the disposable worker (mirrors run: it can "
        "raise isolation, never lower the ADR-015 mandate)",
    )
    parser.add_argument(
        "--trust",
        choices=["trusted", "untrusted", "unknown"],
        default="unknown",
        help="HOST-declared trust posture (ADR-015; never taken from the guest)",
    )
    parser.add_argument(
        "--abi",
        choices=["auto", "preview1", "component"],
        default="auto",
        help="execution ABI; 'auto' reports both (the module bytes decide). Not "
        "combinable with a --abi the language adapter would override — that "
        "combination is refused instead of describing a run that cannot happen",
    )
    parser.add_argument(
        "--allow-dirs",
        action="append",
        nargs="*",
        default=None,
        help="host dir to preopen (optionally host::guest-name); repeatable",
    )
    parser.add_argument(
        "--allow-env", action="append", nargs="*", default=None, metavar="NAME=VALUE"
    )
    parser.add_argument("--memory-mb", type=int, default=None)
    parser.add_argument("--fuel", type=int, default=None)
    parser.add_argument("--timeout", type=int, default=None)
    parser.add_argument("--memory64", action="store_true")
    parser.add_argument("--no-memory64", action="store_true")
    parser.add_argument("--max-wasm-bytes", type=int, default=None)
    parser.add_argument("--allow-fsync", action="store_true")
    parser.add_argument(
        "--json", action="store_true", help="machine-readable snapshot on stdout"
    )


def main():
    from ephemora_cell import __version__
    from ephemora_cell.profiles import list_profiles

    # Both console scripts resolve here. Keep "ephemora-cell" as the default
    # when invoked another way (python -m) so --version output stays pinned
    # by the tests; print the invoked name for the new `ephemora` alias.
    _invoked = os.path.basename(sys.argv[0]) if sys.argv and sys.argv[0] else ""
    prog = _invoked if _invoked in ("ephemora", "ephemora-cell") else "ephemora-cell"
    parser = argparse.ArgumentParser(
        prog=prog, description="Ephemora Cell — Isolated WASM sandbox"
    )
    parser.add_argument(
        "--version", action="version", version=f"%(prog)s {__version__}"
    )
    sub = parser.add_subparsers(dest="command")

    p_run = sub.add_parser(
        "run", help="Execute a WASM module or Python/JavaScript source"
    )
    p_run.add_argument("module", help="Path to .wasm file, or a .py/.js script")
    p_run.add_argument(
        "--language",
        choices=["auto", "wasm", "python", "javascript"],
        default="auto",
        help="run a .wasm module (default), or Python/JavaScript source through "
        "the installed language guests; 'auto' detects .py/.js by extension",
    )
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
    p_run.add_argument(
        "--allow-dirs",
        action="append",
        nargs="*",
        default=None,
        help="host dir to preopen (optionally host::guest-name); " "repeatable",
    )
    p_run.add_argument(
        "--allow-env", action="append", nargs="*", default=None, metavar="NAME=VALUE"
    )
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
        "--no-memory64",
        action="store_true",
        help="disable Wasm 3.0 memory64 — overrides --profile analytical which enables it",
    )
    p_run.add_argument(
        "--isolated",
        action="store_true",
        help="force the run into a disposable worker subprocess with OS-level "
        "limits. Redundant for untrusted/unknown (the 1.2.0 mandate always "
        "isolates); it can only RAISE isolation, never lower it.",
    )
    p_run.add_argument(
        "--trust",
        choices=["trusted", "untrusted", "unknown"],
        default="unknown",
        help="HOST-declared trust posture (ADR-015; never taken from the guest). "
        "Default 'unknown' is fail-closed and runs on the protected worker for "
        "BOTH ABIs under the 1.2.0 mandate; 'untrusted' is identical. Only the "
        "explicit 'trusted' posture re-enables the in-process fast path.",
    )
    p_run.add_argument(
        "--max-wasm-bytes",
        type=int,
        default=None,
        help="module size cap in bytes (overrides --profile; default "
        "33554432 = 32 MiB, 0 = no cap — what a BYO interpreter guest "
        "needs)",
    )
    p_run.add_argument(
        "--allow-fsync",
        action="store_true",
        help="permit WASI fd_fsync/fd_datasync imports (the sync blockade "
        "otherwise refuses such modules) — interpreter guests like "
        "CPython-WASI need this; --profile interpreter sets it",
    )
    p_run.add_argument(
        "--abi",
        choices=["auto", "preview1", "component"],
        default="auto",
        help="execution ABI (auto detects WASI 0.2 components by magic bytes)",
    )
    p_run.add_argument(
        "--tenant",
        metavar="ID",
        default=None,
        help="ADR-012 billing identity for this run (operator-chosen; the guest "
        "never sees it). Attribution only — it isolates nothing.",
    )
    p_run.add_argument(
        "--tenant-book",
        metavar="PATH",
        default=None,
        help="append-only tenant book (JSONL) to admit this run against and "
        "bill it in; required with --tenant",
    )
    p_run.add_argument(
        "--tenant-max-runs",
        type=int,
        default=None,
        help="cumulative run cap for --tenant (checked BEFORE the run starts)",
    )
    p_run.add_argument(
        "--tenant-max-fuel",
        type=int,
        default=None,
        help="cumulative fuel cap for --tenant, compared against settled plus "
        "reserved units",
    )
    p_run.add_argument(
        "--json",
        action="store_true",
        help="machine-readable report on stdout; for a .wasm module this is the "
        "ExecutionReport schema plus stdin_capped, for --language a narrower "
        "shape (status/exit_code/elapsed_ms/fuel_consumed plus stdout/stderr/"
        "output/language/script) — see docs/recipes.md; guest stdout/stderr are "
        "routed to stderr so the document stays parseable",
    )
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
    p_bench.add_argument("--allow-dirs", action="append", nargs="*", default=[])
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

    p_ledger = sub.add_parser(
        "ledger",
        help=(
            "Verify an execution ledger chain (order and linkage; holds no key, "
            "so authorship is not checked)"
        ),
    )
    p_ledger.add_argument("path", help="ledger JSONL file written by Ledger.append")
    p_ledger.add_argument(
        "--json",
        action="store_true",
        help="machine-readable verdict on stdout",
    )
    p_ledger.set_defaults(func=cmd_ledger)

    p_doctor = sub.add_parser(
        "doctor",
        help=(
            "Check the local installation, platform and runtime (offline; "
            "exit 0 = no failure, 1 = at least one)"
        ),
    )
    p_doctor.add_argument(
        "--json", action="store_true", help="machine-readable report on stdout"
    )
    p_doctor.set_defaults(func=cmd_doctor)

    p_verify = sub.add_parser(
        "verify",
        help=(
            "Verify an execution-evidence artefact (ledger, signed record, "
            "DSSE envelope, pre-exec/receipt chain); exit 3 = signed but no --key"
        ),
    )
    p_verify.add_argument(
        "path", help="evidence file (JSONL ledger, DSSE envelope or signed record)"
    )
    p_verify.add_argument(
        "--key",
        metavar="PEM",
        help="Ed25519 public key (PEM file) for real signature verification; "
        "without it the report states exactly what was NOT checked",
    )
    p_verify.add_argument(
        "--json", action="store_true", help="machine-readable verdict on stdout"
    )
    p_verify.set_defaults(func=cmd_verify)

    p_policy = sub.add_parser(
        "policy",
        help="Show the effective permissions and isolation BEFORE a run",
    )
    policy_sub = p_policy.add_subparsers(dest="policy_command")
    p_check = policy_sub.add_parser(
        "check",
        help=(
            "Print the effective policy for a configuration (budgets, "
            "preopens, isolation, sync blockade, fingerprint); exit 1 when a "
            "requested directory would be refused"
        ),
    )
    _policy_check_flags(p_check)
    p_check.set_defaults(func=cmd_policy_check)

    args = _parse_argv(parser)
    if not args.command:
        parser.print_help()
        sys.exit(1)
    if args.command == "policy" and not getattr(args, "policy_command", None):
        p_policy.print_help()
        sys.exit(1)
    args.func(args)


if __name__ == "__main__":
    main()
