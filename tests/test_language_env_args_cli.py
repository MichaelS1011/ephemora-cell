# SPDX-License-Identifier: BUSL-1.1
# Copyright 2026 Michael Soppa
"""``--allow-env`` and positional args on the LANGUAGE run path.

Two product promises existed only as prose plus a *negative* pin before this
file. `docs/languages.md` says the language adapters replace ``allow_dirs``
only — so ``--allow-env`` pairs reach the guest — and that a caller's
positional arguments reach the guest's ``sys.argv``. The measured state agreed
(independent review, 2026-10-17), but no test said so positively:

* ``tests/test_cli_new_commands.py`` pinned only that ``--allow-env`` is NOT
  refused — a refusal test, not a carry test;
* the args pins sat one layer down: adapter call shape
  (``test_component_path_forwards_user_args_to_the_guest``) and guest effect
  (``test_component_guest_real_args_reach_sys_argv``). Neither covered the CLI
  class itself, ``run --language python <script> a b``.

Both promises are therefore pinned twice, at two strengths:

1. **Deterministic, always running.** The real ``main()`` is executed
   in-process down to a recording ``WASISandbox`` boundary — the technique
   ``test_policy_cli.py::TestAdapterBuildsWhatTheViewPromises`` uses: run the
   code and read what it ACTUALLY built, never grep the source text. This
   catches a future ``dataclasses.replace(..., allow_env=())`` or a dropped
   ``args`` on a host that has no interpreter guest installed at all.
2. **Real guest, opt-in.** The same CLI runs as a subprocess against a
   bring-your-own CPython-WASI *component* guest, and the grant is read back
   out of the guest (``os.environ`` / ``sys.argv``) — only that proves the
   pairs survive the worker pipe and the WASI env wiring instead of merely
   reaching a Python object. Gated on an ``EPHEMORA_*`` variable exactly like
   the existing opt-in guest tests: with no guest these SKIP honestly, they
   never pass silently and never fail CI.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import os
import subprocess
import sys
from pathlib import Path
from typing import ClassVar

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from ephemora_cell import cli, get_profile, lang_py

REPO = Path(__file__).resolve().parent.parent

#: Opt-in gate + optional digest pin, the names the component-guest tests use.
GUEST_ENV = "EPHEMORA_PY_COMPONENT_GUEST"
GUEST_SHA_ENV = "EPHEMORA_PY_COMPONENT_GUEST_SHA256"

#: A deliberately distinct probe pair: it is not a credential shape, and if it
#: ever surfaced in a refusal or a report it would be visible as such.
PROBE_NAME = "R4_ALLOW_ENV_PROBE"
PROBE_VALUE = "carry-me-through"

# A component is \0asm + layer 0x0d + version; that header alone routes
# lang_py to the WASI-0.2 branch. The extra bytes are padding — this file is
# never executed, it only selects a branch.
FAKE_COMPONENT_GUEST = b"\x00asm\x0d\x00\x01\x00" + b"\x00" * 8

# The user script for both legs: it reports its own argv and its full visible
# environment, so the assertion is about what the GUEST observed rather than
# about what the host built.
PROBE_SCRIPT = (
    "import json, os, sys\n"
    "print(json.dumps({'argv': sys.argv, 'env': dict(os.environ)}, "
    "sort_keys=True))\n"
)


def _component_guest_or_skip() -> str:
    """Return a pinned component guest path, or skip the test honestly."""
    guest = os.environ.get(GUEST_ENV)
    if not guest or not os.path.exists(guest):
        pytest.skip(
            f"no component Python guest at {GUEST_ENV} — a bring-your-own guest "
            "is required for a real round-trip (nothing is downloaded)"
        )
    expected = os.environ.get(GUEST_SHA_ENV)
    if expected:
        digest = hashlib.sha256(Path(guest).read_bytes()).hexdigest()
        assert digest == expected, f"{GUEST_SHA_ENV} mismatch — refusing to run"
    return str(Path(guest).resolve())


def _guest_cli_env(guest: str) -> dict[str, str]:
    """Environment for a CLI subprocess that must resolve ``guest``.

    The explicit BYO pin is the documented way to hand the CLI a guest without
    installing the optional package. The stdlib pin is cleared because a
    component guest takes none, and an ambient legacy pin would otherwise send
    this probe down the other branch. The variable set is per-subprocess only.
    """
    env = dict(os.environ)
    env["EPHEMORA_BYO_PYTHON_GUEST"] = guest
    env.pop("EPHEMORA_BYO_PYTHON_STDLIB", None)
    env.pop("EPHEMORA_BYO_PYTHON_SHA256", None)
    return env


# --------------------------------------------------------------------------- #
# 1. deterministic leg: the real CLI, executed, measured at the sandbox boundary
# --------------------------------------------------------------------------- #


class _Result:
    """Minimal stand-in for an ExecutionResult (shape_result needs six)."""

    status = "ExecutionStatus.SUCCESS"
    stdout = '{"ok": true}\n'
    stderr = ""
    exit_code = 0
    fuel_consumed = 1
    elapsed_ms = 1.0


class _RecordingSandbox:
    """Stand-in for WASISandbox that records exactly what the run built."""

    last: ClassVar[dict] = {}

    def __init__(self, config=None):
        _RecordingSandbox.last["config"] = config

    def run(self, path, **kwargs):
        _RecordingSandbox.last["path"] = path
        _RecordingSandbox.last.update(kwargs)
        return _Result()

    def cleanup(self):
        pass


def _cli_inprocess(monkeypatch, capsys, argv: list[str]):
    """Execute the real ``main()`` in-process; return (exit_code, captured)."""
    monkeypatch.setattr(sys, "argv", ["ephemora-cell", *argv])
    monkeypatch.setattr(
        sys,
        "stdin",
        type("FakeStdin", (), {"read": lambda self: "", "isatty": lambda self: True})(),
    )
    try:
        cli.main()
        return None, capsys.readouterr()
    except SystemExit as exc:
        return exc.code, capsys.readouterr()


@pytest.fixture()
def fake_component(monkeypatch, tmp_path):
    """A component-headed guest file plus the recording sandbox boundary.

    No WebAssembly executes here: the CLI and the adapter run for real, and
    only the engine is observed. That keeps the test deterministic on a machine
    with no interpreter guest installed.
    """
    guest = tmp_path / "component-guest.wasm"
    guest.write_bytes(FAKE_COMPONENT_GUEST)
    script = tmp_path / "probe.py"
    script.write_text(PROBE_SCRIPT)
    monkeypatch.setenv("EPHEMORA_BYO_PYTHON_GUEST", str(guest))
    monkeypatch.delenv("EPHEMORA_BYO_PYTHON_STDLIB", raising=False)
    monkeypatch.delenv("EPHEMORA_BYO_PYTHON_SHA256", raising=False)
    _RecordingSandbox.last = {}
    monkeypatch.setattr(lang_py, "WASISandbox", _RecordingSandbox)
    return guest, script


def _guest_paths(entries) -> list[str]:
    """Guest side of an ``allow_dirs`` tuple, in the order it was built."""
    return [str(entry).split("::")[-1] for entry in entries]


class TestCliCarriesEnvAndArgsToTheAdapter:
    """``run --language python`` must hand env pairs and argv to the adapter.

    The assertions read the call the CLI actually made, at two layers: the
    config the adapter received and the ``sandbox.run`` kwargs it then built.
    A refusal-style test cannot catch a silent drop; these do.
    """

    def test_allow_env_pair_survives_into_the_run_config(
        self, monkeypatch, capsys, fake_component
    ):
        _guest, script = fake_component
        code, out = _cli_inprocess(
            monkeypatch,
            capsys,
            [
                "run",
                str(script),
                "--language",
                "python",
                "--allow-env",
                f"{PROBE_NAME}={PROBE_VALUE}",
            ],
        )
        assert code == 0, out.err
        assert "cannot carry these flags" not in out.err
        config = _RecordingSandbox.last["config"]
        # the pair is still there after CLI -> adapter -> sandbox
        assert list(config.allow_env) == [(PROBE_NAME, PROBE_VALUE)]
        # the run really was built on the interpreter profile, so nothing was
        # rebuilt from defaults while allow_dirs was replaced
        interpreter = get_profile("interpreter")
        assert interpreter.allow_env == ()  # the pair came from the CLI alone
        assert config.max_fuel == interpreter.max_fuel
        assert config.timeout_seconds == interpreter.timeout_seconds
        assert config.allow_fsync is False  # the sync blockade did not move
        # ...and allow_dirs is the ONE field the adapter replaced
        assert interpreter.allow_dirs == ()
        assert _guest_paths(config.allow_dirs) == ["/work"]
        assert str(script.parent) not in " ".join(
            str(d) for d in config.allow_dirs
        ), "the caller's script directory would have been mounted"

    def test_positional_args_reach_the_sandbox_argv(
        self, monkeypatch, capsys, fake_component
    ):
        """``run --language python s.py a b`` must not drop ``a b``.

        The argv chain has three hand-offs (CLI namespace -> dispatcher kwargs
        -> adapter -> ``sandbox.run(args=...)``); the pins that existed before
        this file covered the last two. This one covers the first.
        """
        _guest, script = fake_component
        code, out = _cli_inprocess(
            monkeypatch,
            capsys,
            ["run", str(script), "--language", "python", "--json", "a", "b"],
        )
        assert code == 0, out.err
        seen = _RecordingSandbox.last
        assert list(seen["args"]) == ["a", "b"]
        # the branch this run actually took: component ABI, disposable worker
        assert seen["abi"] == "component"
        assert seen["use_subprocess"] is True

    def test_no_positional_args_means_no_guest_argv(
        self, monkeypatch, capsys, fake_component
    ):
        """A bare run must not invent guest argv (empty, not ``['']``)."""
        _guest, script = fake_component
        code, out = _cli_inprocess(
            monkeypatch, capsys, ["run", str(script), "--language", "python"]
        )
        assert code == 0, out.err
        assert list(_RecordingSandbox.last.get("args") or []) == []

    def test_env_with_an_empty_value_is_carried_and_warned(
        self, monkeypatch, capsys, fake_component
    ):
        """``NAME=`` stays an explicit empty-value grant (measured), warned
        rather than guessed away — the pair still reaches the config."""
        _guest, script = fake_component
        code, out = _cli_inprocess(
            monkeypatch,
            capsys,
            [
                "run",
                str(script),
                "--language",
                "python",
                "--allow-env",
                f"{PROBE_NAME}=",
            ],
        )
        assert code == 0, out.err
        assert "empty value" in out.err
        assert list(_RecordingSandbox.last["config"].allow_env) == [(PROBE_NAME, "")]

    def test_greedy_allow_env_group_refuses_a_following_arg_cleanly(
        self, monkeypatch, capsys, fake_component
    ):
        """Characterization (measured, not invented): ``--allow-env`` is a
        greedy ``nargs="*"`` flag, so a guest argument written straight after
        it is parsed as another ``NAME=VALUE`` item — and the CLI says so
        instead of running a different command than the operator asked for.

        ``run s.py --language python --json --allow-env A=b a b`` therefore
        exits with the ``NAME=VALUE`` error rather than passing ``a b`` to the
        guest; the working spellings are ``--allow-env A=b --json a b``,
        ``--allow-env A=b -- a b`` or the arguments before the flag. This pin
        exists so that change to this parse (a repair, or a move to
        ``nargs=1``) is a deliberate act instead of a silent drift, and so the
        ``--`` advice in ``docs/languages.md`` is checked against a run.
        """
        _guest, script = fake_component
        code, out = _cli_inprocess(
            monkeypatch,
            capsys,
            [
                "run",
                str(script),
                "--language",
                "python",
                "--json",
                "--allow-env",
                "A=b",
                "a",
                "b",
            ],
        )
        # caller class, and the reason on stderr — the message used to travel as
        # the SystemExit argument itself, which is why str(code) once held it
        assert code == 2, (code, out.err)
        assert "NAME=VALUE" in out.err, out.err
        assert "Traceback" not in out.err
        # nothing ran: the greedy group was refused before any sandbox existed
        assert _RecordingSandbox.last == {}

    def test_the_separator_and_the_pre_flag_spellings_both_reach_the_guest(
        self, monkeypatch, capsys, fake_component
    ):
        """The two working orders are pinned beside the refusal above, so the
        contract is 'these spellings carry a b', not merely 'that one fails'.
        """
        _guest, script = fake_component
        for argv in (
            [
                "run",
                str(script),
                "--language",
                "python",
                "--allow-env",
                "A=b",
                "--",
                "a",
                "b",
            ],
            [
                "run",
                str(script),
                "--language",
                "python",
                "a",
                "b",
                "--allow-env",
                "A=b",
            ],
        ):
            _RecordingSandbox.last = {}
            code, out = _cli_inprocess(monkeypatch, capsys, argv)
            assert code == 0, (argv, out.err)
            assert list(_RecordingSandbox.last["args"]) == ["a", "b"], argv
            assert list(_RecordingSandbox.last["config"].allow_env) == [("A", "b")]


# --------------------------------------------------------------------------- #
# 2. real-guest leg: the promise is read back out of the guest itself
# --------------------------------------------------------------------------- #


def _run_cli_with_guest(
    guest: str, argv: list[str], extra_env: dict[str, str] | None = None
) -> subprocess.CompletedProcess:
    env = _guest_cli_env(guest)
    env.update(extra_env or {})
    return subprocess.run(
        [sys.executable, "-m", "ephemora_cell.cli", *argv],
        capture_output=True,
        text=True,
        input="",
        timeout=600,
        cwd=str(REPO),
        env=env,
    )


@pytest.mark.parametrize("extra", [[], ["--isolated"]])
def test_real_guest_sees_exactly_the_granted_env_and_the_caller_args(extra, tmp_path):
    """Opt-in CLI round-trip: env pairs and argv measured INSIDE the guest.

    ``--isolated`` is included because the adapters force the worker either
    way: the payload (env values, argv, stdin) travels to that worker over a
    pipe, so a regression in that transport would surface here as an empty or
    partial environment rather than as a green run.
    """
    guest = _component_guest_or_skip()
    script = tmp_path / "probe.py"
    script.write_text(PROBE_SCRIPT)
    proc = _run_cli_with_guest(
        guest,
        [
            "run",
            str(script),
            "--language",
            "python",
            "--json",
            *extra,
            "--allow-env",
            f"{PROBE_NAME}={PROBE_VALUE}",
            # the separator is load-bearing, not decoration: see
            # test_greedy_allow_env_group_refuses_a_following_arg_cleanly
            "--",
            "a",
            "b",
        ],
    )
    assert proc.returncode == 0, (proc.returncode, proc.stdout, proc.stderr)
    doc = json.loads(proc.stdout)
    assert doc["status"] == "success", doc
    seen = doc["output"]
    # The granted pair arrived, and it is the ONLY thing that arrived: the
    # host's own environment never reaches a guest (control-plane rule, and
    # the negative half of this promise is pinned in
    # test_control_plane_reachability.py).
    assert seen["env"] == {PROBE_NAME: PROBE_VALUE}
    # argv[0] is the runner's neutral tag; the caller owns argv[1:]
    assert seen["argv"] == ["wasm-module", "a", "b"]
    # no host path leaked into either observable channel
    assert str(script) not in json.dumps(seen)
    assert str(tmp_path) not in json.dumps(seen)


class TestParseArgvOnAnInterpreterThatCannotIntermix:
    """The repair that makes ``run target --json a b`` one contract on 3.10.

    CPython fixed positional/optional intermixing in 3.12.5 (gh-61252); before
    that the same CLI exited with "unrecognized arguments: a b" and the guest
    never saw its arguments — measured on 3.10.20 and 3.11.15 while the suite
    was being qualified per version. ``cli._parse_argv`` attaches the leftovers
    only on those interpreters, so a 3.12+ run never reaches the attach path on
    its own. The seam is therefore exercised here with the leftovers a
    pre-3.12.5 parse actually produces, and the integrated behaviour is the
    same file's ``test_positional_args_reach_the_sandbox_argv`` under each
    matrix interpreter.
    """

    class _StubParser:
        """The two entry points ``_parse_argv`` uses, and nothing else."""

        def __init__(self, extras, namespace):
            self.extras = extras
            self.namespace = namespace
            self.used: str | None = None
            self.error_message: str | None = None

        def parse_args(self):
            self.used = "parse_args"
            return self.namespace

        def parse_known_args(self):
            self.used = "parse_known_args"
            return self.namespace, list(self.extras)

        def error(self, message):
            self.error_message = message
            raise SystemExit(2)

    @pytest.fixture()
    def old_argparse(self, monkeypatch):
        """Force the pre-3.12.5 regime regardless of the interpreter running."""
        monkeypatch.setattr(cli, "_ARGPARSE_INTERMIXES", False)

    def test_trailing_positionals_are_attached_as_guest_argv(self, old_argparse):
        parser = self._StubParser(["a", "b"], argparse.Namespace(args=["s.py"]))
        namespace = cli._parse_argv(parser)
        assert namespace.args == ["s.py", "a", "b"]
        assert parser.used == "parse_known_args"
        assert parser.error_message is None

    def test_the_separator_hands_the_rest_over_verbatim(self, old_argparse):
        parser = self._StubParser(["--", "a", "-x"], argparse.Namespace(args=["s.py"]))
        namespace = cli._parse_argv(parser)
        assert namespace.args == ["s.py", "a", "-x"]

    def test_an_option_shaped_leftover_stays_the_error_it_is(self, old_argparse):
        """Repairing the drop must not turn a mistyped flag into guest data."""
        parser = self._StubParser(["--jsno"], argparse.Namespace(args=["s.py"]))
        with pytest.raises(SystemExit) as exc:
            cli._parse_argv(parser)
        assert exc.value.code == 2
        assert parser.error_message == "unrecognized arguments: --jsno"

    def test_a_bare_dash_is_a_positional(self, old_argparse):
        """``-`` is the stdin convention, not an option."""
        parser = self._StubParser(["-"], argparse.Namespace(args=["s.py"]))
        assert cli._parse_argv(parser).args == ["s.py", "-"]

    def test_a_subcommand_without_guest_args_keeps_refusing_leftovers(
        self, old_argparse
    ):
        parser = self._StubParser(["stray"], argparse.Namespace(command="inspect"))
        with pytest.raises(SystemExit) as exc:
            cli._parse_argv(parser)
        assert exc.value.code == 2
        assert "unrecognized arguments: stray" in parser.error_message

    def test_modern_argparse_is_left_completely_alone(self, monkeypatch):
        """On an interpreter that intermixes, the parse is the parse_args one."""
        monkeypatch.setattr(cli, "_ARGPARSE_INTERMIXES", True)
        parser = self._StubParser(["a"], argparse.Namespace(args=["s.py"]))
        assert cli._parse_argv(parser).args == ["s.py"]
        assert parser.used == "parse_args"
