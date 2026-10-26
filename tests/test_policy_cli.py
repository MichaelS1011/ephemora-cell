# SPDX-License-Identifier: BUSL-1.1
# Copyright 2026 Michael Soppa
"""``ephemora policy check`` — the pre-run policy view.

``policy_cli`` computes the ACTUAL permissions and isolation a run would carry
BEFORE anything executes, and it must do so ONLY by re-reading the
authoritative policy functions (``isolation_required_for``,
``sync_blockade_holds``, ``policy_fingerprint``, ``security_baseline_for`` and
the shared preopen guard in ``_sandbox_common``). No second policy engine, no
engine instantiation, no guest execution. These tests pin that: they compare
the snapshot against the REAL functions' return values instead of hardcoding a
second copy of the truth table.

Note: preopen targets live under a temp root (like tests/test_effective_preopens)
— pytest's tmp_path realpath is a canonical exception on macOS, but mkdtemp()
keeps the fixture meaningful on a container where $HOME is ``/root`` (blocked).
"""

from __future__ import annotations

import dataclasses
import json
import os
import shutil
import subprocess
import sys
import tempfile
from pathlib import Path

import pytest
import wasmtime

sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))

from ephemora_cell import ExecutionStatus, WASISandbox
from ephemora_cell.execution_report import (
    TRUST_TRUSTED,
    isolation_required_for,
    policy_fingerprint,
    security_baseline_for,
    sync_blockade_holds,
)
from ephemora_cell.policy_cli import (
    EXECUTION_MODE_IN_PROCESS,
    EXECUTION_MODE_SUBPROCESS,
    SCHEMA,
    format_report,
    snapshot,
    to_json,
)
from ephemora_cell.wasi_runtime import WASIConfig

SECRET_VALUE = "geheim123"


@pytest.fixture
def tmp_root():
    d = Path(tempfile.mkdtemp(prefix="ephemora_policy_"))
    yield d
    shutil.rmtree(d, ignore_errors=True)


def _snap(
    config: WASIConfig | None = None,
    *,
    trust: str = "unknown",
    abi: str = "preview1",
    profile_name: str | None = None,
    isolated: bool = False,
    language: str = "wasm",
) -> dict:
    return snapshot(
        config if config is not None else WASIConfig(),
        trust=trust,
        abi=abi,
        profile_name=profile_name,
        isolated=isolated,
        language=language,
    )


def _serialized(snap: dict) -> str:
    """Every byte a consumer could ever see of this snapshot."""
    return json.dumps(snap, sort_keys=True) + "\n" + format_report(snap)


class TestDefaultSnapshot:
    def test_schema_and_required_keys(self):
        snap = _snap(profile_name="llm")
        assert snap["schema"] == SCHEMA
        assert SCHEMA == "ephemora-cell/policy-check/1"
        for key in (
            "profile",
            "trust",
            "abi",
            "budgets",
            "isolation",
            "sync_blockade",
            "preopens",
            "env",
            "fingerprint",
            "security_baseline",
        ):
            assert key in snap, key
        assert snap["profile"] == "llm"
        assert snap["trust"] == "unknown"
        assert snap["abi"] == "preview1"

    def test_json_roundtrip(self):
        snap = _snap()
        assert json.loads(json.dumps(snap)) == snap
        assert to_json(snap)["schema"] == SCHEMA

    def test_deterministic(self):
        first, second = _snap(), _snap()
        assert first["fingerprint"] == second["fingerprint"]
        assert json.dumps(first, sort_keys=True) == json.dumps(second, sort_keys=True)

    def test_budgets_cover_every_config_field(self):
        snap = _snap()
        budgets = snap["budgets"]
        for field in dataclasses.fields(WASIConfig):
            if field.name == "allow_env":
                # Env VALUES are secrets: names only, never the pair.
                assert "allow_env" not in budgets
                assert budgets["allow_env_names"] == []
                continue
            assert field.name in budgets, field.name
        assert budgets["max_memory_mb"] == 128
        assert budgets["allow_dirs"] == []

    def test_invalid_trust_and_abi_fail_closed(self):
        with pytest.raises(ValueError):
            _snap(trust="bogus")
        with pytest.raises(ValueError):
            _snap(abi="wasm3")


class TestIsolationMatrix:
    @pytest.mark.parametrize("abi", ["preview1", "component"])
    def test_untrusted_and_unknown_require_isolation(self, abi):
        assert _snap(trust="unknown", abi=abi)["isolation"]["required"] is True
        assert _snap(trust="untrusted", abi=abi)["isolation"]["required"] is True

    @pytest.mark.parametrize("abi", ["preview1", "component"])
    def test_required_mirrors_the_real_function(self, abi):
        for trust in ("trusted", "untrusted", "unknown"):
            snap = _snap(trust=trust, abi=abi)
            assert snap["isolation"]["required"] is isolation_required_for(trust, abi)

    def test_execution_mode_is_subprocess_only_for_the_mandate(self):
        assert _snap(trust="unknown")["isolation"]["execution_mode"] == "subprocess"
        assert _snap(trust="trusted")["isolation"]["execution_mode"] == "in_process"

    def test_trusted_keeps_the_in_process_fast_path(self):
        iso = _snap(trust="trusted")["isolation"]
        assert iso["required"] is False
        assert "in-process" in iso["detail"]

    def test_untrusted_detail_names_the_worker_mandate(self):
        iso = _snap(trust="untrusted")["isolation"]
        assert "mandatory" in iso["detail"].lower()
        assert "ADR-015" in iso["detail"]
        assert "no in-process fallback" in iso["detail"]

    def test_auto_covers_both_abis_and_names_the_run_time_decision(self):
        snap = _snap(trust="unknown", abi="auto")
        iso = snap["isolation"]
        assert set(iso["per_abi"]) == {"preview1", "component"}
        assert "module bytes decide at run time" in iso["detail"]
        for abi in ("preview1", "component"):
            assert iso["per_abi"][abi]["required"] is isolation_required_for(
                "unknown", abi
            )
        assert iso["required"] is True


class TestSyncBlockade:
    def test_preview1_closed_fsync_enforces(self):
        snap = _snap(config=WASIConfig(allow_fsync=False), abi="preview1")
        assert snap["sync_blockade"]["holds"] is True

    def test_allow_fsync_open_lifts_it(self):
        snap = _snap(config=WASIConfig(allow_fsync=True), abi="preview1")
        assert snap["sync_blockade"]["holds"] is False

    def test_mirrors_the_real_function_per_abi(self):
        for allow_fsync in (True, False):
            for abi in ("preview1", "component"):
                snap = _snap(config=WASIConfig(allow_fsync=allow_fsync), abi=abi)
                assert snap["sync_blockade"]["holds"] is sync_blockade_holds(
                    abi, allow_fsync
                )
        # component + closed fsync is NOT a blockade — the component path has no
        # sync trap at all.
        assert (
            _snap(config=WASIConfig(allow_fsync=False), abi="component")[
                "sync_blockade"
            ]["holds"]
            is False
        )

    def test_auto_covers_both_abis(self):
        sync = _snap(config=WASIConfig(allow_fsync=False), abi="auto")["sync_blockade"]
        assert set(sync["per_abi"]) == {"preview1", "component"}
        assert sync["per_abi"]["preview1"] is True
        assert sync["per_abi"]["component"] is False

    def test_detail_states_the_enforcement_equation(self):
        detail = _snap()["sync_blockade"]["detail"]
        assert "preview1" in detail
        assert "allow_fsync" in detail


class TestPreopens:
    def test_empty_allow_dirs_yields_empty_buckets(self):
        pre = _snap(config=WASIConfig(allow_dirs=()))["preopens"]
        assert pre["requested"] == []
        assert pre["effective"] == []
        assert pre["refused"] == []

    def test_forbidden_dir_is_refused_with_a_reason_not_an_exception(self):
        snap = _snap(config=WASIConfig(allow_dirs=("/etc",)))
        pre = snap["preopens"]
        assert pre["requested"] == ["/etc"]
        assert pre["effective"] == []
        assert len(pre["refused"]) == 1
        assert pre["refused"][0]["entry"] == "/etc"
        assert isinstance(pre["refused"][0]["reason"], str)
        assert pre["refused"][0]["reason"]

    def test_forbidden_mapping_host_is_refused(self):
        pre = _snap(config=WASIConfig(allow_dirs=("/etc::guest-etc",)))["preopens"]
        assert pre["effective"] == []
        assert pre["refused"][0]["entry"] == "/etc::guest-etc"
        assert pre["refused"][0]["reason"]

    def test_granted_dir_matches_the_run_side_normalisation(self, tmp_root):
        data = tmp_root / "data"
        data.mkdir()
        entry = f"{data}::/data"
        pre = _snap(config=WASIConfig(allow_dirs=(entry,)))["preopens"]
        assert pre["refused"] == []
        assert pre["effective"] == [{"host": str(data.resolve()), "guest": "/data"}]

    def test_missing_dir_is_refused_like_a_run_would_skip_it(self, tmp_root):
        missing = tmp_root / "does-not-exist"
        pre = _snap(config=WASIConfig(allow_dirs=(str(missing),)))["preopens"]
        assert pre["effective"] == []
        assert pre["refused"][0]["entry"] == str(missing)

    def test_partial_refusal_keeps_the_good_entry(self, tmp_root):
        data = tmp_root / "data"
        data.mkdir()
        pre = _snap(config=WASIConfig(allow_dirs=(str(data), "/etc")))["preopens"]
        assert [e["host"] for e in pre["effective"]] == [str(data.resolve())]
        assert [r["entry"] for r in pre["refused"]] == ["/etc"]

    def test_report_shows_refusals(self):
        text = format_report(_snap(config=WASIConfig(allow_dirs=("/etc",))))
        assert "/etc" in text
        assert "refused" in text.lower()


class TestEnvSecrets:
    CONFIG = WASIConfig(
        allow_env=(("SECRET_TOKEN", SECRET_VALUE), ("PATH", "/usr/bin"))
    )

    def test_env_reports_names_and_count_only(self):
        env = _snap(config=self.CONFIG)["env"]
        assert env["names"] == ["SECRET_TOKEN", "PATH"]
        assert env["count"] == 2

    def test_secret_value_never_reaches_any_output(self):
        snap = _snap(config=self.CONFIG)
        assert SECRET_VALUE not in _serialized(snap)
        assert "/usr/bin" not in json.dumps(snap, sort_keys=True)

    def test_secret_value_absent_from_fingerprint_input_and_baseline(self):
        snap = _snap(config=self.CONFIG)
        assert SECRET_VALUE not in snap["fingerprint"]
        assert SECRET_VALUE not in json.dumps(snap["security_baseline"])


class TestAuthoritativeReuse:
    def test_fingerprint_is_the_record_fingerprint(self):
        config = WASIConfig(max_fuel=42, allow_dirs=(), allow_env=(("A", "b"),))
        assert _snap(config)["fingerprint"] == policy_fingerprint(config)

    def test_baseline_is_the_record_baseline(self):
        config = WASIConfig(max_fuel=7, allow_fsync=True)
        assert _snap(config)["security_baseline"] == security_baseline_for(config)

    def test_no_engine_no_execution_path_is_wired_in(self, monkeypatch):
        """The view must build no engine and start no guest."""
        import ephemora_cell.policy_cli as policy_cli

        def _boom(*args, **kwargs):
            raise AssertionError("snapshot must not build a wasmtime object")

        for name in ("Engine", "Store", "Module"):
            monkeypatch.setattr(wasmtime, name, _boom, raising=False)
        # No sandbox class, no runner: the module has no execution path at all.
        code = Path(policy_cli.__file__).read_text(encoding="utf-8").split('"""', 2)[2]
        for forbidden in (
            "WASISandbox",
            "ComponentSandbox",
            "run_isolated",
            "wasmtime",
        ):
            assert forbidden not in code, forbidden
        snap = _snap(config=WASIConfig(allow_dirs=("/etc",)))
        assert snap["preopens"]["refused"]


TRIVIAL_WAT = b"""
(module
  (import "wasi_snapshot_preview1" "proc_exit" (func $exit (param i32)))
  (memory (export "memory") 1)
  (func (export "_start")
    i32.const 0
    call $exit
  )
)
"""


class TestRunParity:
    """The display must equal what a run ACTUALLY enforces."""

    def test_effective_host_matches_a_real_preview1_grant(self, tmp_root):
        data = tmp_root / "data"
        data.mkdir()
        module = tmp_root / "trivial.wasm"
        module.write_bytes(wasmtime.wat2wasm(TRIVIAL_WAT))
        config = WASIConfig(max_fuel=1_000_000, allow_dirs=(str(data),))
        sandbox = WASISandbox(config=config)
        try:
            result = sandbox.run(
                str(module),
                use_subprocess=False,
                use_engine_pool=False,
                trust=TRUST_TRUSTED,
            )
        finally:
            sandbox.cleanup()
        assert result.status == ExecutionStatus.SUCCESS
        reported = {entry["host"] for entry in _snap(config)["preopens"]["effective"]}
        granted = set(result.effective_preopens) - {"/sandbox"}
        assert reported == granted == {str(data.resolve())}


class TestIsolatedRaise:
    """``--isolated`` can only RAISE isolation (same rule as the run gate).

    A trusted run keeps its in-process fast path, but an operator who passes
    ``--isolated`` gets a subprocess whether the mandate asked for it or not —
    the view must show that raise, or ``policy check && run`` would describe a
    different run than the one the flags select.
    """

    def test_trusted_without_isolated_keeps_the_fast_path(self):
        snap = _snap(trust="trusted", abi="preview1")
        assert snap["isolation"]["required"] is False
        assert snap["isolation"]["execution_mode"] == EXECUTION_MODE_IN_PROCESS
        assert snap["isolation"].get("raised_by") is None

    def test_trusted_with_isolated_shows_the_subprocess_raise(self):
        snap = _snap(trust="trusted", abi="preview1", isolated=True)
        assert snap["isolation"]["required"] is True
        assert snap["isolation"]["execution_mode"] == EXECUTION_MODE_SUBPROCESS
        assert snap["isolation"]["raised_by"] == "--isolated"

    def test_the_raise_also_applies_to_the_per_abi_entries(self):
        snap = _snap(trust="trusted", abi="auto", isolated=True)
        for entry in snap["isolation"]["per_abi"].values():
            assert entry["required"] is True
            assert entry["execution_mode"] == EXECUTION_MODE_SUBPROCESS

    def test_isolated_never_lowers_an_untrusted_mandate(self):
        """Isolation already mandatory: the raise is not an extra owner."""
        for abi in ("preview1", "component"):
            snap = _snap(trust="untrusted", abi=abi, isolated=True)
            assert snap["isolation"]["required"] is True
            assert snap["isolation"].get("raised_by") is None


class TestLanguageView:
    """A source run is not a compiled-module run — the view must say so.

    The language adapters force the worker themselves, and the source adapters
    REPLACE the caller's ``allow_dirs`` instead of adding to them — with
    different mount sets per guest, and for JavaScript with a mount set that
    depends on whether the artifact is source or a pre-compiled module. A view
    that showed the caller's directories as granted, or an explicit ``trusted``
    posture as an in-process path, would pre-approve a run that never happens.
    """

    def test_python_view_forces_the_worker_even_when_trusted(self):
        snap = _snap(trust="trusted", abi="component", language="python")
        assert snap["language"] == "python"
        assert snap["isolation"]["required"] is True
        assert snap["isolation"]["execution_mode"] == EXECUTION_MODE_SUBPROCESS
        assert "adapter" in snap["isolation"]["detail"].lower()

    def test_python_view_is_guest_dependent_because_the_adapter_branches_on_bytes(
        self, tmp_root
    ):
        """``run_python_script`` picks its mount set from the GUEST bytes, not
        from a flag: the installed product guest is a WASI-0.2 component and
        gets one private per-run dir, a legacy Preview1 interpreter guest also
        mounts its stdlib and the script's OWN directory. Showing only one of
        the two would pre-approve grants a run never gets, or hide grants the
        run really does get.
        """
        from ephemora_cell import lang_py

        caller = tmp_root / "data"
        caller.mkdir()
        config = WASIConfig(allow_dirs=(str(caller),))
        snap = _snap(config, trust="unknown", abi="component", language="python")
        effect = snap["preopens"]["language_effect"]
        assert effect["path_dependent"] is True
        # both branches replace, so THIS much is a single honest answer
        assert effect["replaces_allow_dirs"] is True
        assert effect["dropped_allow_dirs"] == snap["preopens"]["requested"]

        component = effect["component_run"]
        assert component["adapter_entry"] == "lang_py.run_python_script"
        assert [m["guest_path"] for m in component["mounts"]] == [
            lang_py._WORK_GUEST_PATH
        ]
        assert "throwaway per-run" in component["mounts"][0]["owner"]
        # the component path is the one branch that really gets no /sandbox —
        # pinned independently by a real component run in
        # tests/test_effective_preopens.py::TestComponentAttestation
        assert component["abi"] == "component"
        assert component["sandbox_scratch"] is False
        assert "no /sandbox" in component["extra_grants"]

        legacy = effect["legacy_interpreter_run"]
        assert legacy["adapter_entry"] == "lang_py.run_python_script"
        assert [m["guest_path"] for m in legacy["mounts"]] == [
            lang_py._STDLIB_GUEST_PATH,
            lang_py._WORK_GUEST_PATH,
        ]
        # the /work grant here is the SCRIPT'S OWN directory — not a private one
        work_mount = next(
            m for m in legacy["mounts"] if m["guest_path"] == lang_py._WORK_GUEST_PATH
        )
        assert "NOT a private" in work_mount["owner"]
        assert legacy["abi"] == "preview1"
        assert legacy["sandbox_scratch"] is True
        assert "/sandbox" in legacy["extra_grants"]

    def test_javascript_view_is_path_dependent_and_forces_the_worker(self):
        """One answer for both JavaScript artifacts would be wrong for one of
        them: the source run replaces the grants, the module run keeps them."""
        from ephemora_cell import lang_js

        snap = _snap(trust="trusted", abi="auto", language="javascript")
        assert snap["isolation"]["required"] is True
        assert snap["isolation"]["execution_mode"] == EXECUTION_MODE_SUBPROCESS
        effect = snap["preopens"]["language_effect"]
        assert effect["path_dependent"] is True
        # here even the replacement differs, so no single verdict is printed
        assert effect["replaces_allow_dirs"] is None
        # ...but the key is always present: an absent field must not be read by a
        # consumer as "nothing is dropped"
        assert effect["dropped_allow_dirs"] == snap["preopens"]["requested"]
        source = effect["source_run"]
        assert source["adapter_entry"] == "lang_js.run_javascript_source"
        assert source["replaces_allow_dirs"] is True
        assert [m["guest_path"] for m in source["mounts"]] == [lang_js._WORK_GUEST_PATH]
        # A preview1 run ALSO gets its ephemeral /sandbox scratch. Claiming the
        # staged directory were the run's only preopen was the exact error the
        # first correction left in — measured: effective_preopens contained it.
        assert "/sandbox" in source["mounts"][0]["owner"]
        assert source["sandbox_scratch"] is True
        assert "/sandbox" in source["extra_grants"]
        assert source["abi"] == "preview1"
        module = effect["module_run"]
        assert module["adapter_entry"] == "lang_js.run_javascript_module"
        assert module["replaces_allow_dirs"] is False
        assert module["mounts"] == []
        assert module["dropped_allow_dirs"] == []
        assert module["abi"] == "preview1"
        assert module["sandbox_scratch"] is True
        # and the CLI cannot reach the module entry at all — saying so stops the
        # view from presenting two live options where the product has one
        assert "library-only" in module["reachability"]
        assert "run --language javascript" in source["reachability"]

    def test_javascript_drops_are_the_callers_requested_dirs(self, tmp_root):
        caller = tmp_root / "data"
        caller.mkdir()
        snap = _snap(
            WASIConfig(allow_dirs=(str(caller),)),
            trust="unknown",
            abi="preview1",
            language="javascript",
        )
        effect = snap["preopens"]["language_effect"]
        assert (
            effect["source_run"]["dropped_allow_dirs"] == snap["preopens"]["requested"]
        )

    def test_the_per_abi_entries_are_raised_for_a_language_run_too(self):
        snap = _snap(trust="trusted", abi="auto", language="python")
        for entry in snap["isolation"]["per_abi"].values():
            assert entry["required"] is True
            assert entry["execution_mode"] == EXECUTION_MODE_SUBPROCESS

    def test_wasm_view_carries_no_language_effect(self):
        snap = _snap(trust="trusted", abi="preview1")
        assert "language_effect" not in snap["preopens"]
        assert snap["isolation"]["required"] is False

    def test_an_unknown_guest_is_refused_not_silently_wasm(self):
        with pytest.raises(ValueError, match="unknown language"):
            snapshot(
                WASIConfig(),
                trust="unknown",
                abi="auto",
                profile_name=None,
                language="kotlin",
            )

    def test_the_adapter_facts_the_view_asserts_are_pinned_in_the_adapters(self):
        """Every language claim is read from the shipped adapters and from the
        dispatcher that selects them, so a change there breaks this test
        instead of silently stale-mating the view."""
        import inspect

        from ephemora_cell import lang, lang_js, lang_py

        for mod in (lang_py, lang_js):
            assert "use_subprocess=True" in inspect.getsource(mod)

        # the dispatcher decides which adapter entry a run reaches
        dispatch = inspect.getsource(lang.run_language)
        assert "adapter.run_python_script" in dispatch
        assert "adapter.run_javascript_source" in dispatch
        assert "adapter.run_javascript_module" in dispatch

        # Python: stdlib + the script's OWN dir replace the caller's grants
        py_script = inspect.getsource(lang_py.run_python_script)
        assert '_WORK_GUEST_PATH = "/work"' in inspect.getsource(lang_py)
        assert 'f"{os.path.abspath(stdlib_dir)}::{_STDLIB_GUEST_PATH}"' in py_script
        assert 'f"{script_dir}::{_WORK_GUEST_PATH}"' in py_script
        assert "use_subprocess=True" in py_script

        # JavaScript source: one private tmp mount replaces the grants
        js_source = inspect.getsource(lang_js.run_javascript_source)
        assert 'allow_dirs=(f"{work}::{_WORK_GUEST_PATH}",)' in js_source
        assert "use_subprocess=True" in js_source

        # JavaScript module: touching no allow_dirs at all is the point — the
        # call-site form is tested, so a prose sentence about allow_dirs in the
        # docstring cannot make this a false alarm
        js_module = inspect.getsource(lang_js.run_javascript_module)
        assert "allow_dirs=" not in js_module
        # and it passes no abi — the preview1 ABI the view reports is the
        # sandbox's own default, not a choice the caller gets to make
        assert "abi=" not in js_module

    def test_the_component_python_path_is_the_private_tmp_mount(self):
        """The branch the product guest takes really does use a throwaway
        directory — the view's ``component_run`` must match that source."""
        import inspect

        from ephemora_cell import lang_py

        component = inspect.getsource(lang_py._run_component_script)
        assert 'allow_dirs=(f"{work}::{_WORK_GUEST_PATH}",)' in component

    def test_human_report_names_the_worker_mandate_and_the_mounts(self):
        text = format_report(_snap(trust="trusted", abi="component", language="python"))
        assert "adapter" in text.lower()
        assert "/work" in text
        assert "/opt/wasi-python/lib/python3.10" in text

    def test_human_report_shows_both_javascript_paths(self):
        text = format_report(_snap(trust="trusted", abi="auto", language="javascript"))
        assert "source_run" in text
        assert "module_run" in text
        assert "MODULE run keeps them" in text


COMPONENT_BYTES = b"\x00asm\x0d\x00\x01\x00" + b"\x00" * 8


class _FakeResult:
    """Minimal stand-in for an ``ExecutionResult`` (shape_result needs six)."""

    status = "ExecutionStatus.SUCCESS"
    stdout = ""
    stderr = ""
    exit_code = 0
    fuel_consumed = 1
    elapsed_ms = 1.0


def _recording(sink: dict):
    """A ``WASISandbox`` stand-in that records what the adapter tried to build."""

    class _Recording:
        def __init__(self, config=None):
            sink["config"] = config

        def run(self, path, **kwargs):
            sink.update(kwargs)
            return _FakeResult()

        def cleanup(self):
            pass

    return _Recording


def _dir_names(entries) -> list[str]:
    """Guest names of an ``allow_dirs`` tuple, in the order the adapter built it."""
    return [str(e).split("::", 1)[1] if "::" in str(e) else str(e) for e in entries]


class TestAdapterBuildsWhatTheViewPromises:
    """The grant promises driven through the adapters, not just read off them.

    Source-text pinning is what let one false promise through (the ``/sandbox``
    exclusivity of a preview1 run), so each adapter entry is executed against a
    recording sandbox and the ``allow_dirs`` it ACTUALLY builds — plus the ABI it
    passes and the worker flag it sets — are compared with the sub-view that
    makes the same promise.
    """

    @staticmethod
    def _core_guest(tmp_path):
        g = tmp_path / "core.wasm"
        g.write_bytes(wasmtime.wat2wasm(TRIVIAL_WAT))
        return str(g)

    @staticmethod
    def _component_guest(tmp_path):
        g = tmp_path / "comp.wasm"
        g.write_bytes(COMPONENT_BYTES)
        return str(g)

    @staticmethod
    def _caller(tmp_path):
        d = tmp_path / "data"
        d.mkdir()
        return d

    def test_python_component_branch(self, tmp_path, monkeypatch):
        from ephemora_cell import lang_py

        script = tmp_path / "s.py"
        script.write_text("print(1)\n")
        caller = self._caller(tmp_path)
        config = WASIConfig(allow_dirs=(str(caller),))
        sink: dict = {}
        monkeypatch.setattr(lang_py, "WASISandbox", _recording(sink))
        lang_py.run_python_script(
            self._component_guest(tmp_path), script_path=str(script), config=config
        )
        view = _snap(config, language="python")["preopens"]["language_effect"]
        promise = view["component_run"]
        assert _dir_names(sink["config"].allow_dirs) == [
            m["guest_path"] for m in promise["mounts"]
        ]
        assert sink.get("abi") == promise["abi"] == "component"
        assert sink.get("use_subprocess") is True
        # the caller's own directory is gone, exactly as the view says
        assert str(caller) not in _dir_names(sink["config"].allow_dirs)

    def test_python_legacy_interpreter_branch(self, tmp_path, monkeypatch):
        from ephemora_cell import lang_py

        script = tmp_path / "s.py"
        script.write_text("print(1)\n")
        stdlib = tmp_path / "stdlib"
        stdlib.mkdir()
        caller = self._caller(tmp_path)
        config = WASIConfig(allow_dirs=(str(caller),))
        sink = {}
        monkeypatch.setattr(lang_py, "WASISandbox", _recording(sink))
        lang_py.run_python_script(
            self._core_guest(tmp_path),
            stdlib_dir=str(stdlib),
            script_path=str(script),
            config=config,
        )
        promise = _snap(config, language="python")["preopens"]["language_effect"][
            "legacy_interpreter_run"
        ]
        assert _dir_names(sink["config"].allow_dirs) == [
            m["guest_path"] for m in promise["mounts"]
        ]
        # and the HOST side of the same promise: stdlib plus the script's own
        # directory — a guest name alone could hide a mount of the wrong tree
        hosts = sorted(str(e).split("::", 1)[0] for e in sink["config"].allow_dirs)
        assert hosts == sorted({str(stdlib), str(tmp_path)})
        assert str(caller) not in hosts
        assert sink.get("use_subprocess") is True
        # no abi is passed here, so this branch runs preview1 — what the view says
        assert promise["abi"] == "preview1"
        assert "abi" not in sink

    def test_javascript_source_branch(self, tmp_path, monkeypatch):
        from ephemora_cell import lang_js

        caller = self._caller(tmp_path)
        config = WASIConfig(allow_dirs=(str(caller),))
        sink = {}
        monkeypatch.setattr(lang_js, "WASISandbox", _recording(sink))
        lang_js.run_javascript_source(
            self._core_guest(tmp_path), source="1;", config=config
        )
        promise = _snap(config, language="javascript")["preopens"]["language_effect"][
            "source_run"
        ]
        assert _dir_names(sink["config"].allow_dirs) == [
            m["guest_path"] for m in promise["mounts"]
        ]
        assert sink.get("use_subprocess") is True
        assert "abi" not in sink  # → the sandbox default the view reports
        assert promise["abi"] == "preview1"

    def test_javascript_module_branch_keeps_the_callers_dirs(
        self, tmp_path, monkeypatch
    ):
        from ephemora_cell import lang_js

        caller = self._caller(tmp_path)
        config = WASIConfig(allow_dirs=(str(caller),))
        sink = {}
        monkeypatch.setattr(lang_js, "WASISandbox", _recording(sink))
        lang_js.run_javascript_module(self._core_guest(tmp_path), config=config)
        assert _dir_names(sink["config"].allow_dirs) == [str(caller)]
        assert sink.get("use_subprocess") is True
        promise = _snap(config, language="javascript")["preopens"]["language_effect"][
            "module_run"
        ]
        assert promise["mounts"] == []
        assert promise["replaces_allow_dirs"] is False
        # host side: the caller's own directory is the preopen, unchanged
        assert sink["config"].allow_dirs == config.allow_dirs

    def test_every_branch_passes_the_worker_flag_it_promises(
        self, tmp_path, monkeypatch
    ):
        """The view's 'a source run is always isolated' claim, checked per call

        rather than per module: a stray ``use_subprocess=False`` in one of the
        four entries would otherwise stay invisible to a module-wide grep.
        """
        from ephemora_cell import lang_js, lang_py

        script = tmp_path / "s.py"
        script.write_text("print(1)\n")
        stdlib = tmp_path / "stdlib"
        stdlib.mkdir()
        core = self._core_guest(tmp_path)
        component = self._component_guest(tmp_path)
        cases = (
            (
                lang_py,
                component,
                lambda p: lang_py.run_python_script(p, script_path=str(script)),
            ),
            (
                lang_py,
                core,
                lambda p: lang_py.run_python_script(
                    p, stdlib_dir=str(stdlib), script_path=str(script)
                ),
            ),
            (lang_js, core, lambda p: lang_js.run_javascript_source(p, source="1;")),
            (lang_js, core, lambda p: lang_js.run_javascript_module(p)),
        )
        for module, guest, call in cases:
            sink: dict = {}
            monkeypatch.setattr(module, "WASISandbox", _recording(sink))
            call(guest)
            assert sink.get("use_subprocess") is True, module
        # the isolation view reports subprocess for every language guest
        for language in ("python", "javascript"):
            iso = _snap(trust="trusted", abi="auto", language=language)["isolation"]
            assert iso["execution_mode"] == EXECUTION_MODE_SUBPROCESS


class TestLanguageAbiIsTheAdaptersFact:
    """A language run's ABI belongs to the adapter, not to ``--abi``.

    Reporting the caller's choice would print a sync blockade and a sandbox note
    for a run that cannot happen — measured as a false promise for
    ``--language javascript --abi component``.
    """

    def test_javascript_view_reports_preview1_with_the_source_named(self):
        snap = _snap(trust="unknown", abi="auto", language="javascript")
        assert snap["abi"] == "preview1"
        assert "javascript adapter" in snap["abi_source"]
        sync = snap["sync_blockade"]
        # a single, correct verdict instead of a both-ABI hedge
        assert "per_abi" not in sync
        assert sync["holds"] is True

    def test_javascript_view_still_reports_preview1_if_asked_for_component(self):
        # library-level defence: the view cannot be talked into another ABI
        snap = _snap(trust="unknown", abi="component", language="javascript")
        assert snap["abi"] == "preview1"
        assert snap["sync_blockade"]["holds"] is True

    def test_python_view_reports_both_abis_because_the_guest_bytes_decide(self):
        snap = _snap(trust="unknown", abi="auto", language="python")
        assert snap["abi"] == "auto"
        assert "guest's own bytes" in snap["abi_source"]
        assert set(snap["sync_blockade"]["per_abi"]) == {"preview1", "component"}

    def test_a_wasm_view_keeps_the_callers_abi_and_names_no_source(self):
        snap = _snap(abi="component")
        assert snap["abi"] == "component"
        assert "abi_source" not in snap
        assert "fingerprint_note" not in snap


class TestLanguageFingerprintScope:
    """The view's digest is not the run's attestation."""

    def test_language_view_labels_its_digest_scope(self):
        snap = _snap(trust="unknown", abi="auto", language="python")
        note = snap["fingerprint_note"]
        assert "DIFFERENT digest" in note
        assert "attestation" in note
        text = format_report(snap)
        assert "fingerprint scope:" in text

    def test_wasm_view_needs_no_scope_note(self):
        assert "fingerprint_note" not in _snap()

    def test_the_digest_is_still_the_records_own_function_of_this_config(self):
        config = WASIConfig(max_fuel=99, allow_dirs=("/tmp",))
        assert _snap(config, language="python")["fingerprint"] == policy_fingerprint(
            config
        )


class TestPreAdapterLabel:
    """A caller dir the adapter will drop must not read as an approval."""

    def test_language_report_marks_the_line_pre_adapter(self, tmp_root):
        caller = tmp_root / "data"
        caller.mkdir()
        text = format_report(
            _snap(WASIConfig(allow_dirs=(str(caller),)), language="javascript")
        )
        assert "allowed (pre-adapter)" in text

    def test_wasm_report_still_says_plain_allowed(self, tmp_root):
        caller = tmp_root / "data"
        caller.mkdir()
        text = format_report(_snap(WASIConfig(allow_dirs=(str(caller),))))
        assert "allowed (pre-adapter)" not in text
        assert f"allowed: {caller.resolve()}" in text


class TestOutputGuards:
    def test_to_json_refuses_a_foreign_snapshot(self):
        with pytest.raises(ValueError, match="not a policy-check snapshot"):
            to_json({"schema": "someone-elses/1"})

    def test_human_report_names_the_isolated_raise(self):
        text = format_report(_snap(trust="trusted", abi="preview1", isolated=True))
        assert "isolation raised by: --isolated" in text


class TestFormatReport:
    def test_reports_isolation_and_fingerprint(self):
        snap = _snap(trust="untrusted", abi="preview1", profile_name="llm")
        text = format_report(snap)
        assert isinstance(text, str)
        assert "untrusted" in text
        assert "preview1" in text
        assert snap["fingerprint"][:16] in text
        assert "ADR-015" in text

    def test_names_env_by_name_only(self):
        text = format_report(_snap(config=TestEnvSecrets.CONFIG))
        assert "SECRET_TOKEN" in text
        assert SECRET_VALUE not in text

    def test_zero_refusals_say_so(self):
        text = format_report(_snap())
        assert "refused" in text.lower()


class TestTheViewAndARunAgreeThroughTheCommands:
    """The promise is that the view and the run read the SAME
    authorities. Measured here through the two commands a user calls — a library
    unit test cannot show that the CLI wires them to the same primitives.
    """

    REPO = Path(__file__).resolve().parent.parent
    COMPONENT = REPO / "tests" / "fixtures" / "hello02.wasm"

    def _cli(self, *args: str) -> subprocess.CompletedProcess:
        return subprocess.run(
            [sys.executable, "-m", "ephemora_cell.cli", *args],
            capture_output=True,
            text=True,
            timeout=300,
            cwd=str(self.REPO),
        )

    def _document(self, proc: subprocess.CompletedProcess) -> dict:
        assert proc.returncode == 0, (proc.returncode, proc.stderr)
        return json.loads(proc.stdout[proc.stdout.index("{") :])

    @staticmethod
    def _any_document(proc: subprocess.CompletedProcess) -> dict:
        """Parse the view even where the view itself is a refusal (exit 1)."""
        return json.loads(proc.stdout[proc.stdout.index("{") :])

    def test_grants_isolation_and_sync_answer_the_same_way(self, tmp_path):
        grant = tmp_path / "granted"
        grant.mkdir()
        view = self._document(
            self._cli("policy", "check", "--allow-dirs", str(grant), "--json")
        )
        run = self._document(
            self._cli("run", str(self.COMPONENT), "--allow-dirs", str(grant), "--json")
        )
        record_baseline = run["security_baseline"]
        # the granted host path is the SAME decision in both documents
        assert [e["host"] for e in view["preopens"]["effective"]] == record_baseline[
            "preopens"
        ], (view["preopens"], record_baseline["preopens"])
        assert view["preopens"]["refused"] == []
        # ADR-015: unknown trust forces the worker, and the run went there
        assert view["isolation"]["required"] is True
        assert view["isolation"]["execution_mode"] == record_baseline["execution_mode"]
        # the sync blockade is per-ABI in the view; the record states the ABI it
        # actually ran and the one enforcement that ABI got
        abi = record_baseline["abi"]
        assert abi in view["sync_blockade"]["per_abi"]
        assert (
            view["sync_blockade"]["per_abi"][abi]
            == record_baseline["sync_blockade_enforced"]
        )
        # budgets the view promises are the budgets the record attests
        assert view["budgets"]["max_fuel"] == record_baseline["fuel"]
        assert (
            view["budgets"]["memory_capacity_bytes"]
            == record_baseline["memory_limit_bytes"]
        )

    def test_a_forbidden_grant_is_refused_by_both_commands(self):
        """A capability neither command grants, and neither one invents.

        The two commands refuse in their own roles: `policy check` answers with a
        verdict about the configuration (its documented non-zero), `run` with the
        caller class — and neither reports success for a grant it did not make.
        """
        check = self._cli("policy", "check", "--allow-dirs", "/etc", "--json")
        assert check.returncode == 1, (check.returncode, check.stderr)
        view = self._any_document(check)
        assert view["preopens"]["effective"] == []
        assert len(view["preopens"]["refused"]) == 1
        forbidden_run = self._cli(
            "run", str(self.COMPONENT), "--allow-dirs", "/etc", "--json"
        )
        # caller class: nothing was executed (docs/cli-errors.md)
        assert forbidden_run.returncode == 2, (
            forbidden_run.stdout,
            forbidden_run.stderr,
        )
        assert "Traceback" not in forbidden_run.stderr
        assert "forbidden" in forbidden_run.stderr.lower()

    def test_a_config_changed_between_check_and_run_is_the_run_that_counts(
        self, tmp_path
    ):
        """The view is advisory and holds no state — a different call is a
        different policy, and the run attests its OWN config, never the last
        snapshot someone looked at."""
        other = tmp_path / "other"
        other.mkdir()
        checked = self._document(
            self._cli(
                "policy",
                "check",
                "--allow-dirs",
                str(other),
                "--memory-mb",
                "512",
                "--json",
            )
        )
        run = self._document(
            self._cli("run", str(self.COMPONENT), "--memory-mb", "64", "--json")
        )
        assert checked["budgets"]["max_memory_mb"] == 512
        assert [e["host"] for e in checked["preopens"]["effective"]] == [str(other)]
        # the run asked for neither that grant nor that memory: its own record says so
        assert run["security_baseline"]["memory_limit_bytes"] == 64 * 1024 * 1024
        assert str(other) not in run["security_baseline"]["preopens"]

    def test_a_grant_swapped_between_check_and_run_is_not_inherited(self, tmp_path):
        """B15, the host half of the race: the operator's flag never changed — the
        directory behind it did. The run re-decides from the host as it is NOW, so
        a moved entry cannot inherit the earlier "granted" verdict.

        Measured: the swapped path is canonicalised to a blocked location and
        refused when the run's config is built (caller class, exit 2 — nothing
        started). If the swap happens later, inside the run, the grant-time
        revalidation skips it instead — `tests/test_effective_preopens.py`.
        """
        victim = tmp_path / "data"
        victim.mkdir()
        checked = self._document(
            self._cli("policy", "check", "--allow-dirs", str(victim), "--json")
        )
        assert [e["host"] for e in checked["preopens"]["effective"]] == [str(victim)]
        # between the check and the run, the path stops being a directory and
        # becomes a link into a forbidden location
        victim.rmdir()
        os.symlink("/etc", victim)
        run = self._cli(
            "run", str(self.COMPONENT), "--allow-dirs", str(victim), "--json"
        )
        assert run.returncode == 2, (run.returncode, run.stdout, run.stderr)
        assert "forbidden" in run.stderr.lower(), run.stderr
        assert (
            "/private/etc" in run.stderr or "blocked location" in run.stderr
        ), run.stderr
        assert "Traceback" not in run.stderr

    def test_the_view_states_which_field_a_run_records(self):
        """The one place the two documents legitimately differ, said out loud."""
        view = self._document(self._cli("policy", "check", "--json"))
        scope = view["preopens"]["baseline_scope"]
        assert "AS REQUESTED" in scope
        assert "canonical host paths" in scope
