# SPDX-License-Identifier: BUSL-1.1
# Copyright 2026 Michael Soppa
"""Assertion harness over the agent-framework integration examples.

The scripts in ``integration/agent_frameworks/`` are runnable demonstrations:
each prints a JSON report and exits 0, so a wrong result would still look
green (measured: zero ``assert`` statements in every script). This harness
imports each example, calls the same function its ``main()`` calls, and
asserts the values the example itself reports — turning "the script did not
crash" into "the script's claim is true". It also pins the untrusted-input
contract of the shared ``EphemoraCellExecutor`` (the substrate every
framework example runs through): non-string arguments, path escapes, NUL
bytes, directories, missing files and sha256 pinning must all be refused
fail-closed before anything executes.

Usage:
    python integration/verify_agent_frameworks.py

Exit code 0 = every executed check passed; 1 = at least one failed. A
missing framework is reported as an explicit SKIP and is never counted as a
pass. The harness creates its fixtures in a temporary directory and removes
them again; it never writes into the repository.
"""

from __future__ import annotations

import asyncio
import importlib.metadata as md
import importlib.util
import json
import sys
import tempfile
from pathlib import Path

REPO = Path(__file__).resolve().parent.parent
AF = REPO / "integration" / "agent_frameworks"
WORKLOADS = REPO / "benchmarks" / "workloads"
sys.path.insert(0, str(REPO))

failures: list[str] = []
skipped: list[str] = []


def check(cond: bool, msg: str) -> None:
    print(("PASS  " if cond else "FAIL  ") + msg)
    if not cond:
        failures.append(msg)


def note_skip(msg: str) -> None:
    print("SKIP  " + msg)
    skipped.append(msg)


def load_or_skip(name: str, path: Path):
    """Import an example; a missing framework must not be a pass and must not
    kill this harness (the examples call ``sys.exit(0)`` on a missing
    framework, which would end the import mid-run)."""
    try:
        spec = importlib.util.spec_from_file_location(name, path)
        if spec is None or spec.loader is None:
            failures.append(f"{name}: cannot load {path}")
            print(f"FAIL  {name}: cannot load {path}")
            return None
        mod = importlib.util.module_from_spec(spec)
        sys.modules[name] = mod
        spec.loader.exec_module(mod)
        return mod
    except ImportError as exc:
        note_skip(f"{name}: framework absent ({exc}) — NOT EXECUTED, not a pass")
        return None
    except SystemExit as exc:
        code = getattr(exc, "code", 0)
        if code in (0, None):
            note_skip(
                f"{name}: module called sys.exit(0) at import "
                f"(framework absent) — NOT EXECUTED, not a pass"
            )
            return None
        failures.append(f"{name}: module exited {code} at import")
        print(f"FAIL  {name}: module exited {code} at import")
        return None


def section(title: str) -> None:
    print()
    print(f"--- {title} ---")


# --------------------------------------------------------------------------
# 1. EphemoraCellExecutor — untrusted-input contract (shared by every example,
#    independent of any framework being installed).
# --------------------------------------------------------------------------
def executor_contract(tmp: Path) -> None:
    section("EphemoraCellExecutor: untrusted model/agent input contract")
    from integration.ephemora_cell_agent_executor import EphemoraCellExecutor

    light = WORKLOADS / "hello_rust.wasm"
    assert light.is_file(), f"workload missing: {light}"

    ex = EphemoraCellExecutor(max_fuel=200_000, timeout=5)
    r = ex.execute(str(light))
    check(
        r.status == "success" and not r.blocked,
        f"allowlisted module runs ({r.status}, {r.elapsed_ms}ms)",
    )
    check(
        isinstance(r.module_sha256, str) and len(r.module_sha256) == 64,
        "run binds a sha256 module identity",
    )
    check(r.exit_code == 0, "successful run reports exit_code 0")

    for label, arg in [
        ("non-string (None)", None),
        ("non-string (int)", 42),
        ("empty string", ""),
        ("whitespace only", "   "),
        ("embedded NUL", "hello\x00.wasm"),
        ("outside allowlist (absolute)", "/etc/hosts"),
        ("outside allowlist (relative escape)", "../../etc/hosts"),
    ]:
        rr = ex.execute(arg)
        check(
            rr.status == "policy_denied"
            and rr.blocked is True
            and rr.elapsed_ms == 0.0,
            f"{label} refused fail-closed, nothing executed ({rr.status}/{rr.reason})",
        )

    # a private fixture root proves the containment and file-type rules
    root = tmp / "fixture_root"
    root.mkdir(parents=True, exist_ok=True)
    (root / "fake.wasm").write_bytes(b"not a wasm module")
    link = root / "escape.wasm"
    if link.is_symlink() or link.exists():
        link.unlink()
    link.symlink_to(light)

    confined = EphemoraCellExecutor(
        max_fuel=200_000, timeout=5, allowed_roots=(str(root),)
    )
    r = confined.execute(str(root / "fake.wasm"))
    check(
        r.status == "policy_denied" and r.reason == "not_a_wasm_module",
        f"non-WASM bytes in an allowed root refused ({r.reason})",
    )
    r = confined.execute(str(link))
    check(
        r.status == "policy_denied" and r.reason == "outside_allowed_roots",
        f"symlink out of the allowed root refused, target not run ({r.reason})",
    )
    r = confined.execute(str(root))
    check(
        r.status == "policy_denied" and r.reason == "not_a_regular_file",
        f"a directory refused as not-a-regular-file ({r.reason})",
    )
    r = confined.execute(str(root / "absent.wasm"))
    check(
        r.status == "policy_denied" and r.reason.startswith("stat_failed:"),
        f"missing module refused, not raised ({r.reason})",
    )

    pinned = EphemoraCellExecutor(
        max_fuel=200_000, timeout=5, allowed_sha256={"hello_rust.wasm": "0" * 64}
    )
    r = pinned.execute(str(light))
    check(
        r.status == "policy_denied" and r.reason.startswith("digest_pin_mismatch:"),
        f"wrong sha256 pin refuses the run ({r.reason})",
    )
    pinning = EphemoraCellExecutor(max_fuel=200_000, timeout=5, allowed_sha256={})
    r = pinning.execute(str(light))
    check(
        r.status == "policy_denied" and r.reason == "module_not_pinned",
        f"pinning mode refuses an unpinned module ({r.reason})",
    )

    r = ex.execute("/etc/hosts")
    check(
        r.reason == "outside_allowed_roots",
        "an arbitrary host path is refused before any interpreter starts",
    )


# --------------------------------------------------------------------------
# 2..7 framework examples: assert what their own reporter claims
# --------------------------------------------------------------------------
def langgraph_checks() -> None:
    section("LangGraph example (test_langgraph.py::test_langgraph)")
    mod = load_or_skip("example_langgraph", AF / "test_langgraph.py")
    if mod is None:
        return
    r = mod.test_langgraph()
    statuses = [t["status"] for t in r["tool_calls"]]
    check(r["nodes_executed"] == 4, f"4 graph nodes executed ({r['nodes_executed']})")
    check(
        statuses == ["success", "success", "success", "fuel_exhausted"],
        f"per-node statuses are exactly the expected 3+1 ({statuses})",
    )
    check(r["all_tools_ran"] is True, "all_tools_ran is True")
    check(r["lightweight_tools_succeeded"] is True, "3 lightweight tools succeeded")
    check(
        r["heavy_tool_bounded_by_fuel"] is True,
        "heavy tool was bounded by fuel (sandbox stopped a runaway guest)",
    )
    check(
        all(t["elapsed_ms"] > 0 for t in r["tool_calls"]),
        "every node reports a non-zero wall time",
    )
    check(
        r["langgraph_version"] == md.version("langgraph"),
        f"reported langgraph version matches the env ({r['langgraph_version']})",
    )


def langchain_checks() -> None:
    section("LangChain example (test_langchain.py::test_langchain)")
    mod = load_or_skip("example_langchain", AF / "test_langchain.py")
    if mod is None:
        return
    r = mod.test_langchain()
    check(r["tools_invoked"] == 3, f"3 tool invocations ({r['tools_invoked']})")
    check(
        [x["status"] for x in r["runs"]] == ["success", "success", "fuel_exhausted"],
        "statuses are success/success/fuel_exhausted",
    )
    check(r["lightweight_tools_succeeded"] is True, "2 lightweight tools succeeded")
    check(r["heavy_tool_bounded_by_fuel"] is True, "heavy tool bounded by fuel")
    check(
        hasattr(mod.ephemora_cell_execute, "invoke"),
        f"the Cell wrapper is a real LangChain tool ({r['tool_type']})",
    )


def openai_agents_checks() -> None:
    section("OpenAI Agents SDK example (test_openai_agents.py)")
    mod = load_or_skip("example_openai_agents", AF / "test_openai_agents.py")
    if mod is None:
        return
    r = asyncio.run(mod.test_openai_agents())
    check(r["tool_binding_verified"] is True, "the Cell function became a FunctionTool")
    check(
        r["tools_registered"] == ["execute_wasm"],
        f"exactly one registered tool ({r['tools_registered']})",
    )
    check(
        r["tool_execution_status"] == "success",
        f"the tool executed WASM in the sandbox ({r['tool_execution_status']})",
    )
    check(
        r["tool_denies_arbitrary_path"] is True,
        "an arbitrary host path named by a model is refused (policy_denied)",
    )
    check(
        r.get("llm_loop") in ("skipped", "executed"),
        f"LLM loop state is explicit ({r.get('llm_loop')}: {r.get('llm_reason', '-')})",
    )
    if r.get("llm_loop") == "skipped":
        note_skip(
            "openai_agents Runner.run() decision loop: NOT EXECUTED "
            "(no OPENAI_API_KEY/model endpoint) — tool binding only"
        )


def crewai_checks() -> None:
    section("CrewAI example (test_crewai.py::test_crewai)")
    mod = load_or_skip("example_crewai", AF / "test_crewai.py")
    if mod is None:
        return
    r = mod.test_crewai()
    check(
        r["tool_binding_verified"] is True, "the Cell tool is bound to the CrewAI agent"
    )
    check(
        r["tools_registered"] == ["ephemora_cell_execute"],
        f"registered tool name is stable ({r['tools_registered']})",
    )
    check(
        r["tool_execution_status"] == "success",
        f"invoking through CrewAI's wrapper runs real WASM ({r['tool_execution_status']})",
    )
    if r.get("llm_loop") == "skipped":
        note_skip(
            "crewai crew.kickoff() decision loop: NOT EXECUTED "
            "(no OPENAI_API_KEY) — tool binding only"
        )


def autogen_checks() -> None:
    section("AutoGen example (test_autogen.py::test_autogen)")
    mod = load_or_skip("example_autogen", AF / "test_autogen.py")
    if mod is None:
        return
    r = mod.test_autogen()
    check(r["modules_executed"] == 3, f"3 modules executed ({r['modules_executed']})")
    check(
        all(
            x["status"] in ("success", "fuel_exhausted", "policy_denied")
            for x in r["results"]
        ),
        "every module reports a concrete sandbox status",
    )
    check(
        any(x["status"] == "success" for x in r["results"]),
        "at least one module ran to success",
    )
    note_skip(
        "autogen agent class is only an availability gate in this example "
        "(its own docstring says so) — no AssistantAgent.run() is exercised"
    )


def semantic_kernel_checks() -> None:
    section("Semantic Kernel example (test_semantic_kernel.py::run_test)")
    mod = load_or_skip("example_semantic_kernel", AF / "test_semantic_kernel.py")
    if mod is None:
        return
    r = asyncio.run(mod.run_test())
    check(
        r["modules_executed"] == 3,
        f"3 modules executed via Kernel.invoke ({r['modules_executed']})",
    )
    parsed = []
    for item in r["results"]:
        try:
            parsed.append(json.loads(item["output"]))
        except (KeyError, json.JSONDecodeError):
            parsed.append(None)
    check(
        all(p and p.get("status") in ("success", "fuel_exhausted") for p in parsed),
        f"every plugin result is real JSON with a sandbox status ({parsed})",
    )


def main() -> int:
    print(f"python {sys.version.split()[0]}")
    with tempfile.TemporaryDirectory(prefix="ephemora-integ-") as td:
        executor_contract(Path(td))
    langgraph_checks()
    langchain_checks()
    openai_agents_checks()
    crewai_checks()
    autogen_checks()
    semantic_kernel_checks()
    print()
    print(f"CHECKS FAILED: {len(failures)}")
    for f in failures:
        print(f"  FAIL: {f}")
    print(f"EXPLICIT SKIPS (no evidence claimed): {len(skipped)}")
    for s in skipped:
        print(f"  SKIP: {s}")
    return 1 if failures else 0


if __name__ == "__main__":
    sys.exit(main())
