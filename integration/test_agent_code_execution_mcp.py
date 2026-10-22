"""Agent-to-sandbox end-to-end over the advertised MCP stdio surface.

The 1.2.0 directive asks for two things this file is the evidence for:

1. **at least one real agent code execution over an advertised integration**,
   not an import check and not a mocked call, and
2. **an enforced refusal on that same path**, so the proof is a boundary, not a
   demo.

The integration exercised here is the one a user actually mounts: the stdio MCP
server, driven by the OFFICIAL MCP Python SDK client (`mcp`), the same client
Claude Desktop, Cursor, VS Code and Codex speak. The "agent" in this test is the
driver: it authors the module and its sidecar, drops them into a registry
directory, and hands the directory to the server with ``--tools-dir`` — exactly
the operator-free path a tool-writing agent takes. Nothing in the module comes
from this repository; the bytes are compiled here, by the test, from WAT.

**This is not an LLM run.** No model is called, no prompt is sent, and no
reasoning loop is claimed: what is proven is the *execution* half of an agent
integration — that code an agent hands over is registered, executed inside the
sandbox and refused at the boundary when it asks for more than it was granted.
The autonomous, model-driven loop is a separate claim that this file does not
make (see docs/product_contract.md).

Four measurements, in the order a user meets them:

* the authored tool is **registered** and appears in ``tools/list``;
* calling it **executes** the agent's own code and returns its stdout, with the
  execution identity in ``_meta.execution``;
* a second tool whose sidecar asks for ``/etc`` **cannot get it**: the sidecar
  can only narrow the profile's grants, so the guest finds no preopen to escape
  through and reports the failing errno itself — and ``get-policy``, the
  control plane, states the enforced preopen list;
* a third tool that never returns is **stopped by the fuel budget** and comes
  back as an ``isError`` result with a status, not as a hang and not as a
  success.

Skipped, never silently passed, when the SDK is absent:

    uv venv /tmp/sdk && uv pip install --python /tmp/sdk/bin/python \
        --no-index --find-links <wheelhouse> "wasmtime==49.0.4.post1+git.2c2970205f" \
        "pytest" "mcp>=2" -e .
    /tmp/sdk/bin/python -m pytest integration/test_agent_code_execution_mcp.py -v
"""

from __future__ import annotations

import asyncio
import json
import os
import sys
from pathlib import Path

import pytest

mcp = pytest.importorskip("mcp")

import wasmtime  # noqa: E402
from mcp import ClientSession, StdioServerParameters  # noqa: E402
from mcp.client.stdio import stdio_client  # noqa: E402

# The repository is NOT put on sys.path. An earlier version did (`sys.path.insert(
# 0, REPO)`, copied from the interop test) and the positive control below then
# imported `ephemora_cell` from the source tree while the server under test was
# the installed console script — the control validated a different package than
# the one under test (independent review, 2026-10-20). Everything here imports
# the package the server actually runs.

MARKER = "AGENT-AUTHORED-6f1c"
ESCAPE_TARGET = "/etc/passwd"

#: Writes ``MARKER`` to stdout and exits 0. The module the agent "wrote".
MARKER_WAT = f"""
(module
  (import "wasi_snapshot_preview1" "fd_write"
    (func $fd_write (param i32 i32 i32 i32) (result i32)))
  (import "wasi_snapshot_preview1" "proc_exit" (func $proc_exit (param i32)))
  (memory (export "memory") 1)
  (data (i32.const 8) "{MARKER}")
  (data (i32.const 64) "\\08\\00\\00\\00\\15\\00\\00\\00")
  (func (export "_start")
    i32.const 1 i32.const 64 i32.const 1 i32.const 100
    call $fd_write drop
    i32.const 0
    call $proc_exit))
"""

#: Tries to open ``passwd`` READ-ONLY through the FIRST preopen (fd 3) and
#: prints ``escape=1`` when the open was refused, ``escape=0`` when it succeeded.
#:
#: The path is relative to the preopen root on purpose: if fd 3 pointed at
#: ``/etc`` this same module would open ``/etc/passwd`` and print ``escape=0``.
#: An earlier version asked for ``etc/passwd`` with O_CREAT, which resolves to
#: ``/etc/etc/passwd`` even under the very grant it was meant to detect — it
#: could not tell a refused escape from a granted one (independent review,
#: 2026-10-20). Read-only, no O_CREAT: opening a file is the measurement.
ESCAPE_WAT = """
(module
  (import "wasi_snapshot_preview1" "fd_write"
    (func $fd_write (param i32 i32 i32 i32) (result i32)))
  (import "wasi_snapshot_preview1" "path_open"
    (func $path_open (param i32 i32 i32 i32 i32 i64 i64 i32 i32) (result i32)))
  (memory (export "memory") 1)
  (data (i32.const 8) "passwd")
  ;; iovec for the report: {ptr=128, len=8}
  (data (i32.const 64) "\\80\\00\\00\\00\\08\\00\\00\\00")
  (data (i32.const 128) "escape=")
  (func (export "_start") (local $errno i32)
    i32.const 3 i32.const 0 i32.const 8 i32.const 6 i32.const 0
    i64.const 2 i64.const 0 i32.const 0 i32.const 100
    call $path_open
    local.set $errno
    ;; "escape=" is at 128..134; byte 135 is '1' when refused, '0' when opened
    i32.const 128
    i32.const 49
    i32.const 48
    local.get $errno i32.const 0 i32.ne
    select
    i32.store8 offset=7
    i32.const 1 i32.const 64 i32.const 1 i32.const 160
    call $fd_write drop))
"""

#: Never returns: the fuel budget has to stop it.
BOMB_WAT = """
(module
  (func (export "_start")
    (loop $l
      br $l)))
"""


def _server_command() -> list[str]:
    """The installed console script of THIS environment, else its module form."""
    candidate = Path(sys.executable).with_name("ephemora-cell-mcp")
    if candidate.exists() and os.access(str(candidate), os.X_OK):
        return [str(candidate)]
    return [sys.executable, "-m", "ephemora_cell_mcp"]


def _author_tool(tools: Path, name: str, wat: str, allow_dirs=()) -> None:
    """Write a WASM module and its sidecar — the agent's whole contribution."""
    (tools / f"{name}.wasm").write_bytes(wasmtime.wat2wasm(wat))
    (tools / f"{name}.json").write_text(
        json.dumps(
            {
                "name": name,
                "description": "agent-authored module for the 1.2.0 E2E",
                "input_schema": {
                    "type": "object",
                    "properties": {},
                    "additionalProperties": True,
                },
                "profile": "llm",
                "allow_dirs": list(allow_dirs),
            }
        ),
        encoding="utf-8",
    )


def _is_error(result) -> bool:
    """The SDK spells the flag camelCase in 1.x and snake_case in 2.x."""
    for attr in ("isError", "is_error"):
        value = getattr(result, attr, None)
        if value is not None:
            return bool(value)
    return False


def _execution(result) -> dict:
    meta = getattr(result, "meta", None) or {}
    return dict(meta.get("execution", {}))


def _text(result) -> str:
    return "".join(
        block.text for block in result.content if getattr(block, "text", None)
    )


@pytest.fixture()
def authored_tools(tmp_path) -> Path:
    tools = tmp_path / "agent-tools"
    tools.mkdir()
    _author_tool(tools, "agent_marker", MARKER_WAT)
    _author_tool(tools, "agent_escape", ESCAPE_WAT, allow_dirs=["/etc"])
    _author_tool(tools, "agent_bomb", BOMB_WAT)
    return tools


def test_agent_authored_code_executes_and_the_boundary_refuses(authored_tools):
    """One session: register, execute, refuse, stop."""

    command = _server_command()
    params = StdioServerParameters(
        command=command[0], args=[*command[1:], "--tools-dir", str(authored_tools)]
    )

    async def drive() -> dict:
        async with stdio_client(params) as (read, write):
            async with ClientSession(read, write) as session:
                await session.initialize()
                listed = await session.list_tools()
                marker = await session.call_tool("agent_marker", {})
                escape = await session.call_tool("agent_escape", {})
                policy = await session.call_tool("get-policy", {"tool": "agent_escape"})
                bomb = await session.call_tool("agent_bomb", {})
                return {
                    "names": [tool.name for tool in listed.tools],
                    "marker": marker,
                    "escape": escape,
                    "policy": policy,
                    "bomb": bomb,
                }

    seen = asyncio.run(drive())

    # 1. The agent's modules were registered from the directory it handed over.
    for authored in ("agent_marker", "agent_escape", "agent_bomb"):
        assert authored in seen["names"], seen["names"]

    # 2. The agent's own code really ran, in the sandbox, and said so.
    marker = seen["marker"]
    assert not _is_error(marker), _text(marker)
    assert _execution(marker).get("status") == "success", _execution(marker)
    assert MARKER in _text(marker), _text(marker)
    assert int(_execution(marker).get("fuel_consumed", 0)) > 0

    # 3. The escape was refused by the capability model. Two independent
    #    readings, because each alone can be fooled:
    #    (a) what the RUN attests it preopened — `_meta.execution` carries the
    #        baseline of the execution that actually happened, not a prediction;
    #    (b) what the guest itself observed — this module opens `passwd`
    #        read-only through fd 3, so it prints `escape=0` for real if (and
    #        only if) that preopen resolves to a directory holding a readable
    #        `passwd`, which is exactly what /etc does and /sandbox does not.
    policy = json.loads(_text(seen["policy"]))
    assert policy["allow_dirs_configured"] == ["/etc"], policy
    predicted = policy["security_baseline"]["preopens"]
    assert ESCAPE_TARGET not in predicted, predicted
    assert "/etc" not in predicted, predicted

    escape_run = _execution(seen["escape"])
    attested = escape_run.get("security_baseline", {}).get("preopens")
    assert attested == ["/sandbox"], attested
    assert not any(p == "/etc" or p.startswith("/etc/") for p in attested), attested

    escape_text = _text(seen["escape"])
    # the guest ran to completion; only the capability was missing
    assert escape_run.get("status") == "success", (escape_run, escape_text)
    assert escape_text.strip() == "escape=1", (
        "the guest opened a file through the preopen, so the grant was real: "
        f"{escape_text}"
    )

    # 4. A module that never returns is stopped by the budget, as an error.
    bomb = seen["bomb"]
    assert _is_error(bomb), _text(bomb)
    assert _execution(bomb).get("status") == "fuel_exhausted", _execution(bomb)


def test_the_escape_probe_notices_a_granted_directory(tmp_path):
    """Positive control for the module above — without it, "refused" is unfalsifiable.

    The same ESCAPE_WAT runs against a sandbox whose FIRST preopen is a real
    directory that does contain a readable ``passwd``. If the probe were blind
    (the earlier ``etc/passwd`` + O_CREAT form was, because it resolved to
    ``/etc/etc/passwd`` under the very grant it was meant to detect), this leg
    would report ``escape=1`` and the test would fail. Here it must report
    ``escape=0``: the measurement can see a grant.
    """
    from ephemora_cell import WASIConfig, WASISandbox

    granted = tmp_path / "granted"
    granted.mkdir()
    (granted / "passwd").write_text("root:x:0:0\n", encoding="utf-8")
    wasm = tmp_path / "escape.wasm"
    wasm.write_bytes(wasmtime.wat2wasm(ESCAPE_WAT))

    sandbox = WASISandbox(
        config=WASIConfig(
            max_fuel=2_000_000,
            timeout_seconds=30,
            allow_dirs=(str(granted),),
        )
    )
    try:
        result = sandbox.run(wasm, trust="trusted")
    finally:
        sandbox.cleanup()
    assert result.stdout.strip() == "escape=0", (
        f"the probe cannot see a granted preopen, so its refusal proves nothing: "
        f"{result.stdout!r} / {result.stderr!r}"
    )
