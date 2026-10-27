"""End-to-end MCP client test against `ephemora-cell-mcp` using the OFFICIAL MCP
Python SDK (`mcp`). Skipped when the SDK is not installed.

This proves the dependency-free server implementation interoperates with the
reference client — the real-world mount point for Hermes Desktop, Claude,
Cursor, Codex, VS Code and any other stdio MCP client.

Run with a venv that has `pip install mcp`:

    python -m pytest integration/test_mcp_sdk_client.py -q
"""

from __future__ import annotations

import os
import shutil
import subprocess
import sys
from pathlib import Path

import pytest

mcp = pytest.importorskip("mcp")

REPO = Path(__file__).resolve().parent.parent
if str(REPO) not in sys.path:
    sys.path.insert(0, str(REPO))

from mcp import ClientSession, StdioServerParameters
from mcp.client.stdio import stdio_client

from ephemora_cell_mcp import __version__

# Resolve the installed entry point portably — and resolve it in the
# environment that is RUNNING this test, not in whichever venv happens to sit in
# the checkout. The earlier order (PATH, then REPO/.venv) silently launched the
# server of a different interpreter when the test ran from another venv, so the
# "official SDK interop" claim could be measured against an engine the release
# does not qualify. Order now: this env's console script, this env's module
# entry point, the active PATH, and only last a dev .venv (which is reported, not
# trusted silently).
_here = Path(sys.executable).parent
_candidates = [
    _here / "ephemora-cell-mcp",
    shutil.which("ephemora-cell-mcp"),
    REPO / ".venv" / "bin" / "ephemora-cell-mcp",
]
SERVER = next(
    (
        Path(c)
        for c in _candidates
        if c and Path(str(c)).exists() and os.access(str(c), os.X_OK)
    ),
    None,
)
# Same-interpreter fallback: `python -m ephemora_cell_mcp` runs the server of the
# env under test even when no console script was installed.
SERVER_ARGS: list[str] = []
if SERVER is None:
    SERVER = Path(sys.executable)
    SERVER_ARGS = ["-m", "ephemora_cell_mcp"]
# These tests prove the dependency-free server speaks the MCP PROTOCOL to the
# reference SDK client (and, in the agent test, that the SANDBOX boundary holds) —
# neither is about per-subject authorization. Since 1.2 the server DEFAULTS to
# deny (no policy → no tool runs), so an interop probe that wants its `echo` call
# to actually execute must opt into the compatibility posture explicitly. This is
# the measured v1.2 impact on shipped SDK integrations.
LEGACY_ARGS = ["--legacy-allow-all"]


def _server_engine() -> str:
    """Which Wasmtime the server that is about to be launched actually carries.

    Read off the interpreter the server really runs on (the console script's
    shebang, or this interpreter for the module fallback) — the interop claim is
    only worth what the engine under it is qualified for.
    """
    if SERVER_ARGS:
        interpreter = str(SERVER)
    else:
        with open(SERVER, "rb") as handle:
            first = handle.readline()
        interpreter = (
            first[2:].split()[0].decode() if first.startswith(b"#!") else str(SERVER)
        )
    probe = subprocess.run(
        [
            interpreter,
            "-c",
            "import importlib.metadata as m; print(m.version('wasmtime'))",
        ],
        capture_output=True,
        text=True,
    )
    return probe.stdout.strip() or "unknown"


@pytest.mark.skipif(
    not os.access(SERVER, os.X_OK),
    reason="no ephemora-cell-mcp entry point in this environment",
)
def test_official_sdk_interop() -> None:
    import asyncio

    async def run() -> tuple[str, list[str], str, dict]:
        params = StdioServerParameters(
            command=str(SERVER), args=[*SERVER_ARGS, *LEGACY_ARGS]
        )
        async with stdio_client(params) as (read, write):
            async with ClientSession(read, write) as session:
                init = await session.initialize()
                tools = await session.list_tools()
                res = await session.call_tool("echo", {"greeting": "sdk", "n": 7})
                meta = (res.meta or {}).get("execution", {})
                return (
                    f"{init.server_info.name} {init.server_info.version}",
                    [t.name for t in tools.tools],
                    res.content[0].text,
                    {"status": meta.get("status"), "fuel": meta.get("fuel_consumed")},
                )

    name, names, text, exec_meta = asyncio.run(run())
    # An interop claim is worth the engine under it: if the server this test
    # launched runs an engine outside the qualified line, its calls are refused
    # by the runtime gate and the exchange below would prove nothing about
    # interop. Name the engine that was measured instead of failing silently.
    engine = _server_engine()
    assert "refused: unqualified runtime" not in text, (
        f"the server was launched on wasmtime {engine!r}, which the runtime "
        "gate refuses — run this test in the environment carrying the "
        "qualified line"
    )
    assert name == f"ephemora-cell-mcp {__version__}"
    assert names == ["clock", "echo", "get-policy"]
    assert '"greeting": "sdk"' in text
    assert exec_meta["status"] == "success"
    assert isinstance(exec_meta["fuel"], int) and exec_meta["fuel"] > 0


@pytest.mark.skipif(
    not os.access(SERVER, os.X_OK),
    reason="no ephemora-cell-mcp entry point in this environment",
)
def test_official_sdk_stateless_2026_07_28() -> None:
    """The official SDK (2.1.1) speaks the stateless 2026-07-28 era to us.

    The client probes ``server/discover`` and adopts the modern per-request
    stamp WITHOUT ever sending ``initialize`` — ``tools/list`` and
    ``tools/call`` then run statelessly against the server's dual-era
    dispatch. This is the reference-implementation proof for the stateless
    surface the unit tests cover in-process (test_mcp_2026_07_28.py).
    """
    import asyncio

    async def run() -> tuple[list[str], list[str], str, dict, dict]:
        params = StdioServerParameters(
            command=str(SERVER), args=[*SERVER_ARGS, *LEGACY_ARGS]
        )
        async with stdio_client(params) as (read, write):
            async with ClientSession(read, write) as session:
                # Modern era: probe + adopt. No initialize() anywhere.
                discover = await session.discover()
                tools = await session.list_tools()
                res = await session.call_tool(
                    "echo", {"greeting": "sdk-stateless", "n": 7}
                )
                meta = dict(res.meta or {})
                execution = meta.get("execution", {})
                return (
                    list(discover.supported_versions),
                    [t.name for t in tools.tools],
                    res.content[0].text,
                    {
                        "status": execution.get("status"),
                        "fuel": execution.get("fuel_consumed"),
                    },
                    {
                        "server_info": meta.get("io.modelcontextprotocol/serverInfo"),
                        "list_changed": (
                            discover.capabilities.tools.list_changed
                            if discover.capabilities.tools is not None
                            else None
                        ),
                    },
                )

    versions, names, text, exec_meta, extra = asyncio.run(run())
    assert "2026-07-28" in versions
    # stateless tools/list worked without any handshake
    assert names == ["clock", "echo", "get-policy"]
    assert '"greeting": "sdk-stateless"' in text
    assert exec_meta["status"] == "success"
    assert isinstance(exec_meta["fuel"], int) and exec_meta["fuel"] > 0
    # the 2026-07-28 result envelope survived the SDK's pydantic parsing
    assert extra["server_info"]["name"] == "ephemora-cell-mcp"
    assert extra["server_info"]["version"] == __version__
    assert extra["list_changed"] is False


if __name__ == "__main__":
    sys.exit(pytest.main([__file__, "-v"]))
