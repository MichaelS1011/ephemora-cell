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
import sys
from pathlib import Path

import pytest

mcp = pytest.importorskip("mcp")

REPO = Path(__file__).resolve().parent.parent
if str(REPO) not in sys.path:
    sys.path.insert(0, str(REPO))

from mcp import ClientSession, StdioServerParameters  # noqa: E402
from mcp.client.stdio import stdio_client  # noqa: E402

from ephemora_cell_mcp import __version__  # noqa: E402

# Resolve the installed entry point portably: CI installs into the active
# env's bin (on PATH); a local dev checkout has it under .venv/bin. Skip
# cleanly only when neither exists — never green-by-skip when it is runnable.
_candidates = [
    shutil.which("ephemora-cell-mcp"),
    REPO / ".venv" / "bin" / "ephemora-cell-mcp",
]
SERVER = next(
    (Path(c) for c in _candidates if c and Path(c).exists() and os.access(c, os.X_OK)),
    _candidates[-1],
)


@pytest.mark.skipif(
    not (SERVER.exists() and os.access(SERVER, os.X_OK)),
    reason="ephemora-cell-mcp entry point not found",
)
def test_official_sdk_interop() -> None:
    import asyncio

    async def run() -> tuple[str, list[str], str, dict]:
        params = StdioServerParameters(command=str(SERVER), args=[])
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
    assert name == f"ephemora-cell-mcp {__version__}"
    assert names == ["clock", "echo", "get-policy"]
    assert '"greeting": "sdk"' in text
    assert exec_meta["status"] == "success"
    assert isinstance(exec_meta["fuel"], int) and exec_meta["fuel"] > 0


if __name__ == "__main__":
    sys.exit(pytest.main([__file__, "-v"]))
