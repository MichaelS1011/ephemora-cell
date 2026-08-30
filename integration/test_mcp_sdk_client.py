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
import sys
from pathlib import Path

import pytest

mcp = pytest.importorskip("mcp")

from mcp import ClientSession, StdioServerParameters  # noqa: E402
from mcp.client.stdio import stdio_client  # noqa: E402

REPO = Path(__file__).resolve().parent.parent
SERVER = REPO / ".venv" / "bin" / "ephemora-cell-mcp"


@pytest.mark.skipif(not (SERVER.exists() and os.access(SERVER, os.X_OK)), reason="ephemora-cell-mcp entry point not found")
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
    assert name == "ephemora-cell-mcp 0.1.0"
    assert names == ["echo"]
    assert '"greeting": "sdk"' in text
    assert exec_meta["status"] == "success"
    assert isinstance(exec_meta["fuel"], int) and exec_meta["fuel"] > 0


if __name__ == "__main__":
    sys.exit(pytest.main([__file__, "-v"]))