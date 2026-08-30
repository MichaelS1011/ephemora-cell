"""Run ephemora-cell-mcp as an MCP stdio server: ``python -m ephemora_cell_mcp``.

The server speaks NDJSON/JSON-RPC 2.0 on stdin/stdout — the standard MCP
stdio transport. Point any MCP client (Claude Desktop, generic MCP
clients) at this command; tool implementations are WASM modules in the
tools directory.
"""

from __future__ import annotations

import argparse
import sys


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(
        prog="ephemora-cell-mcp",
        description="MCP stdio server executing WASM tools in the Ephemora Cell",
    )
    parser.add_argument(
        "--tools-dir",
        default=None,
        metavar="DIR",
        help="directory with <toolname>.wasm files (default: bundled tools)",
    )
    parser.add_argument(
        "--version",
        action="version",
        version=f"ephemora-cell-mcp {__import__('ephemora_cell_mcp').__version__}",
    )
    args = parser.parse_args(argv)

    from .server import Server

    Server(tools_dir=args.tools_dir).serve()
    return 0


if __name__ == "__main__":
    sys.exit(main())