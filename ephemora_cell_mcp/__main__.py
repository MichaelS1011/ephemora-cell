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
        "--pooled",
        action="store_true",
        help=(
            "trusted fast path: disable the sandbox-dir I/O byte wall so "
            "the pooled engine serves each call (~0.5 ms/call instead of "
            "~12 ms); the relaxed wall is attested in get-policy — use only "
            "where the byte wall is not required"
        ),
    )
    parser.add_argument(
        "--require-signed-tools",
        default=None,
        metavar="PUBKEY_PEM",
        help=(
            "ADR-006 verify-before-register: Ed25519 public key (PEM file); "
            "every tool sidecar must carry a valid manifest signature and "
            "unsigned/tampered tools are rejected at load. Needs the "
            "optional 'cryptography' package (tools-signing extra). Sign "
            "sidecars with: python -m ephemora_cell_mcp.sign_tool"
        ),
    )
    parser.add_argument(
        "--version",
        action="version",
        version=f"ephemora-cell-mcp {__import__('ephemora_cell_mcp').__version__}",
    )
    args = parser.parse_args(argv)

    verifier = None
    if args.require_signed_tools:
        from .tool_registry import ed25519_verifier_from_pem

        try:
            verifier = ed25519_verifier_from_pem(args.require_signed_tools)
        except (OSError, ValueError, RuntimeError) as e:
            print(f"error: {e}", file=sys.stderr)
            return 2

    from .server import Server

    Server(
        tools_dir=args.tools_dir,
        pooled=args.pooled,
        manifest_verifier=verifier,
    ).serve()
    return 0


if __name__ == "__main__":
    sys.exit(main())
