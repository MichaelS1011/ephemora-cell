"""ephemora-cell-mcp — MCP (Model Context Protocol) adapter on top of Ephemora Cell.

Tool implementations are WASM modules executed inside the Ephemora Cell
sandbox (deterministic, fuel-metered, 10 KB output cap, no network). The
host process speaks the MCP stdio protocol (JSON-RPC 2.0, NDJSON lines)
and mediates tool calls: ``tools/call`` params are passed to the guest as
stdin JSON ``{"params": ...}`` and the guest's stdout JSON is returned as
the MCP result, enriched with the Cell's ``ExecutionReport`` in ``_meta``.

Dependency-free: this package implements the small JSON-RPC surface it
needs (initialize, tools/list, tools/call, notifications/initialized)
itself and only depends on ``ephemora_cell``.

Example:
    from ephemora_cell_mcp import Server

    server = Server(tools_dir="tools")  # <toolname>.wasm + optional <toolname>.json
    server.serve()                      # stdio loop (also: python -m ephemora_cell_mcp)
"""

from .server import Server

__version__ = "0.1.0"

__all__ = ["Server", "__version__"]