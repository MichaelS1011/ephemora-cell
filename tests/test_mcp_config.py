"""Root ``.mcp.json`` project-scope server config (0b2caa5) pinned.

The file exists so MCP clients (and plugin scanners) discover the shipped
MCP server when a repo checkout is opened as a workspace. These tests pin
its contract: exactly one server, the PyPI-distributed entry point via
``uvx``, and agreement with the Smithery deployment config — so a docs or
packaging change cannot silently diverge the two advertised start commands.

pyyaml is NOT a project dependency: the YAML file is parsed only when
pyyaml happens to be importable, otherwise the smithery.yaml check stays at
the text level (the checked snippet lives inside a JS template string,
where text matching is the authority anyway). No new dependencies.
"""

from __future__ import annotations

import json
import os
import sys
from pathlib import Path

sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))

REPO = Path(__file__).resolve().parent.parent
EXPECTED_ARGS = ["--from", "ephemora-cell", "ephemora-cell-mcp"]
EXPECTED_COMMAND = "uvx"

try:
    import yaml as _yaml
except ImportError:
    _yaml = None


def _mcp_json() -> dict:
    path = REPO / ".mcp.json"
    assert path.exists(), ".mcp.json missing from the repo root"
    try:
        return json.loads(path.read_text(encoding="utf-8"))
    except json.JSONDecodeError as exc:
        raise AssertionError(f".mcp.json is not valid JSON: {exc}") from exc


def test_mcp_json_has_exactly_one_server():
    data = _mcp_json()
    servers = data.get("mcpServers")
    assert isinstance(servers, dict), ".mcp.json must carry a mcpServers object"
    assert list(servers) == [
        "ephemora-cell"
    ], f"expected exactly one server 'ephemora-cell', found {list(servers)}"


def test_mcp_json_start_command_matches_distribution():
    server = _mcp_json()["mcpServers"]["ephemora-cell"]
    assert (
        server.get("command") == EXPECTED_COMMAND
    ), f"command must be {EXPECTED_COMMAND!r} (no global install required)"
    assert server.get("args") == EXPECTED_ARGS, (
        f"args must be {EXPECTED_ARGS!r} — run the MCP server from PyPI, "
        "not a stray local path"
    )


def test_smithery_start_command_matches_mcp_json():
    """smithery.yaml advertises the same uvx start command: its
    commandFunction builds the same args array (--tools-dir is appended
    only when the operator configures it) and returns command "uvx"."""
    text = (REPO / "smithery.yaml").read_text(encoding="utf-8")
    # The authoritative snippet inside commandFunction (text level):
    assert (
        '"--from", "ephemora-cell", "ephemora-cell-mcp"' in text
    ), "smithery.yaml commandFunction must pass the PyPI-distributed args"
    assert 'command: "uvx"' in text, 'smithery.yaml commandFunction must use "uvx"'
    # Structural check when pyyaml is available (optional, no new dependency).
    if _yaml is not None:
        data = _yaml.safe_load(text)
        assert isinstance(data, dict), "smithery.yaml must parse to a mapping"
        start = data.get("startCommand")
        assert isinstance(start, dict) and start.get("type") == "stdio"
