"""Tool registry — the MCP tools exposed by ephemora-cell-mcp.

Convention: every ``<toolname>.wasm`` in the tools directory is a tool.
Optional ``<toolname>.json`` sidecar carries MCP metadata:

.. code-block:: json

    {
      "name": "echo",
      "description": "Echoes its arguments back",
      "input_schema": {"type": "object", "properties": {}},
      "profile": "llm",
      "allow_dirs": []
    }

Defaults when no sidecar exists: name = file stem, description
"Executes <toolname>", generic object input schema, profile "llm", no
preopened directories. ``allow_dirs`` can ONLY be granted through the
sidecar — the server never invents file access — and is INTERSECTED with
the profile's grants, so a sidecar can narrow but never widen permissions.

Registry notes:
* the tool name is ALWAYS the ``.wasm`` file stem; a sidecar ``name`` is
  advisory and overridden on mismatch (advertised must equal callable);
* ``input_schema`` is purely informative: the server does not validate
  ``arguments`` against it — tools receive the raw arguments as stdin
  JSON and are responsible for their own input handling.
"""

from __future__ import annotations

import json
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

DEFAULT_INPUT_SCHEMA: dict[str, Any] = {"type": "object", "properties": {}}


@dataclass(frozen=True)
class ToolSpec:
    """A single WASM-backed MCP tool."""

    name: str
    wasm_path: str
    description: str
    input_schema: dict[str, Any] = field(default_factory=lambda: dict(DEFAULT_INPUT_SCHEMA))
    profile: str = "llm"
    allow_dirs: tuple[str, ...] = ()
    metadata_path: str | None = None

    def to_mcp(self) -> dict[str, Any]:
        """The ``tools/list`` entry for this tool."""
        return {
            "name": self.name,
            "description": self.description,
            "inputSchema": self.input_schema,
        }


class ToolRegistry:
    """Scans a tools directory for ``.wasm`` + optional ``.json`` sidecars."""

    def __init__(self, tools_dir: str | Path) -> None:
        self.tools_dir = Path(tools_dir)
        self._tools: dict[str, ToolSpec] = {}
        self._scan()

    def _scan(self) -> None:
        if not self.tools_dir.is_dir():
            return
        for wasm in sorted(self.tools_dir.glob("*.wasm")):
            stem = wasm.stem
            sidecar = self.tools_dir / f"{stem}.json"
            spec = self._build_spec(stem, wasm, sidecar)
            if spec is None:
                continue
            # The advertised name must be the registry identity.
            # Advertised != callable is a bug (tools/list would offer a
            # name tools/call cannot resolve), so a mismatching sidecar
            # name is overridden, never trusted.
            if spec.name != stem:
                import warnings

                warnings.warn(
                    f"tool {stem!r}: sidecar name {spec.name!r} does not "
                    "match the file stem - using the stem as the tool name",
                    RuntimeWarning,
                    stacklevel=2,
                )
                spec = ToolSpec(
                    name=stem,
                    wasm_path=spec.wasm_path,
                    description=spec.description,
                    input_schema=spec.input_schema,
                    profile=spec.profile,
                    allow_dirs=spec.allow_dirs,
                    metadata_path=spec.metadata_path,
                )
            if stem in self._tools:
                raise ValueError(
                    f"tool name collision: {stem!r} is defined more than "
                    f"once in {self.tools_dir}"
                )
            self._tools[stem] = spec

    def _build_spec(
        self, stem: str, wasm: Path, sidecar: Path
    ) -> ToolSpec | None:
        metadata: dict[str, Any] = {}
        if sidecar.is_file():
            try:
                metadata = json.loads(sidecar.read_text(encoding="utf-8"))
            except (OSError, ValueError):
                # A broken sidecar must not silently corrupt the registry:
                # fall back to defaults and let the tool list itself anyway.
                metadata = {}
            if not isinstance(metadata, dict):
                metadata = {}
        # The sidecar "name" is advisory; the registry identity is the
        # file stem (enforced in _scan, which overrides mismatches).
        name = stem
        description = metadata.get("description", f"Executes {stem}")
        input_schema = metadata.get("input_schema")
        if not isinstance(input_schema, dict):
            input_schema = dict(DEFAULT_INPUT_SCHEMA)
        profile = str(metadata.get("profile", "llm"))
        allow_dirs = metadata.get("allow_dirs", [])
        if not isinstance(allow_dirs, list):
            allow_dirs = []
        return ToolSpec(
            name=name,
            wasm_path=str(wasm),
            description=str(description),
            input_schema=input_schema,
            profile=profile,
            allow_dirs=tuple(str(d) for d in allow_dirs),
            metadata_path=str(sidecar) if sidecar.is_file() else None,
        )

    def list_tools(self) -> list[ToolSpec]:
        return [self._tools[key] for key in sorted(self._tools)]

    def get(self, name: str) -> ToolSpec | None:
        """Look a tool up by its file stem (the registry identity)."""
        return self._tools.get(name)