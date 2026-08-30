"""WASM Module Inspector — analyse a module before execution."""

from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

import wasmtime

DANGEROUS_IMPORTS = {
    "path_open": "filesystem — requires preopen",
    "fd_write": "output — capped at 10KB",
    "environ_get": "env — controlled via allow_env",
    "environ_sizes_get": "env — controlled via allow_env",
}


@dataclass
class ModuleInfo:
    path: str
    raw_size: int = 0
    wasi_dependent: bool = False
    has_start: bool = False
    num_functions: int = 0
    num_globals: int = 0
    num_tables: int = 0
    memory_pages: int = 0
    memory_max_pages: int = 0
    imports: list[dict[str, str]] = field(default_factory=list)
    exports: list[dict[str, str]] = field(default_factory=list)
    wasi_imports: list[str] = field(default_factory=list)
    risks: list[dict[str, str]] = field(default_factory=list)

    def to_dict(self) -> dict[str, Any]:
        return {
            "path": self.path,
            "raw_size": self.raw_size,
            "wasi_dependent": self.wasi_dependent,
            "has_start": self.has_start,
            "memory_pages": self.memory_pages,
            "memory_max_pages": self.memory_max_pages,
            "num_functions": self.num_functions,
            "num_globals": self.num_globals,
            "num_tables": self.num_tables,
            "imports": self.imports,
            "exports": self.exports,
            "wasi_imports": self.wasi_imports,
            "risks": self.risks,
        }

    def summary(self) -> str:
        lines = [
            f"Module: {self.path} ({self.raw_size:,} bytes)",
            f"Memory: {self.memory_pages} pages (max {self.memory_max_pages})",
            f"Functions: {self.num_functions} | Globals: {self.num_globals} | Tables: {self.num_tables}",
            f"Start: {'yes' if self.has_start else 'no'}",
            f"WASI: {'yes' if self.wasi_dependent else 'no'}",
            f"Imports: {len(self.imports)}",
            f"Exports: {len(self.exports)}",
        ]
        if self.risks:
            lines.append(f"Risks: {len(self.risks)} flagged")
            for r in self.risks:
                lines.append(f"  {r['name']}: {r['reason']}")
        return "\n".join(lines)


def inspect_module(path: str | Path) -> ModuleInfo:
    """Return ModuleInfo by parsing the WASM binary (no execution)."""
    wasm_bytes = Path(path).read_bytes()
    engine = wasmtime.Engine()
    module = wasmtime.Module(engine, wasm_bytes)
    info = ModuleInfo(path=str(path), raw_size=len(wasm_bytes))

    # Parse imports
    for imp in module.imports:
        info.imports.append(
            {"module": imp.module, "name": imp.name, "kind": type(imp.type).__name__}
        )
        if imp.module == "wasi_snapshot_preview1":
            info.wasi_dependent = True
            info.wasi_imports.append(imp.name)
            if imp.name in DANGEROUS_IMPORTS:
                info.risks.append(
                    {
                        "name": f"{imp.module}::{imp.name}",
                        "reason": DANGEROUS_IMPORTS[imp.name],
                        "severity": "warning",
                    }
                )

    # Parse exports
    for exp in module.exports:
        info.exports.append({"name": exp.name, "kind": type(exp.type).__name__})
        if exp.name == "_start":
            info.has_start = True
        t = type(exp.type).__name__
        if t == "FuncType":
            info.num_functions += 1
        elif t == "GlobalType":
            info.num_globals += 1
        elif t == "TableType":
            info.num_tables += 1
        elif t == "MemoryType":
            limits = exp.type.limits
            info.memory_pages = limits.min
            info.memory_max_pages = limits.max or 0

    return info
