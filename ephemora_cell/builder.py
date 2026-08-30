# Ephemora Cell — one-command WASM builds (ADR-005)
# SPDX-License-Identifier: Apache-2.0
"""``ephemora build`` — compile a tool to WASM without toolchain archaeology.

The builder turns language-specific toolchain knowledge into recipes
(detected from the source file), runs the toolchain, and — when a build
fails — maps the verbatim toolchain error to an actionable hint. The
hint table is driven by the measured friction matrix
(``benchmarks/build_friction/``): missing toolchains, missing WASM
targets, missing wasi-sysroot, wrong GOOS/GOARCH.

Languages:
  * Rust            — real recipe (``cargo build --target wasm32-wasip1``)
  * Go              — real recipe (``GOOS=wasip1 GOARCH=wasm go build``)
  * C               — real recipe when WASI_SDK_PATH points at a
                      wasi-sdk install; guidance otherwise
  * AssemblyScript  — real recipe when ``asc`` is on PATH; guidance
                      otherwise (npm i -g assemblyscript)
  * Zig             — real recipe when ``zig`` is on PATH; guidance
                      otherwise
  * Python          — guidance: no AOT compile exists; scripts run on a
                      wasi-python interpreter (structural, measured)

Guidance raises :class:`BuildGuidance` — an actionable message, never a
silent wrong guess.
"""

from __future__ import annotations

import os
import re
import shutil
import subprocess
import time
from dataclasses import dataclass, field
from pathlib import Path

DEFAULT_TIMEOUT = 600.0

# (language, regex, hint) — matched against the toolchain's stderr.
# Classes sourced from benchmarks/build_friction (measured).
_ERROR_HINTS: list[tuple[str, str, str]] = [
    (
        "rust",
        r"may not be installed|target .* not installed",
        "the WASM target is missing: run `rustup target add wasm32-wasip1`",
    ),
    (
        "rust",
        r"no matching package named|failed to select a version",
        "cargo could not resolve a crate: check network access / the "
        "dependency registry, then retry",
    ),
    (
        "c",
        r"stdio\.h.*not found|wasi-sysroot",
        "no WASI libc: install the WASI SDK "
        "(https://github.com/WebAssembly/wasi-sdk/releases) or build "
        "freestanding guests without C stdio",
    ),
    (
        "go",
        r"requires go1\.(2[1-9]|[3-9]\d)",
        "GOOS=wasip1 needs Go 1.21 or newer: upgrade Go",
    ),
]


class BuildGuidance(Exception):
    """The language has no direct compiler recipe — the message guides instead."""


class BuildError(Exception):
    """The build failed; ``hint`` carries the actionable explanation."""


@dataclass(frozen=True)
class BuildRecipe:
    """A detected, executable WASM build for one source file."""

    language: str
    source: Path
    output: Path
    command: list[str]
    cwd: Path
    env: dict = field(default_factory=dict)
    produced_path: Path | None = None  # rust: artifact lands under target/

    @property
    def display_command(self) -> str:
        parts = [str(p) for p in self.command]
        return " ".join(parts)


@dataclass
class BuildResult:
    ok: bool
    language: str
    output_path: Path | None
    elapsed_s: float
    hint: str | None = None


def detect_recipe(source: Path, output: Path | None = None) -> BuildRecipe | None:
    """Detect the build recipe for ``source``; None = unsupported language.

    Raises :class:`BuildGuidance` for languages with structural guidance
    (python: no AOT compile; c: WASI-SDK required on this host).
    """
    source = Path(source).resolve()
    suffix = source.suffix.lower()

    if suffix == ".rs" or source.name == "Cargo.toml":
        # cargo itself searches upward for the manifest — do the same
        project = source.parent
        while not (project / "Cargo.toml").is_file():
            if project.parent == project:
                raise BuildGuidance(
                    f"{source}: no Cargo.toml found in any parent directory "
                    "(a Rust build needs a cargo project)"
                )
            project = project.parent
        cargo = (project / "Cargo.toml").read_text(encoding="utf-8")
        match = re.search(r"\[package\][^\[]*?name\s*=\s*\"([^\"]+)\"", cargo, re.S)
        crate_name = match.group(1) if match else source.stem
        produced = (
            project / "target" / "wasm32-wasip1" / "release" / f"{crate_name}.wasm"
        )
        return BuildRecipe(
            language="rust",
            source=source,
            output=output or produced,
            command=["cargo", "build", "--release", "--target", "wasm32-wasip1"],
            cwd=project,
            produced_path=produced,
        )

    if suffix == ".go":
        out = output or source.parent / f"{source.stem}.wasm"
        return BuildRecipe(
            language="go",
            source=source,
            output=out,
            command=[
                "go",
                "build",
                "-o",
                str(out),
                source.name,
            ],
            cwd=source.parent,
            env={"GOOS": "wasip1", "GOARCH": "wasm"},
        )

    if suffix == ".c":
        sdk = os.environ.get("WASI_SDK_PATH")
        if not sdk or not Path(sdk, "bin", "clang").is_file():
            raise BuildGuidance(
                f"{source}: C needs a WASI-SDK toolchain (host clang has no "
                "wasi sysroot) — install https://github.com/WebAssembly/"
                "wasi-sdk/releases and point WASI_SDK_PATH at the install "
                "directory"
            )
        out = output or source.parent / f"{source.stem}.wasm"
        return BuildRecipe(
            language="c",
            source=source,
            output=out,
            command=[
                str(Path(sdk) / "bin" / "clang"),
                "--target=wasm32-wasip1",
                "--sysroot",
                str(Path(sdk) / "share" / "wasi-sysroot"),
                "-O2",
                str(source),
                "-o",
                str(out),
            ],
            cwd=source.parent,
            produced_path=out,
        )

    if suffix == ".ts":
        asc = shutil.which("asc")
        if asc is None:
            raise BuildGuidance(
                f"{source}: AssemblyScript compiles with asc — install it "
                "with `npm install -g assemblyscript` "
                "(https://www.assemblyscript.org/)"
            )
        out = output or source.parent / f"{source.stem}.wasm"
        return BuildRecipe(
            language="assemblyscript",
            source=source,
            output=out,
            command=[
                asc,
                str(source),
                "--outFile",
                str(out),
                "--runtime",
                "stub",
                "-O1",
            ],
            cwd=source.parent,
            produced_path=out,
        )

    if suffix == ".zig":
        zig = shutil.which("zig")
        if zig is None:
            raise BuildGuidance(
                f"{source}: Zig compiles to WASI natively — install zig "
                "(https://ziglang.org/download/)"
            )
        out = output or source.parent / f"{source.stem}.wasm"
        return BuildRecipe(
            language="zig",
            source=source,
            output=out,
            # build-exe with default emit: for wasm32-wasi targets zig
            # writes <stem>.wasm into the cwd (-femit-bin=x.wasm is
            # rejected outright, and build-lib produces a static .a).
            command=[
                zig,
                "build-exe",
                source.name,
                "-target",
                "wasm32-wasi",
            ],
            cwd=source.parent,
            produced_path=out,
        )

    if suffix == ".py":
        raise BuildGuidance(
            f"{source}: Python has no AOT-to-WASM compiler — run scripts on "
            "a wasi-python (CPython wasm32-wasip1) interpreter instead; see "
            "https://github.com/python/cpython/blob/main/Platforms/WASI/README.md"
        )

    return None


def hint_for(language: str, stderr: str) -> str | None:
    """Map a verbatim toolchain error to an actionable hint (measured table)."""
    for lang, pattern, hint in _ERROR_HINTS:
        if lang == language and re.search(pattern, stderr, re.I):
            return hint
    return None


def build(recipe: BuildRecipe, timeout: float = DEFAULT_TIMEOUT) -> BuildResult:
    """Run a recipe; failures carry a hint derived from the toolchain output."""
    started = time.perf_counter()
    try:
        proc = subprocess.run(
            recipe.command,
            cwd=recipe.cwd,
            env={**_base_env(), **recipe.env},
            capture_output=True,
            text=True,
            timeout=timeout,
        )
    except FileNotFoundError:
        elapsed = time.perf_counter() - started
        tool = recipe.command[0]
        return BuildResult(
            ok=False,
            language=recipe.language,
            output_path=None,
            elapsed_s=round(elapsed, 1),
            hint=f"toolchain {tool!r} is not installed (or not on PATH)",
        )
    except subprocess.TimeoutExpired:
        elapsed = time.perf_counter() - started
        return BuildResult(
            ok=False,
            language=recipe.language,
            output_path=None,
            elapsed_s=round(elapsed, 1),
            hint=f"build exceeded {timeout:.0f}s timeout",
        )
    elapsed = time.perf_counter() - started

    output_path = recipe.output
    if recipe.language == "rust" and recipe.produced_path is not None:
        # cargo writes into target/; if --out was given, copy the artifact
        if recipe.produced_path.exists():
            if output_path != recipe.produced_path:
                output_path.write_bytes(recipe.produced_path.read_bytes())
        else:
            stderr = proc.stderr or proc.stdout or ""
            return BuildResult(
                ok=False,
                language=recipe.language,
                output_path=None,
                elapsed_s=round(elapsed, 1),
                hint=hint_for("rust", stderr)
                or (stderr.strip().splitlines()[-1] if stderr.strip() else None),
            )

    ok = proc.returncode == 0 and output_path.exists()
    stderr = (proc.stderr or proc.stdout or "").strip()
    last_line = stderr.splitlines()[-1] if stderr else None
    hint = (
        None
        if ok
        else hint_for(recipe.language, stderr)
        or last_line
        or "build failed without output"
    )
    return BuildResult(
        ok=ok,
        language=recipe.language,
        output_path=output_path if ok else None,
        elapsed_s=round(elapsed, 1),
        hint=hint,
    )


def _base_env() -> dict:
    import os

    return dict(os.environ)
