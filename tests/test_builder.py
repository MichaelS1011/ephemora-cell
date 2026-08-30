"""ADR-005: `ephemora-cell build` — recipes, hints, real toolchain builds.

Unit tests run without any toolchain. Real builds (rust, go) are
skipif-guarded on toolchain availability and mirror the CI build job.
"""

from __future__ import annotations

import os
import shutil
import sys
from pathlib import Path

import pytest

sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))

from ephemora_cell import ExecutionStatus, WASIConfig, WASISandbox
from ephemora_cell.builder import (
    BuildGuidance,
    build,
    detect_recipe,
    hint_for,
)

HAS_CARGO = shutil.which("cargo") is not None
HAS_GO = shutil.which("go") is not None


def _has_wasm_target() -> bool:
    """cargo alone is not enough: the wasm32-wasip1 target must be installed
    (CI's coverage job has no rust toolchain — real builds run in the
    dedicated build-recipes job)."""
    if not HAS_CARGO:
        return False
    import subprocess

    probe = subprocess.run(
        ["rustup", "target", "list", "--installed"],
        capture_output=True,
        text=True,
        timeout=30,
    )
    return probe.returncode == 0 and "wasm32-wasip1" in probe.stdout


HAS_WASM_TARGET = _has_wasm_target()
HAS_ASC = shutil.which("asc") is not None
HAS_ZIG = shutil.which("zig") is not None


def _has_wasi_sdk() -> bool:
    sdk = os.environ.get("WASI_SDK_PATH")
    return bool(sdk) and Path(sdk, "bin", "clang").is_file()


class TestDetection:
    def test_rust_recipe(self, tmp_path):
        (tmp_path / "Cargo.toml").write_text(
            '[package]\nname = "mytool"\nversion = "0.1.0"\nedition = "2021"\n'
        )
        src = tmp_path / "main.rs"
        src.write_text("fn main() {}")
        recipe = detect_recipe(src)
        assert recipe is not None and recipe.language == "rust"
        assert "--target" in recipe.command and "wasm32-wasip1" in recipe.command
        assert recipe.produced_path is not None
        assert "mytool.wasm" in str(recipe.produced_path)

    def test_rust_without_cargo_manifest_is_guidance(self, tmp_path):
        src = tmp_path / "loose.rs"
        src.write_text("fn main() {}")
        with pytest.raises(BuildGuidance, match=r"Cargo\.toml"):
            detect_recipe(src)

    def test_go_recipe(self, tmp_path):
        src = tmp_path / "tool.go"
        src.write_text("package main\n\nfunc main() {}\n")
        recipe = detect_recipe(src)
        assert recipe is not None and recipe.language == "go"
        assert recipe.env == {"GOOS": "wasip1", "GOARCH": "wasm"}
        assert recipe.output == tmp_path / "tool.wasm"

    def test_python_is_guidance_not_a_guess(self, tmp_path):
        src = tmp_path / "tool.py"
        src.write_text("print('hi')\n")
        with pytest.raises(BuildGuidance, match="wasi-python"):
            detect_recipe(src)

    @pytest.mark.skipif(
        bool(os.environ.get("WASI_SDK_PATH")),
        reason="WASI_SDK_PATH set — C builds for real",
    )
    def test_c_is_guidance(self, tmp_path):
        src = tmp_path / "tool.c"
        src.write_text("int main(void){return 0;}\n")
        with pytest.raises(BuildGuidance, match="WASI-SDK"):
            detect_recipe(src)

    def test_unknown_extension_is_none(self, tmp_path):
        src = tmp_path / "tool.kt"
        src.write_text("export {}\n")
        assert detect_recipe(src) is None


class TestHints:
    def test_rust_missing_target(self):
        stderr = "error: the target wasm32-wasip1 may not be installed"
        hint = hint_for("rust", stderr)
        assert hint is not None and "rustup target add" in hint

    def test_c_missing_sysroot(self):
        stderr = "hello.c:1:10: fatal error: 'stdio.h' file not found"
        hint = hint_for("c", stderr)
        assert hint is not None and "WASI SDK" in hint

    def test_go_old_version(self):
        stderr = "note: build constraints exclude all Go files (requires go1.21)"
        hint = hint_for("go", stderr)
        assert hint is not None and "Go 1.21" in hint

    def test_unknown_error_no_hint(self):
        assert hint_for("rust", "something unexplained") is None


class TestBuildEngine:
    def test_fake_recipe_build(self, tmp_path):
        """The engine itself: run a command, verify the artifact."""
        from ephemora_cell.builder import BuildRecipe

        out = tmp_path / "fake.wasm"
        recipe = BuildRecipe(
            language="rust",
            source=tmp_path / "x.rs",
            output=out,
            command=[
                sys.executable,
                "-c",
                "import sys; open(sys.argv[-1], 'wb').write(b'ok')",
                str(out),
            ],
            cwd=tmp_path,
        )
        result = build(recipe, timeout=30)
        assert result.ok is True
        assert result.output_path == out
        assert out.read_bytes() == b"ok"

    def test_missing_toolchain_hint(self, tmp_path):
        from ephemora_cell.builder import BuildRecipe

        recipe = BuildRecipe(
            language="go",
            source=tmp_path / "t.go",
            output=tmp_path / "t.wasm",
            command=["definitely-not-a-real-tool-3f9a", "build"],
            cwd=tmp_path,
        )
        result = build(recipe, timeout=30)
        assert result.ok is False
        assert "not installed" in result.hint


@pytest.mark.skipif(
    not HAS_WASM_TARGET, reason="rust toolchain without the wasm32-wasip1 target"
)
class TestRustBuild:
    def test_hello_world_build_and_run(self, tmp_path):
        """Hello-world -> wasm -> executed in the cell."""
        (tmp_path / "Cargo.toml").write_text(
            '[package]\nname = "hello"\nversion = "0.1.0"\nedition = "2021"\n'
        )
        (tmp_path / "src").mkdir()
        (tmp_path / "src" / "main.rs").write_text(
            "fn main() { let x = 41; if x != 41 { panic!(); } }"
        )
        recipe = detect_recipe(tmp_path / "main.rs")
        result = build(recipe, timeout=300)
        assert result.ok, result.hint
        sandbox = WASISandbox(config=WASIConfig(max_fuel=20_000_000))
        try:
            run_result = sandbox.run(str(result.output_path))
        finally:
            sandbox.cleanup()
        assert run_result.status == ExecutionStatus.SUCCESS, run_result.stderr[:200]


def _run_in_sandbox(wasm_path, check_stdout=None):
    sandbox = WASISandbox(config=WASIConfig(max_fuel=20_000_000))
    try:
        run_result = sandbox.run(str(wasm_path))
    finally:
        sandbox.cleanup()
    assert run_result.status == ExecutionStatus.SUCCESS, run_result.stderr[:200]
    if check_stdout is not None:
        assert check_stdout in run_result.stdout


@pytest.mark.skipif(not _has_wasi_sdk(), reason="WASI_SDK_PATH not set")
class TestCBuild:
    def test_hello_world_build_and_run(self, tmp_path):
        """C -> wasm32-wasip1 -> executed in the cell (real wasi-sdk)."""
        (tmp_path / "hello.c").write_text(
            '#include <stdio.h>\nint main(void) { printf("hello from c\\n"); return 0; }\n'
        )
        recipe = detect_recipe(tmp_path / "hello.c")
        result = build(recipe, timeout=300)
        assert result.ok, result.hint
        _run_in_sandbox(result.output_path, check_stdout="hello from c")


@pytest.mark.skipif(not HAS_ASC, reason="asc not installed")
class TestAssemblyScriptBuild:
    def test_module_build_and_run(self, tmp_path):
        """AssemblyScript -> wasm -> executed in the cell."""
        (tmp_path / "tool.ts").write_text(
            "export let result: i32 = 0;\n"
            "export function _start(): void {\n"
            "  let s: i32 = 0;\n"
            "  for (let i = 0; i < 10; i++) { s += i; }\n"
            "  result = s;\n"
            "}\n"
        )
        recipe = detect_recipe(tmp_path / "tool.ts")
        result = build(recipe, timeout=300)
        assert result.ok, f"asc failed: {result.hint!r}"
        _run_in_sandbox(result.output_path)


@pytest.mark.skipif(not HAS_ZIG, reason="zig not installed")
class TestZigBuild:
    def test_module_build_and_run(self, tmp_path):
        """Zig -> wasm32-wasi -> executed in the cell."""
        (tmp_path / "tool.zig").write_text(
            "export fn _start() void {\n"
            "    var s: i32 = 0;\n"
            "    var i: i32 = 0;\n"
            "    while (i < 10) : (i += 1) { s += i; }\n"
            "    if (s != 45) unreachable;\n"
            "}\n"
        )
        recipe = detect_recipe(tmp_path / "tool.zig")
        result = build(recipe, timeout=300)
        assert result.ok, f"zig failed: {result.hint!r}"
        _run_in_sandbox(result.output_path)


@pytest.mark.skipif(not HAS_GO, reason="go not installed")
class TestGoBuild:
    def test_hello_world_build_and_run(self, tmp_path):
        src = tmp_path / "tool.go"
        src.write_text("package main\n\nfunc main() {}\n")
        recipe = detect_recipe(src)
        result = build(recipe, timeout=300)
        assert result.ok, result.hint
        sandbox = WASISandbox(config=WASIConfig(max_fuel=20_000_000))
        try:
            run_result = sandbox.run(str(result.output_path))
        finally:
            sandbox.cleanup()
        assert run_result.status == ExecutionStatus.SUCCESS, run_result.stderr[:200]


class TestCliBuild:
    @staticmethod
    def _run_cli(*argv):
        import subprocess
        from pathlib import Path

        console = Path(sys.executable).parent / "ephemora-cell"
        return subprocess.run(
            [str(console), *argv],
            capture_output=True,
            text=True,
            timeout=300,
        )

    def test_python_source_gives_guidance(self, tmp_path):
        src = tmp_path / "tool.py"
        src.write_text("print('hi')\n")
        proc = self._run_cli("build", str(src))
        assert proc.returncode == 2
        assert "wasi-python" in proc.stderr

    def test_unknown_extension_gives_error(self, tmp_path):
        src = tmp_path / "tool.kt"
        src.write_text("export {}\n")
        proc = self._run_cli("build", str(src))
        assert proc.returncode == 2
        assert "no WASM build recipe" in proc.stderr

    def test_missing_source(self, tmp_path):
        proc = self._run_cli("build", str(tmp_path / "nope.go"))
        assert proc.returncode == 1

    @pytest.mark.skipif(
        not HAS_WASM_TARGET, reason="rust toolchain without the wasm32-wasip1 target"
    )
    def test_real_rust_build_via_cli(self, tmp_path):
        (tmp_path / "Cargo.toml").write_text(
            '[package]\nname = "clihello"\nversion = "0.1.0"\nedition = "2021"\n'
        )
        (tmp_path / "src").mkdir()
        (tmp_path / "src" / "main.rs").write_text("fn main() {}")
        proc = self._run_cli("build", str(tmp_path / "src" / "main.rs"))
        assert proc.returncode == 0, proc.stderr
        assert "built rust ->" in proc.stdout
        assert "run it: ephemora-cell run " in proc.stdout
        assert (
            tmp_path / "target" / "wasm32-wasip1" / "release" / "clihello.wasm"
        ).exists()


@pytest.mark.skipif(_has_wasi_sdk(), reason="WASI_SDK_PATH set — C builds for real")
def test_c_without_sdk_gives_guidance(tmp_path):
    src = tmp_path / "tool.c"
    src.write_text("int main(void){return 0;}\n")
    with pytest.raises(BuildGuidance, match="WASI-SDK"):
        detect_recipe(src)


@pytest.mark.skipif(HAS_ASC, reason="asc installed — .ts builds for real")
def test_ts_without_asc_gives_guidance(tmp_path):
    src = tmp_path / "tool.ts"
    src.write_text("export {}\n")
    with pytest.raises(BuildGuidance, match="assemblyscript"):
        detect_recipe(src)


@pytest.mark.skipif(HAS_ZIG, reason="zig installed — .zig builds for real")
def test_zig_without_zig_gives_guidance(tmp_path):
    src = tmp_path / "tool.zig"
    src.write_text("export fn _start() void {}\n")
    with pytest.raises(BuildGuidance, match="ziglang"):
        detect_recipe(src)
