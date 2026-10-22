"""Generic Ephemora Cell execution layer for any agent framework.

Ephemora Cell is a WASM execution primitive — not a framework library.
Any framework, any model, any language, any OS can use this adapter.

Usage:
    from integration.ephemora_cell_agent_executor import EphemoraCellExecutor

    executor = EphemoraCellExecutor(max_fuel=100_000, timeout=5)
    result = executor.execute("module.wasm")
    if result.blocked:
        print(f"Blocked: {result.status}")
"""

from __future__ import annotations

import hashlib
import os
import stat
import tempfile
from dataclasses import dataclass
from pathlib import Path

sys_path = str(Path(__file__).parent.parent)
import sys

sys.path.insert(0, sys_path)

from ephemora_cell import WASIConfig, WASISandbox

#: The curated, operator-owned workload directories an agent-driven caller may
#: execute from by default. A model or workflow input names a module; it does
#: NOT get to point the sandbox at an arbitrary host file (criterion 3 of the
#: agent-surface review: no trust elevation via agent/workflow input).
_DEFAULT_ROOTS: tuple[Path, ...] = (
    (Path(sys_path) / "benchmarks" / "workloads").resolve(),
    (Path(sys_path) / "examples").resolve(),
)


@dataclass
class ExecutionResult:
    """Structured result from an isolated execution."""

    status: str
    exit_code: int
    stdout: str
    stderr: str
    elapsed_ms: float
    blocked: bool
    #: Machine-readable refusal reason, set only on a refusal (never on a run).
    reason: str | None = None
    #: sha256 of the exact bytes this call authorized (module identity).
    module_sha256: str | None = None


class EphemoraCellExecutor:
    """Drop-in execution layer for any agent framework.

    Wraps Ephemora Cell WASISandbox with a simple execute() interface.
    Framework-agnostic — usable from Hermes, NemoClaw, LangGraph, CrewAI, etc.

    An agent's tool arguments are UNTRUSTED model output, so ``execute()`` is a
    confinement boundary, not a convenience wrapper:

    * **Path normalisation** — only a module resolving under an operator-supplied
      ``allowed_roots`` entry runs; anything else is refused fail-closed with
      ``policy_denied`` and NO sandbox created (agent-surface criterion 3: no
      trust elevation via agent/workflow input).
    * **Symlinks** — the path is resolved (full symlink chain) before the
      containment test, and the file is then opened with ``O_NOFOLLOW``, so a
      link planted inside an allowed root cannot reach a host file outside it.
    * **Malformed input** — a non-string argument or an embedded NUL is ordinary
      model noise, not a crash: it returns ``policy_denied`` instead of raising.
    * **Module identity** — the bytes are read exactly once, hashed, and that
      digest is bound onto the run as ``expected_sha256``, so the sandbox refuses
      if the executed bytes differ from the authorized ones. An operator can pin
      expected digests with ``allowed_sha256`` to reject a swapped workload.
    * **TOCTOU** — because the authorized bytes are re-materialised into a
      private ``0700`` directory and that copy is what runs, swapping or
      re-linking the allowlisted path after authorization cannot change the
      executed module.
    """

    def __init__(
        self,
        max_fuel: int = 100_000,
        timeout: int = 5,
        max_memory_mb: int = 16,
        allowed_roots: tuple[str, ...] | None = None,
        allowed_sha256: dict[str, str] | None = None,
    ):
        self.config = WASIConfig(
            max_fuel=max_fuel,
            timeout_seconds=timeout,
            max_memory_mb=max_memory_mb,
        )
        roots = allowed_roots if allowed_roots is not None else _DEFAULT_ROOTS
        # Resolve once, at construction (a host/operator decision, never per call).
        self._allowed_roots = tuple(Path(r).resolve() for r in roots)
        # Operator-owned module identity pins, keyed by absolute path or by file
        # name (path wins when both are present, so same-named modules in
        # different roots can carry different digests).
        self._digest_pins = {
            str(Path(k).resolve()).lower(): v.lower()
            for k, v in (allowed_sha256 or {}).items()
        }
        self._digest_pins.update(
            {Path(k).name.lower(): v.lower() for k, v in (allowed_sha256 or {}).items()}
        )
        self._digest_roots = allowed_sha256 is not None

    def _pinned_digest(self, target: Path) -> str | None:
        key = str(target).lower()
        if key in self._digest_pins:
            return self._digest_pins[key]
        return self._digest_pins.get(target.name.lower())

    def _refusal(self, reason: str) -> ExecutionResult:
        """A denial that started nothing: no sandbox, no guest, no side effect."""
        return ExecutionResult(
            status="policy_denied",
            exit_code=0,
            stdout="",
            stderr="",
            elapsed_ms=0.0,
            blocked=True,
            reason=reason,
        )

    def _authorized(self, wasm_path: str) -> Path | None:
        """Return the resolved module path if it sits under an allowed root, else None."""
        try:
            resolved = Path(wasm_path).resolve()
        except (OSError, RuntimeError, ValueError):
            return None
        return (
            resolved
            if any(
                resolved == root or root in resolved.parents
                for root in self._allowed_roots
            )
            else None
        )

    def _read_authorized_bytes(
        self, target: Path
    ) -> tuple[bytes | None, str, str | None]:
        """Open the authorized path once and return (bytes, sha256, refusal reason).

        ``O_NOFOLLOW`` makes a final-component symlink an error rather than a
        redirect, ``fstat`` on the same descriptor rejects anything that is not a
        regular file within the configured module-size cap, and the hash is taken
        over the very bytes handed back — so identity cannot drift from content.

        The type/size check runs on ``lstat`` BEFORE opening and the open itself
        is ``O_NONBLOCK``: a FIFO or character device a model may name would
        otherwise block the tool call until some other process served it, which
        is a denial of service on the integration, not a refusal.
        """
        try:
            pre = target.lstat()
        except OSError as exc:
            return None, "", f"stat_failed:{exc.__class__.__name__}"
        if not stat.S_ISREG(pre.st_mode):
            return None, "", "not_a_regular_file"
        cap = self.config.max_wasm_bytes
        if cap not in (None, 0) and pre.st_size > cap:
            return None, "", f"module_too_large:{pre.st_size}>{cap}"
        flags = (
            os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0) | getattr(os, "O_NONBLOCK", 0)
        )
        try:
            fd = os.open(str(target), flags)
        except OSError as exc:
            return None, "", f"open_refused:{exc.__class__.__name__}"
        try:
            info = os.fstat(fd)
            if not stat.S_ISREG(info.st_mode):
                return None, "", "not_a_regular_file"
            if cap not in (None, 0) and info.st_size > cap:
                return None, "", f"module_too_large:{info.st_size}>{cap}"
            chunks: list[bytes] = []
            total = 0
            while True:
                chunk = os.read(fd, 1 << 20)
                if not chunk:
                    break
                total += len(chunk)
                if cap not in (None, 0) and total > cap:
                    return None, "", f"module_too_large:{total}>{cap}"
                chunks.append(chunk)
        finally:
            os.close(fd)
        data = b"".join(chunks)
        if not data.startswith(b"\x00asm"):
            return None, "", "not_a_wasm_module"
        return data, hashlib.sha256(data).hexdigest(), None

    def execute(self, wasm_path: str) -> ExecutionResult:
        """Execute an allowlisted WASM module in isolation.

        Args:
            wasm_path: Path to a compiled .wasm module, which MUST resolve under
                one of the operator's ``allowed_roots``; a model-supplied path is
                treated as untrusted and confined.

        Returns:
            ExecutionResult; ``status='policy_denied'`` (``blocked=True``) with a
            ``reason`` when the path is outside the allowlist, malformed, not a
            regular WASM file, or fails a pinned digest — nothing is created or
            executed in those cases.
        """
        # Model output is arbitrary: a non-string/non-path argument or a
        # NUL-bearing path is a refusal, never an exception escaping the tool.
        if not isinstance(wasm_path, (str, os.PathLike)):
            return self._refusal("path_not_a_string")
        if isinstance(wasm_path, str) and (
            "\x00" in wasm_path or not wasm_path.strip()
        ):
            return self._refusal("path_malformed")
        target = self._authorized(str(wasm_path))
        if target is None:
            # Fail closed BEFORE the sandbox exists: refuse the model's path.
            return self._refusal("outside_allowed_roots")
        data, digest, reason = self._read_authorized_bytes(target)
        if data is None:
            return self._refusal(reason or "unreadable_module")
        pin = self._pinned_digest(target)
        if pin is not None and digest != pin:
            return self._refusal(f"digest_pin_mismatch:{digest}")
        if self._digest_roots and pin is None:
            # Pinning mode: an unnamed module has no operator-approved identity.
            return self._refusal("module_not_pinned")
        # Run the bytes we authorized, from a directory only we own, with the
        # measured digest bound onto the load: a later swap of ``target`` cannot
        # change what executes (closes the check-to-use window).
        staging = tempfile.mkdtemp(prefix="ephemora-agent-")
        os.chmod(staging, 0o700)
        staged = Path(staging) / target.name
        try:
            fd = os.open(str(staged), os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
            with os.fdopen(fd, "wb") as handle:
                handle.write(data)
            sandbox = WASISandbox(config=self.config)
            try:
                result = sandbox.run(str(staged), abi="auto", expected_sha256=digest)
            finally:
                sandbox.cleanup()
        finally:
            try:
                staged.unlink(missing_ok=True)
                os.rmdir(staging)
            except OSError:
                pass
        return ExecutionResult(
            status=result.status.value,
            exit_code=result.exit_code,
            stdout=result.stdout[:1000],
            stderr=result.stderr[:1000],
            elapsed_ms=round(result.elapsed_ms, 2),
            blocked=result.status.value != "success",
            module_sha256=digest,
        )
