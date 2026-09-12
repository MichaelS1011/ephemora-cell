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
from collections.abc import Callable
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

from ephemora_cell.execution_report import jcs_canonicalize

DEFAULT_INPUT_SCHEMA: dict[str, Any] = {"type": "object", "properties": {}}

# Manifest fields that carry the signature itself (never part of the
# signing input).
_SIGNATURE_FIELDS = ("alg", "signature")


def manifest_payload(manifest: dict[str, Any]) -> dict[str, Any]:
    """The manifest without its signature fields (the signing input)."""
    return {k: v for k, v in manifest.items() if k not in _SIGNATURE_FIELDS}


def sign_manifest(
    manifest: dict[str, Any],
    signer: Callable[[bytes], bytes],
    *,
    alg: str = "EdDSA",
) -> dict[str, Any]:
    """Return a SEP-2787-style signed copy of a tool manifest sidecar.

    The signing input is the RFC 8785 (JCS) canonicalization of every
    field EXCEPT ``alg``/``signature`` (``alg`` is added to the payload so
    it is covered by the signature); ``signature`` is the lowercase hex of
    the signer's raw output. The signer is an opaque bytes->bytes callable
    — Cell ships no crypto dependency, the operator brings the keys (see
    :mod:`ephemora_cell_mcp.sign_tool` for the Ed25519 helper).
    """
    if not callable(signer):
        raise TypeError(
            f"signer must be callable bytes->bytes, got {type(signer).__name__}"
        )
    if not isinstance(manifest, dict):
        raise TypeError(f"manifest must be a dict, got {type(manifest).__name__}")
    payload = manifest_payload(manifest)
    payload["alg"] = alg
    raw = signer(jcs_canonicalize(payload).encode("utf-8"))
    if not isinstance(raw, (bytes, bytearray)):
        raise TypeError(f"signer must return bytes, got {type(raw).__name__}")
    signed = dict(manifest)
    signed["alg"] = alg
    signed["signature"] = bytes(raw).hex()
    return signed


def verify_manifest(
    manifest: Any,
    verifier: Callable[[bytes, bytes], bool],
) -> bool:
    """Verify a signed tool manifest. **Fails closed.**

    Any malformed input (not a dict, missing/non-hex signature, unknown
    structure, verifier exception) returns ``False`` — only a valid
    signature over the exact canonical payload returns ``True``.
    """
    if not isinstance(manifest, dict) or not callable(verifier):
        return False
    alg = manifest.get("alg")
    signature_hex = manifest.get("signature")
    if not isinstance(alg, str) or not isinstance(signature_hex, str):
        return False
    payload = manifest_payload(manifest)
    payload["alg"] = alg
    try:
        signature = bytes.fromhex(signature_hex)
        canonical = jcs_canonicalize(payload).encode("utf-8")
    except (TypeError, ValueError):
        return False
    try:
        return bool(verifier(canonical, signature))
    except Exception:
        return False


def ed25519_verifier_from_pem(pem_path: str) -> Callable[[bytes, bytes], bool]:
    """Build a manifest verifier from an Ed25519 public key (PEM file).

    Needs the optional ``cryptography`` package (extra ``tools-signing``);
    the error names it so operators get an actionable message instead of
    an ImportError traceback.
    """
    try:
        from cryptography.hazmat.primitives.serialization import load_pem_public_key
    except ImportError as e:  # pragma: no cover - exercised via flag path
        raise RuntimeError(
            "signature enforcement needs the optional 'cryptography' package "
            "(pip install 'ephemora-cell[tools-signing]') — or verify "
            "manifests in the host process instead"
        ) from e
    with open(pem_path, "rb") as f:
        key = load_pem_public_key(f.read())
    verify = getattr(key, "verify", None)
    if verify is None:
        raise ValueError(f"{pem_path!r} is not a public key")

    def _verify(canonical: bytes, signature: bytes) -> bool:
        from cryptography.exceptions import InvalidSignature

        try:
            verify(signature, canonical)
            return True
        except InvalidSignature:
            return False

    return _verify


@dataclass(frozen=True)
class ToolSpec:
    """A single WASM-backed MCP tool."""

    name: str
    wasm_path: str
    description: str
    input_schema: dict[str, Any] = field(
        default_factory=lambda: dict(DEFAULT_INPUT_SCHEMA)
    )
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
    """Scans a tools directory for ``.wasm`` + optional ``.json`` sidecars.

    With ``manifest_verifier`` the registry runs in **signed-tools mode**
    (ADR-006 verify-before-register): every sidecar must carry a valid
    signature (see :func:`sign_manifest`) and a bare ``.wasm`` without a
    sidecar has no manifest to verify — both are rejected with a warning
    instead of being registered. Without a verifier (default) the legacy
    convention applies: sidecars are metadata only.
    """

    def __init__(
        self,
        tools_dir: str | Path,
        *,
        manifest_verifier: Callable[[bytes, bytes], bool] | None = None,
    ) -> None:
        self.tools_dir = Path(tools_dir)
        self.manifest_verifier = manifest_verifier
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

    def _build_spec(self, stem: str, wasm: Path, sidecar: Path) -> ToolSpec | None:
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
        elif self.manifest_verifier is not None:
            # Signed-tools mode (ADR-006): a bare .wasm has no manifest and
            # therefore no signature — fail closed.
            import warnings

            warnings.warn(
                f"tool {stem!r}: no sidecar manifest - rejected in "
                "signed-tools mode",
                RuntimeWarning,
                stacklevel=2,
            )
            return None
        if self.manifest_verifier is not None and not verify_manifest(
            metadata, self.manifest_verifier
        ):
            import warnings

            warnings.warn(
                f"tool {stem!r}: sidecar failed manifest signature "
                "verification (unsigned, tampered or malformed) - rejected "
                "in signed-tools mode",
                RuntimeWarning,
                stacklevel=2,
            )
            return None
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
