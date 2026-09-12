"""Sign a tool manifest sidecar (ADR-006 verify-before-register).

Usage::

    python -m ephemora_cell_mcp.sign_tool tools/echo.json --key ed25519_private.pem

Adds ``alg`` (default ``EdDSA``) and ``signature`` (lowercase hex) to the
JSON file, signing the RFC 8785 (JCS) canonicalization of the manifest
minus its signature fields. The private key never leaves the operator's
machine; the matching public key PEM is what the server's
``--require-signed-tools`` consumes. Needs the optional ``cryptography``
package (extra ``tools-signing``).
"""

from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path


def _ed25519_signer_from_pem(pem_path: str):
    from cryptography.hazmat.primitives.serialization import load_pem_private_key

    key = load_pem_private_key(Path(pem_path).read_bytes(), password=None)
    sign = getattr(key, "sign", None)
    if sign is None:
        raise ValueError(f"{pem_path!r} is not a private key")

    def _sign(data: bytes) -> bytes:
        return sign(data)

    return _sign


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(
        prog="ephemora-cell-mcp-sign-tool",
        description=(
            "Sign a <toolname>.json tool manifest for --require-signed-tools "
            "(ADR-006 verify-before-register)"
        ),
    )
    parser.add_argument("manifest", help="path to the <toolname>.json sidecar")
    parser.add_argument("--key", required=True, help="Ed25519 private key (PEM file)")
    parser.add_argument("--alg", default="EdDSA", help="JWS alg id (default EdDSA)")
    parser.add_argument(
        "--wasm",
        default=None,
        metavar="MODULE.wasm",
        help=(
            "bind the manifest to a module: adds wasm_sha256 (SHA-256 of "
            "the .wasm bytes, covered by the signature) — required before "
            "governed dynamic loading (ADR-006 tool requests)"
        ),
    )
    args = parser.parse_args(argv)

    try:
        signer = _ed25519_signer_from_pem(args.key)
    except ImportError:
        print(
            "error: signing needs the optional 'cryptography' package "
            "(pip install 'ephemora-cell[tools-signing]')",
            file=sys.stderr,
        )
        return 2
    except (OSError, ValueError) as e:
        print(f"error: cannot load key: {e}", file=sys.stderr)
        return 2

    manifest_path = Path(args.manifest)
    try:
        manifest = json.loads(manifest_path.read_text(encoding="utf-8"))
    except (OSError, ValueError) as e:
        print(f"error: cannot read manifest: {e}", file=sys.stderr)
        return 2
    if not isinstance(manifest, dict):
        print("error: manifest must be a JSON object", file=sys.stderr)
        return 2

    if args.wasm:
        from .tool_registry import tool_wasm_sha256

        try:
            manifest["wasm_sha256"] = tool_wasm_sha256(args.wasm)
        except OSError as e:
            print(f"error: cannot read module: {e}", file=sys.stderr)
            return 2

    from .tool_registry import sign_manifest

    signed = sign_manifest(manifest, signer, alg=args.alg)
    manifest_path.write_text(
        json.dumps(signed, indent=2, ensure_ascii=False) + "\n", encoding="utf-8"
    )
    print(f"signed {args.manifest} (alg={args.alg})")
    return 0


if __name__ == "__main__":
    sys.exit(main())
