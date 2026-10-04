# SPDX-License-Identifier: BUSL-1.1
# Copyright 2026 Michael Soppa

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
        "--tool-requests-dir",
        default=None,
        metavar="DIR",
        help=(
            "governed dynamic loading (ADR-006): the server evaluates "
            "*.tool.request.json files dropped into DIR before each "
            "incoming message — verify-before-register, then rescan "
            "+ notifications/tools/list_changed; requires "
            "--require-signed-tools. initialize advertises listChanged"
        ),
    )
    parser.add_argument(
        "--egress-allow",
        action="append",
        default=None,
        metavar="URL_PREFIX",
        help=(
            "ADR-002 host-sidecar egress: allow this tool-generation to reach "
            "URLs under URL_PREFIX (scheme://host[/path-prefix]); repeatable. "
            "When given, a guest that writes sidecar.request.json into its "
            "sandbox is mediated by the HOST after the run and the decision is "
            "attached to that call's _meta.egress. Without it the mediator is "
            "never invoked. This executes the allowlist — it is not yet a "
            "revocable, usage-capped grant (see ADR-013)."
        ),
    )
    parser.add_argument(
        "--egress-timeout",
        type=float,
        default=10.0,
        metavar="SECONDS",
        help="per-request wall for mediated egress (default 10s)",
    )
    parser.add_argument(
        "--egress-max-response-bytes",
        type=int,
        default=65536,
        metavar="BYTES",
        help="response body cap for mediated egress (default 64 KiB)",
    )
    parser.add_argument(
        "--egress-grants-dir",
        metavar="DIR",
        help=(
            "directory of *.egress.grant.json DSSE envelopes (ADR-013): each tool's "
            "grant whose expiry/usage cap/revocation are ENFORCED via "
            "--grant-ledger and whose SIGNATURE is verified against "
            "--egress-trust. Requires both: an unverified grant is not an "
            "authority this loader will install."
        ),
    )
    parser.add_argument(
        "--egress-trust",
        metavar="FILE",
        help=(
            "trust root for --egress-grants-dir (ADR-013): a JSON file OUTSIDE the "
            "grants directory listing the operator's trusted Ed25519 keys, their "
            "status (active/transition/retired), their validity windows and "
            "replaced_by for rotation. Every grant must be signed by a key named "
            "here — a key delivered with the artefact proves nothing. Needs the "
            "optional 'cryptography' package (tools-signing extra). Issue grants "
            "with: python -m ephemora_cell.grant_trust"
        ),
    )
    parser.add_argument(
        "--grant-ledger",
        metavar="PATH",
        help=(
            "append-only book backing --egress-grants-dir (host-side state; "
            "its parent directory must exist). Refuses a grant whose cap is "
            "spent, window closed or id revoked, before the fetch."
        ),
    )
    parser.add_argument(
        "--receipt-signing-key",
        metavar="PEM",
        help=(
            "Ed25519 private key (PEM) that signs each call's receipt into a "
            "DSSE envelope under _meta.attestation (ADR-008); callers verify "
            "with the matching public key. Needs the optional 'cryptography' "
            "package. Off by default — receipts stay self-reported."
        ),
    )
    parser.add_argument(
        "--receipt-key-id",
        metavar="ID",
        help="key id recorded in the receipt attestation (default none)",
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

    egress_policy = None
    if args.egress_allow:
        from ephemora_cell.egress_sidecar import EgressPolicy

        try:
            egress_policy = EgressPolicy(
                allowed_endpoints=tuple(args.egress_allow),
                max_response_bytes=args.egress_max_response_bytes,
                timeout_seconds=args.egress_timeout,
            )
        except ValueError as e:
            print(f"error: --egress-allow: {e}", file=sys.stderr)
            return 2

    egress_grants = None
    grant_ledger = None
    grant_trust_summary = None
    if args.egress_grants_dir:
        # Grants are only meaningful behind BOTH a ledger (ADR-013 enforcement)
        # and a trust root (authentication): a grant whose cap nobody reads is an
        # allowlist, and a grant nobody signed is a file someone dropped in a
        # directory. Both are refused at startup as a clean error, mirroring the
        # engine's own fail-closed guard.
        if not args.grant_ledger:
            print(
                "error: --egress-grants-dir requires --grant-ledger "
                "(grants are enforced only through the ledger)",
                file=sys.stderr,
            )
            return 2
        if not args.egress_trust:
            print(
                "error: --egress-grants-dir requires --egress-trust "
                "(a grant is authority and must be signed by a key the operator "
                "anchored outside the grants directory)",
                file=sys.stderr,
            )
            return 2
        from ephemora_cell.egress_sidecar import load_egress_grants
        from ephemora_cell.grant_ledger import GrantLedger
        from ephemora_cell.grant_trust import GrantTrustError, GrantTrustRoot

        try:
            trust_root = GrantTrustRoot.load(args.egress_trust)
        except (OSError, ValueError, GrantTrustError) as e:
            print(f"error: --egress-trust: {e}", file=sys.stderr)
            return 2
        try:
            grants, grant_errors = load_egress_grants(
                args.egress_grants_dir, trust_root
            )
        except (OSError, ValueError, GrantTrustError) as e:
            print(f"error: --egress-grants-dir: {e}", file=sys.stderr)
            return 2
        if grant_errors:
            # Fail closed: a half-loaded grant set would enforce some caps and
            # silently not others — and an unverified grant among them would be
            # exactly the authority the trust root exists to prevent.
            print("error: egress grant load failed (none enforced):", file=sys.stderr)
            for err in grant_errors:
                print(f"  - {err}", file=sys.stderr)
            return 2
        try:
            grant_ledger = GrantLedger(args.grant_ledger)
        except (OSError, ValueError, RuntimeError) as e:
            print(f"error: --grant-ledger: {e}", file=sys.stderr)
            return 2
        egress_grants = grants
        grant_trust_summary = trust_root.summary()

    receipt_signer = None
    if args.receipt_signing_key:
        from .tool_registry import ed25519_signer_from_pem

        try:
            receipt_signer = ed25519_signer_from_pem(args.receipt_signing_key)
        except (OSError, ValueError, RuntimeError) as e:
            print(f"error: --receipt-signing-key: {e}", file=sys.stderr)
            return 2

    from .server import Server

    Server(
        tools_dir=args.tools_dir,
        pooled=args.pooled,
        manifest_verifier=verifier,
        tool_requests_dir=args.tool_requests_dir,
        egress_policy=egress_policy,
        egress_grants=egress_grants,
        grant_ledger=grant_ledger,
        grant_trust=grant_trust_summary,
        receipt_signer=receipt_signer,
        receipt_key_id=args.receipt_key_id,
    ).serve()
    return 0


if __name__ == "__main__":
    sys.exit(main())
