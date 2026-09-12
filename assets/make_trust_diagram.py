"""Generate assets/trust-chain-light.svg + trust-chain-dark.svg (adaptive
README diagram for the ADR-006 trust chain).

Deterministic: rerunning produces byte-identical SVGs. Palette derived from
GitHub's primer light/dark tokens (same scheme as make_hero.py) so both
variants sit cleanly on the respective README background.
"""
from pathlib import Path

HERE = Path(__file__).parent

PALETTES = {
    "light": {
        "text": "#1f2328", "muted": "#59636e", "box_fill": "#ffffff",
        "box_stroke": "#d1d9e0", "accent": "#0969da", "accent_fill": "#ddf4ff",
        "danger": "#cf222e", "ok": "#1a7f37",
    },
    "dark": {
        "text": "#e6edf3", "muted": "#9198a1", "box_fill": "#151b23",
        "box_stroke": "#3d444d", "accent": "#4493f8", "accent_fill": "#121d2f",
        "danger": "#f85149", "ok": "#3fb950",
    },
}

W, H = 880, 250

NODES = [
    (20, 175, "VENDOR", "signs manifest", "Ed25519 · RFC 8785 JCS", "box"),
    (255, 220, "HOST VERIFIES", "signature ✓  hash ✓  path ✓", "fail-closed at load", "accent"),
    (530, 175, "CELL SANDBOX", "fuel · memory", "timeout · I/O walls", "box"),
    (745, 115, "SIGNED RECORD", "status · fuel · baseline", "tamper-evident", "ok"),
]


def esc(s: str) -> str:
    return s.replace("&", "&amp;").replace("<", "&lt;")


def node(x, w, title, l1, l2, kind, p):
    fill = p["accent_fill"] if kind == "accent" else p["box_fill"]
    stroke = p["accent"] if kind == "accent" else p["box_stroke"]
    title_fill = p["accent"] if kind == "accent" else (
        p["ok"] if kind == "ok" else p["text"]
    )
    return (
        f'<rect x="{x}" y="70" width="{w}" height="86" rx="12" fill="{fill}" stroke="{stroke}" stroke-width="1.5"/>'
        f'<text x="{x + w / 2}" y="98" text-anchor="middle" font-size="14.5" font-weight="600" fill="{title_fill}" font-family="-apple-system,Segoe UI,Helvetica,Arial,sans-serif">{esc(title)}</text>'
        f'<text x="{x + w / 2}" y="120" text-anchor="middle" font-size="12" fill="{p["text"]}" font-family="-apple-system,Segoe UI,sans-serif">{esc(l1)}</text>'
        f'<text x="{x + w / 2}" y="138" text-anchor="middle" font-size="12" fill="{p["muted"]}" font-family="-apple-system,Segoe UI,sans-serif">{esc(l2)}</text>'
    )


def arrow(x1, x2, p):
    return (
        f'<line x1="{x1}" y1="113" x2="{x2 - 10}" y2="113" stroke="{p["box_stroke"]}" stroke-width="1.5"/>'
        f'<polygon points="{x2 - 10},108 {x2},113 {x2 - 10},118" fill="{p["box_stroke"]}"/>'
    )


def render(theme: str) -> str:
    p = PALETTES[theme]
    parts = [
        f'<svg xmlns="http://www.w3.org/2000/svg" width="{W}" height="{H}" viewBox="0 0 {W} {H}" role="img" '
        f'aria-label="Trust chain: vendor signs manifest, host verifies fail-closed, Cell sandbox runs, signed execution record">',
        f'<rect width="{W}" height="{H}" fill="{"#ffffff" if theme == "light" else "#0d1117"}"/>',
    ]
    for x, w, title, l1, l2, kind in NODES:
        parts.append(node(x, w, title, l1, l2, kind, p))
    # arrows between nodes
    parts.append(arrow(195, 255, p))
    parts.append(arrow(475, 530, p))
    parts.append(arrow(705, 745, p))
    # rejection branch under the host node
    parts.append(
        f'<line x1="365" y1="156" x2="365" y2="184" stroke="{p["danger"]}" stroke-width="1.5" stroke-dasharray="4 3"/>'
        f'<polygon points="360,184 365,194 370,184" fill="{p["danger"]}"/>'
        f'<rect x="255" y="196" width="220" height="30" rx="8" fill="none" stroke="{p["danger"]}" stroke-dasharray="4 3"/>'
        f'<text x="365" y="215" text-anchor="middle" font-size="12" fill="{p["danger"]}" font-family="-apple-system,Segoe UI,sans-serif">✗ unsigned / tampered → REJECTED</text>'
    )
    parts.append(
        f'<text x="{W // 2}" y="244" text-anchor="middle" font-size="12" fill="{p["muted"]}" font-family="-apple-system,Segoe UI,sans-serif">'
        f'the agent proposes; the host disposes — every step attested (ADR-006)</text>'
    )
    parts.append("</svg>")
    return "".join(parts)


if __name__ == "__main__":
    for theme in ("light", "dark"):
        out = HERE / f"trust-chain-{theme}.svg"
        out.write_text(render(theme))
        print(f"wrote {out} ({out.stat().st_size // 1024} KB)")
