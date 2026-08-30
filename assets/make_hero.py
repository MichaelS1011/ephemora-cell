"""Generate assets/hero-light.svg + assets/hero-dark.svg (adaptive GitHub README hero).

Deterministic: rerunning produces byte-identical SVGs. Palette derived from
GitHub's primer light/dark tokens so both variants sit cleanly on the
respective README background.
"""
from pathlib import Path

HERE = Path(__file__).parent

PALETTES = {
    "light": {
        "text": "#1f2328", "muted": "#59636e", "box_fill": "#f6f8fa",
        "box_stroke": "#d1d9e0", "accent": "#0969da", "accent_fill": "#ddf4ff",
        "danger": "#cf222e", "chip_fill": "#ffffff",
    },
    "dark": {
        "text": "#e6edf3", "muted": "#9198a1", "box_fill": "#151b23",
        "box_stroke": "#3d444d", "accent": "#4493f8", "accent_fill": "#121d2f",
        "danger": "#f85149", "chip_fill": "#1c2128",
    },
}

W, H = 880, 320
CX = W // 2


def esc(s: str) -> str:
    return s.replace("&", "&amp;").replace("<", "&lt;")


def chip(x: int, y: int, w: int, label: str, p: dict, fill=None, stroke=None):
    return (
        f'<rect x="{x}" y="{y}" width="{w}" height="34" rx="8" '
        f'fill="{fill or p["chip_fill"]}" stroke="{stroke or p["box_stroke"]}"/>'
        f'<text x="{x + w / 2}" y="{y + 22}" text-anchor="middle" '
        f'font-family="-apple-system,Segoe UI,Helvetica,Arial,sans-serif" '
        f'font-size="14" fill="{p["text"]}">{esc(label)}</text>'
    )


def build(p: dict) -> str:
    parts = [
        f'<svg xmlns="http://www.w3.org/2000/svg" width="{W}" height="{H}" '
        f'viewBox="0 0 {W} {H}" role="img" '
        f'aria-label="AI Agent → Ephemora Cell enforcement stack → bounded result">',
    ]
    # Left: AI Agent
    parts.append(chip(20, 138, 130, "AI Agent", p))
    parts.append(
        f'<text x="85" y="208" text-anchor="middle" font-size="12" '
        f'fill="{p["muted"]}" font-family="-apple-system,Segoe UI,sans-serif">untrusted tool code</text>'
    )
    # Arrow into cell
    parts.append(
        f'<line x1="150" y1="155" x2="255" y2="155" stroke="{p["box_stroke"]}" stroke-width="1.5"/>'
        f'<polygon points="255,150 265,155 255,160" fill="{p["box_stroke"]}"/>'
    )
    # Center: enforcement stack
    bx, by, bw, bh = 265, 40, 350, 240
    parts.append(
        f'<rect x="{bx}" y="{by}" width="{bw}" height="{bh}" rx="14" '
        f'fill="{p["box_fill"]}" stroke="{p["accent"]}" stroke-width="1.5"/>'
    )
    parts.append(
        f'<text x="{CX}" y="{by + 34}" text-anchor="middle" font-size="17" '
        f'font-weight="600" fill="{p["accent"]}" '
        f'font-family="-apple-system,Segoe UI,sans-serif">EPHEMORA CELL</text>'
    )
    parts.append(
        f'<text x="{CX}" y="{by + 54}" text-anchor="middle" font-size="11.5" '
        f'fill="{p["muted"]}" font-family="-apple-system,Segoe UI,sans-serif">capability boundary — every run</text>'
    )
    chips = [
        ("CPU / Fuel metering", "Memory cap (128 MB)"),
        ("Wall-clock timeout", "Filesystem preopens"),
        ("I/O budgets", "Output cap (10 KB)"),
    ]
    y = by + 72
    for left, right in chips:
        parts.append(chip(bx + 20, y, 150, left, p))
        parts.append(chip(bx + 180, y, 150, right, p))
        y += 44
    parts.append(
        f'<text x="{CX}" y="{by + bh - 14}" text-anchor="middle" font-size="11.5" '
        f'fill="{p["danger"]}" font-family="-apple-system,Segoe UI,sans-serif">'
        f'no network · no exec/fork · no host access</text>'
    )
    # Arrow out
    parts.append(
        f'<line x1="{bx + bw}" y1="155" x2="{bx + bw + 30}" y2="155" '
        f'stroke="{p["box_stroke"]}" stroke-width="1.5"/>'
        f'<polygon points="{bx + bw + 30},150 {bx + bw + 40},155 {bx + bw + 30},160" '
        f'fill="{p["box_stroke"]}"/>'
    )
    # Right: bounded result
    parts.append(chip(bx + bw + 40, 138, 165, "bounded result", p, fill=p["accent_fill"], stroke=p["accent"]))
    parts.append(
        f'<text x="{bx + bw + 122}" y="128" text-anchor="middle" font-size="12" '
        f'fill="{p["muted"]}" font-family="-apple-system,Segoe UI,sans-serif">status · fuel · audit</text>'
    )
    # Footer line
    parts.append(
        f'<text x="{CX}" y="{H - 18}" text-anchor="middle" font-size="12" '
        f'fill="{p["muted"]}" font-family="-apple-system,Segoe UI,sans-serif">'
        f'execute(wasm) → result — enforced per run, not promised</text>'
    )
    parts.append("</svg>")
    return "\n".join(parts)


for name, pal in PALETTES.items():
    (HERE / f"hero-{name}.svg").write_text(build(pal))
    print(f"wrote hero-{name}.svg ({(HERE / f'hero-{name}.svg').stat().st_size} bytes)")
