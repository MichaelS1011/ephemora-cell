"""Generate assets/architecture-light.svg + assets/architecture-dark.svg.

The main diagram the README opens with: how untrusted code travels from an
agent into the boundary, station by station — `AI agent / app -> tool, plugin
or MCP server -> Ephemora-cell -> WASM sandbox` — plus the two side facts a
reader needs to place the product correctly:

* the direct embedding path (Python library / CLI) reaches the same boundary,
  drawn as the dashed bypass under the MCP station;
* the return path is a bounded result with a record that can be signed — the
  evidence persists, the execution state does not.

Deterministic: rerunning produces byte-identical SVGs. Palette shared with
make_hero.py (GitHub primer light/dark tokens) so both diagrams sit cleanly on
the respective README background.

Same rule as the hero: no resource numbers in the picture. Budgets exist per
profile; the values live in README and docs/performance.md with their
conditions, not in a drawing.
"""

from pathlib import Path

HERE = Path(__file__).parent

PALETTES = {
    "light": {
        "canvas": "#ffffff",
        "text": "#1f2328",
        "muted": "#444d56",
        "box_fill": "#f6f8fa",
        "box_stroke": "#8b949e",
        "accent": "#0969da",
        "accent_fill": "#ddf4ff",
        "danger": "#cf222e",
        "chip_fill": "#ffffff",
    },
    "dark": {
        "canvas": "#0d1117",
        "text": "#e6edf3",
        "muted": "#a5aeb8",
        "box_fill": "#151b23",
        "box_stroke": "#8b949e",
        "accent": "#4493f8",
        "accent_fill": "#121d2f",
        "danger": "#f85149",
        "chip_fill": "#1c2128",
    },
}

W, H = 880, 328
BOX_Y, BOX_H = 64, 108
MID_Y = BOX_Y + BOX_H // 2

SANS = "-apple-system,Segoe UI,Helvetica,Arial,sans-serif"

# x, width, title, lines, accent_border
STATIONS = [
    (
        24,
        176,
        "AI agent / app",
        ["generated code · tool calls", "untrusted by default", "no ambient authority"],
        False,
    ),
    (
        248,
        176,
        "Tool / plugin / MCP",
        [
            "ephemora-cell-mcp (stdio)",
            "tools are WASM modules",
            "each call → fresh sandbox",
        ],
        False,
    ),
    (
        472,
        176,
        "EPHEMORA CELL",
        [
            "capability boundary",
            "grants: fuel · memory · time",
            "deny: network · fs · exec",
            "untrusted/unknown → worker",
        ],
        True,
    ),
    (
        696,
        160,
        "WASM sandbox",
        ["Wasmtime engine", "guest runs bounded", "state does not survive"],
        False,
    ),
]

ARROW_LABELS = ["calls", "submits", "enforces"]


def esc(s: str) -> str:
    return s.replace("&", "&amp;").replace("<", "&lt;")


def text(x, y, s, size, fill, *, weight=None, anchor="middle"):
    w = f' font-weight="{weight}"' if weight else ""
    return (
        f'<text x="{x}" y="{y}" text-anchor="{anchor}" font-size="{size}"{w} '
        f'fill="{fill}" font-family="{SANS}">{esc(s)}</text>'
    )


def arrow(x1, x2, y, p):
    return (
        f'<line x1="{x1}" y1="{y}" x2="{x2 - 10}" y2="{y}" '
        f'stroke="{p["box_stroke"]}" stroke-width="1.5"/>'
        f'<polygon points="{x2 - 10},{y - 5} {x2},{y} {x2 - 10},{y + 5}" '
        f'fill="{p["box_stroke"]}"/>'
    )


def elbow(x_start, y_start, x_end, y_end, *, into_box_up, p, dashed=False):
    """Orthogonal connector: down from (x_start,y_start), across, then up with
    an arrowhead into (x_end, BOX_Y+BOX_H) — i.e. into a box's bottom edge."""
    dash = ' stroke-dasharray="5 4"' if dashed else ""
    bottom = BOX_Y + BOX_H
    base = bottom + 10
    return (
        f'<polyline points="{x_start},{y_start} {x_start},{y_end} '
        f'{x_end},{y_end} {x_end},{base}" fill="none" '
        f'stroke="{p["box_stroke"]}" stroke-width="1.5"{dash}/>'
        f'<polygon points="{x_end - 5},{base} {x_end + 5},{base} {x_end},{bottom}" '
        f'fill="{p["box_stroke"]}"/>'
    )


def build(p: dict) -> str:
    parts = [
        f'<svg xmlns="http://www.w3.org/2000/svg" width="{W}" height="{H}" '
        f'viewBox="0 0 {W} {H}" role="img" '
        f'aria-label="Architecture: an AI agent or app proposes untrusted code '
        f"through a tool, plugin or MCP server; the Ephemora-cell capability "
        f"boundary grants fuel, memory, time and I/O capabilities and denies "
        f"network, filesystem and process access by default, routing any guest "
        f"the host has not explicitly marked trusted — modules and components "
        f"alike — onto an isolated worker; the guest runs inside a Wasmtime "
        f"WASM sandbox and the run returns a bounded result with a record that "
        f'can be signed, while no execution state survives into the next run">',
        f'<rect width="{W}" height="{H}" fill="{p["canvas"]}"/>',
        text(
            W // 2,
            30,
            "The path of untrusted code — one execution, four stations",
            14,
            p["text"],
            weight="600",
        ),
        text(
            W // 2,
            50,
            "an agent proposes; the host decides what actually runs",
            11.5,
            p["muted"],
        ),
    ]

    # The four stations, left to right.
    for x, w, title, lines, accent in STATIONS:
        stroke = p["accent"] if accent else p["box_stroke"]
        width = 1.5 if accent else 1
        parts.append(
            f'<rect x="{x}" y="{BOX_Y}" width="{w}" height="{BOX_H}" rx="12" '
            f'fill="{p["box_fill"]}" stroke="{stroke}" stroke-width="{width}"/>'
        )
        parts.append(
            text(
                x + w / 2,
                BOX_Y + 26,
                title,
                13.5,
                p["accent"] if accent else p["text"],
                weight="600" if accent else None,
            )
        )
        ly = BOX_Y + (46 if accent else 54)
        for line in lines:
            parts.append(text(x + w / 2, ly, line, 10.5, p["muted"]))
            ly += 18

    # Station-to-station arrows with one-word labels in the gaps.
    gaps = [(200, 248), (424, 472), (648, 696)]
    for (x1, x2), label in zip(gaps, ARROW_LABELS, strict=True):
        parts.append(arrow(x1, x2, MID_Y, p))
        parts.append(text((x1 + x2) / 2, MID_Y - 8, label, 10, p["muted"]))

    # Direct embedding path: same boundary, no MCP station in between.
    parts.append(elbow(88, BOX_Y + BOX_H, 560, 204, into_box_up=True, p=p, dashed=True))
    parts.append(
        text(
            324,
            224,
            "or embed directly: Python library · CLI — the same boundary",
            10.5,
            p["muted"],
        )
    )

    # Return path: what crosses back to the caller, and what does not.
    parts.append(elbow(776, BOX_Y + BOX_H, 136, 252, into_box_up=True, p=p))
    parts.append(
        text(
            456,
            272,
            "result + signable record — evidence persists, execution state does not",
            10.5,
            p["muted"],
        )
    )

    parts.append(
        text(
            W // 2,
            306,
            "no ambient access — every capability is granted, enforced and attested",
            11.5,
            p["muted"],
        )
    )
    parts.append("</svg>")
    return "\n".join(parts)


if __name__ == "__main__":
    for name, pal in PALETTES.items():
        out = HERE / f"architecture-{name}.svg"
        out.write_text(build(pal))
        print(f"wrote {out.name} ({out.stat().st_size} bytes)")
