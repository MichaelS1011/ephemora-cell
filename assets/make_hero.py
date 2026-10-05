"""Generate assets/hero-light.svg + assets/hero-dark.svg (adaptive GitHub README hero).

Deterministic: rerunning produces byte-identical SVGs. Palette derived from
GitHub's primer light/dark tokens so both variants sit cleanly on the
respective README background.

Two rules this file exists to keep true:

* No resource numbers in the picture. 128 MB and 10 KB are defaults that the
  profiles widen, so a cap drawn here reads as a ceiling that the product does
  not have. The picture says `bounded`; README and docs/performance.md carry
  the values with their conditions.
* The hero is the lifecycle, not just the sandbox. `create -> constrain ->
  execute -> prove -> destroy` is drawn as a strip, and the right column shows
  the two different outcomes of one run: evidence that may persist, execution
  state that does not.

Each variant carries its own opaque background. GitHub serves the dark variant
from a `prefers-color-scheme` media query, which follows the *operating
system*, not GitHub's own theme switch — so a transparent canvas can land a
light-mode diagram on a dark page, and vice versa.
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

W, H = 880, 404
CELL_X, CELL_Y, CELL_W, CELL_H = 200, 44, 384, 258
CELL_CX = CELL_X + CELL_W // 2
MID_Y = 167

SANS = "-apple-system,Segoe UI,Helvetica,Arial,sans-serif"

LIFECYCLE = ["create", "constrain", "execute", "prove", "destroy"]


def esc(s: str) -> str:
    return s.replace("&", "&amp;").replace("<", "&lt;")


def text(x, y, s, size, fill, *, weight=None, anchor="middle", family=SANS):
    w = f' font-weight="{weight}"' if weight else ""
    return (
        f'<text x="{x}" y="{y}" text-anchor="{anchor}" font-size="{size}"{w} '
        f'fill="{fill}" font-family="{family}">{esc(s)}</text>'
    )


def chip(x, y, w, label, p, *, size=13, fill=None, stroke=None, dashed=False):
    dash = ' stroke-dasharray="5 4"' if dashed else ""
    body = (
        f'<rect x="{x}" y="{y}" width="{w}" height="34" rx="8" '
        f'fill="{fill or p["chip_fill"]}" stroke="{stroke or p["box_stroke"]}"{dash}/>'
    )
    return body + text(x + w / 2, y + 22, label, size, p["text"])


def arrow(x1, x2, y, p):
    return (
        f'<line x1="{x1}" y1="{y}" x2="{x2 - 10}" y2="{y}" '
        f'stroke="{p["box_stroke"]}" stroke-width="1.5"/>'
        f'<polygon points="{x2 - 10},{y - 5} {x2},{y} {x2 - 10},{y + 5}" '
        f'fill="{p["box_stroke"]}"/>'
    )


def build(p: dict) -> str:
    parts = [
        f'<svg xmlns="http://www.w3.org/2000/svg" width="{W}" height="{H}" '
        f'viewBox="0 0 {W} {H}" role="img" '
        f'aria-label="One execution lifecycle: an agent hands untrusted code to '
        f"the Ephemora-cell capability boundary, which grants explicit "
        f"capabilities and budgets, denies network and process access by "
        f"default, and returns a bounded result with a signed record while the "
        f'execution state is destroyed">',
        f'<rect width="{W}" height="{H}" fill="{p["canvas"]}"/>',
    ]

    # Left: whoever proposes the code. The host is the one who decides.
    parts.append(chip(16, MID_Y - 17, 132, "AI agent / app", p, size=13.5))
    parts.append(text(82, MID_Y + 40, "untrusted tool code", 12, p["muted"]))
    parts.append(text(82, MID_Y - 30, "the host decides", 12, p["muted"]))
    parts.append(arrow(148, 196, MID_Y, p))

    # Center: the boundary itself.
    parts.append(
        f'<rect x="{CELL_X}" y="{CELL_Y}" width="{CELL_W}" height="{CELL_H}" '
        f'rx="14" fill="{p["box_fill"]}" stroke="{p["accent"]}" stroke-width="1.5"/>'
    )
    parts.append(
        text(CELL_CX, CELL_Y + 32, "EPHEMORA CELL", 17, p["accent"], weight="600")
    )
    parts.append(
        text(
            CELL_CX,
            CELL_Y + 52,
            "capability boundary — one execution at a time",
            11.5,
            p["muted"],
        )
    )
    rows = [
        ("Explicit capabilities", "Bounded memory"),
        ("Fuel + time budgets", "Bounded output"),
    ]
    y = CELL_Y + 68
    for left, right in rows:
        parts.append(chip(CELL_X + 16, y, 168, left, p))
        parts.append(chip(CELL_X + 200, y, 168, right, p))
        y += 44
    parts.append(
        chip(CELL_X + 16, y, CELL_W - 32, "Host grants them — guest cannot widen", p)
    )
    parts.append(
        text(
            CELL_CX,
            CELL_Y + CELL_H - 40,
            "network denied by default · no exec/fork",
            13.5,
            p["danger"],
            weight="700",
        )
    )
    parts.append(
        text(
            CELL_CX,
            CELL_Y + CELL_H - 20,
            "no ambient host access — every capability is granted",
            12,
            p["danger"],
        )
    )

    # Right: the two outcomes of one run, kept apart on purpose.
    parts.append(arrow(CELL_X + CELL_W, 632, 141, p))
    parts.append(arrow(CELL_X + CELL_W, 632, 213, p))
    parts.append(
        text(748, 116, "status · fuel · baseline · attested", 11.5, p["muted"])
    )
    parts.append(
        chip(
            632,
            124,
            232,
            "result + signed record",
            p,
            size=13.5,
            fill=p["accent_fill"],
            stroke=p["accent"],
        )
    )
    parts.append(
        chip(632, 196, 232, "execution state destroyed", p, size=13.5, dashed=True)
    )
    parts.append(text(748, 258, "evidence persists · state does not", 12, p["muted"]))

    # Bottom: the lifecycle the boundary implements.
    parts.append(text(W // 2, 330, "one execution, start to finish", 11.5, p["muted"]))
    chip_w, gap = 112, 20
    total = len(LIFECYCLE) * chip_w + (len(LIFECYCLE) - 1) * gap
    x = (W - total) // 2
    for i, label in enumerate(LIFECYCLE):
        parts.append(chip(x, 338, chip_w, label, p, size=12.5))
        if i < len(LIFECYCLE) - 1:
            parts.append(arrow(x + chip_w, x + chip_w + gap, 355, p))
        x += chip_w + gap
    parts.append(
        text(
            W // 2,
            398,
            "nothing carries over: no state, no capability, no authority",
            12,
            p["muted"],
        )
    )
    parts.append("</svg>")
    return "\n".join(parts)


if __name__ == "__main__":
    for name, pal in PALETTES.items():
        out = HERE / f"hero-{name}.svg"
        out.write_text(build(pal))
        print(f"wrote {out.name} ({out.stat().st_size} bytes)")
