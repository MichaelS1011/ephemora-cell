"""Social preview image (1280x640) — GitHub 'Social media preview'.

GitHub has no API for the social preview upload; this script regenerates
the asset deterministically, a human uploads it in repo Settings ->
General -> Social media preview. Same visual language (and headless-Chrome
render path) as assets/make_release_card.py: GitHub Primer dark, blue
accent. Designed for HALF SIZE legibility (link cards render ~600x300):
three large stat numbers instead of a small-badge confetti strip, one
prominent CTA chip, every claim stated exactly once.

Refresh the numbers below on every release (they mirror the README
freshness block: tests passing, coverage, version).

Rendered at 2x and downsampled so text stays crisp after GitHub's resize.
"""

from __future__ import annotations

import struct
import subprocess
from pathlib import Path

from PIL import Image

REPO = Path(__file__).resolve().parent.parent
OUT = REPO / "assets"
CHROME = Path(
    "/Users/mimiai/Library/Caches/ms-playwright/chromium_headless_shell-1243/"
    "chrome-headless-shell-mac-arm64/chrome-headless-shell"
)
W, H = 1280, 640
SCALE = 2

HTML = """<!DOCTYPE html>
<html><head><meta charset="utf-8"><style>
  * { margin: 0; padding: 0; box-sizing: border-box; }
  body {
    width: 1280px; height: 640px; overflow: hidden;
    background: #0d1117; color: #e6edf3;
    font-family: -apple-system, "Helvetica Neue", Arial, sans-serif;
    display: flex; flex-direction: column; padding: 42px 56px 34px;
  }
  .topbar {
    display: flex; justify-content: space-between; align-items: center;
    margin-bottom: 24px;
  }
  .eyebrow {
    color: #4a9eff; font-size: 26px; font-weight: 700; letter-spacing: 5px;
  }
  .pill {
    display: inline-flex; border-radius: 999px; overflow: hidden;
    font-size: 22px; font-weight: 700; line-height: 1;
    box-shadow: 0 0 0 1px #238636;
  }
  .pill i { font-style: normal; padding: 10px 14px; background: #12261a; color: #7ee2a8; }
  .pill b { font-style: normal; padding: 10px 14px; background: #238636; color: #ffffff; }
  .cols { display: flex; gap: 46px; flex: 1; min-height: 0; }
  .left { flex: 1.32; display: flex; flex-direction: column; }
  h1 { font-size: 48px; line-height: 1.1; font-weight: 800; margin-bottom: 16px; }
  h1 .dim { color: #4a9eff; }
  .rule { width: 200px; height: 5px; background: #4a9eff; margin-bottom: 14px; }
  .sub { font-size: 21px; line-height: 1.3; color: #b6c2cf; margin-bottom: 22px;
         white-space: nowrap; }
  .stats { display: flex; gap: 44px; margin-bottom: 24px; }
  .stat b { display: block; font-size: 44px; font-weight: 800; color: #ffffff; line-height: 1; }
  .stat span {
    display: block; margin-top: 8px; font-size: 17px; line-height: 1.25;
    color: #7d8590; font-weight: 600;
  }
  .proof { display: flex; flex-direction: column; gap: 12px; }
  .proof div { font-size: 22px; line-height: 1.3; color: #b6c2cf; white-space: nowrap; }
  .proof .tick { color: #3fb950; font-weight: 800; }
  .right { flex: 1; display: flex; flex-direction: column; justify-content: center;
           gap: 26px; }
  .term {
    background: #161b22; border: 1px solid #30363d; border-radius: 12px;
    padding: 22px 24px; font-family: "SF Mono", Menlo, monospace;
    font-size: 21px; line-height: 1.85; white-space: nowrap;
  }
  .term .p { color: #3fb950; }
  .term .c { color: #8b949e; }
  .term .o { color: #e6edf3; }
  .cta {
    background: #12261a; border: 2px solid #238636; border-radius: 12px;
    padding: 20px 24px; font-family: "SF Mono", Menlo, monospace;
    font-size: 27px; font-weight: 700; color: #ffffff;
    display: flex; align-items: center; gap: 14px; white-space: nowrap;
  }
  .cta .p { color: #3fb950; }
  .foot {
    border-top: 1px solid #30363d; margin-top: 22px; padding-top: 16px;
    display: flex; justify-content: space-between; align-items: baseline;
    font-size: 20px; color: #7d8590;
  }
  .foot .url { color: #4a9eff; font-weight: 700; font-size: 22px; }
</style></head><body>
  <div class="topbar">
    <div class="eyebrow">EPHEMORA CELL</div>
    <div class="pill"><i>released</i><b>v1.0.4.3 &middot; on PyPI</b></div>
  </div>
  <div class="cols">
    <div class="left">
      <h1>Deterministic execution<br>for <span class="dim">untrusted</span> AI-generated code.</h1>
      <div class="rule"></div>
      <div class="sub">Bounded, measured, reproducible &mdash; not &ldquo;isolated and hoped for&rdquo;.</div>
      <div class="stats">
        <div class="stat"><b>532</b><span>tests passing</span></div>
        <div class="stat"><b>86%</b><span>coverage</span></div>
        <div class="stat"><b>8/8</b><span>attack vectors blocked<br>macOS arm64 + DGX aarch64</span></div>
      </div>
      <div class="proof">
        <div><span class="tick">&#10003;</span> <b>~0.5 ms warm</b> &middot; no network &middot; WASI-P1 conformant</div>
      </div>
    </div>
    <div class="right">
      <div class="term">
        <span class="c">$</span> <span class="o">ephemora-cell run untrusted.wasm</span><br>
        <span class="p">&#10003;</span> <span class="o">stopped at exactly 100/100 fuel</span><br>
        <span class="p">&#10003;</span> <span class="o">record signed &middot; DSSE v1 + JWS</span>
      </div>
      <div class="cta"><span class="p">$</span> pip install ephemora-cell</div>
    </div>
  </div>
  <div class="foot">
    <div class="url">github.com/MichaelS1011/ephemora-cell</div>
    <div>MCP Registry listed &middot; Apache-2.0 &middot; Python 3.10+ &middot; macOS &amp; Linux</div>
  </div>
</body></html>"""


def main() -> None:
    html = OUT / "social-preview.html"
    png = OUT / "social-preview.png"
    html.write_text(HTML)
    big = OUT / ".social-preview-2x.png"
    subprocess.run(
        [
            str(CHROME),
            "--no-sandbox",
            "--disable-gpu",
            "--hide-scrollbars",
            "--force-device-scale-factor=2",
            f"--window-size={W},{H}",
            f"--screenshot={big}",
            f"file://{html}",
        ],
        check=True,
        capture_output=True,
    )
    w, h = struct.unpack(">II", big.read_bytes()[16:24])
    assert (w, h) == (W * SCALE, H * SCALE), f"wrong size {w}x{h}"
    img = Image.open(big).convert("RGB")
    img = img.resize((W, H), Image.LANCZOS)
    img.save(png, optimize=True)
    big.unlink()
    print(f"wrote {png} ({png.stat().st_size / 1024:.0f} KB, {W}x{H})")


if __name__ == "__main__":
    main()
