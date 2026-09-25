"""Build the 1.0.4 release card for LinkedIn (single portrait image).

Same visual language as the boundary carousel (dark, blue accent, system
font stack), rendered through the same headless-Chrome screenshot path.
Output: assets/release-card-1.0.4.png (1080x1350) + the HTML source.
"""

import struct
import subprocess
from pathlib import Path

REPO = Path(__file__).resolve().parent.parent
OUT = REPO / "assets"
CHROME = Path("/Users/mimiai/Library/Caches/ms-playwright/chromium_headless_shell-1243/"
              "chrome-headless-shell-mac-arm64/chrome-headless-shell")
W, H = 1080, 1350

HTML = """<!DOCTYPE html>
<html><head><meta charset="utf-8"><style>
  * { margin: 0; padding: 0; box-sizing: border-box; }
  body {
    width: 1080px; height: 1350px; overflow: hidden;
    background: #0d1117; color: #e6edf3;
    font-family: -apple-system, "Helvetica Neue", Arial, sans-serif;
    display: flex; flex-direction: column; padding: 72px 72px 56px;
  }
  .eyebrow {
    color: #4a9eff; font-size: 26px; font-weight: 700;
    letter-spacing: 6px; margin-bottom: 28px;
  }
  .eyebrow span { color: #8b949e; font-weight: 500; letter-spacing: 2px; }
  h1 { font-size: 76px; line-height: 1.08; font-weight: 800; margin-bottom: 30px; }
  .rule { width: 320px; height: 5px; background: #4a9eff; margin-bottom: 34px; }
  .sub { font-size: 31px; line-height: 1.45; color: #b6c2cf; margin-bottom: 46px; }
  .facts { display: flex; flex-direction: column; gap: 26px; margin-bottom: 48px; }
  .fact { display: flex; gap: 20px; align-items: flex-start; }
  .fact .mark {
    color: #4a9eff; font-size: 30px; font-weight: 800; line-height: 1.4;
  }
  .fact .body { font-size: 29px; line-height: 1.4; color: #e6edf3; }
  .fact .body b { color: #ffffff; }
  .term {
    background: #161b22; border: 1px solid #30363d; border-radius: 12px;
    padding: 28px 32px; font-family: "SF Mono", Menlo, monospace;
    font-size: 28px; line-height: 1.7; margin-bottom: auto;
  }
  .term .p { color: #3fb950; }
  .term .c { color: #8b949e; }
  .foot {
    border-top: 1px solid #30363d; padding-top: 24px;
    display: flex; flex-direction: column; gap: 10px;
    font-size: 23px; color: #8b949e;
  }
  .foot b { color: #b6c2cf; font-weight: 600; }
</style></head><body>
  <div class="eyebrow">EPHEMORA CELL &nbsp;<span>· v1.0.4 on PyPI</span></div>
  <h1>The stateless<br>MCP hub —<br>one pip install<br>away.</h1>
  <div class="rule"></div>
  <div class="sub">
    No handshake. No session. Every request stands alone —
    verified against the published wheel, not the docs.
  </div>
  <div class="facts">
    <div class="fact"><div class="mark">&#10003;</div>
      <div class="body"><b>MCP 2026-07-28 stateless era</b> — restart or
      load-balance between calls, agents never notice</div></div>
    <div class="fact"><div class="mark">&#10003;</div>
      <div class="body"><b>Fresh sandbox per call</b> — fuel-metered,
      no network, deterministic across machines</div></div>
    <div class="fact"><div class="mark">&#10003;</div>
      <div class="body"><b>Policy = witness, tested</b> — get-policy
      reports exactly what execution grants; CI fails on drift</div></div>
  </div>
  <div class="term">
    <span class="c">$</span> <span class="p">pip install</span> ephemora-cell<br>
    <span class="c">$</span> ephemora-cell-mcp
  </div>
  <div class="foot">
    <div><b>13/13</b> acceptance checks · deterministic fuel across machines</div>
    <div>github.com/MichaelS1011/ephemora-cell</div>
  </div>
</body></html>"""


def main() -> None:
    html, png = OUT / "release-card-1.0.4.html", OUT / "release-card-1.0.4.png"
    html.write_text(HTML)
    subprocess.run(
        [str(CHROME), "--no-sandbox", "--disable-gpu", "--hide-scrollbars",
         f"--window-size={W},{H}", f"--screenshot={png}", f"file://{html}"],
        check=True, capture_output=True,
    )
    w, h = struct.unpack(">II", png.read_bytes()[16:24])
    assert (w, h) == (W, H), f"wrong size {w}x{h}"
    print(f"{png} ({png.stat().st_size} bytes)")


if __name__ == "__main__":
    main()
