"""Social preview image (1280x640) — GitHub 'Social media preview'.

GitHub has no API for the social preview upload; this script regenerates
the asset deterministically, a human uploads it in repo Settings ->
General -> Social media preview. Same visual language (and headless-Chrome
render path) as assets/make_release_card.py: GitHub Primer dark, blue
accent. Designed for HALF SIZE legibility (link cards render ~600x300).

No volatile numbers on purpose: test counts, coverage and latencies were the
old centre of gravity and each of them moved within a release cycle, which
made the published image stale by definition. What is shown instead is the
positioning line, the five-beat lifecycle, and two terminal lines that are
verbatim output of the commands printed next to them (see assets/demo.gif for
the same captures in context).

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
    margin-bottom: 30px;
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
  .cols { display: flex; gap: 46px; flex: 1; min-height: 0; align-items: center; }
  .left { flex: 0.88; display: flex; flex-direction: column; }
  h1 { font-size: 76px; line-height: 1.04; font-weight: 800; letter-spacing: -1px; }
  h1 .dim { color: #4a9eff; }
  .rule { width: 200px; height: 5px; background: #4a9eff; margin: 20px 0 18px; }
  .sub { font-size: 23px; line-height: 1.42; color: #b6c2cf; }
  .flow {
    display: flex; flex-wrap: nowrap; gap: 10px; align-items: center;
    justify-content: center; margin: 4px 0 0; font-size: 20px; font-weight: 700;
  }
  .flow span {
    border: 1px solid #30363d; border-radius: 999px; padding: 7px 16px;
    background: #161b22; color: #e6edf3;
  }
  .flow i { font-style: normal; color: #4a9eff; font-size: 22px; }
  .right { flex: 1; display: flex; flex-direction: column; justify-content: center;
           gap: 26px; }
  .term {
    background: #161b22; border: 1px solid #30363d; border-radius: 12px;
    padding: 22px 24px; font-family: "SF Mono", Menlo, monospace;
    font-size: 21px; line-height: 1.6; white-space: nowrap;
  }
  .term .p { color: #3fb950; }
  .term .c { color: #8b949e; }
  .term .o { color: #e6edf3; }
  .term .r { color: #f85149; }
  .term .g { color: #3fb950; }
  .cta {
    background: #12261a; border: 2px solid #238636; border-radius: 12px;
    padding: 20px 24px; font-family: "SF Mono", Menlo, monospace;
    font-size: 27px; font-weight: 700; color: #ffffff;
    display: flex; align-items: center; gap: 14px; white-space: nowrap;
  }
  .cta .p { color: #3fb950; }
  .foot {
    border-top: 1px solid #30363d; margin-top: 26px; padding-top: 16px;
    display: flex; justify-content: space-between; align-items: baseline;
    font-size: 20px; color: #7d8590;
  }
  .foot .url { color: #4a9eff; font-weight: 700; font-size: 22px; }
</style></head><body>
  <div class="topbar">
    <div class="eyebrow">EXECUTION BOUNDARY</div>
    <div class="pill"><i>source-available</i><b>BUSL-1.1</b></div>
  </div>
  <div class="cols">
    <div class="left">
      <h1>Ephemora<span class="dim">-cell</span></h1>
      <div class="rule"></div>
      <div class="sub">Ephemeral, stateless, capability-bound execution<br>
        for untrusted AI and agent-generated code.</div>
    </div>
    <div class="right">
      <div class="term">
        <span class="c">$</span> <span class="o">ephemora-cell run examples/fuel_bomb.wasm</span><br>
        <span class="r">&nbsp;&nbsp;"status": "fuel_exhausted",</span><br>
        <span class="o">&nbsp;&nbsp;"fuel_utilization": 1.0,</span><br>
        <span class="c">$</span> <span class="o">python examples/signed_record_demo.py</span><br>
        <span class="g">verify(intact): True</span><br>
        <span class="r">verify(tampered): False</span>
      </div>
      <div class="cta"><span class="p">$</span> pip install ephemora-cell</div>
    </div>
  </div>
  <div class="flow">
    <span>create</span><i>&rarr;</i><span>constrain</span><i>&rarr;</i><span>execute</span><i>&rarr;</i><span>prove</span><i>&rarr;</i><span>destroy</span>
  </div>
  <div class="foot">
    <div class="url">github.com/MichaelS1011/ephemora-cell</div>
    <div>WASM/WASI &middot; MCP &middot; Signed execution evidence</div>
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
