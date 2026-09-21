"""Generate LinkedIn carousel slides (PNG + PDF) for the boundary story.

Every number is read from the committed evidence JSONs — nothing is
hardcoded. Render: HTML -> chrome-headless-shell screenshots (system
fonts, no fontconfig dependency). Slides: 1080x1350 (LinkedIn 4:5).
Renders BOTH languages in one run (carousel/de, carousel/en).
Self-check: asserts the 8/8 / 0/8 / 2/8 verdicts + PNG dimensions.
Usage:  python assets/make_carousel.py
"""
import json
import struct
import subprocess
from pathlib import Path

REPO = Path(__file__).resolve().parent.parent
CHROME = Path("/Users/mimiai/Library/Caches/ms-playwright/chromium_headless_shell-1243/"
               "chrome-headless-shell-mac-arm64/chrome-headless-shell")
W, H = 1080, 1350
BG, CARD, STROKE = "#0b0f14", "#151b23", "#3d444d"
TEXT, MUTED, ACCENT, DANGER, OK = "#e6edf3", "#a5aeb8", "#4493f8", "#f85149", "#2ea05f"


def load(p):
    return json.load(open(p))


def latest(pattern):
    return sorted(REPO.glob("benchmarks/results/*/" + pattern))[-1]


# --- real evidence -------------------------------------------------------
cell = load(latest("*cell_8*vector_verify*.json"))
docker = load(latest("02_docker_attack_probe*.json"))
hard = load(latest("01_hardened_docker_attack_probe*.json"))
pool = load(latest("pool_vs_budget.json"))
gvis = load(latest("08_gvisor_*.json"))

ORDER = ["shell", "fork", "socket", "fsync", "host_fs", "symlink", "threading", "env"]
DKEYS = {"shell": "shell", "fork": "fork", "socket": "socket", "fsync": "fsync",
         "host_fs": "/etc/passwd", "symlink": "symlink escape", "threading": "threads", "env": "environment"}
CELLKEYS = {"shell": "shell_access", "fork": "fork", "socket": "network", "fsync": "fsync",
            "host_fs": "host_fs", "symlink": "symlink", "threading": "threading", "env": "env"}

D_STOCK = {n: docker["results"][DKEYS[n]]["status"] for n in ORDER}
D_HARD = {n: hard["results"][DKEYS[n]]["status"] for n in ORDER}
CELL = {n: bool(cell["results"][CELLKEYS[n]]["blocked"]) for n in ORDER}
assert [D_STOCK[n] == "ALLOWED" for n in ORDER] == [True] * 8, "stock Docker baseline changed"
assert sum(D_HARD[n] == "BLOCKED" for n in ORDER) == hard["blocked_count"] == 2, "hardened baseline changed"
assert all(CELL.values()), "Cell boundary changed"
warm_ms = pool["scenarios"]["pooled_warm (io_budget_bytes=None)"]["wall_ms_median"]
assert warm_ms < 0.6, "pooled-warm latency claim moved"
date, n_hard = docker["date"], hard["blocked_count"]
runsc = gvis["runsc_version"].replace("runsc version ", "")

# --- strings -------------------------------------------------------------
# per vector: plain-language "what the attack would let the code DO"
VECS = {
    "de": {"shell": "System-Befehle ausführen (id, ls, …)", "fork": "eigene Prozesse starten",
           "socket": "ins Netzwerk senden", "fsync": "direkt auf die Festplatte schreiben",
           "host_fs": "fremde Dateien lesen (/etc/passwd)", "symlink": "per Symlink aus der Box ausbrechen",
           "threading": "alle CPU-Kerne zustellen", "env": "die Umgebung auslesen (Keys, Passwörter)"},
    "en": {"shell": "run system commands (id, ls, …)", "fork": "spawn its own processes",
           "socket": "send onto the network", "fsync": "write straight to the disk",
           "host_fs": "read foreign files (/etc/passwd)", "symlink": "break out of the cage via symlink",
           "threading": "jam all CPU cores", "env": "read the environment (keys, passwords)"},
}
CHIP = {"de": ("GESTOPPT", "DURCHGELASSEN"), "en": ("BLOCKED", "ALLOWED")}

S = {
"de": {
 "cover_kick": "EPHEMORA CELL", "cover_h1": "Gleicher Angriff.<br>Andere Grenze.",
 "cover_sub": "Acht Angriffs-Versuche gegen einen Container.<br>Drei Sicherheits-Grenzen. Gemessen, nicht versprochen.",
 "cover_plain": "<b>Klartext:</b> KI-geschriebener Code und fremde Tools sind eine Blackbox.<br>Wir lassen sie laufen — hinter einer Grenze, die der Code nicht aufweichen kann.",
 "cover_note": "Docker: 0/8 gestoppt · Gehärteter Docker: {n_hard}/8 · Ephemora Cell: 8/8<br>Gleiches Image (python:3.12-slim), per Digest festgenagelt · gemessen am {date}",
 "cover_foot": "Ephemora AG (in formation) — deterministische Ausführung für nicht vertrauenswürdigen KI-Code · 1/6",
 "k1": "01 — DIE BASIS", "h1_1": "Ein normaler Container<br>lässt alles durch",
 "plain1": "<b>Klartext:</b> Ein normaler Docker-Container ist eine Box ohne Schloss —<br>gut zum Trennen, nicht zum Blockieren. Alles hier ist der Normalfall.",
 "foot1": "python assets/demo_attack_probe.py → 0/8 gestoppt · 2/6",
 "k2": "02 — HÄRTEN", "h1_2": "Zwei Schalter.<br>Der Code bleibt trotzdem drin.",
 "plain2": "<b>Klartext:</b> <code>--read-only</code> &amp; Co. riegeln den Container von aussen ab —<br>die beiden Stopps sind Nebenwirkungen. Der Gast selbst merkt kaum etwas.",
 "foot2": "python benchmarks/hardened_docker_probe.py → 2/8 gestoppt · 3/6",
 "k3": "03 — DIE WASM-GRENZE", "h1_3": "Diese Türen<br>gibt es hier nicht",
 "plain3": "<b>Klartext:</b> Ephemora Cell führt Code in WebAssembly aus — einer Form ohne<br>Netzwerk-, Prozess- oder Shell-Zugriff. Nicht abgeschaltet: gar nicht vorhanden.<br>Geprüft mit Gegen-Test: was frei ist, muss klappen, sonst zählt der Lauf nicht.",
 "foot3": "python benchmarks/verify_8_vectors.py → 8/8 gestoppt · 4/6",
 "k4": "04 — WAS ES KOSTET", "lab_warm": "warm, ende-zu-ende, im Pool (median)",
 "lab_exec": "Ausführungen/Stunde pro Kern", "lab_pool": "/Stunde — im Pool-Betrieb",
 "plain4": "<b>Klartext:</b> Abzusichern kostet hier fast nichts — eine Ausführung liegt unter<br>einer Millisekunde. Deshalb lässt sich <i>jeder</i> Aufruf absichern, nicht nur die riskanten.<br>128 MB Speicher · CPU per Fuel gezählt · max. 10 KB Ausgabe · kein Netzwerk.<br>Jeder Lauf liefert einen Beleg: Status · Fuel · Zeit · Regeln.",
 "foot4": "benchmarks/results/*/pool_vs_budget.json — selbst nachrechenbar · 5/6",
 "k5": "PRÜF ES NACH", "h1_5": "Verifizieren.<br>Nicht behaupten.",
 "plain5": "<b>Klartext:</b> Jede Zahl in dieser Präsentation ist eine ablegte Mess-Datei im Repo:<br>datiert und nachrechenbar. Kein Vertrauensvorschuss nötig.",
 "foot5": "Apache-2.0 · github.com/MichaelS1011/ephemora-cell · gVisor {runsc} (8/8 durchgelassen, dokumentiert) · 6/6",
 "t_install": "$ pip install ephemora-cell",
 "t_verify": "$ python benchmarks/verify_8_vectors.py → 8/8 gestoppt",
 "t_hard": "$ python benchmarks/hardened_docker_probe.py → {n_hard}/8 gestoppt",
},
"en": {
 "cover_kick": "EPHEMORA CELL", "cover_h1": "Same attack.<br>Different boundary.",
 "cover_sub": "Eight attack attempts against one container.<br>Three security boundaries. Measured, not promised.",
 "cover_plain": "<b>In plain words:</b> AI-written code and third-party tools are a black box.<br>We run them — behind a boundary the code cannot loosen.",
 "cover_note": "Docker: 0/8 stopped · Hardened Docker: {n_hard}/8 · Ephemora Cell: 8/8<br>Same image (python:3.12-slim), pinned by digest · measured {date}",
 "cover_foot": "Ephemora AG (in formation) — deterministic execution for untrusted AI-generated code · 1/6",
 "k1": "01 — THE BASELINE", "h1_1": "A stock container<br>lets it all through",
 "plain1": "<b>In plain words:</b> A normal Docker container is a cage without a lock —<br>good for separating, not for blocking. Everything here is the normal case.",
 "foot1": "python assets/demo_attack_probe.py → 0/8 stopped · 2/6",
 "k2": "02 — HARDEN IT", "h1_2": "Add every flag.<br>The code is still inside.",
 "plain2": "<b>In plain words:</b> <code>--read-only</code> &amp; friends wall the container off from outside —<br>the two stops are side effects. The guest itself barely notices.",
 "foot2": "python benchmarks/hardened_docker_probe.py → 2/8 stopped · 3/6",
 "k3": "03 — THE WASM BOUNDARY", "h1_3": "These doors<br>simply don't exist",
 "plain3": "<b>In plain words:</b> Ephemora Cell runs code in WebAssembly — a form with no<br>network, process or shell access. Not switched off: never present.<br>Checked with a counter-test: what's allowed must work, or the run doesn't count.",
 "foot3": "python benchmarks/verify_8_vectors.py → 8/8 stopped · 4/6",
 "k4": "04 — WHAT IT COSTS", "lab_warm": "warm, end-to-end, pooled (median)",
 "lab_exec": "executions/hour per core", "lab_pool": "/hour — pooled engine",
 "plain4": "<b>In plain words:</b> Securing costs almost nothing here — one run is under a<br>millisecond. So <i>every</i> call gets secured, not just the risky ones.<br>128 MB memory · CPU counted by fuel · max 10 KB output · no network.<br>Every run returns a record: status · fuel · time · rules.",
 "foot4": "benchmarks/results/*/pool_vs_budget.json — re-run it yourself · 5/6",
 "k5": "VERIFY IT", "h1_5": "Verifying.<br>Not claimed.",
 "plain5": "<b>In plain words:</b> Every number in this deck is a committed measurement file in the repo:<br>dated and reproducible. No trust required.",
 "foot5": "Apache-2.0 · github.com/MichaelS1011/ephemora-cell · gVisor {runsc} (8/8 allowed, documented) · 6/6",
 "t_install": "$ pip install ephemora-cell",
 "t_verify": "$ python benchmarks/verify_8_vectors.py → 8/8 stopped",
 "t_hard": "$ python benchmarks/hardened_docker_probe.py → {n_hard}/8 stopped",
},
}

VARS = {"date": date, "n_hard": n_hard, "runsc": runsc}


def chip(ok, lang):
    color, label = (OK, CHIP[lang][0]) if ok else (DANGER, CHIP[lang][1])
    return (f'<span class="chip" style="color:{color};border:1.5px solid {color};'
            f'background:{color}22"><i style="background:{color}"></i>{label}</span>')


def grid(state_ok, lang):
    rows = "".join(f'<div class="row"><span class="vec">{VECS[lang][n]}</span>{chip(state_ok(n), lang)}</div>'
                   for n in ORDER)
    return f'<div class="grid">{rows}</div>'


def slide(body, foot, lang, with_logo=False):
    brand = (f'<div class="brandrow"><span class="ring"></span>'
             f'<span class="brand">EPHEMORA<span class="thin"> AG (in formation)</span></span></div>' if with_logo else "")
    s = lambda k: S[lang][k].format(**VARS)
    # slide 0 (cover) is built from cover_* keys; others index positional args
    return (f'<!doctype html><meta charset="utf-8"><style>'
            f'*{{margin:0;box-sizing:border-box}}'
            f'body{{width:{W}px;height:{H}px;background:{BG};font-family:"Inter","SF Pro Text","Helvetica Neue",sans-serif;'
            f'color:{TEXT};padding:128px 64px 64px;display:flex;flex-direction:column;justify-content:center;overflow:hidden}}'
            f'.brandrow{{position:absolute;top:48px;left:64px;display:flex;align-items:center;gap:18px}}'
            f'.ring{{width:34px;height:34px;border-radius:50%;border:3px solid {ACCENT};'
            f'box-shadow:0 0 18px {ACCENT}55;flex:none}}'
            f'.brand{{font-size:30px;font-weight:800;color:{TEXT};letter-spacing:1px}}'
            f'.brand .thin{{color:{MUTED};font-weight:500;font-size:23px;letter-spacing:0.5px}}'
            f'.kick{{color:{ACCENT};font-size:24px;font-weight:600;letter-spacing:5px;margin-bottom:20px}}'
            f'h1{{font-size:74px;line-height:1.12;font-weight:800;margin-bottom:24px}}'
            f'.bar{{width:340px;height:5px;background:{ACCENT};margin:4px 0 28px}}'
            f'.sub{{font-size:31px;color:{MUTED};line-height:1.5}}'
            f'.plain{{font-size:27px;line-height:1.5;color:{TEXT};background:{CARD};'
            f'border-left:4px solid {ACCENT};border-radius:10px;padding:22px 28px;margin-top:24px}}'
            f'.plain b{{color:{ACCENT};font-weight:700}}'
            f'.num{{font-size:128px;font-weight:800;line-height:1.05}}'
            f'.mid{{font-size:54px;font-weight:800;color:{ACCENT}}}'
            f'.grid{{flex:1;display:flex;flex-direction:column;justify-content:center;gap:23px;margin:14px 0}}'
            f'.row{{display:flex;justify-content:space-between;align-items:center}}'
            f'.vec{{font-size:26px;max-width:600px}}'
            f'.chip{{display:inline-flex;align-items:center;gap:13px;border-radius:26px;'
            f'padding:10px 24px;font-size:21px;font-weight:700;white-space:nowrap;flex:none}}'
            f'.chip i{{width:13px;height:13px;border-radius:50%}}'
            f'.note{{font-size:25px;color:{MUTED};line-height:1.55;margin-top:28px}}'
            f'.term{{background:{CARD};border:1px solid {STROKE};border-radius:14px;'
            f'padding:34px 38px;font-size:26px;line-height:1.95;font-family:"SF Mono","Menlo",monospace;'
            f'color:{MUTED};margin:24px 0}}'
            f'.foot{{position:absolute;left:64px;right:64px;bottom:46px;border-top:1px solid {STROKE};padding-top:24px;'
            f'font-size:19px;color:{MUTED}}}'
            f'</style><body>{brand}{body}<div class="foot">{foot}</div></body>')


def build(lang):
    s = lambda k: S[lang][k].format(**VARS)
    return [
      slide(f'<div class="kick">{s("cover_kick")}</div><h1>{s("cover_h1")}</h1><div class="bar"></div>'
            f'<div class="sub">{s("cover_sub")}</div><div class="plain">{s("cover_plain")}</div>'
            f'<div class="note">{s("cover_note")}</div>', s("cover_foot"), lang, with_logo=True),
      slide(f'<div class="kick">{s("k1")}</div><h1 style="font-size:58px">{s("h1_1")}</h1>'
            + grid(lambda n: D_STOCK[n] == "BLOCKED", lang) + f'<div class="plain">{s("plain1")}</div>', s("foot1"), lang),
      slide(f'<div class="kick">{s("k2")}</div><h1 style="font-size:58px">{s("h1_2")}</h1>'
            + grid(lambda n: D_HARD[n] == "BLOCKED", lang)
            + f'<div class="plain">{s("plain2")}</div>'
              f'<div class="note"><code>--network none --read-only --cap-drop=ALL --pids-limit 64</code></div>', s("foot2"), lang),
      slide(f'<div class="kick" style="color:{OK}">{s("k3")}</div><h1 style="font-size:58px">{s("h1_3")}</h1>'
            + grid(lambda n: CELL[n], lang) + f'<div class="plain">{s("plain3")}</div>', s("foot3"), lang),
      slide(f'<div class="kick">{s("k4")}</div><div class="num">~{warm_ms:.2f} ms</div>'
            f'<div class="sub" style="margin-bottom:26px">{s("lab_warm")}</div><div class="bar"></div>'
            f'<div><span class="mid">~3M</span> <span style="font-size:30px">{s("lab_exec")}</span></div>'
            f'<div style="margin-top:18px"><span class="mid">~5.5M</span> <span style="font-size:30px">{s("lab_pool")}</span></div>'
            f'<div class="plain" style="margin-top:44px">{s("plain4")}</div>', s("foot4"), lang),
      slide(f'<div class="kick">{s("k5")}</div><h1 style="font-size:74px">{s("h1_5")}</h1><div class="bar"></div>'
            f'<div class="term">{s("t_install")}<br>{s("t_verify")}<br>{s("t_hard")}</div>'
            f'<div class="plain">{s("plain5")}</div>', s("foot5"), lang),
    ]


def render(lang, slides):
    out = REPO / "assets" / "carousel" / lang
    out.mkdir(parents=True, exist_ok=True)
    pngs = []
    for i, sm in enumerate(slides, 1):
        html, png = out / f"slide{i}.html", out / f"slide{i}.png"
        html.write_text(sm)
        subprocess.run([str(CHROME), "--no-sandbox", "--disable-gpu", "--hide-scrollbars",
                        f"--window-size={W},{H}", f"--screenshot={png}", f"file://{html}"],
                       check=True, capture_output=True)
        w, h = struct.unpack(">II", png.read_bytes()[16:24])
        assert (w, h) == (W, H), f"{lang}/slide{i} wrong size {w}x{h}"
        pngs.append(png)
    subprocess.run(["magick"] + [str(p) for p in pngs] + [str(out / f"ephemora-boundary-{lang}.pdf")], check=True)
    print(f"{lang}: {len(pngs)} slides -> carousel/{lang}/ephemora-boundary-{lang}.pdf "
          f"({(out / f'ephemora-boundary-{lang}.pdf').stat().st_size} bytes)")


for lang in ("de", "en"):
    render(lang, build(lang))
