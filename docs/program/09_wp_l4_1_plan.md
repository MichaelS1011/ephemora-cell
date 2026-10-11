# WP-L4-1 · Untrusted-Component Subprocess-Isolation — PLAN-Phase

**Lane:** L4 (Engine/Hardening) · **Status:** **CLOSED — VERIFIED WITH
DOCUMENTED LIMITATIONS (2026-10-11)** — CTO Final Evidence Gate bestanden
(siehe Abschnitt „Final Evidence Gate & Closure“ am Ende); zuvor: DO geliefert,
CHECK/ACT verifiziert
**Regel (Direktive §7):** Keine Produktions- oder Architekturänderung ohne
Freigabe. Dieses Dokument leitet die Lösung aus den nachgewiesenen Anforderungen
ab, nicht umgekehrt. Alle Fakten unten sind **gemessen oder im Code verifiziert**,
nicht aus Konfigurationswerten inferiert.

---

## 0. Nachweismatrix (verifizierte Fakten)

| # | Fakt | Quelle | Charakter |
|---|------|--------|-----------|
| V1 | Component-`fd_filestat_set_times(u64::MAX)`-Overflow → **in-process returncode −6 (SIGABRT), Host aborted**; derselbe Gast **im Worker → PARENT-SURVIVED, run=ERROR, worker_crashed** | `benchmarks/results/2026-09-29/datetime_overflow_ghsa_j2g9.json` (GHSA-j2g9) | gemessen |
| V2 | `run_isolated(FS02, abi="component")` führt Component **im Worker** aus: SUCCESS, FS-Grant-Write landet identisch auf dem Host, `effective_preopens` identisch zur In-Process-Ausführung, Baseline attestiert `abi=component / execution_mode=subprocess / sync_blockade_enforced=false` | `tmp_probe_dir/wpl41_cap.py` | gemessen |
| V3 | Worker-Start fehlgeschlagen (kaputtes `PYTHONHOME`) → `ERROR "worker crashed"`, stdout leer, **kein In-Process-Rückfall** | `tmp_probe_dir/wpl41_probe.py` P4 | gemessen |
| V4 | Component-Läufe melden `sandbox_dir=None` in **beiden** Modi → keine Host-Sidecar-Artefaktfläche für Components | `wpl41_probe.py` P1/P2 | gemessen |
| V5 | `run_worker` ruft `sandbox.cleanup()` im `finally` **vor** dem Report-Druck → Sandbox-Dir existiert nicht mehr, wenn der Parent medianieren wollte → Host-Sidecar-Egress ist **in-process-only** | `process_worker.py` L322-325 | Code |
| V6 | `CellToolEngine.execute()` hartcodiert `use_subprocess=False, abi="auto"` → **untrusted Component-Tools laufen im MCP-Host-Prozess** | `engine.py` L272-280 | Code |
| V7 | Auto-Dispatch: explizit `component` downgrade nie auf preview1; `auto` erkennt Component per Magic-Byte (`0x000d`) | `wasi_02.is_component_binary`, `_execute` L726-735 | Code |
| V8 | **Keine** Runtime-"untrusted"-Klassifizierung und **kein** Konfig-Knob, der Isolation erzwingt; `--isolated` (CLI) ist operator-opt-in für ALLGÄSTE, nicht klassenbasiert | grep `untrusted`/`trust` (nur Doku/Labels) | Code |
| V9 | Perf: In-Process-Component **12,3 ms** Median vs. Worker **68,4 ms** Median (~5,6×), dominiert von Child-Interpreter + wasmtime-Import | `wpl41_probe.py` P5 | gemessen |
| V10 | Crash-Containment, Größen-Cap (Parent **und** Worker), `io_cpu`-Watchdog, `RLIMIT_FSIZE`-Quota, Epoch-Timeout leben bereits im Worker | `test_process_executor.py`, `process_worker.py` | gemessen/Code |

**Kernunterscheidung (Direktive §2, ausdrücklich):**
- **Runtime-Isolation** (fuel/epoch/mem-Limits, Sandbox-Dirs, Preopen-Kanonik) —
  gilt in BEIDEN Modi, auch im Worker.
- **Prozesisolation** (OS-Walls: RLIMITs, Hard-Kill, Crash-Containment,
  Disk-Quota, CPU-Watchdog) — **nur** im Worker-Pfad.
- **Darübergehende OS-Garantien** (seccomp/pledge/ namespaces) — **existieren
  nicht**; WP-L4-1 liefert Prozessisolation, kein Full-OS-Sandboxing.

---

## Deliverable 1 — Customer Outcome & Internal FAQ

**Frage:** Was braucht ein Nutzer, der unbekannten Component-Code ausführt?

- **Garantie, ein feindlicher Gast bringt meinen Host-Prozess nicht zu Fall.**
  Real & gemessen (V1): Ein einziger präparierter `set_times`-Call panics die
  wasmtime-Rust-Host-Codezeile → SIGABRT. In-process **stirbt der Host**. Das ist
  kein Gedenkmodell, sondern eine reproduzierte Evidenz (GHSA-j2g9).
- **Vorhersagbarkeit, ohne dass ich den Byte-Code lesen muss.** Isolation muss an
  der *Ausführungsklasse* hängen (untrusted Component), nicht daran, ob der
  Betreiber zufällig `--isolated` gesetzt hat.
- **Ehrliche Quittung.** Der signierte Record muss sagen: welcher ABI, welcher
  Ausführungsmodus, welche Blockaden *wirklich* galten (WP-L4-3-Semantik bleibt).

**Internal FAQ:**
- *Ist Prozessisolation eine Sandbox wie gVisor/Firecracker?* **Nein.** Sie enthält
  Host-Abort/Compile-Bomb/Crash in einem wegwerfbaren Kind und erzwingt RLIMITs —
  aber kein Kernel-Sandboxing. Dokumentation muss das trennen.
- *Behebt Isolation die fehlende Component-Sync-Blockade (R-07)?* **Nein.**
  Direktive §3E warnt ausdrücklich davor. Der Component-Pfad behält
  `sync_blockade_enforced=false`; Isolation ist eine *andere* Garantie (Prozess-
  grenze), nicht eine *bessere* Sync-Kontrolle.
- *Warum nicht einfach alles in den Worker?* ~5,6× Latenz (V9) und stiller
  Verhaltenswechsel für legitime, vertrauenswürdige Workloads → widerspricht §4.

---

## Deliverable 2 — Current-State Analysis

**Vorhandene, wirksame Grenzen:**
- Worker-Pfad (`run_isolated`/`process_worker`) **kann bereits Components
  ausführen** (`abi=component/auto` → `ComponentSandbox`) und enthält die GHSA-j2g9-
  Klasse messbar (V1/V2). Capability-Oberfläche (Preopens) bleibt identisch (V2).
- Fail-closed bei Worker-Start fehlt nicht: kein automatischer Rückfall (V3).
- Ressourcen-/Crash-/Timeout-/Quota- Durchsetzung + Attestierung (`execution_mode`,
  `abi`, `sync_blockade_enforced`) sind im Worker vorhanden (V10, WP-L4-2/3).

**Wo die Grenze fehlt:**
- **Kein Mechanismus wählt Isolation anhand der Vertrauensklasse.** CLI `--isolated`
  ist Global-Opt-in des Betreibers; die Engine entscheidet nicht "untrusted
  Component ⇒ Worker". (V8)
- **MCP führt Components standardmäßig im Host-Prozess aus** (`use_subprocess=False`
  hartcodiert, V6) — exakt der Pfad, den V1 als Host-killend nachweist.
- Isolation ist damit *möglich*, aber nicht *verpflichtend durchsetzbar* — der
  Kern von WP-L4-1.

---

## Deliverable 3 — Threat Model

**Begrenzte Angriffswege (durch Pflicht-Prozessisolation):**
- T1 Host-Abort via wasmtime-Panic (GHSA-j2g9 datetime-Overflow, V1) — **gemessen
 Containment**.
- T2 Compile-Bomb / Engine-Panic, die den Host-Adressraum sprengen würde — Kind
  stirbt, Parent überlebt (V10).
- T3 FD-Draining / Ressourcen-Erschöpfung — `RLIMIT_NOFILE`, CPU-Watchdog, Hard-Kill
  greifen nur prozessbasiert.
- T4 Disk-Füllung über Preopens — `RLIMIT_FSIZE`-Quota nur im Worker.

**Verbleibende Risiken (ehrlich, nicht durch Isolation geschlossen):**
- R-a Keine Component-Sync-Blockade (R-07 bleibt, separat attestiert `false`).
- R-b Kein Kernel-/Syscall-Sandboxing — ein Host-Call *vor* dem Panic (z. B.
  legitimer Write in ein gewährtes Dir) erreicht den Host bewusst (Capability, kein
  Bug). Isolation begrenzt *Prozess-Tod*, nicht *erteilte Rechte*.
- R-c Sidecar-Egress über Prozessgrenze ist nicht gelebter Pfad (V4/V5): Components
  haben keine Sandbox-Dir-Fläche; Worker räumt vor Parent-Lesezugriff auf. →
  Capability-Integritäts-Frage §3C, in Architektur zu adressieren (nicht stumm
  "funktioniert").

---

## Deliverable 4 — Proposed Architecture (Alternativen, Empfehlung)

**Anforderung:** *messbare, erzwingbare, ehrlich attestierte* Isolation für
untrusted Components; kein stummer Rückfall; legitime Workloads nicht unnötig
beschädigen; vorhandene, nachgewiesene Mechanismen wiederverwenden.

- **Option A — Enforcement-Gate am Choke-Point (empfohlen).**
  Neues, *additives* Opt-in wie `require_isolation` (Parameter und/oder
  Klassen-Posture) analog dem bewährten `require_sync_blockade`-Gate (WP-L4-3):
  Ist Isolation gefordert, **muss** der Lauf über `run_isolated` laufen; ist der
  Worker nicht verfügbar (Non-POSIX/Spawn-Fehler), **kontrollierte Ablehnung vor
  Ausführung** — nie In-Process-Fallback (V3 bestätigt die Richtung). Wiederverwendet
  den bestehenden, für Components bewiesenen Worker (V2). Geringste neue
  Komplexität, keine neue Abhängigkeit. Attestierung bleibt beim Worker-Source-Stamp.
- **Option B — Klassen-Trust-Layer atop A.** Dunst "untrusted ⇒ erzunge Isolation"
  als deklarative Host-Posture (ToolSpec/config-Feld) ein. *Kein* Maliz-Erkennung
  aus Bytes (unzuverlässig → falsche Garantie); es ist eine **vom Betreiber
  gesetzte** Sicherheitsstufe. Schließt die MCP-Lücke (V6) gezielt.
- **Option C — MCP-Default-Flip auf Worker.** `execute()` isoliert Components
  standardmäßig. Größter Kompatibilitäts-/Perf-Schaden (~5,6× auf JEDES
  Component-Tool, V9) und stillerDeployement-Wechsel → **abgelehnt** (widerspricht
  §4 "kein unnötiger Schaden", §7 "keine neue Komplexität ohne Begründung").

**Empfehlung:** **A als Durchsetzungs-Primitive**, dünn surfaced als **B** für MCP
(opt-in Posture pro Tool/Betrieb, kein Default-Flip), **C out-of-scope**. Sidecar-
Egress-Frage (R-c) wird als bewusste Grenze dokumentiert, nicht als "unter
Isolation verfügbar" deklariert.

---

## Deliverable 5 — Risk & Compatibility Assessment

| Fläche | Bewertung |
|--------|-----------|
| `componentize-py` / große Components | Kein Zwang für *bestehende* Läufe (Opt-in). Bei Pflicht-Lauf: Worker importiert wasmtime bereits heute für Components (V2) → funktional kompatibel; **+~56 ms Overhead** pro Lauf (V9), zu dokumentieren (§5.10). |
| Filesystem-Grants | Capability-Identität gemessen (V2): Preopens gleich, Write gleich. Kein Upgrade/Downgrade der Rechte durch Moduswechsel. |
| Sidecar-Egress | Under Isolation **nicht** gelebt (V4/V5). Darf nicht als "isoliert verfügbar" attestiert werden; Preview1-Egress bleibt In-Process-Opt-in, unverändert. |
| Existing Reports / Signaturen | Gate ist opt-in; ohne Anforderung byte-identische Records (WP-L4-2/3-Muster). Kein Rückwirk-Interpretationswechsel. |
| Auto-ABI-Dispatch | Explizit `component` downgraded nie (V7); Gate entscheidet *Prozessgrenze*, nicht *ABI*. Kein stilles Downgrade. |
| Preview1-Workloads | Unberührt, sofern nicht selbst als untrusted deklariert. |
| Security | Strengt Host-Containment für die gemessene T1-Klasse (V1) — echter Zugewinn, keine Garantie-Umschreibung von R-07. |

---

## Deliverable 6 — Verification Plan (Verhalten, nicht Konfig)

Positive **und** negative Tests, die echtes Verhalten beobachten:

1. Untrusted Component startet im Worker → **PID des Gastes ≠ Host-PID**
   (nachweisbar, nicht nur `execution_mode`-Flag).
2. Isolation gefordert, aber nicht verfügbar (erzwungener Spawn-Fehler) →
   **Ablehnung VOR Gast-Ausführung**, kein In-Process-Run (V3-Form).
3. Worker-Abort (GHSA-j2g9-Gast) → **Host überlebt**, run=ERROR (V1 als Test).
4. Timeout/Ressourcen-Überschreitung im Worker → korrekte Status-Mapping
   (TIMEOUT/FUEL/MEMORY), Parent nicht blockiert.
5. Capability-Integrität: `effective_preopens` + Grant-Write **identisch**
   in-process vs. Worker (V2).
6. Cleanup: temporäre Ressourcen weg nach Worker-Ende (V5-Residuum messen).
7. Record attestiert `abi` + `execution_mode` korrekt für beide Modi (V2).
8. Legacy-Signaturen/Records kompatibel (Gate aus → byte-identisch).
9. Kein Downgrade: Auto-Dispatch + Fehlerpfade erzwingen nie In-Process für
   untrusted Component.
10. Perf-Delta reproduzierbar dokumentiert (V9, eigene Mess-Legge).

---

## Deliverable 7 — Prioritized Implementation Backlog (noch NICHT umgesetzt)

> Reihenfolge fachlicher Abhängigkeit. Alle Karten sind PLAN; DO erst nach
> CTO-Freigabe dieses Dokuments.

1. **WP-L4-1a · Enforcement-Gate (A)** — `require_isolation`-Gate am
   `WASISandbox.run`-Choke-Point, analog `require_sync_blockade`. Verweigert
   vor Ausführung, wenn Isolation gefordert und nicht verfügbar; erzwingt
   `run_isolated` sonst. *DoD:* Tests 1,2,9; kein Default-Flip; bestehende
   Läufe byte-identisch.
2. **WP-L4-1b · MCP-Klassen-Posture (B)** — deklarativer Pfad
   (`ToolSpec`/engine-Posture) "untrusted ⇒ Isolation", der die V6-Lücke
   schließt, ohne C (Default-Flip). *Abhängig von 1a.* *DoD:* Tests 1,5,7;
   Opt-in pro Tool/Betrieb; Doku der Prozessgrenzen-Garantie.
3. **WP-L4-1c · Egress-Grenz-Doku** — Sidecar-Inkompatibilität unter Isolation
   (V4/V5) als bewusste, dokumentierte Grenze; **keine** Behauptung, Egress sei
   isoliert verfügbar. *DoD:* Test 6 + Doku-Assert.
4. **WP-L4-1d · Perf-Evidenz** — reproduzierbare Mess-Legge für Modus-Delta
   (V9) in Benchmarks/Doku. *DoD:* Test 10.
5. **Doku (SECURITY/README/ADR-015)** — Klassengarantie,Runtime vs. Prozess vs.
   OS-Garantien getrennt; R-07 bleibt separat `false`-attestiert. *DoD:*
   keine Verwechslung von Prozessisolation mit Sync-Blockade.

**Nicht enthalten (bewusst):** OS-Sandboxing (seccomp/nsjail) — wäre neue
Abhängigkeit ohne nachgewiesene Notwendigkeit für die gemessene T1-Klasse; Component-
Sync-Trap (R-07) — laut Direktive nicht via Isolation vorzutäuschen.

---

## Abschluss PLAN

Kein Produktiv-Code geändert (nur `docs/`, `tmp_probe_dir/`). Machbarkeitsproben
V1–V10 gemessen/im Code verifiziert. **Empfehlung zur Freigabe: Option A (Primitive)
+ dünne B-Schicht für MCP, C abgelehnt.** DO-Phase wartet auf CTO-Review.

---

## DO Execution Ergebnis (2026-10-11)

CTO-Freigabe: **Option A + B**, C abgelehnt. Umsetzung in kleinen, überprüfbaren
Schritten (Direktive §4). Kein Produktiv-Default-Flip für Preview1.

### Umsetzung

- **Wahrheitstabelle (Single Source)** — `execution_report.py`:
  `TRUST_TRUSTED/UNTRUSTED/UNKNOWN` + `VALID_TRUST` +
  `isolation_required_for(trust, abi) = (abi==component and trust!=trusted)`.
  Gate UND Record-Layer lesen dieselbe Prädikate → kein Drift. `unknown ≡
  untrusted` (fail-closed); Preview1 nie Mandat-Klasse (V1).
- **Option A — Central Enforcement Gate** (`wasi_runtime.py`):
  `run()`-Param `trust: str = TRUST_UNKNOWN`; Gate `_isolation_gate()` greift
  NACH `require_sync_blockade`-Check, VOR Tenant/dispatch und VOR
  Gast-Ausführung; löst `abi` über `_resolve_executed_abi` auf (kein
  `abi=auto`-Bypass). Hebt `use_subprocess` nur auf `True`, nie herunter.
  `_isolation_available()` prüft Worker-Import; fehlt er ⇒ **Refusal (ERROR)**,
  kein In-Process-Fallback. `run_wasm()` reicht `trust` durch.
- **Option B — MCP Trust Posture** (`engine.py`): `CellToolEngine(trusted_tools=…)`
  host-kontrollierte Allowlist; `execute()` berechnet `trust` allein daraus
  (Gast-Bytes/-Sidecar erhöhen nie Trust). Egress + Isolations-Mandat ⇒
  `_refuse_if_egress_conflicts_with_isolation()` lehnt **explizit** ab
  (§2: kein stiller Capability-Verlust, kein Downgrade).

### Verifikation

- **Neue Verhaltens-Tests** `tests/test_isolation_gate.py` (15, positiv/negativ/
  adversarial): unknown/untrusted⇒subprocess, trusted⇒in_process, Preview1⇒
  in_process, `abi=auto`-Bypass⇒subprocess, Worker nicht verfügbar⇒Refusal
  (keine Datei geschrieben), Worker-Crash⇒ERROR ohne Fallback, invalid
  trust⇒ValueError; Evidence-Integrität (isoliert⇒abi=component,
  sync_blockade_enforced=false, execution_mode=subprocess); MCP-Posture
  (unlisted⇒isolated, trusted⇒in_process, Preview1 unberührt, component+egress
  ⇒Refusal, ToolSpec hat kein trust-Feld).
- **Volle Regression:** `pytest tests/` → **1002 passed, 4 skipped, 0 failed**.
  Einzige Drift-Stelle: Billing-Dispatch-Invariante in
  `test_tenant_budgets.py` erwartet Flag-Passthrough; auf `trust=trusted`
  neutralisiert (Isolation ist dort nicht der Prüfgegenstand, eigen getestet).
- **Perf reproduzierbar** (`benchmarks/isolation_overhead_probe.py`, reps=15,
  über Facade `WASISandbox.run()`): Component hello02 13,89 ms (in-proc) →
  79,59 ms (Worker) = **+65,7 ms / 5,73×**; fs02 19,90 → 86,29 ms =
  **+66,39 ms / 4,34×**. Bestätigt V9-Größenordnung; `execution_mode`/ABI
  korrekt attestiert.

### Grenzen (ehrlich gehalten)

- Prozessisolation ≠ OS-Sandboxing (kein seccomp/pledge behauptet).
- `component → sync_blockade_enforced=false` bleibt (Isolation fixt R-07 nicht).
- Sidecar-Egress über Isolation = separates WP; bis dahin expliziter Refusal.
- **No false guarantees. No silent fallback.**

### Doku-Nachweis

ADR-015 (Gate + Trust-Posture); SECURITY.md „Isolation is enforced, not just
offered“; `docs/security_posture.md` Component-Abschnitt; Risk Register R-03 →
mitigiert (Gate gelandet), R-14 neu (Egress über Isolation, akzeptiert/getrennt);
Backlog WP-L4-1 → geliefert.

---

## CHECK · CTO-Verifikation (2026-10-11, §2 & §3)

CTO hat DO bedingt abgenommen und die finale CHECK/ACT-Verifikation gefordert.
Kein neues Feature — Nachweis, dass die Mandate an den Integrationsgrenzen
halten. Ergebnis: **alle Invarianten erfüllt**, 20 adversariale Boundary-Tests
in `tests/test_wp_l4_1_verification.py` grün, volle Suite **1022 passed,
4 skipped**.

| CTO-Fall | Nachweis | Befund |
|---|---|---|
| §3A Trust Boundary | Params/ToolSpec/Manifest tragen keinen Trust-Kanal; `trusted_tools` nur Host-Konstruktor; Modul-Swap unter `trusted` ⇒ `expected_sha256`-MISMATCH ⇒ fail-closed | **Nein, kein Eskalationsweg** |
| §3B Direct Paths | Gate deckt `run`/`run_wasm`/`run_isolated`/MCP `execute`; `ComponentSandbox` als Nicht-Garantie-Primitive dokumentiert; `abi=preview1` auf Component-Datei linkt nicht (kein In-Process-Component) | **Getrennt & dokumentiert** |
| §3C Tenant Accounting | erzwungener Worker bucht admit+settle **exakt einmal** auf reale Fuel; Worker-Crash ⇒ `unknown`-flag (wall, nie free); Isolations-Refusal ⇒ **keine** Buchung, kein orphan inflight | **Korrekt, keine Doppel-/Nullabrechnung** |
| §3D Evidence Integrity | Record nennt realen `abi`+`execution_mode`+`sync_blockade_enforced`; `trusted`⇒in_process vs. unknown⇒subprocess unterscheidbar/auditierbar; keine Sync-Blockade vorgetäuscht | **Konsistent** |
| §3E Unsupported Caps | Egress+Isolations-Mandat (Policy **und** Grant) ⇒ Refusal **vor** `WASISandbox.run` (Spy: Gast nie erreicht) | **Kein stiller Downgrade** |
| §2 Trusted-Bedingungen | Autorität host-originiert; an Modul-Bytes gebunden; ausnahmefähig auditiert via `execution_mode`; `unknown/untrusted` bleiben pflichtig | **Erfüllt** |
| 4 skipped Tests | alle `test_builder.py` (WASI_SDK/asc/go/zig) — Toolchain-Verfügbarkeit, **kein Bezug** zur Isolations-/Trust-Grenze | **Nicht relevant** |

**Restriktionen (unverändert, §5):** Prozessisolation ≠ OS-Sandboxing;
Component-Sync-Blockade nicht erzwungen; Sidecar-Egress über Isolation =
separates WP; `trusted`-In-Process verzichtet bewusst auf die Prozessgrenze
(auditiert); `trusted_tools`-Bestückung = Operator-Kanal (Default strikt leer).

**Empfehlung Schließung:** WP-L4-1 kann **formal geschlossen** werden — die
Architektur A+B ist implementiert, verifiziert und dokumentiert. Tor B
(Release) bleibt **NO-GO**; dies ist ein Hardening-Zuschluss, keine
Production-Readiness-/Security-Zertifizierung.

---

## Final Evidence Gate & Closure (2026-10-11)

CTO-Direktive „Final Evidence Gate & Formal Closure“ umgesetzt:

- **Reproduzierbare Evidenz (§1):** Branch `wp-l4-1-central-enforcement-gate`
  mit nachvollziehbaren Commits (Fundament WP-L4-2/3 → Gate → MCP-Posture →
  Tests → Bench → Doku → Count-Sync → Schließung); PR
  [#22](https://github.com/MichaelS1011/ephemora-cell/pull/22) mit Architektur-
  entscheidung (ADR-015), Security-Invarianten und Testnachweisen; vollständige
  CI auf dem exakten Head-Commit `bbf2f6b`: lokal **1022 passed / 4 skipped /
  0 failed** im sauberen Worktree des Commits, GitHub Actions **17/17 Checks
  green** (8er OS×Python-Matrix, coverage≥80, security/pip-audit/bandit,
  mcp-sdk-interop, build-recipes, benchmark-guard, action-smoke, release-gate);
  black + ruff + mypy clean, test-count-guard (strict) OK, Integrations-
  laufen (Hermes/NemoClaw) und benchmark-guard grün. Die 4 skipped sind
  ausschließlich `test_builder.py`-Toolchain-Checks (WASI_SDK/asc/go/zig),
  ohne Bezug zur Isolations-/Trust-Grenze. Ungeprüfte Änderungen
  (`.gitignore`, interne BERICHT-/VORSCHLAG-Dateien) bleiben bewusst außerhalb
  des Abnahmeasts.
- **Final Security Confirmation (§2):** Trust-Autorität ausschließlich
  host-seitig (`trusted_tools`, Default leer; kein Params-/Manifest-/ToolSpec-
  Kanal) ✓ · Modul-Identität via `expected_sha256`, Hash-Abweichung fail-closed ✓
  · `ComponentSandbox`-Low-Level-Zugriff ausdrücklich außerhalb der
  Gate-Garantie, für Integratoren in SECURITY.md + Docstring gekennzeichnet ✓ ·
  signierter `execution_mode` belegt die Ausführungsart, ist aber **kein**
  eigenständiger kryptografischer Nachweis der Trusted-Autorisierung
  (Autorisierung lebt in der Host-Konfiguration, nicht im Receipt) ✓ ·
  Sidecar-Egress-Kollisionen mit dem Isolationsmandat bleiben kontrollierte
  Ablehnung ✓.
- **Closure-Kriterien (§3):** A–E-Invarianten unverändert erfüllt; volle
  Regression grün; Evidence-Semantik dokumentiert; Restrisiken bleiben
  sichtbar (R-03 Restriktionen, R-14 Egress-WP, Wasmtime-Advisories,
  kein OS-Sandboxing) und werden durch diese Schließung **nicht** als behoben
  dargestellt.
- **Release Governance (§4):** Tor B bleibt NO-GO. WP-L4-1-Abschluss ist keine
  Freigabe für untrusted Production-Workloads.

**WP-L4-1: CLOSED — VERIFIED WITH DOCUMENTED LIMITATIONS.**
