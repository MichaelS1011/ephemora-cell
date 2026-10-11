# D5 — Prioritized Engineering Backlog

**Lane:** L10 (Backlog-Owner) + Fach-Leads · **Deliverable:** 5 von 8 · **Bezug:** D4
**Regel:** Priorität nach Befund, nicht nach Funktionskategorie (Direktive §7).
Jede WP-Karte ist PDCA-PLAN: Befund · Zielverhalten · Akzeptanz (DoD) · Nachweis.

---

## P0 — Critical Security

### WP-L3-1 · Engine-Upgrade-Gate M2 vorbereiten (L3)
- **Befund:** 47.0.1 in vier offenen Advisory-Ranges; Fix-Wheels 48.0.4/49.0.2
  existieren nicht auf PyPI (ein Wheel pro Major).
- **Zielverhalten:** Sobald ein Wheel erscheint, ist der Upgrade ein
  vorbereiteter, nicht improvisierter Schritt; Garantie lügt nie über die Version.
- **Abhängigkeit:** extern (PyPI). **Kein Code-Zwang jetzt.**
- **Akzeptanz (DoD):** `check_wasmtime_patch.py`-Watcher aktiv (✅ vorhanden) +
  dokumentierte Pre-Regression-Checkliste (8/8, CVE-Replay, Conformance,
  Fuel-Determinismus, fs-escape-Matrix) + Restrisiko im Register akzeptiert.
- **Nachweis:** `scripts/check_wasmtime_patch.py`, `test_watch_upstream.py`,
  M2-Checkliste in `docs/program/`.

### WP-L4-1 · Untrusted-Component ⇒ Subprocess-Pflicht durchsetzbar machen (L4)
- **Status: CLOSED — VERIFIED WITH DOCUMENTED LIMITATIONS (2026-10-11).**
  CTO Final Evidence Gate: dedizierter Branch + PR
  [#22](https://github.com/MichaelS1011/ephemora-cell/pull/22) mit
  commit-gebundener
  CI (1022 passed / 4 skipped / 0 failed; GitHub Actions 17/17 green auf
  `bbf2f6b`; black + ruff + mypy +
  test-count-guard strict), §2-Security-Grenzen abschließend dokumentiert
  (Trust-Autorität host-seitig · Modul-Bytes-Bindung fail-closed ·
  `ComponentSandbox`-Primitive ausdrücklich außerhalb der Gate-Garantie ·
  `execution_mode` kein kryptografischer Autorisierungs-Nachweis ·
  Egress-Mandat-Kollision kontrolliert abgelehnt). Keine funktionalen
  Änderungen nach Verifikation. Ursprünglich: **Status (DO · 2026-10-11):
  geliefert.** CTO-Freigabe Option **A + B**
  (C abgelehnt). **A — Central Enforcement Gate** am Choke-Point
  `WASISandbox.run()`: fehlende/unbekannte Trust-Klassifizierung ⇒ `unknown`
  (≡ untrusted, fail-closed); `abi=component` + nicht `trusted` hebt
  `use_subprocess` auf `True` — vor Gast-Ausführung, über alle Einstiege
  (CLI/MCP/`run_wasm`/`abi=auto`), kein In-Process-Rückfall bei Worker-Fehler
  (Refusal statt Fallback). **B — MCP Trust Posture**: `CellToolEngine`
  erhält host-kontrollierte `trusted_tools`-Allowlist; Gast-Bytes/-Sidecar
  können Trust nie selbst erhöhen. **Single-Source-Wahrheitstabelle**
  `isolation_required_for(trust, abi)` in `execution_report.py` (Gate UND
  Record, kein Drift). Sidecar-Egress über Isolation ⇒ **expliziter Refusal**
  statt stiller Capabilitäts-Verlust (Egress-Parität = separates WP, §2).
  Evidenz: `component → sync_blockade_enforced=false` unverändert (Isolation
  ≠ R-07-Fix; keine falsche Garantie).
- **Befund:** datetime-Overflow (GHSA-j2g9) tötete In-Process-Prozess auf dem
  0.2-Pfad; Fuel/Wall/Memory greifen am Host-Call nicht.
- **Zielverhalten:** Für untrusted/unknown Component-Gäste ist der isolierte
  Pfad der einzig garantierte; In-Process nur noch für ausdrücklich
  host-autorisierte (`trusted`) Workloads.
- **Abhängigkeit:** WP-L4-2 (Attestierung) ✅ geliefert.
- **Akzeptanz (✅ 2026-10-11, DO + CHECK):** `execution_mode`/ABI im Record
  korrekt (isoliert⇒subprocess); Gate-Verhaltensmatrix positiv/negativ/
  adversarial in `tests/test_isolation_gate.py` (15 Tests). CTO-Verifikation
  §3A–E in `tests/test_wp_l4_1_verification.py` (20 Boundary-/Escalations-
  nachweise: Trust-Boundary host-only + Modul-Hash-Bindung, Pfad-Trennung
  `ComponentSandbox`, Tenant-Abrechnung unter erzwungener Isolation, Evidence-
  Integrität, Egress-Refusal pre-run). Nachweis: `pytest tests/` →
  **1022 passed, 4 skipped** (die 4 Skips sind Toolchain-Tests in
  `test_builder.py`, irrelevant für diese Grenze; eine Billing-Dispatch-
  Invariante auf `trust=trusted` neutralisiert, kein Drift). Perf reproduzierbar
  gemessen: Component-Overhead +66 ms / 4,3–5,7×
  (`benchmarks/isolation_overhead_probe.py`). ADR-015 dokumentiert Gate +
  Trust-Posture inkl. Autoritäts-/Bindungs-/Pfad-Trennungs-Semantik; Risk
  Register R-03 → mitigiert + verifiziert, R-14 (Egress über Isolation) akzeptiert.

---

## P1 — Security & Reliability

### WP-L4-2 · `execution_mode` als verpflichtendes Attestier-Feld (L4 + L7 + L8)
- **Status (ACT · 2026-10-11): geliefert.** Attestier-Feld + fail-closed
  Validierung + Source-Stamp im Worker gelandet; Manipulations-Test rot-fähig.
  Nachweis: `pytest tests/` → **966 passed** (Evidence-/Signing-/Ledger-Suite
  296 passed). Nicht-Abschwächung: Stamp ist opt-in — ein bare Report bleibt
  byte-identisch zu früheren Releases (`canonical_bytes` unverändert ohne Modus).
  Rest: anwenderseitige Doku-Schärfe der Modus-Garantie → **gelandet**
  (Doku-Welle 2026-10-11: SECURITY.md „Effective enforcement attestation",
  README, ADR-014 — deckt `execution_mode` + `abi` + `sync_blockade_enforced`).
- **Befund (ursprünglich):** Feld im Code **nicht vorhanden** (grep 0 Treffer),
  obwohl D1/D2
  Modus-Attestierung als MCP-Strategie festlegen. Günstigster Glaubwürdigkeits-
  hebel, **kein externer Blocker**.
- **Zielverhalten:** Jeder Record erklärt `execution_mode ∈ {in_process,
  subprocess}` und ABI; Feld ist Teil der kanonischen, signierten Bytes.
- **Abhängigkeit:** keine (Start sofort möglich). **Empfohlene erste Ausführung.**
- **Akzeptanz:** Feld in `security_baseline`/Record; in `canonical_bytes`
  enthalten (Manipulation des Modus ändert Signatur); Verifier-Test; Doku
  spiegelet Modus-Garantie.
- **Nachweis:** neuer Assert in `test_execution_report.py`/`test_records_envelope.py`
  + Manipulations-Test (Modus-Flip → Signatur ungültig).

### WP-L4-3 · 0.2-Component-Sync-Blockade (L4)
- **Status (ACT · 2026-10-11): geliefert.** (a) Call-Trap **gemessen + verworfen**
  (wasmtime-py 47: Linker-Shadow auf `[method]descriptor.sync` wird akzeptiert,
  bleibt aber **stumm** — Gast-Sync erreicht Host; `component_sync_probe.py`
  Leg B `SYNC-ALL:OK` → falsche Garantie). Per **CTO-Direktive** B1 + explizite
  Enforcement-Semantik umgesetzt: signierte Felder `abi ∈ {preview1, component}`
  + `sync_blockade_enforced` (Wahrheitstabelle über Single-Source-Prädikat
  `sync_blockade_holds`), fail-closed (`absent ≠ true`), ABI-Stamp an der Quelle
  (Worker) + am `run()`-Choke-Point, Strict-Gate `require_sync_blockade=True`
  (kontrollierte Ablehnung **vor** Ausführung, kein stiller Downgrade).
  Nachweis: `pytest tests/` → **987 passed** (4 skipped, +21 R-07; keine
  Regression gegen 966), 90 % Cov. Nicht-Abschwächung: additive opt-in — ein
  Legacy-Record ohne `abi` bleibt byte-identisch (`canonical_bytes` unverändert).
  Akzeptierte Einschränkung (nicht vorgetäuscht): Component-Pfad hat weiterhin
  keine Sync-Blockade — jetzt ehrlich attestiert (ADR-014).
- **Befund:** `wasi:filesystem/types` `sync`/`sync-data` completa ins Host
  (Operator-Preopen vorausgesetzt); Preview1 blockt am Call.
- **Zielverhalten:** Preview1-Parität am Call **oder** ausdrücklich attestierte,
  dokumentierte Abweichung (kein stilles Verhalten).
- **Abhängigkeit:** Binding-Fähigkeit prüfen (wasip2 sync-Aufruf abfangbar?).
- **Akzeptanz:** Regressionstest (Component ruft sync → trapping oder dokumentiert
  erlaubt mit Baseline-Flag); `component_sync_probe.py` als Gegenbeweis.
- **Nachweis:** neuer Test + Posture-Tabellen-Update.

### WP-L6-1 · poll_oneoff interim-Wall + ehrliche Garantie-Formulierung (L6)
- **Befund:** identische Fuel (5 605) über n=0…20 000 bei 1.5 ms→1.25 s Wandzeit —
  Host-Arbeit uncharged; `-Spreview0` aus Binding unerreichbar.
- **Zielverhalten:** „deterministische Fuel-Abrechnung" erhält den Qualifier
  *Guest-Instruktionen*; Host-seitig wird Wandzeit/`io_cpu`(subproc) als Bounding
  dokumentiert.
- **Abhängigkeit:** Full-Fix an M2.
- **Akzeptanz:** Doku-Qualifier; Probe als stehendes Evidence-Artefakt; optional
  Wall-Clock-Doku je Pfad.
- **Nachweis:** `poll_oneoff_fuel_probe.py` (vorhanden) + SECURITY.md-Präzisierung.

### WP-L0-1 · Risk-Register & Go/No-Go-Kriterien (L0) → siehe D7/D8.

---

## P2 — Assurance & Operational Quality

### WP-L7-1 · Missbrauch-Telemetrie *innerhalb* erlaubter Capabilities (L7, Analyse)
- **Befund:** Direktive §5 Auftrag; `[F]` nicht implementiert.
- **Zielverhalten:** Design, das In-Bounds-Missbrauch (z. B. Cap bis Last ausgereizt,
  viele kleine Freigaben) nachvollziehbar macht, **ohne** die
  „Record beweist nicht Minimalität"-Grenze aufzublähen.
- **Abhängigkeit:** D2 §4.
- **Akzeptanz:** Design-Dokument + optionaler Prototyp; keine Garantie-Behauptung
  ohne Test.
- **Nachweis:** Spezifikation; ggf. neuer Zähler im Record mit Assert.

### WP-L6-2 · GC-Heap & fd_readdir Doku-Schärfe (L6 + L11)
- **Ziel:** deklariert≠erzwungen (GC-Heap) und Padding-Leak (fd_readdir) als
  Restrisiko mit klarer Class/Bounding formuliert; Gate-Trigger bei
  Binding-Feature.
- **Akzeptanz:** SECURITY.md-Wording-Prüfung gegen Code; `test_gc_heap_knob.py`
  hält Recorded-not-Enforced fest.

### WP-L11-1 · Doku↔Implementierungs-Abgleich (L11)
- **Ziel:** Jede Garantie-Behauptung im Repo hat einen Code-/Test-Anker; Abweichung
  wird zur Gap-Markierung, nicht zur stillen Zusicherung.
- **Akzeptanz:** Abgleich-Liste für §4.1–§5-Claims; Findings → Backlog.

### WP-L5-1 · Capability-Erhalt + gezielte Ergänzung (L5)
- **Ziel:** Bestehende 9 Testsuiten bleiben grün; neue Asserts nur dort, wo
  WP-L4-2/WP-L4-3 Flächen berühren.

---

## P3 — Scalability (nachgelagert, L12; nicht im Release-Kern)
WP-L12-* Streaming-Verification / Ledger-Indexing / Merkle / Epoch-Checkpoints /
Buffered Append — **Auslösung nur nach Nutzen-Nachweis** (Workload/Benchmark);
Verdrängungsverbot gegenüber P0–P2.

---

## Empfohlene Ausführungsreihenfolge (Welle 2)

1. **WP-L4-2** (`execution_mode`) — kein Blocker, größte Glaubwürdigkeitswirkung.
2. **WP-L4-3** (0.2-Sync) + **WP-L6-1** (poll_oneoff-Doku) — P1, lokal.
3. **WP-L4-1** (Untrusted-Component-Subprocess) — hängt an (1).
4. **WP-L7-1/WP-L6-2/WP-L11-1/WP-L5-1** — P2 Assurance.
5. **WP-L3-1** (M2) — parallel vorbereitend; Ausführung extern blockiert.

> Kein sicherheitskritisches WP wird ohne abgestimmten Plan umgesetzt
> (Direktive §11).WP-L4-2 ist der bewusste erste Schritt, weil er sofort
> verifizierbar ist und die Modus-Garantie erst glaubwürdig macht.
