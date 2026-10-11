# D6 — Verification & Test Strategy

**Lane:** L8 (SDET / Test Architect) · **Deliverable:** 6 von 8 · **Bezug:** D4, D5
**Grundsatz (§8):** Grüne Testsuite ≠ Sicherheitsnachweis. Jede Garantie braucht
einen eigenständigen, reproduzierbaren Nachweis **und** eine Gegenprobe, dass
bestehende Garantien nicht abgeschwächt wurden.

## 1. Vorhandene Verification-Basis (Ist, ausgebaut statt ersetzt)

| Schicht | Artefakt | CI-Job |
|---|---|---|
| Funktion/Unit | 52 Testsuiten (`tests/`) | `ci.yml` |
| Security-Regression | `test_security.py`, `test_fs_escape_matrix.py` (strict, red-fähig), `test_egress_sidecar.py` | `ci.yml` push/PR |
| Adversarial/Attack | `verify_8_vectors.py` (8/8), `mcp_cve_replay.py`, `sandbox_escape_18.py`, `probe_classes_2026.py` | `test-bench` |
| Conformance | Core + WASI-Suite (72 pass) | `core-spec.yml`, `wasi-conformance.yml` |
| Fuzzing | `fuzz_smoke.py` | `fuzz.yml` |
| Determinismus/Perf | `determinism_probe.py`, `fuel_boundary.py`, io_dos | `benchmark-linux.yml` |
| Supply Chain | pip-audit, SBOM, Scorecard | `ci.yml`, `scorecard.yml` |

## 2. Verifikations-Regel je WP (PDCA-CHECK)

| WP | Prüfmethode | Akzeptanz-Nachweis | Rot-Fähigkeit |
|---|---|---|---|
| **L4-2** execution_mode | Feld im Record; `canonical_bytes`-Abdeckung | Assert `test_execution_report.py`/`test_records_envelope.py` + **Manipulations-Test**: Modus flip → Signatur ungültig | Ja: Flip ohne Signaturbruch = rot |
| **L4-3** 0.2-Sync | Component ruft `sync`/`sync-data` | neuer Component-Test + `component_sync_probe.py` als Gegenbeweis | Ja: stilles Durchreichen = rot |
| **L4-1** Crash-Containment | untrusted-Component-Abort | Test: Worker crasht, Parent `ExecutionStatus.ERROR` | Ja: Parent-Abort = rot |
| **L6-1** poll_oneoff | Probe n=0…20 000 | Doku-Qualifier + Probe-Artefakt im Repo | Hinweis: Probe nicht in CI (Versionsabhängigkeit) |
| **L7-1** In-Bounds-Telemetrie | Design + optionaler Zähler | Spezifikation; Zähler nur mit Assert | Ja bei Garantie-Behauptung ohne Test |
| **L3-1** M2-Upgrade | Pre-Regression-Checkliste | alle ↑-Jobs grün + Fuel-Re-Qualifizierung | Gate blockiert Versionswechsel |

## 3. Adversariale Erweiterung (gegen die vier `[E]`-Befunde)

- **Escape-Matrix bleibt strict** (xfail-frei) — eine wieder öffnende Vektor-Form
  muss CI rot machen (bestehendes Prinzip, auf neue Preopen-/Component-Pfade
  ausgedehnt).
- **Component-Path als eigene Grenze** testen: Sync, Preopen-Abwesenheit,
  Datetime-Panic — getrennt von Preview1-Posture (nie zusammenfassen).
- **Fail-closed-Invariant:** jeder neue Verweigerungspfad erzeugt eine
  Audit-Zeile, keine nackte Exception (Muster `TestTransportWalls`).

## 4. Continuous Verification (§6)

- Sicherheitsannahmen werden bei Änderung automatisch re-checkt: Proposal-Policy
  Compile-Probe, `execution_mode`-Assert, Version-Floor-Test, Advisory-Watcher.
- **Engine-Upgrade-Gate:** kein Übersetzen von Garantie-Behauptungen über eine
  Engine-Version mit geänderter Durchsetzung — 8/8 + CVE-Replay + Conformance
  müssen vor Re-Attestierung grün sein.

## 5. Performance-Messung (P3, nicht-Blocker)

Nur Nutzen-Nachweis für L12-Kandidaten; messbasiert, datiert, `measured:true`;
verdrängt keine P0–P2-Arbeit.

## 6. Abnahme-Regel der Lane L8

Ein WP erreicht „Act" erst mit: reproduzierbarem Nachweis + dokumentierter
Nicht-Abschwächung + Restrisiko-Eintrag (falls nicht vollständig geschlossen).
