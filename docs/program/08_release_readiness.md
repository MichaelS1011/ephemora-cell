# D8 — Release Readiness Assessment (Go/No-Go)

**Lane:** L0 (CTO) · **Deliverable:** 8 von 8 · **Bezug:** D5–D7, Direktive §8
**Zwei Tore:** (A) Plan-Freigabe (jetzt), (B) Release-Freigabe (nach Welle 2).
Risikobasierte Bewertung, nicht „Testsuite grün".

---

## Tor A — Plan-Freigabe (Working-Backwards-Plan)

| Kriterium | Bewertung |
|---|---|
| Zielzustand kunden-rückwärts definiert (D1) | ✅ |
| Zielarchitektur mit Trust-Boundaries/Modi/Caps/Evidence (D2) | ✅ |
| Ist-Zustand artefaktgebunden, 6 Klassen (D3) | ✅ |
| Gap-Analyse Soll↔Ist (D4) | ✅ |
| Priorisierter Backlog mit DoD/Nachweis je WP (D5) | ✅ |
| Verifikationsstrategie mit Rot-Fähigkeit (D6) | ✅ |
| Risikoregister mit Akzeptanz/Eskalation (D7) | ✅ |
| Keine unbelegten Garantien (§10) | ✅ |

**Entscheidung Tor A: GO zur Plan-Grundlage**, vorbehaltlich zweier
Projektleitungs-Punkte: (1) **R-06** MCP-Strategie formal bestätigen,
(2) Akzeptanz **R-01..R-05** (M2-abhängige Restrisiken) bis Wheels existieren.

---

## Tor B — Release-Freigabe (Zustand *heute*, vor Welle 2)

Ehrliche Einschätzung des aktuellen harten Zustands gegenüber §8 DoD:

| §8-Abnahmekriterium | Stand |
|---|---|
| Befund je Änderung beschrieben | ✅ für Planung; ⏳ je WP-Ausführung |
| Erwartetes Sicherheitsverhalten definiert | ✅ (D2/D5) |
| Technische Umsetzung geprüft | ⏳ WP L4-2/L4-3/L4-1 **noch nicht umgesetzt** |
| Relevante Regressionstests grün | ⏳ neue Asserts ausstehend |
| Bestehende Garantien nicht abgeschwächt | ✅ (nichts entfernt; nur Zugänge geplant) |
| Kompatibilität/Performance bekannt | ✅ dokumentiert (M2-Trade-off) |
| Restrisiken dokumentiert | ✅ (D7) |
| Doku = Ist-Verhalten | ⚠️ **R-06**: Attest noch nicht im Code |
| Commit/Test zuordenbar | ⏳ je WP |

**Entscheidung Tor B: NO-GO für ein „Hardening-abgeschlossen"-Release jetzt.**
Das Repo ist **produktionsreif im Ist-Umfang** (reife, gemessene, CI-gegate
Sicherheit) — aber die *Hardening-Zusätze* (execution_mode-Attest, 0.2-Sync,
Untrusted-Component-Subprocess-Pflicht, In-Bounds-Telemetrie) sind geplant,
nicht geliefert. Ein Release, das diese als erreicht darstellte, wäre eine
unbelegte Garantie (§10) → genau das, was die Leitlinie verbietet.

---

## Empfohlener Freigabe-Pfad (PDCA-Do)

1. **WP-L4-2** (`execution_mode`) umsetzen + Manipulations-Assert → schließt
   R-06/Doku-Gap ohne externen Blocker. **Erster Ausführungsschritt.**
2. **WP-L4-3** (0.2-Sync) + **WP-L6-1** (poll_oneoff-Doku) → R-07/R-04.
3. **WP-L4-1** (Untrusted-Component-Subprocess) → R-03.
4. **WP-L7-1/L6-2/L11-1/L5-1** (P2) → R-10/R-05/R-08/Doku.
5. **WP-L3-1** (M2) bleibt vorbereitet; Release-Note benennt vier `[E]`-Advisories
   als akzeptierte Restrisiken bis PyPI-Wheel.
6. Tor-B-Re-Bewertung, wenn Schritte 1–3 grün + Gegenproben dokumentiert.

**Go/No-Go-Regel Tor B (final):** GO, wenn WP-L4-2/‑3/‑1 mit rot-fähigen
Nachweisen geliefert, bestehende Garantien per Gegenprobe unangetastet und
R-01..R-05 als akzeptierte, M2-abhängige Restrisiken von der Projektleitung
gezeichnet sind.
