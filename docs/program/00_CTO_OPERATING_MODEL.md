# CTO-Betriebsmodell — Security Hardening & Production Readiness

**Programm:** Ephemora-cell Working-Backwards-Hardening
**Verantwortung:** CTO (L0) — Ein-Personen-Team, Lanes sind rollenbasierte
Workstreams, die der CTO steuert und überwacht.
**Methodik:** Working Backwards · Risk-Based Engineering · PDCA je Lane
**Reifegrad des Repos (Ist):** v1.1.0, wasmtime 47.0.1 gepinnt. Bereits
vorhanden: Threat-Model, Security-Posture mit gemessener Evidence-Ladder,
13 ADRs, WASI-Conformance (72 pass), 8/8-Angriffsvektor-CI-Gate,
Red-Team-Pass 2026-10-05. **Das Programm ist kein Feature-Aufbau, sondern
Nachweis-, Restrisiko- und Isolation-Absicherung.**

---

## 0. Leitprinzip (aus der CTO-Direktive)

> Begin with the desired outcome. Work backwards to the evidence, architecture,
> tests and engineering tasks required to achieve it.

Jede Lane beantwortet: Welchen Kundennutzen sichert sie? Welchen überprüfbaren
Nachweis liefert sie? Kein Arbeitspaket ohne messbares Ergebnis und ohne
Zuordnung zu einem Befund (Direktive §7, §8).

---

## 1. Lane-Landschaft (Rollen, Verantwortlichkeiten, Deliverables)

13 Lanes. Priorität je Lane nach Direktive §7 (P0 Critical Security,
P1 Security & Reliability, P2 Assurance, P3 Scalability).

| Lane | Rolle (Hut) | Prio | Verantwortlicher Scope | Deliverable(s) |
|---|---|---|---|---|
| **L0** | CTO / Program Governance | P0 | Charter, PDCA-Takt, Risk-Register-Owner, Integration & Go/No-Go | D7, D8, Backlog-Konsolidierung |
| **L1** | Chief Storyteller (Working Backwards) | P2 | Kunde-rückwärts Zieldefinition | D1 PR/FAQ (intern + Customer + Technical) |
| **L2** | Principal Security Architect | P1 | Zielarchitektur: Trust Boundaries, Ausführungsmodi, Capability-Regeln, Evidence-Eigenschaften | D2 Target Security Architecture |
| **L3** | Runtime & Supply-Chain Engineer | **P0** | Wasmtime-Version/CVE-Posture, M2-Upgrade-Gate, SBOM, pip-audit, Proposal-Policy | §4.1, §6 Supply Chain |
| **L4** | Execution-Isolation Engineer | **P0** | In-Process vs. Subprocess vs. **MCP-Pfad**, Worker-Lifecycle, OS-Walls, Fail-closed | §4.2 |
| **L5** | Capability & Identity Security Engineer | P1 | Grant↔Tool-Binding, Signaturprüfung, Modul-Hash, TOCTOU, Per-Hop-Allowlist, Concurrency max_calls | §4.3 |
| **L6** | Resource-Enforcement Engineer | P1 | Fuel, Linear Memory, Wall-Clock, Output, I/O-Walls, **poll_oneoff**, GC-Heap | §4.4 |
| **L7** | Evidence & Ledger Integrity Engineer | P1 | Signed Records, Verifikation, Hash-Chain, Tenant-Attribution, Cumulative Accounting, Korruption/Concurrency | §5 |
| **L8** | SDET / Test Architect | P1 | Sicherheits-Regressions-, adversariale, Integrations- und Performance-Strategie, CI | D6 Verification & Test Strategy |
| **L9** | Security Analyst (Current State) | P0 | Ist-Zustand-Inventarisierung nach 6 Zustandsklassen (§4) | D3 Current-State Assessment |
| **L10** | Gap-Analyst & Backlog-Owner (CTO + Leads) | P0 | Gegenüberstellung Ist↔Soll, priorisierter Engineering-Backlog | D4 Gap Analysis, D5 Backlog |
| **L11** | Compliance & Documentation Engineer | P2 | Doku↔Implementierungs-Abgleich, Restrisiko-Transparenz | §8 DoD-Doku, Doku-Korrektheit |
| **L12** | Performance & Scalability (nachgelagert) | P3 | Streaming-Verification, Ledger-Indexing, Epoch-Checkpoints, Merkle — **erst nach Nutzen-Nachweis** | §5 Nachgelagert |

**Abkürzung D1..D8** = die acht Deliverables aus Direktive §9.

---

## 2. Abhängigkeitsgraph (Working-Backwards-Reihenfolge)

```
L1 (PR/FAQ) ─┐
             ├─> L2 (Zielarchitektur) ─> L9 (Ist-Zustand) ─> L10 (Gap + Backlog)
             │                                                     │
             ┘                                                     ▼
   L0 (Governance / Risk-Register)  <───────────  Ausführung L3..L8
                                                      │
                                                      ▼
                                          L8 (Verifikation je WP)
                                                      │
                                                      ▼
                                    L11 (Doku-Abgleich) ─> L0 (Go/No-Go)
```

- **Welle 1 (Plan-Grundlage, Deliverables 1–5):** L1 → L2 → L9 → L10.
  Kein Code, aber belegbare Analysen. L0 begleitet.
- **Welle 2 (Ausführung, Deliverables 6–7):** L3–L8 bearbeiten die aus L10
  abgeleiteten Arbeitspakete; L8 verifiziert jedes Paket.
- **Welle 3 (Freigabe, Deliverable 8):** L11 Doku-Abgleich, L0 Risk-Register
  final + Go/No-Go.
- **L12 (P3) ist bewusst nachgelagert** und darf Grundlagensicherheit nicht
  verdrängen (Direktive §5).

---

## 3. PDCA-Zyklus je Lane (verbindlich)

Jedes Arbeitspaket durchläuft vier Phasen. Eine Lane gilt nur als „clean
abgearbeitet", wenn alle vier dokumentiert sind.

| Phase | Activity | Artefakt / Gate |
|---|---|---|
| **PLAN** | Arbeitspaket (WP) definieren: Problem/Befund, Ziel-Sicherheitsverhalten, Akzeptanzkriterien, erforderliche Nachweise, Abhängigkeiten | WP-Karte mit DoD-Kriterien (§8) |
| **DO** | Analyse/Umsetzung in begrenztem, reviewbarem PR; Regressionstest **zuerst** (Test-Driven Security, §6) | Commit + Test |
| **CHECK** | Tests grün **plus** eigenständiger Nachweis (Benchmark/Conformance/adversarial). Bestehende Garantien nicht abgeschwächt? CTO-Gegenprobe. | Evidence-Link + Check-Protokoll; bestehende Guarantees bleiben rot-fähig |
| **ACT** | Befund korrigieren, Backlog nachpriorisieren, Restrisiko ins Register (L0), Doku nachziehen (L11) | Update Gap/Backlog/Risk-Register |

**CTO-Überwachungsregeln (L0):**
1. Ein WP darf nicht als „done" gelten, wenn nur die Test-Suite grün ist
   (Direktive §8: „Eine erfolgreich durchlaufene Test-Suite allein gilt nicht
   als vollständiger Sicherheitsnachweis").
2. Check ohne reproduzierbaren Nachweis ⇒ zurück in Do.
3. Restrisiko ohne dokumentierte Akzeptanz ⇒ No-Go in der Freigabe.
4. Architektureingriff oder kritische Restrisiko-Akzeptanz ⇒ Eskalation an
   Projektleitung (§10).

---

## 4. Ist-Befunde, die die Priorisierung treiben (belegt, nicht vermutet)

Diese Punkte kommen aus SECURITY.md / threat-model.md / security_posture.md und
müssen in L9/L10 verifiziert und in L3–L7 abgearbeitet werden:

- **L3 / P0 — Engine-Upgrade-Gate M2:** pinned 47.0.1 liegt in mehreren
  offenen Advisory-Ranges; Fix-Wheels (48.0.4/49.0.2) existieren **nicht** auf
  PyPI (47.x-Linie: ein Wheel pro Major, keine Patches). Offen u. a.
  GHSA-m63x (Fuel-Amplifikation, durch Proposal-Disable mitigiert),
  CVE-2026-47261 (FS-Escape, gemessen geblockt + striktes CI-Gate),
  GHSA-j2g9 (Datetime-Overflow, P1 — Crash In-Process auf Component-Pfad),
  GHSA-j366 (**poll_oneoff**, nicht abgerechneter Host-Aufwand, gemessen),
  GHSA-96f6 (**fd_readdir**, 3 Byte uninitialisierter Padding-Leak *in* den
  Guest, WASIp1, braucht Preopen).
- **L4 / P0 — MCP-Ausführung ist In-Process** (`engine.py:190`). Für untrusted
  Guests verlangt die Direktive Prozessisolation; der MCP-Pfad muss damit in
  Einklang gebracht werden (§4.2 explizit).
- **L4 / L6 — WASI-0.2-Component-Pfad ohne Sync-Blockade** („Sync refusal P1
  #12", OODA-4 Arbeit) und ohne Default-Preopen.
- **L6 — In-Process ohne OS-Walls:** `io_cpu_seconds`, `disk_quota_bytes`,
  RLIMITs, 32-MB-Modul-Cap und Hard-Kill gelten **nur** im Subprocess-Pfad.
  GC-Heap nicht byte-begrenzt (nur deklariert).
- **L7 — Ledger ist Enforcement:** ein austauschbares Buch setzt Caps/Windows/
  Revocations still zurück; O_NOFOLLOW + reguläre Datei + atomare Publikation
  ist seit 2026-10-05 Pflicht — Verifikation muss das belastbar halten.

---

## 5. Definition of Done jeWP (aus Direktive §8)

Ein sicherheitsrelevantes WP ist abgeschlossen, wenn **alle** Punkte erfüllt sind:
Befund beschrieben · erwartetes Sicherheitsverhalten definiert · Umsetzung
geprüft · relevante Regressionstests grün · bestehende Garantien nicht
abgeschwächt · Kompatibilitäts-/Performance-Auswirkung bekannt · Restrisiko
dokumentiert · Doku spiegelt Ist-Verhalten · Commit+Test zuordenbar.

---

## 6. Überwachungs-Dashboard (L0)

Der zentrale Fortschritt wird in der Task-Liste des CTO-Boards geführt
(eine Task je Lane, Status = PDCA-Phase). Risk-Register (D7) konsolidiert in
`docs/program/`, Deliverables unter `docs/program/NN_*.md`.

| Deliverable | Owner | Artefakt | Status |
|---|---|---|---|
| D1 PR/FAQ | L1 | `01_working_backwards_pr_faq.md` | ✅ geliefert |
| D2 Target Security Architecture | L2 | `02_target_security_architecture.md` | ✅ geliefert |
| D3 Current-State Assessment | L9 | `03_current_state_assessment.md` | ✅ geliefert |
| D4 Security Gap Analysis | L10 | `04_security_gap_analysis.md` | ✅ geliefert |
| D5 Prioritized Engineering Backlog | L10 | `05_engineering_backlog.md` | ✅ geliefert |
| D6 Verification & Test Strategy | L8 | `06_verification_test_strategy.md` | ✅ geliefert |
| D7 Security Risk Register | L0 | `07_security_risk_register.md` | ✅ geliefert |
| D8 Release Readiness (Go/No-Go) | L0 | `08_release_readiness.md` | ✅ geliefert |

**Tor A (Plan-Freigabe): GO.** **Tor B (Release): weiter NO-GO** — Welle-2-Schritte
**WP-L4-2 (`execution_mode`) + WP-L4-3 (`abi`/`sync_blockade_enforced` Enforcement-
Attest + Strict-Gate) geliefert & verifiziert** (987 passed, +21 R-07, keine
Regression; Wahrheitstabelle + Claim≡Enforcement rot-fähig getestet;
CTO-Direktive abgearbeitet, ADR-014; 2026-10-11). **WP-L4-1 gelandet
(Central Enforcement Gate, Option A+B, CTO-Freigabe; 2026-10-11):** untrusted/
unknown Component ⇒ erzwungene Prozessisolation am `WASISandbox.run()`-Choke-
Point, Trust nur host-kontrolliert, kein In-Process-Rückfall; R-03 → mitigiert,
ADR-015; 15 Gate-Tests, **1002 passed**, Perf-Overhead reproduzierbar gemessen
(+66 ms / 4,3–5,7×). M2-Engine-Gate extern blockiert; Sidecar-Egress-Parität
über Isolation = separates WP (R-14, bis dahin expliziter Refusal).

---

## 7. Governance-Grundsätze (verbindlich, Direktive §10)

Keine unkontrollierten Architekturänderungen · keine unnötige neue Technologie ·
keine Abschwächung von Sicherheitsgrenzen zugunsten Performance · keine
unbelegten Garantien · keine Gleichsetzung „Tests grün = sicher" · keine
stillschweigende Akzeptanz kritischer Restrisiken · kein Scope ohne
Kundennutzen · keine Entscheidung ohne Wartbarkeit/Betriebssicherheit.
