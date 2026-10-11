# D7 — Security Risk Register

**Lane:** L0 (CTO, Owner) · **Deliverable:** 7 von 8 · **Bezug:** D4, D5, D6
**Statuswerte:** offen · mitigiert-teils · akzeptiert (mit Begründung) · geschlossen.
**Regel (§10):** Kein kritisches Restrisiko ohne dokumentierte Akzeptanz;
Akzeptanz kritischer Risiken und Architekturänderungen → Projektleitung.

| ID | Risiko (Befund) | Klasse | Lane | Maßnahme / WP | Status | Restrisiko & Akzeptanz |
|---|---|---|---|---|---|---|
| R-01 | GHSA-m63x Fuel-Amplifikation | P0→gehalten | L3 | Proposal-Disable (gc/exceptions/func-ref/tail) | **mitigiert-teils** | Guests mit GC/Exceptions blockiert; Trade-off akzeptiert bis M2 |
| R-02 | CVE-2026-47261 FS-Escape | P0 | L3/L6 | gemessen geblockt + strict CI-Gate | **mitigiert-teils** | Advisory upstream offen; M2 = final; Matrix bleibt red-fähig |
| R-03 | GHSA-j2g9 datetime-Overflow (0.2 In-Process-Abort) | P1 | L4 | Central Enforcement Gate — untrusted/unknown Component ⇒ erzwungene Prozessisolation (WP-L4-1) + M2 | **mitigiert (Gate gelandet + verifiziert)** | Gate hebt `use_subprocess` vor Gast-Ausführung für `abi=component` + nicht `trusted`; kein In-Process-Rückfall (Refusal statt Fallback); `unknown≡untrusted` fail-closed; 15 Verhaltens-/Adversarial-Tests (`test_isolation_gate.py`) + 20 Boundary-/Escalations-Nachweise (`test_wp_l4_1_verification.py`, CTO §3A–E), 1022 passed; ADR-015. Verifiziert: Trust nur host-seitig (kein Params/Manifest/ToolSpec-Kanal), Trusted an Modul-Hash gebunden (Swap ⇒ fail-closed), erzwungene Isolation bucht Tenant exakt einmal real, primitive `ComponentSandbox` als Nicht-Garantie-Pfad getrennt/doku. Rest: In-Process bleibt für ausdrücklich `trusted` (host-authorisiert) erlaubt — designgemäß, auditiert über `execution_mode`; `trusted_tools`-Bestückung ist Operator-Kanal (Default strikt leer); R-07-Sync-Blockade gilt weiterhin NICHT für Component |
| R-04 | GHSA-j366 poll_oneoff uncharged | P1 | L6 | Wandzeit/`io_cpu`(subproc) +Qualifier-Doku (WP-L6-1) | **offen** | In-Process unbegrenzt außer Wall-Clock; M2 final |
| R-05 | GHSA-96f6 fd_readdir Padding-Leak *in* Guest | P2 | L6 | Doku-Restrisiko (WP-L6-2) | **offen** | Disclosure in Guest, kein Escape; M2 final |
| R-06 | MCP In-Process, Modus nicht attestiert | P2 (Entsch.) | L4/L7 | `execution_mode`-Attest (WP-L4-2) + Doku | **mitigiert (Attest gelandet)** | Attest-Feld + Worker-Source-Stamp + Manipulations-Test ✅ (2026-10-11, 966 passed); Rest: anwenderseitige Doku-Schärfe folgt Doku-Welle; D2-Strategie Doku+Attest statt erzwungener Isolation |
| R-07 | 0.2-Component ohne Sync-Blockade | P1 | L4 | WP-L4-3 — `abi`+`sync_blockade_enforced` Enforcement-Attest + Strict-Gate (B1+B2) | **mitigiert (Claim≡Enforcement)** | Wahrheitstabelle signiert (component→enforced:false, auch bei allow_fsync=false); fail-closed (absent≠true); 21 Verhaltens-/Signiertests, 987 passed; ADR-014. Rest (attestiert, keine Blockade): Component-Pfad hat keinen Sync-Trap → M2-Engine-Ast |
| R-08 | GC-Heap nicht byte-begrenzt | P2 | L6 | Doku-Schärfe + Binding-Gate-Trigger (WP-L6-2) | **akzeptiert** | Fuel = effektive GC-Grenze; dokumentiert |
| R-09 | In-Process OS-Walls dokumentiert-vertraut | P2 | L4 | Matrix + Subprocess-Empfehlung | **akzeptiert** | designbedingt (deckelte eigenen Prozess) |
| R-10 | Missbrauch *innerhalb* Caps nicht nachvollziehbar | P2 | L7 | WP-L7-1 (Design) | **offen** | §5-Auftrag; kein Garantie-Verstoß, aber Transparenz-Lücke |
| R-11 | Supply-Chain-Vertrauen wasmtime (TCB) | P1 | L3 | pip-audit + SBOM + Scorecard + Watcher | **mitigiert-teils** | nie durch Sandbox; CI-seitig gehalten |
| R-12 | TOCTOU Swap *während* des Laufs | P2 | L5 | Grant-Time-Revalidierung (✅) | **akzeptiert** | außerhalb Sandbox-Kontrolle; dokumentiert |
| R-13 | Trust-Root-Distribution / Issuer-Vertrauen | P2 | L5/L11 | Operator-Kanal (ADR-013 Roadmap) | **akzeptiert** | bewusst außerhalb Cell; Doku muss das benennen |
| R-14 | Sidecar-Egress nicht über Isolationstrennwand | P2 (Entsch.) | L4 | Expliziter Refusal bei Egress+Isolation (WP-L4-1 Option B); Egress-Parität = separates WP (§2 CTO) | **akzeptiert (bewusst getrennt)** | Kein stiller Capability-Verlust: betroffener Run wird abgelehnt statt ohne Egress auszuführen; kein Downgrade auf In-Process. Rest: isolierter Egress-Handshake folgt eigenem WP; bis dahin dokumentierte Einschränkung |

## Eskalationsliste an Projektleitung (§10)
- **R-03/R-06/R-07:** Architekturentscheidungen zur Isolation/Attestierung.
  R-03 Enforcement-Gate **umgesetzt** (WP-L4-1, 2026-10-11, CTO-Freigabe A+B):
  untrusted/unknown Component läuft erzwungen im Worker; Trust ist host-
  kontrolliert, nie gastseitig erhöhbar; die `trusted`-Ausnahme ist durch den
  CTO formal bestätigt (Conditional Security Sign-off 2026-10-11, an die 7
  Bedingungen gebunden) und WP-L4-1 ist **CLOSED — VERIFIED WITH DOCUMENTED
  LIMITATIONS** (commit-gebundene CI, Final Evidence Gate 2026-10-11); die
  Restriktionen bleiben als offene Einträge sichtbar.
  R-06 Attest-Zusage **umgesetzt** (WP-L4-2, 2026-10-11): Modus ist jetzt
  signiert-attestiert + manipulationsfähig nachgewiesen; formal-Confirm der
  D2-Strategie (Doku+Attest) bleibt als Projektleitungs-Punkt bestehen.
  R-07 Enforcement-Attest **umgesetzt** (WP-L4-3, 2026-10-11): `abi` +
  `sync_blockade_enforced` signiert, Wahrheitstabelle + Strict-Gate
  (`require_sync_blockade`) verhaltensgetestet; Claim≡Enforcement erreicht
  (CTO-Direktive abgearbeitet, ADR-014).
- **R-01..R-05:** Akzeptanz der M2-abhängigen Restrisiken bis Wheels existieren.

## CTO-Gesamtbewertung des Registers
Kein **unbelegtes** Risiko: jeder Eintrag hat Befund + Nachweis-Anker. Die
kritische Masse ist **extern blockiert** (Engine-Linie) oder **dokumentarisch/
architektonisch** (Modus, Sync, Telemetrie) — kein Hinweis auf eine verdeckte,
unkontrollierte Schwachstelle im ausgeführten Pfad.
