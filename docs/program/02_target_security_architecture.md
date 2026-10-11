# D2 — Ziel-Sicherheitsarchitektur (Target Security Architecture)

**Lane:** L2 (Principal Security Architect) · **Deliverable:** 2 von 8
**Bezug:** Direktive §9.2 · ADR-001..013 · SECURITY.md · threat-model.md
**Charakter:** Soll-Zustand. Wo Ist ≠ Soll, ist der Delta als **[GAP→Lx]**
markiert und fließt in D4 (Gap-Analyse)/D5 (Backlog).

---

## 1. Trust Boundaries (Soll)

| # | Boundary | Überquert sie | Durchsetzung (Soll) | Status |
|---|---|---|---|---|
| B1 | Guest → WASI-Surface | nur syscalls (Preview1) / typisierte Calls (0.2) | capability-based, Preopen-only, Dangerous-Dir-Filter, Sync-Refusal am Call | Preview1 ✅ · **0.2 ohne Sync-Blockade [GAP→L4]** |
| B2 | Guest → Host-Compute | Fuel, Memory-Pages, Wall-Clock | Fuel-Metering, `Store.set_limits`, Epoch-Interruption — **beide Pfade** | ✅ |
| B3 | Sandbox-Dir → Host-Disk | guest-geschriebene Bytes | `io_budget_bytes` (beide Pfade); `disk_quota_bytes`/`io_cpu_seconds` **nur Subprocess** | Pfadabhängig, attestiert |
| B4 | Worker → OS (Subprocess) | Prozess-Erzeugung | RLIMIT_NOFILE/AS/RSS, 32-MB-Modul-Cap, Hard-Kill | ✅ Subprocess |
| B5 | Host-Code → gast­erstellte Namen | Reads/Writes im Sandbox-Dir | `O_NOFOLLOW` + reguläre-Datei-Am-descriptor + atomare Publikation | ✅ (2026-10-05) |
| B6 | Sandbox → Netzwerk | default: nichts | P1: kein Socket-API; 0.2: `wasi:sockets` verlinkt, `connect` am Call verweigert; Egress nur host-vermittelt | ✅ gemessen |
| B7 | Grant → Tool-Identität | Berechtigung | Re-Keying nach `grant.tool`; DSSE-Signatur über canonical bytes; Audience-Bindung | ✅ |

**Grundsatz B5 (architektonisch verankert):** Der Host folgt **keinem** Namen,
den der Gast erzeugen kann. Capability-Schutz bewahrt den *Gast* vorm Host;
B5 bewahrt den *Host* vorm Gast-eigenen Verzeichnis (sidecar-Artefakte, Grant-
Dateien, Audit-Bücher). Ein austauschbares Buch = stiller Reset von
Caps/Fenstern/Revocations ⇒ **Ledger ist Enforcement, nicht Protokoll.**

---

## 2. Ausführungsmodi (Soll)

```
                     In-Process (Default)     Subprocess run_isolated()   MCP-Pfad
Fuel/Memory/Wall     ✅                        ✅                          ✅
10KB Output / Byte   ✅                        ✅                          ✅
OS-Walls/RLIMIT      ❌ dokumentiert-vertraut  ✅                           [entschieden, s. u.]
Hard-Kill            ❌                        ✅
Sync-Refusal         ✅ (Preview1)             ✅ (Preview1)               0.2: [GAP→L4]
```

- **Standardmodus (in-process):** Garantie ist *dokumentiert-vertraut* bei den
  Limits, die den eigenen Prozess deckeln würden. Für untrusted Gäste **nicht**
  ausreichend.
- **Isolationsmodus (subprocess):** Garantieträger für untrusted Workloads;
  alle OS-Walls + Hard-Kill.
- **MCP-Pfad — Entscheidung (Projektleitung):** *dokumentierte Einschränkung +
  Attestierung.* Der Ausführungsmodus wird in jedem Execution Record attestiert;
  die Deployment-Doku benennt die Garantie je Modus ausdrücklich. Die Pflicht
  „untrusted ⇒ Subprocess" bleibt als **Restrisiko mit Akzeptanz** im
  Risk-Register (D7). Alternativen (MCP zwingend auf Subprocess;
  Vertrauensmodell je Tool-Quelle) sind verworfen zugunsten von Latenz- und
  Wartbarkeits-Ehrlichkeit — **bei Bedarf umkehrbar.**
  **[GAP→L4/L11: Attestierungs-Feld „execution_mode" verpflichtend + Doku]**

---

## 3. Capability-Regeln (Least Privilege, Soll)

1. **Default-deny.** Gast erhält nur explizit erteilte Preopens; `/dev`, `/proc`,
   `/sys` + 11 weitere Dangerous Dirs geblockt; Env deny-by-default (`allow_env`).
2. **Grant spricht nur für das Tool, dessen Signatur es nennt.** Engine re-keyed
   nach `grant.tool`, lehnt Doppel-Behauptung ab.
3. **Egress = Schnittmenge, pro Hop und pro Byte.** Signed Grant ∩ serverweites
   `--egress-allow`; jeder Redirect-Hop re-validiert; strengster Ressourcen-
   Envelope; `grant_scope` disclose welche Autorität gilt.
4. **Fail-closed allüberall.** Fehlendes/korruptes Grant-Set, leeres
   Grants-Verzeichnis hinter `--egress-grants-dir`, led­ger-los Grant,
   unreadbares Ledger ⇒ Verweigerung **mit Audit-Zeile**, nicht Exception.
5. **TOCTOU am Grant-Time geschlossen** (re-realpath vor `preopen_dir`); Swap
   *während* des Laufs bleibt außerhalb der Sandbox-Kontrolle (dokumentiert).
6. **Vorgeschlagene Proposals = gesetzt, nicht geerbt.** Jedes nicht benötigte
   Proposal `False` an allen Config-Stellen; attested; strukturell gegen
   Default-Drift geschützt (Threads/Multi-Memory **eingefroren**).

---

## 4. Evidence-Eigenschaften (Soll)

- **Struktur:** RFC-8785-canonicalisierter Execution Record, DSSE v1 PAE mit
  Artifact-Audience als Payload-Type.
- **Signaturaufhebung (drei getrennte Antworten):** *Was signiert* =
  `canonical_bytes(record)`; *Wer* = operator-verankerter Key
  (Receipt: `--receipt-signing-key`; Grants: `GrantTrustRoot` außerhalb des
  Grants-Dirs, active/transition/retired mit Per-Key-Fenstern); *Was es beweist*
  = Integrität exakter Bytes zu `evidence.issued_at` unter Vertrauensannahmen.
- **Vertrauensgrenze (verbindlich formuliert):** Ein gültiger Record beweist
  **weder** semantische Korrektheit des Ergebnisses **noch** Minimalität der
  erteilten Capabilities.
- **Manipulationssicherheit:** Hash-Chaining, Tenant-Attribution, kumulierte
  Ressourcenabrechnung, Integrity bei Concurrency/Crash; Replay-Erkennung liegt
  beim Verifier („Cell beweist Eindeutigkeit; der Verifier entscheidet über
  Wiederholung").
- **Zukünftige Telemetrie [GAP→L7/L10]:** zu prüfen sind zusätzliche Signale,
  die Missbrauch *innerhalb* erlaubter Capabilities nachvollziehbarer machen,
  ohne die Garantie-Grenze aufzublähen.

---

## 5. Nachgelagert (P3, nicht Teil der Grundlagensicherheit)

Streaming-Verification, Ledger-Indexing, Epoch-Checkpoints, Merkle-Strukturen,
Buffered Append — **erst** nach Nutzen-Nachweis durch Workload/Benchmark und
ohne Verdrängung der Sicherheitsarbeit (L12).

---

## 6. Architektur-Deltas für D4/D5 (Vormerkung)

| Delta | Lane | Prio |
|---|---|---|
| 0.2-Component-Sync-Blockade | L4 | P1 |
| MCP `execution_mode`-Attestierung + Doku | L4/L11 | P2 |
| Engine-Upgrade-Gate M2 (multiple GHSA) | L3 | P0 |
| poll_oneoff uncharged Host-Arbeit | L6 | P1 |
| fd_readdir Padding-Leak in Guest | L6 | P2 |
| datetime-Overflow In-Process-Abort (0.2) | L4 | P1 |
