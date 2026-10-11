# D4 — Security Gap Analysis (Ist ↔ Soll)

**Lane:** L10 (Gap-Analyst) · **Deliverable:** 4 von 8 · **Bezug:** D2 (Soll), D3 (Ist)
Jede Zeile: Soll-Garantie · Ist-Nachweis · Lücke · Schließweg · Lane/Prio.

## Runtime / Supply Chain (§4.1)

| Soll | Ist | Lücke | Schließweg | Lane·Prio |
|---|---|---|---|---|
| Engine frei von ausnutzbaren CVEs | 47.0.1, vier `[E]`-Advisories offen | extern: Fix-Wheels 48.0.4/49.0.2 nicht auf PyPI | M2-Gate vorbereiten (Watcher + Pre-Regression), Restrisiko akzeptieren bis Wheel da | L3 · P0 |
| Fuel-Accounting ohne Amplifikation | GHSA-m63x durch Proposal-Disable geblockt | Guests mit Exceptions/GC können nicht laufen (dokumentierter Trade-off) | mit M2 re-qualifizieren | L3 · P1 |

## Execution Isolation (§4.2)

| Soll | Ist | Lücke | Schließweg | Lane·Prio |
|---|---|---|---|---|
| Untrusted ⇒ Prozessisolation | MCP läuft In-Process (`engine.py:190`) | **Modus nicht attestiert** (`execution_mode` fehlt) | Attestier-Feld + Doku-Garantie je Modus (D2-Entscheidung) | L4 · P2 |
| Sync-Refusal auf allen Pfaden | Preview1 ✅, 0.2 ❌ | component `sync`/`sync-data` reaches host | Call-time-Refusal oder attestierte Abweichung (OODA-4) | L4 · P1 |
| Host-Call-Panic enthält sich | 0.2-datetime-Overflow tötet In-Process-Prozess | keine Wand im Default-Pfad | untrusted-component ⇒ Subprocess-Pflicht + Doku; Full-Fix M2 | L4 · P1 |

## Capability Security (§4.3)

| Soll | Ist | Lücke | Schließweg | Lane·Prio |
|---|---|---|---|---|
| Least-Privilege & Binding voll validiert | [A] über 9 Testsuiten | **keine materielle Lücke** | nur Erhalt + gezielte Ergänzung bei WP-01/02 | L5 · P2 |
| Grant-Fallback transparent | `ungranted_tools` disclosed, `--egress-grants-required` opt-in | Embedder-In-Process-Installation authentifiziert nicht (ADR-013, by design) | Doku-Deutlichkeit; Operator-Kanal benennen | L11 · P2 |

## Resource Enforcement (§4.4)

| Soll | Ist | Lücke | Schließweg | Lane·Prio |
|---|---|---|---|---|
| Alle Host-Arbeit abgerechnet | poll_oneoff uncharged (gemessen) | kein `-Spreview0` aus Binding | interim Wandzeit/`io_cpu`(subproc) + Doku; Full-Fix M2 | L6 · P1 |
| GC-Heap byte-begrenzt | nur deklariert, nicht erzwungen | Binding-Lücke (wasmtime-py 47) | Doku-Wording schärfen; Gate bei Binding-Feature | L6 · P2 |
| fd_readdir gibt nur Grantdaten | 3 Byte Padding-Leak *in* Guest | kein Workaround < Patch | Doku-Restrisiko; optional Preopen-Verengung prüfen | L6 · P2 |

## Evidence & Verification (§5)

| Soll | Ist | Lücke | Schließweg | Lane·Prio |
|---|---|---|---|---|
| Record-Integrität + Kette | [A] (Chain, Tenant, Concurrency) | keine | Erhalt | L7 · P1 |
| Missbrauch *innerhalb* Caps nachvollziehbar | nicht implementiert `[F]` | Direktive-§5-Auftrag | Design/Analyse zusätzl. Telemetrie ohne Garantie-Aufblähung | L7 · P2 |
| `execution_mode` im attestierten Record | fehlt | Glaubwürdigkeit der Modus-Garantie | Feld + kanonische Signaturabdeckung + Assert | L7 · P2 |

## Nachgelagert (§5, P3)
Streaming-Verification / Ledger-Indexing / Merkle / Epoch-Checkpoints /
Buffered Append — **kein Gap**, sondern optionale Skalierung; erst nach
Nutzen-Nachweis, darf P0–P2 nicht verdrängen (L12).

---

## Gap-Bewertung (CTO-Sicht)

Das Repo hat **keine Nachweis-Lücke** bei Capability/Evidence — die ungewöhnlich
reife, mess-basierte Testlandschaft trägt. Die realen Lücken bündeln sich auf:

1. **Externer Blocker** (Engine-Linie) → 4 Advisories, nicht durch Config löschbar.
2. **Architekturgrenzen** (MCP-Modus, 0.2-Sync/Preopen) → teils Entscheidung,
   teils Code.
3. **Ein sofort schließbarer Integritäts-Gap** → `execution_mode`-Attest;
   günstigster Hebel für Glaubwürdigkeit, kein externer Blocker.
4. **Ein Analyse-Auftrag** → Missbrauch-Telemetrie innerhalb Capabilities.
