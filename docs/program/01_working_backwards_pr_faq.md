# D1 — Working-Backwards PR/FAQ

**Lane:** L1 (Chief Storyteller) · **Deliverable:** 1 von 8 (Direktive §9)
**Status:** PLAN/DO — Zielbeschreibung, **keine** Ankündigung bereits erreichter
Eigenschaften (Direktive §3.1). Offene Fragen sind als offen markiert.

> Leitsatz: „Trust the result. Not the code."

---

## Teil A — Internal Press Release (Zielzustand des Hardening-Releases)

**Release-Kodename:** Ephemora-cell Hardening (Working-Backwards-Ziel)

**Welches Problem lösen wir?**
Entwickler und Unternehmen, die nicht vertrauenswürdigen, oft LLM-generierten
Code (AI-Agent-Tools, MCP-Tools, Plugins) ausführen, können heute weder
verlassen darauf bauen, dass ein Container die Gast-Primitives tatsächlich
begrenzt, noch glaubwürdig belegen, *welche* Sicherheitsgrenze *welcher*
Modus *wirklich* durchsetzt. Ephemora-cell soll genau diese Lücke zwischen
„behaupteter Sicherheit" und „verifizierter Grenze" schließen.

**Was verbessert sich für Nutzer konkret (Ziel)?**
Ein Nutzer kann nicht vertrauenswürdigen WASM-Workload unter dokumentierten,
*gemessenen* Grenzen ausführen und für jede Ausführung einen überprüfbaren,
signierten Nachweis darüber erhalten, welche Limits galten, welche Capabilities
erteilt waren und welche Ressourcen verbraucht wurden — mit klar benannten
Grenzen dieses Nachweises.

**Welche Sicherheitsgrenzen werden verstärkt (Ziel)?**
- Der **MCP-Ausführungspfad** steht für untrusted Gäste gleichwertig unter
  Prozessisolation wie `run_isolated()` (offener Befund, siehe Technical FAQ).
- Der **WASI-0.2-Component-Pfad** erhält eine Sync-Blockade entsprechend dem
  Preview1-Verhalten (OODA-4, aktuell offen).
- Die **Engine-Bindung** wird auf eine gepatchte wasmtime-Linie gehoben, sobald
  PyPI-Wheels existieren (M2-Gate), ohne dass Garantien über die Version lügen.

**Welche Risiken werden beseitigt oder reduziert (Ziel)?**
Die als „exposure YES" klassifizierten Restrisiken (poll_oneoff-Host-Aufwand,
fd_readdir-Padding-Leak, datetime-Overflow-Absturz im In-Process-Component-Pfad)
werden entweder durch den Engine-Upgrade geschlossen oder durch
Prozesisolation eingegrenzt und *transparent* dokumentiert.

**Welche Einschränkungen bestehen weiterhin (Ziel, ehrlich)?**
- Fuel ist **nicht** plattformübergreifend deterministisch; Budgets gelten je
  Plattform.
- GC-Heap ist in wasmtime-py 47 nicht byte-begrenzt; Fuel bleibt die effektive
  GC-Grenze.
- Single-Tenant-Design: `--tenant` abrechnet und begrenzt ein Konto, isoliert
  aber kein Memory/Dateien/CPU zwischen Mandanten.
- Ein **gültiger Execution Record beweist die Integrität der dokumentierten
  Informationen unter den Vertrauensannahmen** — nicht die semantische
  Korrektheit des Ergebnisses und nicht, dass die Berechtigungen minimal waren.

**Welche technischen Nachweise belegen die Verbesserungen (Ziel)?**
Reproduzierbar, datiert, mit `measured:true`: 8/8-Vektor-Gate, CVE-Replays,
SandboxEscapeBench-18-Mapping, WASI-Conformance, 2026-Probe-Klassen,
Cross-Architektur-Determinismus — alle als CI-Schritt gegen die Auslieferung.

---

## Teil B — Customer FAQ

**Kann ich unbekannten AI-generierten Code sicher ausführen?**
Eingegrenzt: ja. Der Gast sieht nur explizit erteilte Capabilities (Preopens,
kontrollierte Env, Fuel/Memory/Wall-Clock, 10-KB-Output-Cap). „Sicher" meint
*contained*, nicht *vertrauenswürdig* — Cell prüft nicht, ob der Code gut ist.

**Wann muss ich zusätzliche Prozessisolation verwenden?**
Für untrusted Gäste immer den Subprocess-Pfad (`run_isolated()` /
`use_subprocess=True`). Nur dort greifen die OS-Walls: RLIMIT_NOFILE/AS/RSS,
per-File-`disk_quota_bytes`, `io_cpu_seconds`-Watchdog, 32-MB-Modul-Cap,
Hard-Kill bei Timeout. In-Process sind diese als *deklarierte Capabilities*
behandelt, nicht erzwingt.

**Welche Ressourcen werden tatsächlich begrenzt?**
Überall: Fuel (CPU), Linear Memory (`Store.set_limits`), Wall-Clock (Epoch),
Output (10 KB), I/O-Byte-Wall (`io_budget_bytes`). Nur Subprocess: I/O-CPU-Wall,
Disk-Quota, RLIMITs, Modulgröße, Prozess-Kill.

**Welche Host-Ressourcen bleiben erreichbar?**
Default: keine. Kein exec/fork/socket in WASI Preview1; kein Netzwerk —
Component-Pfad verlinkt `wasi:sockets`, verweigert `connect` aber zur Call-Zeit
(gemessen). Egress nur über den host-vermittelten, allowlist-geregelten Sidecar.

**Was passiert bei Host- oder Worker-Absturz?**
Subprocess: Worker stirbt, Parent überlebt mit sauberem
`ExecutionStatus.ERROR`. Im-Process: ein Host-Call-Panic (z. B.
datetime-Overflow auf dem Component-Pfad) kann das einbettende Process
beenden — ein Kernbefund, den das Hardening adressiert.

**Was beweist ein signierter Execution Record?**
Dass ein vertrauenswürdiger Signierer *exakt diese Bytes* zu einer Zeit
bezeugt (DSSE v1 über RFC-8785-canonicalisierte Records, Audience-gebunden).
Er beweist *nicht*, dass die Ausführung sicher war, und nicht, dass mehr
erzwungen wurde als der Record selbst angibt.

**Welche Abhängigkeiten / Upstream-Risiken bestehen?**
wasmtime ist die Trusted Computing Base. Mehrere offene 2026-Advisories betreffen
die gepinnte 47.0.1-Linie; Fix-Wheels (48.0.4/49.0.2) fehlen auf PyPI —
Schließung läuft über das M2-Engine-Upgrade-Gate, nicht über Config.

**Welche Garantien gelten Standard- vs. Isolations-Modus?**
Standard (in-process): Fuel/Memory/Wall/Output/Byte-Wall erzwungen;
OS-Walls dokumentiert-vertraut. Isoliert (subprocess): zusätzlich OS-Walls und
Hard-Kill. Für untrusted Gäste ist der Isolations-Modus der Garantieträger.

---

## Teil C — Internal Technical FAQ (offene/architekturelle Fragen)

**Q1 — MCP-Pfad ist In-Process (`engine.py:190`). Zielkonflikt zur Direktive §4.2?**
**OFFEN / architekturkritisch.** Die Direktive verlangt für untrusted Workloads
Prozessisolation und nennt den MCP-Pfad explizit. Optionen: (a) MCP-Ausführung
auf Subprocess umstellen (Lifecycle-/Latenz-Kosten, Tool-Bootstrap), (b)
Vertrauensmodell je Tool-Quelle definieren (signierte/governed Tools vs.
untrusted), (c) dokumentierte Einschränkung je Deployment-Modus. **Eskalation an
Projektleitung** (Richtungsentscheidung, nicht Detailfix) — L4/L10.

**Q2 — Component-Pfad ohne Sync-Blockade. Gleiche Garantie wie Preview1 nötig?**
**OFFEN (P1, OODA-4).** Preview1 fängt `fd_sync`/`fd_datasync`/`fd_psync` am
Call. `wasi:filesystem/types` `sync`/`sync-data` completa auf dem Component-Pfad
ins Host (gemessen), braucht aber Operator-Preopen. Ziel: Call-time-Refusal oder
dokumentierte, attestierte Abweichung.

**Q3 — poll_oneoff / fd_readdir: Konfig-Workaround oder nur Engine-Upgrade?**
Befund: `poll_oneoff` abrechnet n=0…20 000 gleich (5 605 Fuel) bei 1.5 ms→1.25 s
Wandzeit — Host-Arbeit uncharged; upstream-Flag `-Spreview0` aus wasmtime-py
nicht erreichbar. `fd_readdir` leakt 3 Byte Padding *in* den Guest (braucht
Preopen). **Beide: M2-Engine-Upgrade als Schließung; interim Wandzeit-CPU-Wall
(Subprocess) bzw. dokumentiertes Restrisiko.**

**Q4 — Darf eine bestehende Garantie für Performance abgeschwächt werden?**
Nein (§10). Vorschläge aus §5 (Streaming-Verification, Ledger-Indexing,
Merkle, Epoch-Checkpoints) sind P3 und nur nach Nutzen-Nachweis (L12).

**Q5 — Reicht „Testsuite grün" als Sicherheitsnachweis?**
Nein (§8). Check-Phase verlangt eigenständigen, reproduzierbaren Nachweis plus
Gegenprobe, dass bestehende Garantien nicht abgeschwächt wurden.

**Q6 — Welche Vertrauensannahmen trägt die Signaturkette?**
Operator-verankerte Keys (`GrantTrustRoot` außerhalb des Grants-Dirs;
`--receipt-signing-key`). Root-Distribution und vertraute Issuer-Keys bleiben
Operator-Kanal (ADR-013 Roadmap) — **OFFEN, bewusst außerhalb Cell**.
