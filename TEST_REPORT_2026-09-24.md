# Test-Report 2026-09-24 — Vollabnahme Ephemora Cell v1.0.4.1

**Umfang:** Ausführung der gesamten bestehenden Testlandschaft + manuelle End-to-End-Abnahme jeder User-Sichtbarkeit-Funktion, ohne Code-Änderungen. Plattformen: macOS (Apple Silicon, arm64) und DGX Spark GB10 (Ubuntu aarch64-Linux, über Tailscale). Agent-Framework-Integrationen wurden mitinstalliert und ausgeführt.

**TL;DR:** Das Produkt funktioniert professionell — 440/436 Tests grün auf beiden Plattformen, alle Security-Proofs bestanden, MCP beider Ären verifiziert gegen Doku und offizielles SDK, Quick Start wörtlich reproduzierbar. Zwei Befunde erfordern Aufmerksamkeit: **H-1** (der Registry-Load-Pfad von `--require-signed-tools` re-hasht das Modul nicht — ein nachträglich ausgetauschtes, gültiges WASM-Modul wird registriert *und ausgeführt*, entgegen der dokumentierten Fail-Closed-Zusage) und **M-1** (Oversize-Zeilen am stdio-Transport verschlucken die nächste Nachricht und verletzen die dokumentierte Fehlerzeile).

---

## 1. Umgebungen

| | macOS | DGX Spark |
|---|---|---|
| Plattform | Apple Silicon, macOS arm64, Docker 28.5.1 | GB10, Ubuntu aarch64 (Kernel 6.17), Docker vorhanden |
| Python | 3.12.13 | 3.12.3 |
| wasmtime | 47.0.1 | 47.0.1 (aus `requirements.txt`) |
| Installationsart | dev-venv (editable) + frisches Wheel in sauberer venv | rsync + editable install |
| Version | 1.0.4.1 konsistent in pyproject, `ephemora_cell/__init__.py`, `ephemora_cell_mcp/_version.py`, CHANGELOG, PyPI | dito |

## 2. Suite & Gates

| Gate | macOS | DGX Spark |
|---|---|---|
| pytest tests/ | **440 passed, 4 skipped**, 35,5 s | **436 passed, 8 skipped**, 45,1 s |
| Coverage (Gate 80 %) | **86 %** (2454 Stmts, 348 miss) | **85 %** |
| black --check | pass (47 files) | — (CI-Matrix deckt ab) |
| ruff check | pass | — |
| mypy | pass ("22 source files", 0 errors) | — |
| MCP-SDK-Interop (`integration/test_mcp_sdk_client.py`, offizielles SDK) | **2/2 passed** (Legacy-Ära + stateless 2026-07-28) | stateless-Aufrufe manuell verifiziert (s. § 4) |
| pip-audit (requirements.txt) | **No known vulnerabilities found** | — |
| bandit `-ll` | **0 Medium / 0 High** (9 Low/High-Confidence, wie CI-Nullbefund) | — |

Skips sind ausschließlich umweltbedingt, keine Defekte:
- macOS (4): `test_builder.py` — WASI_SDK nicht gesetzt, `asc`/`go` fehlen, zig-Skip ("builds for real" ist CI vorbehalten).
- DGX (8): 6× Toolchain-Skips (kein cargo-wasm32-Target, zig, go, WASI-SDK), 2× macOS-spezifische Security-Tests (`/tmp`-Symlink in `/private`) — korrekt plattformkonditioniert.

Schwächste Module (Coverage, beide Plattformen konsistent): `ephemora_cell_mcp/__main__.py` **0 %**, `transport.py` **65 %**, `sign_tool.py` / `process_executor.py` **77 %**.

## 3. Security-Proofs

| Proof | macOS | DGX | Evidence |
|---|---|---|---|
| `verify_8_vectors.py` — 8 Angriffsvektoren | **8/8 BLOCKED** | **8/8 BLOCKED** | `/tmp/ephemora_cell-8-vector-verify.json` |
| Docker stock (Gegenprobe) | 8/8 ALLOWED (erwartet) | — | `benchmarks/results/2026-09-24/02_docker_attack_probe.json` |
| Docker hardened (Gegenprobe) | 2/8 blocked, 8/8 Erwartungen erfüllt | — | `benchmarks/results/2026-09-18/01_…` |
| `mcp_cve_replay.py` (EscapeRoute, MCPoison, Komponenten-ABI) | **PASS** (Preview1 + Component + Network-Intent) | — | `benchmarks/results/2026-09-24/mcp_cve_replay*.json` |
| `sandbox_escape_18.py` | **PASS** — 8/18 execution-tested denied, 10/18 strukturell nicht ausdrückbar (ehrliche Anspruchsausweisung) | — | `benchmarks/results/2026-09-24/04_sandbox_escape_18.json` |
| `fuzz_smoke.py` (100 Module, seed 20260813) | PASS — keine Crashes/Hangs | — | Log |
| `benchmark_guard.py` | pass (pooled 0,480 ms / default 0,983 ms / Fuel-Invarianz 9002=9002) | pass (0,488 / 2,089 / 9002=9002) | Logs |
| `auto_grader.py --strict` | PASS — Verdict-Mapping 3/3 | — | Log |
| `determinism_probe.py` | fuel_median **20891**, **spread 0** | fuel_median **4506**, **spread 0** | JSON-Output |

**Boundary-Matrix heute live bestätigt (macOS):** Docker 0/8 · hardened Docker 2/8 · Cell 8/8 — deckungsgleich mit der README-Tabelle.

**Fuel ist plattformgebunden — beachte die Größenordnung:** `hello.wasm` 16397 (macOS) vs. **12** (DGX); Echo-Tool 20564 vs. 3727; Probe-Workload 20891 vs. 4506. Je Plattform deterministisch (spread 0 auf beiden), aber die Cross-Platform-Deltas sind groß. Der README-Disclaimer („fuel counts are per-platform, not cross-platform") deckt das ab; für Billing-/Quoten-Features auf Fuel-Basis wäre ein kurzer Doc-Hinweis mit Beispielszahlen wertvoll (INFO).

## 4. End-to-End-Abnahme der User-Funktionen

### 4.1 Installation & Distribution
| # | Szenario | Ergebnis |
|---|---|---|
| A1 | Wheel frisch bauen (`uv build`), gebundelte Tools im Wheel | **PASS** |
| A2 | Saubere venv → Wheel-Install → beide Entry-Points (`ephemora-cell --help`, `ephemora-cell-mcp --version`) | **PASS** — 1.0.4.1 |
| A3 | Versionskonsistenz (4 Quellen + PyPI) | **PASS** |
| A4 | PyPI-Install (`pip install ephemora-cell`) aus frischem Clone | **PASS** |
| A5 | Docker-Image-Build + stdio-Smoke im Linux-Container (initialize + echo) | **PASS** — aber s. Befund M-2 (1,45 GB, kein .dockerignore) |

### 4.2 CLI (`ephemora-cell`)
| # | Szenario | Ergebnis |
|---|---|---|
| C1 | `run examples/hello.wasm --isolated` | **PASS** |
| C2 | `run examples/fuel_bomb.wasm --fuel 100 --isolated --json` — exakt 100/100, `fuel_utilization` 1.0, vollständige `security_baseline` | **PASS** |
| C3 | `--json`: stdout bleibt reines JSON (Gast-stdout → stderr, wie dokumentiert) | **PASS** |
| C4 | `--stdin -` (Pipe) mit gebündeltem echo.wasm | **PASS** |
| C5 | `--profile analytical` (4,5 GB / 50M Fuel / 120 s) | **PASS** |
| C6 | `inspect` auf hello.wasm + clock.wasm (Imports/Exports/Risiken) | **PASS** |
| C7 | `benchmark` (cold 2,07 ms / warm 0,99 ms auf macOS; 27,3/2,3 ms auf DGX) | **PASS** |
| C8 | `build src/main.rs` — echter Rust→WASM-Build (cargo, 0,5 s) → gebautes Modul sofort ausgeführt | **PASS** |
| C9 | `build` ohne Cargo-Projekt → actionable guidance, Exit 2 | **PASS** |
| C10 | Fehlerfälle: fehlende Datei / kein WASM → saubere Meldung, Exit 1; Erfolg 0; Fuel-Bombe 1 | **PASS** |

### 4.3 Python-API (Black-Box über öffentliche API — 11/11 PASS)
`run_wasm` (SUCCESS / FUEL_EXHAUSTED exakt am Budget / TIMEOUT via Epoch), `run_isolated` (Subprozess + Fuel + Hybrid-Dict-Zugriff), `WASIConfig.allow_dirs` (`/etc` fail-closed mit ValueError beim Run, legitimes Temp-Dir gewährt), `StateStore` set/get/delete, `ComponentSandbox` (WASI-0.2-Component), `ExecutionReport` (Ed25519 sign → verify(intact)=True → Tamper → False), 5 Profile mit dokumentierten Budgets, Egress-Sidecar (allow/deny/junk fail-closed/Userinfo-Policy abgelehnt), `wasm_inspector`. Details: `/tmp/ephemora-testrun/api_acceptance-macos.log`.

### 4.4 MCP-Server über echte stdio-Prozesse (Wheel-Install; 14/16 — Details `/tmp/ephemora-testrun/mcp_acceptance-macos.log`)
| # | Szenario | Ergebnis |
|---|---|---|
| D1 | Legacy `initialize` → `2025-06-18`, serverInfo 1.0.4.1, `listChanged:false` | **PASS** |
| D2 | `notifications/initialized` still (korrekte JSON-RPC-Notification) | **PASS** |
| D3 | `tools/list` — clock + echo + get-policy, inputSchema/description | **PASS** |
| D4 | `tools/call echo` — `_meta.execution` (status, fuel, `security_baseline` mit wasmtime 47.0.1, attested `/sandbox`-Preopen) | **PASS** |
| D5 | `tools/call clock` (echtes UTC-Datum) | **PASS** |
| D6 | `get-policy` — profile/llm/2M-Fuel/64-MiB-Wall, Policy == Enforcement-Pfad | **PASS** |
| D7 | `--pooled` — `io_budget_bytes: null` in get-policy attestiert | **PASS** |
| D8 | Fehlerpfade `-32602` unknown tool / `-32601` method / `-32700` parse; Server überlebt | **PASS** |
| D9 | Stateless `tools/list` ohne Handshake — `resultType`, `ttlMs` 3600000, `cacheScope private` | **PASS** |
| D10 | Stateless `tools/call` — `resultType complete` + serverInfo in `_meta` | **PASS** (macOS + DGX) |
| D11 | Unbekannte Version → `-32022` mit `data.supported` | **PASS** |
| D12 | `server/discover` — `supportedVersions` (alle 4 Revisionen), TTL-Hinweise | **PASS** |
| D13 | Cell-Failure → `isError:true` mit `status: fuel_exhausted` + Report; `--tools-dir` ersetzt gebündelte Tools | **PASS** |
| D14 | Governed Loading (in-process): validierter Request installiert, `notifications/tools/list_changed`, Tamper fail-closed mit Reason auf Disk | **PASS** |
| D15 | `--require-signed-tools` fail-closed-Kette | **FAIL → Befund H-1** (unsigned korrekt abgelehnt, signiert korrekt geladen, **tampered/gewechseltes Modul wird geladen und ausgeführt**) |
| D16 | Oversize-Zeile (11 MB > 10-MB-Cap) | **FAIL → Befund M-1** |

## 5. Agent-Framework- & sonstige Integrationen (eigenes venv, macOS)

| Test | Ergebnis | Anmerkung |
|---|---|---|
| `test_langgraph.py` | **PASS** (exit 0) | StateGraph + EphemoraCellExecutor, model-free |
| `test_crewai.py` | **PASS** | model-free |
| `test_autogen.py` | **PASS** | model-free |
| `test_openai_agents.py` | **PASS** | nur mit `OPENAI_BASE_URL` → **lokales Ollama** (qwen3.5:9b, OpenAI-kompatibler Endpoint); ohne Endpoint: APIConnectionError |
| `test_semantic_kernel.py` | **SKIP (graceful, exit 0)** | SK-interne Plugin-Initialisierung scheitert an der Pydantic-Version (SK braucht altes pydantic mit `pydantic.networks.Url`, crewai braucht neues) — die beiden SDKs sind in einer venv nicht ko-installierbar; Zellseite degradiert korrekt |
| `test_hermes_subagent.py --json` | **PASS** (exit 0, benign/exploit/fuel) | stdlib-only |
| `test_nemoclaw_isolation.py --json` | **PASS** (exit 0, valid/tampered/expired) | stdlib-only |
| `test_language_compatibility.py` | **PASS** — 4 Rust-Module kompiliert & ausgeführt (cargo lokal) | |
| `test_model_independence.py` | **PASS** — 3 Live-Modelle (llama3:8b, mistral, qwen3.5:9b) via lokalem Ollama | Bonus: Ollama war lokal verfügbar |

Diese Suite ist im Repo bewusst nicht in `testpaths`/CI verdrahtet (SDK-Konflikte) — der heutige Lauf bestätigt, dass sie mit den richtigen venvs funktioniert.

## 6. README-/Doku-Abnahme

- Quick Start wörtlich aus frischem Clone mit PyPI-Install: alle drei Befehle reproduziert (`run --isolated`, `--fuel 100 --json`, Python-API-Snippet). **PASS**
- `examples/signed_record_demo.py`: verify(intact)=True, verify(tampered)=False — exakt wie dokumentiert. **PASS**
- Badge-Zahlen vs. Ist: **440 Tests ✓** · **86 % Coverage ✓** · **mypy 22 files ✓** — keine Badge-Drift.

## 7. Befunde

### H-1 (Hoch, sicherheitsrelevant): `--require-signed-tools` re-hasht das Modul beim Registrieren nicht
- **Dokumentiert:** README („rejects unsigned, tampered or hash-mismatched tools fail-closed"), Trust-Chain-Grafik („HOST VERIFY — fail-closed, hash + policy check"), `tool_wasm_sha256`-Docstring („a register-time re-hash proves the module is those bytes").
- **Tatsächlich:** `ToolRegistry._build_spec` (ephemora_cell_mcp/tool_registry.py, Load-Pfad) ruft nur `verify_manifest` (reine Signaturprüfung über das Manifest, ephemora_cell_mcp/tool_registry.py:89). Ein Vergleich `manifest["wasm_sha256"]` gegen `tool_wasm_sha256(wasm)` fehlt auf diesem Pfad. Der governed-loading-Pfad (`Server.process_tool_requests`, ephemora_cell_mcp/server.py:504) re-hasht korrekt — deshalb besteht der CVE-Replay dort.
- **Live-Beweis (beide Plattformen):** Manifest für echo.wasm signiert (Signatur bindet an den Echo-Hash), dann clock.wasm unter gleichem Namen eingesetzt → Server registriert „vendor" und **führt clock erfolgreich aus** (`status: success`). Auch 1-Byte-Tamper: Tool bleibt geladen; der Call scheitert nur, weil das Modul dabei zufällig invalid wurde — kein Hash-Gate.
- **Impact:** Die MCPoison-Klasse (Payload-Swap nach Trust) ist auf dem statischen `--require-signed-tools`-Load-Pfad wirksam, sobald ein Angreifer nach der Signierung Dateien im Tools-Dir austauschen kann. Preview1-Restrisiko bleibt gebunden (Fuel/Memory/Output-Cap gelten weiter) — aber Manifest→Modul-Bindung und Attestierung stimmen nicht.
- **Empfehlung:** In `_build_spec` nach der Signaturprüfung den Hash vergleichen, wenn das Manifest `wasm_sha256` trägt (`tool_wasm_sha256` existiert bereits); Manifeste ohne Feld in Signed-Mode behandeln wie dokumentiert (fail-closed oder warnen). Ergänzend ein Unit-Test „tampered wasm at load" (der CVE-Replay deckt nur den Request-Pfad).

### M-1 (Mittel, Verfügbarkeit/Korrektheit): Oversize-Zeilen am StdioTransport
- **Dokumentiert** (transport.py-Docstring): „Lines beyond max_line_bytes are drained and reported as a JSON-RPC error line so the sender gets a specification-conform reply instead of a silent hang."
- **Tatsächlich** (live verifiziert): Nach einer 11-MB-Zeile kommt **keine** Antwort; der Server blockiert still, bis der Client die nächste Zeile sendet — **diese nächste gültige Nachricht wird vom Drain-Loop verschluckt** (das erste `readline()` hatte die Riesenzeile bereits komplett konsumiert, der Drain liest daher die Folgelinie weg). Der zurückgegebene Fehler-String wird zudem selbst als Eingabe re-pariert und der Client erhält generisches `-32600 "invalid request"` (id null) statt der dokumentierten Transportlimit-Meldung.
- **Impact:** Message-Loss am Control-Plane und ein falscher Fehlertext — Richtung fail-closed, kein Sicherheitsloch, aber für robuste/fehlerhafte Hosts relevant.
- **Empfehlung:** Drain-Logik entfernen bzw. reparieren (readline liefert die ganze Zeile; Overflow-Flag statt Nachlesen), Fehler-Response direkt aus dem Transport-Pfad ausliefern statt als Pseudo-Zeile zu re-parsen. Unit-Test „oversize + subsequent message intact".

### M-2 (Mittel, Hygiene/Vertrieb): Docker-Image 1,45 GB, kein `.dockerignore`
- `COPY . .` bündelt das lokale dev-venv (166 MB), `.git` (12 MB), `tmp_probe_dir` (9,5 MB), `dist/`, `build/`, `coverage.xml` in das Image; das Dockerfile (untracked) hat zudem keinen non-root-User und kein HEALTHCHECK. Für den Glama-Container-Check funktioniert der Smoke, die Größe/Hygiene ist aber ein sichtbares Qualitätssignal.
- **Empfehlung:** `.dockerignore` (`.venv`, `.git`, `tmp_probe_dir`, `dist`, `build`, `__pycache__`, Test-Artefakte), dann Image neu messen; optional non-root-User.

### L-1 (Niedrig, UX): `--stdin`-Fehlbedienung erzeugt rohen Traceback
`ephemora-cell run tool.wasm --stdin '<json>'` (Payload statt Dateipfad — naheliegende Verwechslung, da `-` Piped-stdin liest) endet in `FileNotFoundError`-Traceback statt einer sauberen argparse-Fehlermeldung (cli.py:103). Empfehlung: FileNotFoundError abfangen und usage-hinweis geben.

### L-2 (Niedrig, UX/Doku): Governed Loading über den shipped-Stdio-Server unerreichbar
`--tool-requests-dir` existiert, `initialize` advertisiert `listChanged:true` — aber `process_tool_requests()` wird nur vom einbettenden Host aufgerufen (CVE-Replay, In-Process-Tests); der stdio-Prozess bewertet abgelegte Requests nie (verhaltensbasiert verifiziert). Die Doku sagt „the HOST evaluates" — für den Standalone-stdio-Anwender ist die Funktion damit tot. Empfehlung: entweder periodische/ereignisbasierte Auswertung im `serve()`-Loop oder expliziter Doku-Hinweis „nur bei In-Process-Embedding funktionsfähig".

### L-3 (Niedrig, API-Konsistenz): `result["status"]` liefert Enum statt String
Der Unified-Wrapper `run_isolated()` (ephemora_cell/__init__.py:69) verspricht dict-ähnlichen Legacy-Zugriff; `result["status"]` liefert aber das `ExecutionStatus`-Enum, während der dokumentierte Legacy-Dict-Pfad (`process_executor.run_isolated`) den String `"success"` liefert. Außerdem brechen `dict(result)`/`len(result)` mit TypeError (sequenz-Protokoll-Leck im `__getitem__`). Empfehlung: `__getitem__` für `status` den String liefern lassen und `keys()`/`__iter__` implementieren — oder die Hybrid-Implizit-Doku präzisieren.

### L-4 (Niedrig, Qualitätssicherung): pytest-Pinning inkonsistent
pyproject dev-Extra: `pytest<9` (Kommentar: Python-3.11-Support), `requirements-dev.lock`: pytest==8.4.2 — aber der CI-Test-Job installiert `pytest pytest-cov` unversioniert (= 9.1.1, lokal grün verifiziert). Suite läuft unter beiden; die Pin-Begründung ist gegen CI-Stand nicht wirksam. Empfehlung: eine Quelle wählen.

### L-5 (Niedrig, Hygiene): Repository-Restdaten
`testpaths = ["tests", "benchmarks"]` ohne Wirkung (keine `test_*.py` in benchmarks/), veraltete `coverage.xml` (Stand 2. Sep) + `ephemora_cell.egg-info/` (zeigt 1.0.4) + ungetrackte `.hermes_probe.py`, `tmp_probe_dir/`, `Dockerfile` im Arbeitsverzeichnis. Empfehlung: egg-info/coverage.xml aus dem Repo bzw. .gitignore, testpaths bereinigen, Dockerfile committen (nach M-2).

### INFO: Fuel-Werte sind plattformgebunden (Größenordnung beachten)
Siehe § 3 — je Plattform deterministisch (spread 0 auf macOS und DGX), Cross-Platform-Deltas bis Faktor ~1000 (hello.wasm). Durch Doku abgedeckt; für Fuel-basiertes Billing ggf. Beispielszahlen je Plattform dokumentieren.

## 8. Nicht ausgeführt (bewusst)
- gVisor-/Firecracker-/Benchmark-Linux-Probes: wöchentliche CI-Jobs mit committeter Evidence, lokaler Docker-Smoke deckt den Container-Pfad ab.
- GUI-MCP-Clients (Claude Desktop, VS Code): vertreten durch offizielles MCP-SDK-Interop + Roh-Protokoll-Abnahme über echte stdio-Prozesse.
- Conformance-Suiten (WASI-Testsuite, Core-Spec): wöchentliche CI-Jobs mit committeter Evidence; nicht Teil der lokalen Kampagne.

## 9. Fazit

Ephemora Cell v1.0.4.1 funktioniert in allen abgenommenen User-Pfaden professionell und dokumentationsgetreu: Installation (PyPI/Wheel/Docker), CLI, Python-API, MCP beider Ären, Policy-Attestierung, Fail-Closed-Verhalten der Sandbox selbst (8/8 auf beiden Plattformen) und die Framework-Integrationen. Die zwei handlungsbedürftigen Befunde betreffen beide die **Perimeter-Software, nicht die Sandbox**: H-1 (Manifest-Hash-Bindung im Load-Pfad) sollte vor dem nächsten Release geschlossen werden, M-1 ist ein robuster Reparaturkandidat mit klarem Reproduktionspfad.

---

## 10. Nachgang: Befunde abgearbeitet (Fixplan, 2026-09-24)

Alle Befunde wurden am selben Tag im `TEST_FINDINGS_FIXPLAN_2026-09-24.md` (intern, git-ignored) Schritt für Schritt geschlossen — je Schritt Code-Fix + Regressionstest + Gate:

| Befund | Status |
|---|---|
| H-1 Register-time Re-Hash (`--require-signed-tools`) | **GEFIXT** — MCPoison-Rezept führt am Load-Pfad nicht mehr aus (beide Plattformen verifiziert) |
| M-1 Oversize-Zeilen am StdioTransport | **GEFIXT** — Limit-Antwort sofort, Folge-Nachricht intakt (Abnahme 16/16) |
| M-2 Docker-Image-Hygiene | **GEFIXT** — 1,45 GB → 271 MB, non-root, Smoke grün |
| L-1 `--stdin`-Traceback | **GEFIXT** — saubere Fehlerzeile, Exit 1 |
| L-2 Governed Loading am Stdio-Server | **GEFIXT** — Lazy-Trigger vor jeder Nachricht + stderr-Reason; Doku angepasst |
| L-3 Hybrid-dict | **GEFIXT** (berichtete String-Diskrepanz korrigiert: Legacy-Dict trägt ebenfalls das Enum; verbleibendes `dict()`/`len()`-Leck geschlossen) |
| L-4 pytest-Pinning | **GEFIXT** — CI pinnt `pytest<9` in allen Jobs |
| L-5 Repo-Hygiene | **GEFIXT** — testpaths nur `tests/`, `.gitignore`-Ergänzungen, stale coverage.xml entfernt |
| INFO Fuel plattformgebunden | **DOKUMENTIERT** — `docs/performance.md` mit Messwerten |

Regressionsschutz: +8 Tests (`tests/test_transport.py` neu, `tests/test_tool_signing.py` erweitert inkl. stdio-Lazy-Trigger). Gesamt-Gate: komplette Suite + Gates grün auf macOS und DGX Spark.

*Erstellt 2026-09-24 · Alle Logs/Evidence: `/tmp/ephemora-testrun/` · Neue Evidence-JSONs: `benchmarks/results/2026-09-24/`*
