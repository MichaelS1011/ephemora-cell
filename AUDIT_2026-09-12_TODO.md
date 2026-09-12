# Audit 2026-09-12 — verifizierte Nachbesserungs-Liste

Verifikation: 18 externe Findings einzeln gegen Repo-Stand `main` (f65bc06) geprüft.
Repros live ausgeführt (`.venv/bin/python` 3.12.13, wasmtime 47.0.1, macOS arm64):
F1 (Fuel-None), F3 (`/private/tmp` ValueError), F4 (CLI `--json`-Split), CLI-Profil-Bug (F2).
Benchmark-Evidence einbezogen: `benchmarks/results/2026-09-12/pool_vs_budget.json` (heute 18:16),
`benchmarks/results/2026-09-02/02_cell_8_vector_verify.json`.

**Zählerstand: 10 voll bestätigt (davon 1 verschärft), 6 teils (real, aber schon dokumentiert bzw.
Fix anders als vorgeschlagen), 2 widerlegt (F17, F18). Kein Finding ist ein offener
Security-Durchbruch.**

---

## Umsetzungsstand (Abend 12.09)

**Batch A + B implementiert und lokal committed (b22b140 runtime · a7be759 cli ·
952b04f benchmarks+Evidence · ca904f3 docs — Push-Fenster offen beim User).**
Lokal verifiziert: 386 Tests bestanden / 4 skipped,
Coverage 85 % (CI-Gate 80 %), black + ruff grün. Beweis-Trio nach dem Fix:
F1 `fuel_exhausted → fuel_consumed=100` (vorher None) · F2 CLI `--profile analytical →
io_cpu_seconds=10.0` (vorher 2.0) · F3 `tempfile.mkdtemp()` in `allow_dirs` akzeptiert
(vorher ValueError). GitHub Private Vulnerability Reporting wurde per API aktiviert (PUT 204).

**A5-Wurzelursache korrigiert (wichtiger als im Audit vermutet):** Der Harness-Bug war nicht
primär das falsch kommentierte Rights-Mask (`0x2801`) — der WAT pushte `{n}` als Pfad-**Pointer**
und `0` als Pfad-**Länge**, öffnete also einen leeren Pfad. Control UND Attack scheiterten an
errno 44 (ENOENT), der Symlink wurde nie wirklich geöffnet. Nach Fix (`path=0, len={n}`, Rights
`FD_READ|FD_SEEK=0x6` für den neuen fd): Positive Control **öffnet** (errno 0), der Attack
scheitert an **errno 32 (ELOOP)** — der kanonischen „Symlink nicht verfolgt"-Antwort. Der 8/8-Claim
ist damit erstmals aus dem richtigen Grund live belegt; Evidence regeneriert:
`benchmarks/results/2026-09-12/02_cell_8_vector_verify.json` (8/8, positive_control_opened=true).

## Batch A — Code-Fixes für 1.0.2 (klein, testbar, keine Design-Frage)

- [x] **A1 (F1, P0) `fuel_consumed=None` bei FUEL_EXHAUSTED** — BESTÄTIGT (Repro:
  `run_wasm(hello.wasm, max_fuel=100)` → `fuel_exhausted, None`; Kontrolle: `success, 16397`).
  Kostenabrechnung blind genau bei der teuersten Kategorie.
  **Gefixt:** neuer Helper `WASISandbox._fuel_consumed()` (`max_fuel - store.get_fuel()`,
  Fallback `max_fuel`, weil der Trap den Verbrauch beweist) an beiden Ausstiegsstellen
  (`wasi_runtime.py` Fuel-Trap-Pfad + generischer Exception-Pfad). Tests: `tests/test_wasm_runtime.py`
  (`test_fuel_exhaustion_reports_consumed_fuel`) + CLI-Ende-zu-Ende in `test_cli.py`
  (`doc["fuel_consumed"] == 100`).
- [x] **A2 (F2, P0 — VERSCHÄRFT) CLI verwirft Profil-I/O-Knobs** — live geprüft:
  `--profile analytical` resolved zu `io_cpu_seconds=2.0`, Profil sagt 10.0.
  **Gefixt:** `_resolve_config` via `dataclasses.replace(base, **overrides)` — alle Knobs ohne
  CLI-Flag (io_budget/io_cpu/disk_quota/gc_heap/sandbox_base_dir) tragen jetzt durch.
  Zusätzlich attested `apply_config`/`security_baseline` nun `io_budget_bytes` + `io_cpu_seconds`.
  Tests: `test_analytical_profile.py` (`test_profile_io_knobs_survive_cli_resolution`,
  `test_flag_override_keeps_profile_io_knobs`).
- [x] **A3 (F3, P1) macOS: `tempfile.mkdtemp()` in `allow_dirs` hart gescheitert** — BESTÄTIGT
  (Repro: `ValueError … canonical path '/private/var/folders/…'`).
  **Gefixt:** modulweite `_CANONICAL_EXCEPTIONS` (`/private/tmp`, `/private/var/folders`) +
  `_under_canonical_exception()` — angewendet in `_forbidden_canonical_match`, dem
  String-Filter `_filter_dangerous_dirs`, dem Warn-Pfad `_check_dangerous_dirs` **und** der
  Komponenten-Kopie in `wasi_02.py` (die ruft die Filter ungebunden / dupliziert sie).
  Kein Security-Downgrade: `/private/etc` & Co. bleiben gesperrt (Tests bleiben grün).
  Tests: `test_security.py` (`test_macos_tmp_parity_allowed`,
  `test_private_tmp_string_survives_denylist`) ersetzen den alten Verbots-Test.
- [x] **A4 (F5, P1) CLI-`--json`-Schema an `ExecutionReport.to_dict()` angleichen** — BESTÄTIGT
  (inkl. ungerundetem `elapsed_ms`). **Gefixt:** CLI baut den Report voll (`fuel_budget`,
  `stdout_bytes`, `stderr_bytes`, `fuel_utilization`) und gibt `report.to_dict() + stdin_capped`
  aus — ein Shape für Library, CLI und MCP-`_meta`. Tests in `test_cli.py` erweitert.
- [x] **A5 (F10, P1) 8-Vektor-Harness: Positive Control reparieren** — BESTÄTIGT; Wurzelursache
  siehe Umsetzungsstand oben (vertauschte path/len, nicht nur Rights-Kommentar).
  **Gefixt:** `benchmarks/verify_8_vectors.py` WAT korrigiert, Harness neu gelaufen,
  Evidence `02_cell_8_vector_verify.json` (8/8, `positive_control_opened=true`, errno 32/ELOOP)
  committed-fertig im datierten Ergebnisse-Ordner.
- [x] **A6 (F14-Teil, P2) `dist/`-Hygiene** — alte 1.0.0-Artefakte gelöscht; dist/ enthält nur
  noch das 1.0.1-Wheel (Sdist liegt auf PyPI).
  *Widerlegt-Teil: „2.2.0 im venv" nicht reproduzierbar — `.venv` hat 1.0.1.*

## Batch B — Docs & Honesty (IP-Posture-konform, nur gemessene Fakten)

- [x] **B1 (F6, P1) README:213 „~0.89 ms per warm tool call" war stale** — Mechanismus
  bestätigt (io_budget-Default 64 MiB → Per-Run-Engine, `wasi_runtime.py:451-455` bypassed den
  Pool); heute gemessen: Sandbox-Layer 1.06 ms Median (Default) vs. 0.48 ms (pooled).
  **Gefixt:** README:213 nennt jetzt beide Zahlen (0.48 ms pooled / ~12 ms shipped stdio
  inkl. ADR-002-Begründung), README:98 auf heutige Messung refreshiert (0.17/0.48 ms).
- [x] **B2 (F4, P2) `--json`-Inversion dokumentiert** — `--help`-Text gesetzt; `docs/recipes.md`
  hat einen neuen Abschnitt „Reading `run --json` output" (stdout=JSON, Guest-Output=stderr,
  `1>report.json 2>guest.log`-Muster). Der alte „/tmp abgelehnt by design"-Absatz wurde auf
  A3 umgeschrieben (war sonst sofort stale).
- [x] **B3 (F11, P1) Disclosure-Kanal** — **Gefixt:** GitHub Private Vulnerability Reporting
  per API aktiviert (PUT `private-vulnerability-reporting`, 204) und in SECURITY.md als
  primärer Kanal eingetragen (LinkedIn als Sekundärkanal).
- [x] **B4 (F8, P2) GC-Heap: Upgrade-Trigger notiert** — wasmtime-py 47 hat weder
  `wasm_gc`-Config-Attribut noch ResourceLimiter-Binding (live geprüft) → Gate heute nicht
  umsetzbar. SECURITY.md Dependency-Policy trägt jetzt den Trigger („wenn Binding kommt,
  Enforcement in die Upgrade-Validierung").
- [x] **B5 (F13, P2) CONTRIBUTING: uv-Realität ergänzt** — uv-Alternative + Python-Version-
  Voraussetzung + PEP-668-Hinweis. (Anleitung selbst funktionierte für Newcomer bereits.)
- [x] **B6 (F16, P2) Toolchain-Versionen dokumentiert** — neuer CONTRIBUTING-Abschnitt
  „Toolchain Versions" (Zig 0.13.0 CI-Pin, builder-Hint referenziert).

## Batch C — Design-Entscheidungen (User fragen, dann bauen)

- [ ] **C1 (F2b)** `run_wasm(config=WASIConfig)`-Overload — API-Form festlegen
  (Overload vs. `**kwargs` vs. Doku „für volle Knobs WASISandbox nutzen").
- [ ] **C2 (F6b)** MCP-Performance: (a) Server-Option „pooled/trusted" (`io_budget_bytes=None`)
  mit klarer Doku, oder (b) pool-kompatibles io_budget (größerer Umbau — Epoch-Deadline-
  Semantik aus ADR-002 an Pool-Stores anpassen). Empfehlung: erst (a), (b) als v2.
- [ ] **C3 (F7)** In-Process-Default: SECURITY-Matrix + README:132 decken es ab; optional
  UX-Hint im CLI bei `--allow-dirs` ohne `--isolated` („OS-Wände nur auf dem Subprocess-Pfad").
- [ ] **C4 (F9)** `disk_quota_bytes` ist per-file (RLIMIT_FSIZE, dokumentiert) — Aggregate-Wall
  für preopen-Trees = du-delta-Watcher als ADR-002-v2. Sandbox-Dir hat bereits eine
  Aggregate-Wall (`io_budget_bytes`). Kein 1.0.2-Blocker.
- [ ] **C5 (F15)** mypy-/pre-commit-Gate: entweder dev-Extra + CI-Job ergänzen oder den
  „type hints required"-Claim in CONTRIBUTING soften. Für eine Security-Lib wäre ein
  nicht-striktes mypy-Gate plausibel.
- [ ] **C6 (F11b)** security@-Mailbox + PGP-Key (Domain-/Infra-Frage — User).

## D — Widerlegt / kein Handlungsbedarf

- **D1 (F17)** `testpaths=["tests","benchmarks"]` ist harmlos: benchmarks/ enthält keine
  `test_*.py`-Dateien, pytest sammelt nur 386 Tests, keine Benchmark-Skripte (live geprüft).
- **D2 (F18)** Pin-vs-Range ist bereits erklärt — SECURITY.md „Dependency & Upgrade Policy"
  + ci.yml:31-33-Kommentar. Optional eine Zeile in CONTRIBUTING, kein Muss.
- **D3 (F12)** TOCTOU während Run: dokumentiertes Residuum (SECURITY.md:65,
  threat-model). openat-Pinning ist auf wasmtime-Core-Ebene, per wasmtime-py nicht
  erreichbar — beobachten, kein Action.
- **D4 (F7 als Neuheit)** „Default in-process ohne OS-Wände" ist kein undokumentiertes
  Finding: README:132, SECURITY.md-Matrix und threat-model zeichnen die Grenze explizit.

---

## Nächste Schritte

1. Commits aus Batch A+B (Vorschlag: `fix(runtime)` A1+A3, `fix(cli)` A2+A4,
   `fix(benchmarks)` A5+Evidence, `docs` B) — weiße Rahmen: user-eigene Whitepaper-Änderungen
   (docs/ephemora-cell-whitepaper.pdf, docs/whitepaper_linkedin.md) bleiben unangetastet.
2. 1.0.2-Kerbe (CHANGELOG, Version, Tag, PyPI) — User-Entscheidung, danach Batch C einzeln.
