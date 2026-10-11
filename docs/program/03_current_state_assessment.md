# D3 — Current-State Assessment (Ist-Zustand)

**Lane:** L9 (Security Analyst) · **Deliverable:** 3 von 8 · **Bezug:** Direktive §4, §9.3
**Methode:** Jede Behauptung ist an ein Artefakt gebunden (Test-Datei, CI-Job,
Benchmark-JSON mit `measured:true`, ADR, Code-Stelle). Inventar-Stand: v1.1.0,
wasmtime 47.0.1, 52 Testsuiten, 9 CI-Workflows.

## Zustandsklassen (Direktive §4)

`[A]` implementiert+geprüft · `[B]` implementiert, unzureichend validiert ·
`[C]` dokumentiert, technisch nicht nachgewiesen · `[D]` teilweise mitigiert ·
`[E]` bekannte Lücke/Architekturgrenze · `[F]` noch nicht implementiert

---

## 1. Wasmtime Runtime Security (§4.1)

| Befund | Klasse | Nachweis |
|---|---|---|
| Engine gepinnt 47.0.1, Version-Floor-Test `>=43.0.1` | [A] | `requirements.txt`, `tests/test_proposal_policy.py` |
| Proposal-Policy gesetzt (nicht geerbt), attested | [A] | `tests/test_proposal_policy.py`, `test_threads_baseline.py`, `test_surface_audit.py` |
| CVE-Posture via pip-audit + SBOM in CI | [A] | `.github/workflows/ci.yml`, `scorecard.yml` |
| **GHSA-m63x Fuel-Amplifikation** | [D] | mitigiert durch Proposal-Disable; Full-Fix = M2-Upgrade (kein 47.x-Patch) |
| **CVE-2026-47261 FS-Escape** | [D] | gemessen geblockt + striktes CI-Gate `test_fs_escape_matrix.py`; Advisory upstream offen |
| **GHSA-j2g9 datetime-Overflow** (0.2 in-process Abort) | [E] | gemessen `benchmarks/results/2026-09-29/…`; Fix = M2 |
| **GHSA-j366 poll_oneoff** uncharged Host-Arbeit | [E] | gemessen `poll_oneoff_fuel_probe.py`; kein `-Spreview0` aus Binding |
| **GHSA-96f6 fd_readdir** Padding-Leak in Guest | [E] | dokumentierte Exposure; Fix = M2 |
| GHSA-x84v / RUSTSEC-0324 (WASIp3) | [A]* | strukturell unerreichbar (kein `add_wasi_http`, `stack_switching=False`) |

## 2. Execution Isolation (§4.2)

| Befund | Klasse | Nachweis |
|---|---|---|
| Zwei Pfade, Kontroll-Matrix dokumentiert | [A] | SECURITY.md matrix, `test_run_io_budgets.py`, `test_process_executor.py` |
| Subprocess-OS-Walls (RLIMITs, Disk, CPU-Watchdog, Hard-Kill, 32MB) | [A] | `tests/test_disk_quota.py`, `test_module_size_cap.py` |
| Worker-Lifecycle/Crash → `ExecutionStatus.ERROR` | [A] | `test_process_worker_main.py`, `test_sandbox_cleanup.py` |
| Fail-closed bei Grant-/Ledger-Fehlern | [A] | `test_egress_sidecar.py` (2227 Z.), `test_transport.py` |
| **MCP-Pfad In-Process, nicht isoliert** | [E] | `engine.py:190`; **kein `execution_mode`-Attest im Code** (grep: 0 Treffer) → D2-Entscheidung offen |
| **0.2-Component ohne Sync-Blockade** | [E] | `wasi_02.py:293-294`; `component_sync_probe.py` gemessen; OODA-4 |

## 3. Capability Security (§4.3)

| Befund | Klasse | Nachweis |
|---|---|---|
| Grant↔Tool-Binding, Re-Keying, Doppel-Behauptung abgelehnt | [A] | `test_tool_signing.py`, `TestEngineGrantEnforcement` |
| Modul-Hash / `expected_sha256` alle Pfade | [A] | `test_load_guard.py` (ADR-006) |
| DSSE-Signaturprüfung, Audience-Bindung, Trust-Root-Fenster | [A] | `test_grant_trust.py` (955 Z.), `test_signed_receipt.py` |
| Network-Allowlist + Per-Hop-Redirect-Validierung | [A] | `test_egress_sidecar.py`, `TestGrantConcurrency` |
| Dateisystem-/Symlink-Escape + TOCTOU am Grant-Time | [A] | `test_fs_escape_matrix.py`, `test_host_file_boundaries.py`, `test_dir_guard.py` |
| Operator-Policies / Grant-Fallback (`--egress-grants-required`) | [A] | `test_mcp_config.py`, `test_policy_agreement.py` |
| SSRF-Klassifikation interpreter-stabil (67-Adr.-Set) | [A] | `test_egress_sidecar.py::TestSSRF*`, CHANGELOG 1.1.0 |

## 4. Resource Enforcement (§4.4)

| Befund | Klasse | Nachweis |
|---|---|---|
| Fuel, Memory (`set_limits`), Wall-Clock, Output-Cap, Byte-Wall | [A] | `test_io_budget.py`, `test_fuel_hardening.py`, `test_execution_invariants.py` |
| **GC-Heap nicht byte-begrenzt** (nur deklariert) | [E/C] | `test_gc_heap_knob.py` — Recorded-not-Enforced, Binding-Lücke |
| **In-Process: CPU-/Disk-Walls dokumentiert-vertraut** | [D] | matrix; `disk_quota`/`io_cpu` nur subprocess |
| **poll_oneoff Host-Aufwand uncharged** | [E] | s. o. |

## 5. Execution Evidence & Verification (§5)

| Befund | Klasse | Nachweis |
|---|---|---|
| Strukturierte Records + Signatur + Verifikation | [A] | `test_execution_report.py`, `test_records_envelope.py` |
| Hash-Chaining / Ledger-Integrity | [A] | `test_ledger_chain.py` (ADR-011) |
| Tenant-Attribution + kumulierte Budgets | [A] | `test_tenant_budgets.py` (ADR-012) |
| Manipulationserkennung, Concurrency/Crash-Fehlerfreiheit | [A] | `test_egress_sidecar.py`, `test_host_file_boundaries.py` |
| **Zusatz-Telemetrie für Missbrauch innerhalb erlaubter Caps** | [F] | Direktive §5 Auftrag — nicht implementiert |

## 6. Engineering-Standards & Supply Chain (§6)

| Befund | Klasse | Nachweis |
|---|---|---|
| Conformance (Core + WASI) in CI | [A] | `core-spec.yml`, `wasi-conformance.yml`, 72 pass |
| Fuzzing | [A] | `fuzz.yml`, `benchmarks/fuzz_smoke.py` |
| SBOM + pip-audit + Scorecard | [A] | `ci.yml`, `scorecard.yml` |
| Engine-Advisory-Überwachung | [A] | `scripts/watch_upstream.py`, `check_wasmtime_patch.py`, `test_watch_upstream.py` |
| **Engine-Upgrade-Gate M2** (mehrere offene GHSA) | [D] | Räder 48.0.4/49.0.2 fehlen PyPI-seitig; Blocker extern |

---

## 7. Aggregat für L10 (Gap-Analyse)

- **Kein Nachweis-Defizit** bei Capability-, Evidence- und Isolation-Tests — das
  Gefüge ist ungewöhnlich reif, mess-basiert, CI-verankert.
- **Treiber der verbleibenden Arbeit:** (a) externe Engine-Linie (M2-Gate) für
  vier `[E]`-Advisories, (b) zwei Architekturgrenzen (MCP-In-Process,
  0.2-Sync/Preopen), (c) dokumentierte Nicht-Isolation (GC-Heap, In-Process-
  OS-Walls), (d) ein `[F]`-Auftrag (Missbrauch-Telemetrie innerhalb Caps).
- **Kernrisiko für Glaubwürdigkeit:** Das Feld „execution_mode" ist im Code
  **nicht vorhanden**, obwohl D2/D1 Attestierung als MCP-Strategie festlegen →
  konkreter, sofort schließbarer Gap (L4/L7/L11).
