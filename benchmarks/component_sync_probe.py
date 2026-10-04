#!/usr/bin/env python3
"""Measure the sync surface of the WASI 0.2 component path (OODA-4).

Cell's sync blockade is a Preview1 control: `fd_sync`, `fd_datasync` and
`fd_psync` are shadowed by trapping shims at the link layer. The component
route goes through `Linker.add_wasip2()` and has no such shim — the docs say
so, and this file turns that sentence into a measurement instead of leaving it
as a code-reading claim.

Two legs, one guest (`benchmarks/component_probes/sync_probe.wasm`, a
wasip2 component that opens a file in its first granted preopen and calls the
`wasi:filesystem/types` `sync` and `sync-data` entry points):

  A  default config, no `allow_dirs` — how much of the sync surface does an
     unmodified run even expose?
  B  one operator-granted directory — does the intent reach the host?

Exit codes: 0 = the documented posture still holds (leg A grants nothing, leg
B reaches the host). Anything else means the component surface changed and
SECURITY.md/README have to be re-read before their scope sentences are quoted
again.

Run: .venv/bin/python benchmarks/component_sync_probe.py
"""

from __future__ import annotations

import sys
import tempfile
from pathlib import Path

REPO = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(REPO))

from ephemora_cell import WASIConfig, WASISandbox  # noqa: E402

PROBE = REPO / "benchmarks" / "component_probes" / "sync_probe.wasm"


def run_leg(label: str, grant: Path | None) -> dict:
    config = WASIConfig(
        max_fuel=1_000_000,
        allow_dirs=(str(grant),) if grant is not None else (),
    )
    sandbox = WASISandbox(config=config)
    try:
        result = sandbox.run(str(PROBE), abi="component")
    finally:
        sandbox.cleanup()
    out = (result.stdout or "").strip()
    tokens = [line.split(":", 1) for line in out.splitlines() if ":" in line]
    parsed = {k: v for k, v in tokens}
    print(f"[{label}] status={result.status.value} fuel={result.fuel_consumed}")
    for line in out.splitlines():
        print(f"    {line}")
    if result.stderr:
        print(f"    stderr: {result.stderr.strip()[:160]}")
    host_file = (grant / "sync_probe.tmp") if grant is not None else None
    if host_file is not None:
        exists = host_file.exists()
        size = host_file.stat().st_size if exists else 0
        print(f"    host artifact: {exists} ({size} bytes)")
        parsed["HOST_ARTIFACT"] = str(exists)
    parsed["STATUS"] = result.status.value
    return parsed


def main() -> int:
    if not PROBE.is_file():
        print(
            f"missing {PROBE} — rebuild with benchmarks/component_probes/rebuild.sh",
            file=sys.stderr,
        )
        return 2
    print(f"probe: {PROBE.name}, component ABI, wasi:filesystem/types sync calls\n")

    a = run_leg("A default posture", None)
    print()
    with tempfile.TemporaryDirectory(prefix="component-sync-") as tmp:
        b = run_leg("B operator-granted directory", Path(tmp))

    print("\nDeutung:")
    problems: list[str] = []

    if a.get("NO-PREOPEN") is not None or a.get("PREOPEN-COUNT") == "0":
        print("  A: ohne Grant sieht der Gast kein Verzeichnis — die Sync-Fläche")
        print("     ist im Default nicht erreichbar, nicht nur ungeblockt.")
    else:
        problems.append(f"A: Default gewährt ein Preopen ({a})")

    if b.get("SYNC-ALL") == "OK" and b.get("HOST_ARTIFACT") == "True":
        print("  B: mit Grant gehen beide Durability-Aufrufe durch bis in den")
        print("     Host — die Preview1-Blockade gilt der Component-Pfad nicht.")
        print("     Das ist der dokumentierte Scope, hier gemessen.")
    elif b.get("STATUS") != "success":
        problems.append(f"B: Gast lief nicht ({b.get('STATUS')}) — Messung wertlos")
    else:
        print("  B: Sync wird jetzt verweigert — die Lücke ist offenbar zu.")
        problems.append(
            f"B: Component-Sync verweigert ({b}); SECURITY.md/README muss den"
            " Scope-Satz neu bekommen, bevor er zitiert wird"
        )

    if problems:
        print("\n  ABWEICHUNG GEGENÜBER DOKUMENTATION:")
        for p in problems:
            print(f"    - {p}")
        return 1
    print("  Dokumentation hält: kein Sync-Shim auf dem Component-Pfad, aber")
    print("  auch kein Preopen ohne Betreiber-Gabe. Geschlossen wird das mit")
    print("  OODA-4 (Component-Blockade), nicht durch diese Messung.")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
