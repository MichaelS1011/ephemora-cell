//! Burst-write probe fixture for the component hard-exit budget case,
//! added during the 1.2.0 release qualification.
//!
//! Schreibt genau `argv[2]` Bytes (Default 19) nach `<argv[1]>/out.bin` und
//! beendet den Gast HART ueber `std::process::exit(0)` — d.h. ueber
//! `wasi:cli/exit`, NICHT ueber einen regulaeren Rueckgabewert der
//! `wasi:cli/run`-Exportfunktion. Genau dieser Exit-Pfad fuehrt im
//! Component-Sandbox-Code auf die "exit status 0"-Trap-Route.
//!
//! Kein Exploit: reine Ressourcen-/Attestierungs-Probe (Budget-Ueberschreitung
//! durch einen einzelnen Burst-Schreibvorgang). Kein Speicher-, kein
//! Preopen-Escape, keine Host-Wirkung ausserhalb des uebergebenen Verzeichnisses.
use std::env;

fn main() {
    let args: Vec<String> = env::args().collect();
    let dir = args.get(1).cloned().unwrap_or_else(|| ".".to_string());
    let n: usize = args
        .get(2)
        .and_then(|s| s.parse().ok())
        .unwrap_or(19);
    let target = std::path::Path::new(&dir).join("out.bin");
    let payload = vec![b'A'; n];
    // EIN Schreibvorgang (std::fs::write), kein Flut-Loop: das ist der
    // Sub-Intervall-Burst, den der Poller nicht sieht.
    std::fs::write(&target, &payload).expect("write out.bin");
    // Harter Exit ueber wasi:cli/exit(0).
    std::process::exit(0);
}
