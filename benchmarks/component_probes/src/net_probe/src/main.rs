//! WASI 0.2 component probe for the network-intent verification (U4).
//!
//! One run proves two things on the SAME sandbox config:
//!   1. FS positive control — a granted preopen read MUST succeed (argv[1]).
//!   2. Network intent — a plain TCP connect to an IP literal (no DNS, so
//!      the wasi:sockets/ip-name-lookup interface is not involved) must be
//!      fail-closed. In WASI Preview1 the socket APIs do not exist; in the
//!      WASI 0.2 world they are LINKED and denied at call time. This probe
//!      makes that call-time verdict a measured fact, not an assumption.

use std::io::Read;

fn main() {
    // 1. FS positive control (granted read via preopen, host-path mapping).
    let args: Vec<String> = std::env::args().collect();
    let mut fs_ok = false;
    if let Some(p) = args.get(1) {
        match std::fs::read_to_string(p) {
            Ok(c) => fs_ok = c.starts_with("SAFE-"),
            Err(_) => {}
        }
    }
    println!("FS:{}", if fs_ok { "OK" } else { "DENIED" });

    // Marker the host pipes in on stdin to prove stdin reaches the guest.
    let mut stdin = String::new();
    let _ = std::io::stdin().read_to_string(&mut stdin);

    // 2. Network intent: connect to an IP literal (example.com AS IPv4,
    //    no name lookup). Any successful connection prints NET:CONNECTED —
    //    the harness treats that as an open network vector (fail-open).
    match std::net::TcpStream::connect("93.184.216.34:80") {
        Ok(_stream) => println!("NET:CONNECTED"),
        Err(e) => println!("NET:DENIED:{}", e),
    }
}
