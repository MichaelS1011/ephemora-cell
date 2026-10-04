//! Does a WASI 0.2 COMPONENT guest reach a real host fsync through Cell?
//!
//! Cell's sync blockade (`fd_sync`/`fd_datasync`/`fd_psync` trapped at the
//! link layer) is a WASI Preview1 control. This probe measures what the
//! component route does instead of asserting it: it opens a file inside the
//! first granted preopen and calls the two durability entry points Rust std
//! maps onto `wasi:filesystem/types.descriptor/sync` and `/sync-data`.
//!
//! Print protocol (one token per line, read by
//! `benchmarks/component_sync_probe.py`):
//!   PREOPEN-COUNT:<n>          how many directories the guest was granted
//!   NO-PREOPEN                 default posture — nothing to sync on
//!   OPEN:ERR:<e>               grant present but the path is not writable
//!   SYNC-ALL:OK | ERR          descriptor/sync reached the host or did not
//!   SYNC-DATA:OK | ERR         descriptor/sync-data likewise
//!
//! Rebuild: `cargo build --release --target wasm32-wasip2` here, then
//! `wasm-tools strip -a` (see ../rebuild.sh).

use std::fs::OpenOptions;
use std::io::Write;
use wasi::filesystem::preopens::get_directories;

fn main() {
    let dirs = get_directories();
    println!("PREOPEN-COUNT:{}", dirs.len());
    let Some((_desc, path)) = dirs.into_iter().next() else {
        println!("NO-PREOPEN");
        return;
    };
    let target = format!("{}/sync_probe.tmp", path.trim_end_matches('/'));
    let mut file = match OpenOptions::new()
        .create(true)
        .write(true)
        .truncate(true)
        .open(&target)
    {
        Ok(f) => f,
        Err(e) => {
            println!("OPEN:ERR:{e}");
            return;
        }
    };
    if let Err(e) = file.write_all(b"cell component sync-surface probe\n") {
        println!("WRITE:ERR:{e}");
        return;
    }
    match file.sync_all() {
        Ok(()) => println!("SYNC-ALL:OK"),
        Err(e) => println!("SYNC-ALL:ERR:{e}"),
    }
    match file.sync_data() {
        Ok(()) => println!("SYNC-DATA:OK"),
        Err(e) => println!("SYNC-DATA:ERR:{e}"),
    }
}
