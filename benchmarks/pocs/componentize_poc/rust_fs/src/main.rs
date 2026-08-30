// Ephemora Cell — Componentize PoC payload.
// A tiny wasm32-wasip1 (WASI preview1) command that exercises:
//   * args passthrough      (arg0=wasm-module, arg1..=user args)
//   * env passthrough       (EPHEMORA_* vars)
//   * filesystem preopens   (writes <argv[1]>/out.txt)
// Build:  cargo build --target wasm32-wasip1 --release
use std::env;

fn main() {
    let args: Vec<String> = env::args().collect();
    for (i, a) in args.iter().enumerate() {
        println!("arg{}={}", i, a);
    }
    for (k, v) in env::vars() {
        if k.starts_with("EPHEMORA") {
            println!("env_{}={}", k.to_lowercase(), v);
        }
    }
    if let Some(dir) = args.get(1) {
        let _ = std::fs::create_dir_all(dir);
        let _ = std::fs::write(
            std::path::Path::new(dir).join("out.txt"),
            "pwned-by-lifted-rust\n",
        );
    }
    println!("rust-wasip1-done");
}