//! WASI 0.2 component probe for the CVE-2025-53109/53110 replay.
//!
//! Reads one JSON line on stdin ({"params": {"path": ...}} — the same shape
//! the Preview1 probe receives) and attempts to read that path. Prints the
//! file content on success, or `ERR:<io error>` on failure. The harness
//! verdict is marker-based, exactly like the Preview1 branch: the
//! LEAKMARKER must never reach stdout.

use std::io::Read;

fn extract_path(s: &str) -> String {
    // json.dumps emits "path": "..." (space after the colon); accept both
    // spellings. Paths are harness-controlled and contain no quotes.
    for key in ["\"path\": \"", "\"path\":\""] {
        if let Some(start) = s.find(key) {
            let rest = &s[start + key.len()..];
            if let Some(end) = rest.find('"') {
                return rest[..end].to_string();
            }
        }
    }
    String::new()
}

fn main() {
    let mut stdin = String::new();
    let _ = std::io::stdin().read_to_string(&mut stdin);
    let path = extract_path(&stdin);
    if path.is_empty() {
        println!("ERR:no path in stdin");
        return;
    }
    match std::fs::read_to_string(&path) {
        Ok(content) => println!("{}", content),
        Err(e) => println!("ERR:{}", e),
    }
}
