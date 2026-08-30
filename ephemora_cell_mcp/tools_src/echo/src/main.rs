// ephemora-cell-mcp example tool: echo
//
// Dependency-free stdin/stdout convention for Ephemora Cell MCP tools:
//
//   stdin : {"params": <any JSON value>}
//   stdout: {"echo": <params>}            (exit 0)
//   stdout: {"error": "<message>"}        (exit 1 on malformed input)
//
// No network, no crates.io dependencies — the JSON handling is a small
// scanner tailored to this contract. Build:
//
//   cargo build --release --target wasm32-wasip1
//
// The resulting binary is shipped as ephemora_cell_mcp/tools/echo.wasm.

use std::io::{self, Read, Write};

/// Find the raw JSON value for the top-level `"params"` key.
fn extract_params(input: &str) -> Option<&str> {
    let bytes = input.as_bytes();
    let mut i = 0;
    while i < bytes.len() {
        let rest = &input[i..];
        if rest.starts_with("\"params\"") {
            let mut j = i + 8;
            // skip whitespace
            while j < input.len() && input.as_bytes()[j].is_ascii_whitespace() {
                j += 1;
            }
            if j < input.len() && input.as_bytes()[j] == b':' {
                let mut k = j + 1;
                while k < input.len() && input.as_bytes()[k].is_ascii_whitespace() {
                    k += 1;
                }
                return scan_value(input, k);
            }
        }
        i += 1;
    }
    None
}

/// Scan one JSON value starting at `start`; returns its slice.
fn scan_value(input: &str, start: usize) -> Option<&str> {
    let b = input.as_bytes();
    if start >= b.len() {
        return None;
    }
    match b[start] {
        b'{' | b'[' => {
            let mut depth = 0i32;
            let mut in_string = false;
            let mut escaped = false;
            for (off, ch) in input[start..].char_indices() {
                if in_string {
                    if escaped {
                        escaped = false;
                    } else if ch == '\\' {
                        escaped = true;
                    } else if ch == '"' {
                        in_string = false;
                    }
                    continue;
                }
                match ch {
                    '"' => in_string = true,
                    '{' | '[' => depth += 1,
                    '}' | ']' => {
                        depth -= 1;
                        if depth == 0 {
                            return Some(&input[start..start + off + ch.len_utf8()]);
                        }
                    }
                    _ => {}
                }
            }
            None
        }
        b'"' => {
            let mut escaped = false;
            for (off, ch) in input[start..].char_indices().skip(1) {
                if escaped {
                    escaped = false;
                } else if ch == '\\' {
                    escaped = true;
                } else if ch == '"' {
                    return Some(&input[start..start + off + ch.len_utf8()]);
                }
            }
            None
        }
        _ => {
            // number / true / false / null — ends at delimiter or EOF
            let mut end = start;
            for ch in input[start..].chars() {
                if ch.is_ascii_whitespace() || ch == ',' || ch == '}' || ch == ']' {
                    break;
                }
                end += ch.len_utf8();
            }
            if end > start {
                Some(&input[start..end])
            } else {
                None
            }
        }
    }
}

fn main() {
    let mut buf = String::new();
    if io::stdin().read_to_string(&mut buf).is_err() {
        fail("cannot read stdin");
    }

    match extract_params(&buf) {
        Some(raw) => {
            let trimmed = raw.trim();
            if trimmed.is_empty() {
                fail("no JSON value after \"params\"");
            }
            println!("{{\"echo\": {}}}", trimmed);
        }
        None => {
            // No "params" key: echo null (the tool still succeeded).
            println!("{{\"echo\": null}}");
        }
    }
}

fn fail(message: &str) -> ! {
    let _ = write!(io::stdout(), "{{\"error\": {}}}\n", json_escape(message));
    let _ = io::stdout().flush();
    std::process::exit(1);
}

fn json_escape(s: &str) -> String {
    let mut out = String::with_capacity(s.len() + 2);
    for ch in s.chars() {
        match ch {
            '"' => out.push_str("\\\""),
            '\\' => out.push_str("\\\\"),
            '\n' => out.push_str("\\n"),
            '\r' => out.push_str("\\r"),
            '\t' => out.push_str("\\t"),
            c if (c as u32) < 0x20 => out.push_str(&format!("\\u{:04x}", c as u32)),
            c => out.push(c),
        }
    }
    out
}