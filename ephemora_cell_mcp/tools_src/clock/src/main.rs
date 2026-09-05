// ephemora-cell-mcp bundled tool: clock
//
// Dependency-free stdin/stdout convention for Ephemora Cell MCP tools:
//
//   stdin : {"params": <any JSON value>}   (ignored — the tool takes no input)
//   stdout: {"utc": "<ISO-8601>", "unix_ms": <int>}   (exit 0)
//
// Reads the WASI real-time clock only. No filesystem access, no network,
// no environment — the sandbox fuel meter still applies to every call.
//
// Build (shipped as ephemora_cell_mcp/tools/clock.wasm):
//
//   cargo build --release --target wasm32-wasip1

use std::io::{self, Read};
use std::time::{SystemTime, UNIX_EPOCH};

/// Civil-from-days (Howard Hinnant's algorithm): days since 1970-01-01
/// -> (year, month, day).
fn civil_from_days(z: i64) -> (i64, u32, u32) {
    let z = z + 719_468;
    let era = z.div_euclid(146_097);
    let doe = z - era * 146_097; // [0, 146096]
    let yoe = (doe - doe / 1460 + doe / 36_524 - doe / 146_096) / 365; // [0, 399]
    let y = yoe + era * 400;
    let doy = doe - (365 * yoe + yoe / 4 - yoe / 100); // [0, 365]
    let mp = (5 * doy + 2) / 153; // [0, 11]
    let d = doy - (153 * mp + 2) / 5 + 1; // [1, 31]
    let m = if mp < 10 { mp + 3 } else { mp - 9 }; // [1, 12]
    (if m <= 2 { y + 1 } else { y }, m as u32, d as u32)
}

fn main() {
    let mut input = String::new();
    let _ = io::stdin().read_to_string(&mut input);

    let unix_ms = match SystemTime::now().duration_since(UNIX_EPOCH) {
        Ok(d) => (d.as_secs() as i64) * 1000 + (d.subsec_millis() as i64),
        Err(e) => {
            let d = e.duration();
            -((d.as_secs() as i64) * 1000 + (d.subsec_millis() as i64))
        }
    };

    match render(unix_ms) {
        Ok(line) => println!("{line}"),
        Err(msg) => {
            println!("{{\"error\": \"{msg}\"}}");
            std::process::exit(1);
        }
    }
}

/// Render {"utc": "<ISO-8601 milliseconds, Z>", "unix_ms": <int>}.
fn render(unix_ms: i64) -> Result<String, String> {
    // Year-9999 cap keeps the output a stable-width, ISO-parseable string.
    if unix_ms > 253_402_300_799_999 {
        return Err("timestamp out of supported range".into());
    }
    let secs = unix_ms.div_euclid(1000);
    let ms = unix_ms.rem_euclid(1000) as u32;
    let days = secs.div_euclid(86_400);
    let secs_of_day = secs.rem_euclid(86_400);
    let (y, mo, d) = civil_from_days(days);
    let h = secs_of_day / 3600;
    let mi = (secs_of_day % 3600) / 60;
    let s = secs_of_day % 60;
    Ok(format!(
        "{{\"utc\": \"{y:04}-{mo:02}-{d:02}T{h:02}:{mi:02}:{s:02}.{ms:03}Z\", \"unix_ms\": {unix_ms}}}"
    ))
}
