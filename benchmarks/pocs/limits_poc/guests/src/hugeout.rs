//! hugeout — guest that writes far more than the 10 KB output budget.
//! B5: proves the Cell's stdout byte-budget (ENOSPC) is enforced on the
//! guest: writes after the budget fail with ENOSPC, capture stays <= 10 KB.

use std::io::Write;

fn main() {
    let mut stdout = std::io::stdout();
    let line: Vec<u8> = vec![b'X'; 128];
    let mut written: usize = 0;
    loop {
        if stdout.write_all(&line).is_err() {
            println!("ENOSPC_AFTER_{}_BYTES", written);
            break;
        }
        written += line.len();
        if written > 64 * 1024 {
            println!("NO_BUDGET_ENFORCED {} bytes", written);
            break;
        }
    }
}