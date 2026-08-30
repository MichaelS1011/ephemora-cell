//! busy — guest that burns CPU in an infinite loop.
//! B5: proves the Cell's fuel metering (max_fuel) stops runaway guests and
//! reports FUEL_EXHAUSTED with the exact fuel consumed.

fn main() {
    let mut acc: u64 = 0;
    loop {
        acc = acc.wrapping_add(1);
        if acc & 0xFFFF == 0 {
            // occasional progress marker (tiny, stays far below the budget)
            println!("iter {}", acc);
        }
    }
}