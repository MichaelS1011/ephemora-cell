//! memhog — guest that grows linear memory until allocation fails.
//! B5: proves the Cell's memory limit (max_memory_mb) is enforced on the
//! guest: memory.grow eventually fails, guest reports the failure.

fn main() {
    let mut pages: usize = 1;
    loop {
        let result = unsafe { core::arch::wasm32::memory_grow(0, pages) };
        if result == usize::MAX {
            println!("MEMORY_LIMIT_REACHED at {} pages ({} MB)", pages, pages * 64 / 1024);
            break;
        }
        pages += 512;
    }
}