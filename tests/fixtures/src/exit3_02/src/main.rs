//! Hard-exit probe fixture: leaves through `wasi:cli/exit` with a NON-ZERO
//! status, which is the one component exit route whose FAILURE the host must
//! report faithfully.
//!
//! `std::process::exit(3)` does not return a value from the `wasi:cli/run`
//! export; it aborts the run through `wasi:cli/exit`, and wasmtime surfaces
//! that as a trap. Measured on the component ABI, only the non-zero FACT
//! survives the transition, not the guest's number: `exit(3)` and `exit(7)`
//! both arrive as "Exited with i32 exit status 1". A caller that treats the
//! run as failed must therefore see `status: error` with the code wasmtime
//! actually observed (`exit_code: 1`) and `exit_status_fidelity:
//! non_zero_only` — never a success, and never a fabricated 3.
//!
//! No exploit, no filesystem effect: a pure exit-status attestation probe.
fn main() {
    std::process::exit(3);
}
