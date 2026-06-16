//! Steady-state decrypt benchmark (Task 1 walking skeleton).
//!
//! Installs the External-tier governor once, then compares decrypting the
//! 10 masked literals against cloning the plain-literal baseline. The
//! baseline is the `~0`-cost reference the masked number is read against.
//!
//! Run via `just bench` (sets `LITMASK_UNLOCK_KEY` for build + run).

use litmask::{EnvVarProvider, init};

fn main() {
    // One process-global governor for the whole run; the lazy path then
    // unlocks the fixture wrapper on first `mask!`.
    init!(EnvVarProvider::default()).expect("External-tier unlock");
    divan::main();
}

#[divan::bench]
fn decrypt_masked() -> Vec<String> {
    litmask_bench::masked()
}

#[divan::bench]
fn plain_baseline() -> Vec<String> {
    litmask_bench::PLAINTEXTS
        .iter()
        .map(|s| (*s).to_owned())
        .collect()
}
