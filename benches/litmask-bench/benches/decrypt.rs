//! Steady-state decrypt benchmark (Task 1 walking skeleton).
//!
//! Installs the External-tier governor once, then times a single `mask!`
//! against the equivalent plain literal. `decrypt_masked` returns the
//! owned `String` that `mask!` produces — the AEAD open *and* its heap
//! allocation, both real per-access costs. `plain_baseline` returns the
//! `&'static str` a no-litmask user would write (zero work, zero alloc).
//! The gap between them is the true cost of adopting litmask, allocation
//! included — nothing is hidden behind scaffolding.
//!
//! Run via `just bench` (sets `LITMASK_UNLOCK_KEY` for build + run).

use litmask::{EnvVarProvider, init, mask};

fn main() {
    // One process-global governor for the whole run; the lazy path then
    // unlocks the fixture wrapper on first `mask!`.
    init!(EnvVarProvider::default()).expect("External-tier unlock");
    divan::main();
}

#[divan::bench]
fn decrypt_masked() -> String {
    mask!("alpha-roundtrip-canary-0")
}

#[divan::bench]
fn plain_baseline() -> &'static str {
    "alpha-roundtrip-canary-0"
}
