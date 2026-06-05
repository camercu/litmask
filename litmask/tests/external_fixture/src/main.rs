//! External-tier e2e fixture. Sealed under `LITMASK_UNLOCK_KEY` at build
//! time; at runtime `EnvVarProvider::default()` re-reads that variable,
//! re-derives the `unlock_key`, and `init!` unwraps `mask_key`. A wrong
//! runtime value fails the wrapper's AEAD check, so `init!` returns
//! `Err` and the canary below never prints.

use litmask::{EnvVarProvider, init, mask};

fn main() -> Result<(), Box<dyn std::error::Error>> {
    init!(EnvVarProvider::default())?;
    // MUST match `CANARY` in tests/external_tier_e2e.rs — the test asserts
    // this exact string appears in captured stdout.
    println!("{}", mask!("external-tier-roundtrip-canary-9f3a2c"));
    Ok(())
}
