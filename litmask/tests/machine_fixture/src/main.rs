//! Machine-tier e2e fixture. Sealed under `LITMASK_MACHINE_ID` at build
//! time; at runtime `init!(machine_id)` recomputes the host id via
//! `machine_uid::get()`, re-derives the `unlock_key`, and unwraps
//! `mask_key`. When the build-time id matches the runtime host id the
//! canary below prints; when it does not, the wrapper's AEAD check fails,
//! `init!` returns `Err`, and the canary never prints.

use litmask::{init, mask};

fn main() -> Result<(), Box<dyn std::error::Error>> {
    init!(machine_id)?;
    // MUST match `CANARY` in tests/machine_tier_e2e.rs — the test asserts
    // this exact string appears in captured stdout.
    println!("{}", mask!("machine-tier-roundtrip-canary-7b1e4d"));
    Ok(())
}
