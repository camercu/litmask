//! MachineExternal two-factor e2e fixture. Sealed under BOTH
//! `LITMASK_MACHINE_ID` and `LITMASK_UNLOCK_KEY` at build time; at runtime
//! `init!(bind_to_machine + EnvVarProvider::default())` recomputes the host id
//! via `machine_uid::get()` AND re-reads `LITMASK_UNLOCK_KEY`, composes
//! the two finished factor keys, and unwraps `mask_key`. The canary below
//! prints only when BOTH factors match the seal; if either diverges the
//! composed key differs, the wrapper's AEAD check fails, `init!` returns
//! `Err`, and the canary never prints.

use litmask::{EnvVarProvider, init, mask};

fn main() -> Result<(), Box<dyn std::error::Error>> {
    init!(bind_to_machine + EnvVarProvider::default())?;
    // MUST match `CANARY` in tests/machine_external_tier_e2e.rs — the test
    // asserts this exact string appears in captured stdout.
    println!("{}", mask!("machine-external-tier-roundtrip-canary-3c8f5a"));
    Ok(())
}
