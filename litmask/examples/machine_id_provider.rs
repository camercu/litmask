//! `MachineIdProvider` end-to-end example: bind the build's
//! `unlock_key` to the host machine ID so the binary decrypts only
//! on the same machine it was bound to. The example itself does
//! NOT rebind the binary — `litmask bind` re-encrypts the
//! embedded wrapper under the host's machine-id-derived key.
//! Here we just demonstrate the provider plumbing: a host with a
//! stable machine ID will recover the key on every run.
//!
//! ```sh
//! cargo build --release --features machine-id --example machine_id_provider
//!
//! # Rebind the binary so its embedded wrapper is encrypted under
//! # this host's machine-id-derived key.
//! litmask bind target/release/examples/machine_id_provider \
//!     --config target/release/litmask.config
//!
//! # Then run the bound binary directly — no env var, no key file.
//! ./target/release/examples/machine_id_provider
//! ```
//!
//! Run the bound binary directly, never `cargo run`: a release
//! `cargo run` reruns `build.rs` and recompiles the example, which
//! overwrites the freshly bound wrapper with a brand-new one keyed to
//! the EnvVar-style `unlock_key` — undoing the bind and making init
//! fail with `decryption_failed`.
//!
//! Skipping the bind step makes init fail with `decryption_failed`:
//! the freshly built wrapper is encrypted under the EnvVar-style key,
//! not the machine-ID-derived one, so the runtime `MachineIdProvider`
//! recovers a key the wrapper was not encrypted under.

use litmask::{MachineIdProvider, init_with, mask};

fn main() -> Result<(), Box<dyn std::error::Error>> {
    init_with!(MachineIdProvider::new())?;
    println!(
        "{}",
        mask!("The reports of my death have been greatly exaggerated. — Mark Twain"),
    );
    Ok(())
}
