//! `HardwareIdProvider` end-to-end example: bind the build's
//! `unlock_key` to the host machine ID so the binary decrypts only
//! on the same hardware it was bound to. The example itself does
//! NOT rebind the binary — that's `litmask-cli bind`'s job (Task 25).
//! Here we just demonstrate the provider plumbing: a host with a
//! stable machine ID will recover the key on every run.
//!
//! ```sh
//! # First, rebind the binary so its embedded wrapper is encrypted
//! # under this host's machine-id-derived key. (Once Task 25 lands.)
//! litmask-cli bind target/release/examples/hw_id_provider \
//!     --config target/release/litmask.config
//!
//! # Then run — no env var, no key file, just the bare binary.
//! cargo run --release --features hw-id --example hw_id_provider
//! ```
//!
//! Until `litmask-cli bind` is wired up the example will fail
//! init with `decryption_failed` — the build's wrapper is encrypted
//! under the EnvVar-style key, not the hardware-derived one. The
//! example still builds and is a useful template for downstream
//! integrations.

use litmask::{HardwareIdProvider, init_with, mask};

fn main() -> Result<(), Box<dyn std::error::Error>> {
    init_with!(HardwareIdProvider::new())?;
    println!(
        "{}",
        mask!("The reports of my death have been greatly exaggerated. — Mark Twain"),
    );
    Ok(())
}
