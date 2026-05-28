//! `StaticProvider` end-to-end example — **also a cautionary
//! fixture**.
//!
//! `StaticProvider::new(UnlockKey)` is intended for tests and
//! one-shot demos. Production code that pins a hard-coded
//! `unlock_key` literally bakes the secret into the binary —
//! defeating the entire layered-key design. Use [`EnvVarProvider`],
//! [`FileProvider`], or [`HardwareIdProvider`] instead.
//!
//! The example reads the build's `unlock_key` from the `LITMASK_UNLOCK_KEY`
//! environment variable (the same variable [`EnvVarProvider`] consumes)
//! and hands it to `StaticProvider`. It then masks the canonical
//! Twain quote and proves the round-trip succeeds at runtime.
//!
//! ```sh
//! cargo build --release --example static_provider
//! LITMASK_UNLOCK_KEY=$(awk -F'"' '/^unlock_key/ {print $2}' \
//!     target/release/litmask.config) \
//!     cargo run --release --example static_provider
//! ```
//!
//! Verify the masked plaintext is absent from `.rodata`:
//!
//! ```sh
//! strings target/release/examples/static_provider | grep "greatly exaggerated"
//! # (no output — the plaintext is absent from the binary)
//! ```
//!
//! [`EnvVarProvider`]: litmask::EnvVarProvider
//! [`FileProvider`]: litmask::FileProvider
//! [`HardwareIdProvider`]: litmask::HardwareIdProvider

use litmask::{StaticProvider, UnlockKey, init_with, mask};

fn main() -> Result<(), Box<dyn std::error::Error>> {
    let key_b64 = std::env::var("LITMASK_UNLOCK_KEY")?;
    let key = UnlockKey::from_base64url(&key_b64)?;
    init_with!(StaticProvider::new(key))?;
    println!(
        "{}",
        mask!("The reports of my death have been greatly exaggerated. — Mark Twain"),
    );
    Ok(())
}
