//! Minimal end-to-end example: mask a string at compile time,
//! decrypt at runtime.
//!
//! Without `mask!`, the Franklin quotation below would land verbatim
//! in the compiled binary's `.rodata` and be recoverable by
//! `strings(1)`. With `mask!`, it's AEAD-encrypted at compile time
//! and decrypted on first access. Prove it to yourself:
//!
//! ```sh
//! cargo build --release --example hello_world
//! strings target/release/examples/hello_world | grep "if two of them are dead"
//! # (no output — the plaintext is absent from the binary)
//!
//! LITMASK_UNLOCK_KEY=$(awk -F'"' '/^unlock_key/ {print $2}' target/release/litmask.config) \
//!     ./target/release/examples/hello_world
//! # prints the decrypted quotation at runtime
//! ```
//!
//! Run the prebuilt binary directly — not `cargo run`. A release
//! build mints a fresh RNG seed each time `build.rs` runs (the seed
//! persists only under the debug profile), so re-invoking cargo
//! rewrites `litmask.config` with an `unlock_key` that no longer
//! matches the wrapper already compiled into the binary. Pin
//! `LITMASK_RNG_SEED` if you need a reproducible build that survives
//! repeated `cargo run`.
//!
//! The fixture is Benjamin Franklin (d. 1790, US public domain),
//! chosen so the `strings` grep above can't false-positive against std
//! or dependency text. Every example in this directory uses the same
//! verify-via-strings recipe; the build requires a `build.rs`
//! calling `litmask_build::emit()` — see the workspace `build.rs`
//! for the canonical setup.

use litmask::mask;

fn main() {
    proprietary_gonculator(mask!(
        "Three may keep a secret, if two of them are dead. — Benjamin Franklin"
    ));
}

fn proprietary_gonculator(data: impl AsRef<str>) {
    // do magic stuff
    println!("{}", data.as_ref());
}
