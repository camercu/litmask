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
//! ./target/release/examples/hello_world
//! # prints the decrypted quotation at runtime — the keyless Embedded
//! # tier self-initializes on the first mask!(), so nothing is supplied
//! ```
//!
//! Run the prebuilt binary you just inspected, not `cargo run`: a
//! release `cargo run` reruns `build.rs`, minting a fresh RNG seed (the
//! seed persists only under the debug profile) and resealing the wrapper,
//! so you'd be running a different binary than the one you grep'd. Pin
//! `LITMASK_RNG_SEED` if you need a reproducible build across repeated
//! `cargo run`.
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
