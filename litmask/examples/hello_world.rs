//! Minimal end-to-end example: mask a string at compile time,
//! decrypt at runtime.
//!
//! Without `mask!`, the Twain quotation below would land verbatim
//! in the compiled binary's `.rodata` and be recoverable by
//! `strings(1)`. With `mask!`, it's AEAD-encrypted at compile time
//! and decrypted on first access. Prove it to yourself:
//!
//! ```sh
//! cargo build --release --example hello_world
//! strings target/release/examples/hello_world | grep "greatly exaggerated"
//! # (no output — the plaintext is absent from the binary)
//!
//! LITMASK_UNLOCK_KEY=$(awk -F'"' '/^unlock_key/ {print $2}' target/release/litmask.config) \
//!     cargo run --release --example hello_world
//! # prints the decrypted quotation at runtime
//! ```
//!
//! The fixture is Mark Twain (d. 1910, US public domain), chosen so
//! the `strings` grep above can't false-positive against std or
//! dependency text. Every example in this directory uses the same
//! verify-via-strings recipe; the build requires a `build.rs`
//! calling `litmask_build::emit()` — see the workspace `build.rs`
//! for the canonical setup.

use litmask::mask;

fn main() {
    println!(
        "{}",
        mask!("The reports of my death have been greatly exaggerated. — Mark Twain")
    );
}
