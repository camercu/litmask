//! Minimal end-to-end example: mask a public-domain fixture string
//! and print the decrypted plaintext at runtime.
//!
//! The fixture is Mark Twain (d. 1910, US public domain). It is
//! lexically unusual enough that a `strings` grep for the substring
//! is unlikely to false-positive against std / dependency text.
//!
//! Run with `LITMASK_UNLOCK_KEY` set to the value found in
//! `target/<profile>/litmask.config`:
//!
//! ```sh
//! LITMASK_UNLOCK_KEY=$(awk -F'"' '/^unlock_key/ {print $2}' target/debug/litmask.config) \
//!     cargo run --example hello_world
//! ```

use litmask::mask;

fn main() {
    println!(
        "{}",
        mask!("The reports of my death have been greatly exaggerated. — Mark Twain")
    );
}
