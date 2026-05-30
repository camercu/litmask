//! `mask_include_str!("path")` reads the file at compile time and
//! masks its contents. Use for embedded config templates, baked-in
//! prompts, or any string payload too large for a literal.
//!
//! Path is resolved relative to `CARGO_MANIFEST_DIR`. Edits to the
//! included file do NOT auto-rebuild on stable Rust — see the
//! macro's rustdoc for the workaround.
//!
//! Verify masking via the strings/grep recipe in `hello_world.rs`.

use litmask::mask_include_str;

fn main() {
    let quote: String = mask_include_str!("fixtures/quote.txt");
    println!("quote={quote:?}");
}
