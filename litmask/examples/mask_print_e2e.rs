//! E2E fixture for `mask_print!` / `mask_println!` stdout capture tests.
//!
//! Each line is a known fixture string; the integration test in
//! `tests/mask_print.rs` runs this binary and asserts exact stdout match.

use litmask::{mask_print, mask_println};

fn main() {
    mask_println!("celadon-wren-8f4a2d");
    mask_println!("topaz-gecko-{}", 7u32);
    mask_print!("viridian-pika-3e9b1c");
}
