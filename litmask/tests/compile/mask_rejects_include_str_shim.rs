//! `mask!(include_str!(...))` no longer compiles after Amendment
//! 2026-05-17(b) removed the shim. Verifies the breaking change in
//! Task 13A: users must call `mask_include_str!` directly.

use litmask::mask;

fn main() {
    let _: String = mask!(include_str!("examples/fixtures/quote.txt"));
}
