//! `mask!(include_str!(...))` no longer compiles after Amendment
//! 2026-05-17(b) removed the shim — users must call
//! `mask_include_str!` directly.

use litmask::mask;

fn main() {
    let _: String = mask!(include_str!("examples/fixtures/noc_list.txt"));
}
