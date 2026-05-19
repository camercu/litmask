//! `mask!(concat!(...))` no longer compiles after Amendment
//! 2026-05-17(b) removed the shim. Users must call `mask_concat!`
//! directly.

use litmask::mask;

fn main() {
    let _: String = mask!(concat!("a", "b", "c"));
}
