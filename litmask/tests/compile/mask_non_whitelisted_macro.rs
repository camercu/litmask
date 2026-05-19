//! `mask!` rejects any macro invocation as input per spec
//! Amendment 2026-05-17(b). The earlier `include_str!` / `concat!`
//! whitelist is removed; users wanting those forms invoke
//! `mask_include_str!` or `mask_concat!` directly.

use litmask::mask;

fn main() {
    let _ = mask!(vec![1, 2, 3]);
}
