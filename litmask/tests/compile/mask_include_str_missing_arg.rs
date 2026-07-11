//! An empty `mask_include_str!()` is `missing-arg`, not `non-literal`
//! (§1.9.6) — the `require_lit_str` path.

use litmask::mask_include_str;

fn main() {
    let _ = mask_include_str!();
}
