//! `mask_format!` mirrors `format!`'s arg-count check. A positional
//! argument with no corresponding placeholder must fail at compile
//! time — the binding fires `unused_variables`, which `-D warnings`
//! upgrades to a compile error.

use litmask::mask_format;

fn main() {
    let _ = mask_format!("{}", "used", "unused");
}
