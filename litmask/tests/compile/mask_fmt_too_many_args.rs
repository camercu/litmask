//! `mask_fmt!` mirrors `format!`'s arg-count check. A positional
//! argument with no corresponding placeholder must fail at compile
//! time — the binding fires `unused_variables`, which `-D warnings`
//! upgrades to a compile error.

use litmask::mask_fmt;

fn main() {
    let _ = mask_fmt!("{}", "used", "unused");
}
