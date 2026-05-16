//! §2.2.3.2: `maskfmt!` mirrors `format!`'s arg-count check. A
//! positional argument with no corresponding placeholder must fail
//! at compile time — the binding fires `unused_variables`, which
//! `-D warnings` upgrades to a compile error.

use litmask::maskfmt;

fn main() {
    let _ = maskfmt!("{}", "used", "unused");
}
