//! `mask_format!` mirrors `format!`'s "named argument never used"
//! hard error: a `name = expr` argument with no matching placeholder
//! must fail at compile time, just as stdlib `format!` rejects it.

use litmask::mask_format;

fn main() {
    let _ = mask_format!("{}", "used", unused = 2);
}
