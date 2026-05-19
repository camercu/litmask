//! `mask_fmt!` mirrors `format!`'s rule that positional arguments
//! must precede named ones. A positional expression after a
//! `name = expr` form is a parse-time rejection in `format!`;
//! mask_fmt enforces the same with a typed error pointing at the
//! offending positional.

use litmask::mask_fmt;

fn main() {
    let _ = mask_fmt!("{} {x}", "a", x = 1, "b");
}
