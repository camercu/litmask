//! §2.2.3.2: `maskfmt!` mirrors `format!`'s rule that positional
//! arguments must precede named ones. A positional expression after
//! a `name = expr` form is a parse-time rejection in `format!`;
//! maskfmt enforces the same with a typed error pointing at the
//! offending positional.

use litmask::maskfmt;

fn main() {
    let _ = maskfmt!("{} {x}", "a", x = 1, "b");
}
