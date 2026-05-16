//! `unmasked!` accepts only string / byte string / C string literals.
//! Other literal kinds and non-literal expressions must fail at
//! compile time so the macro stays an honest identity over the
//! `mask!` grammar.

use litmask::unmasked;

fn main() {
    let _ = unmasked!(42);
}
