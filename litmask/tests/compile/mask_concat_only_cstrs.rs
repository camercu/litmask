//! C-string-only `concat!` inside `mask!` is rejected for the same
//! reason as byte-string concat: only the all-string-literal arm is
//! currently wired.

use litmask::mask;

fn main() {
    let _ = mask!(concat!(c"a", c"b"));
}
