//! `mask!` must not be usable in `static` initializers, parallel to
//! the `const` case. The rejection rides on the natural compiler
//! error against the non-const runtime helper.

use litmask::mask;

static X: String = mask!("x");

fn main() {
    let _ = &X;
}
