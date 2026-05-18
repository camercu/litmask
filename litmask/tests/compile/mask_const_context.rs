//! `mask!` must not be usable in `const`/`static` initializers. On
//! Rust 1.88 stable, proc-macros cannot detect the call-site
//! context, so the rejection rides on the natural compiler error
//! against the non-`const` runtime helper. The snapshot below locks
//! the current error so unintentional changes to the expansion
//! become visible during review.

use litmask::mask;

const X: String = mask!("x");

fn main() {
    let _ = X;
}
