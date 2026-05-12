//! Demonstrates `weak_mask!()` against a unique fixture string.
//!
//! The fixture deliberately uses an unusual phrase so the integration
//! test that asserts "this substring is absent from the compiled
//! binary" cannot false-positive against std / dependency strings.

use litmask::weak_mask;

fn main() {
    println!("{}", weak_mask!("yellow-velvet-tortoise-9c4f1a — fixture"));
}
