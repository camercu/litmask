//! `unmasked!` accepts exactly one literal — extra arguments must
//! fail at compile time.

use litmask::unmasked;

fn main() {
    let _ = unmasked!("a", "b");
}
