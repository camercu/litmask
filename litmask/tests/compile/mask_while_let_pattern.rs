//! `mask!` must not be usable in pattern positions inside `while let`,
//! parallel to the `match` and `if let` cases. The macro expands to an
//! expression, not a pattern, so the surrounding `while let` fails
//! syntactically — locking spec §2.1.1.10's enumeration of pattern
//! positions.

use litmask::mask;

fn main() {
    let items = ["foo", "bar"];
    let mut iter = items.iter();
    while let Some(&mask!("foo")) = iter.next() {
        println!("match");
    }
}
