//! `mask!` must not be usable in pattern positions inside `if let`,
//! parallel to the `match` case. The macro expands to an expression,
//! not a pattern, so the surrounding `if let` fails syntactically.

use litmask::mask;

fn main() {
    let s = String::from("foo");
    if let mask!("foo") = s.as_str() {
        println!("match");
    }
}
