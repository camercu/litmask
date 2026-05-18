//! `mask!` must not be usable in pattern positions. As with the
//! const-context fixture, this rides on the natural compiler error
//! — the macro expansion is an expression, not a pattern, so
//! pattern position fails syntactically.

use litmask::mask;

fn main() {
    let s = String::from("foo");
    match s.as_str() {
        mask!("foo") => println!("match"),
        _ => println!("no"),
    }
}
