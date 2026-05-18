//! `concat!` arguments inside `mask!` must all be of one literal
//! kind. Mixed kinds must fail with the required substring "concat!
//! arguments inside mask! must be string, byte string, or C string
//! literals".

use litmask::mask;

fn main() {
    let _ = mask!(concat!("a", b"b"));
}
