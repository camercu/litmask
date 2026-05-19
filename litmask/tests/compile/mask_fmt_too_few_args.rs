//! `mask_fmt!` rejects placeholders that reference an argument
//! index beyond the supplied positional list.

use litmask::mask_fmt;

fn main() {
    let _ = mask_fmt!("{} {} {}", "only-one");
}
