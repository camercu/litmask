//! `mask_format!` rejects placeholders that reference an argument
//! index beyond the supplied positional list.

use litmask::mask_format;

fn main() {
    let _ = mask_format!("{} {} {}", "only-one");
}
