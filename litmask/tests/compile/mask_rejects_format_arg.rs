//! `mask!(format!(...))` is rejected (mask! takes no macro arguments,
//! §2.1.1.5) with a detail naming `mask_format!` as the fix.

use litmask::mask;

fn main() {
    let user = "amos";
    let _: String = mask!(format!("hello {user}"));
}
