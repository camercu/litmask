//! `mask!` must reject non-literal expressions with the required
//! substring "mask! accepts string, byte string, or C string
//! literals".

use litmask::mask;

fn main() {
    let s = "runtime value";
    let _ = mask!(s);
}
