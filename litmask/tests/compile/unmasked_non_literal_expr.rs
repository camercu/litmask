//! `unmasked!` rejects non-literal expressions — only string / byte
//! string / C string literals are accepted.

use litmask::unmasked;

fn main() {
    let s = "runtime value";
    let _ = unmasked!(s);
}
