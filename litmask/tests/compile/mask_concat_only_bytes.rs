//! Byte-string-only `concat!` inside `mask!` is rejected: the
//! all-string-literal arm is the only one currently wired, and byte
//! concatenation would change the return type from `String` to
//! `Vec<u8>` — a separate codepath.

use litmask::mask;

fn main() {
    let _ = mask!(concat!(b"a", b"b"));
}
