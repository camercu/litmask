//! `mask_concat!` rejects arguments that aren't string / integer /
//! float / bool / char literals (or one of the three accepted nested
//! macros). Byte-string literals are rejected, matching stdlib
//! `concat!`'s grammar.

use litmask::mask_concat;

fn main() {
    let _: String = mask_concat!("prefix-", b"bytes");
}
