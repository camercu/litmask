//! `mask_concat!` rejects arguments that aren't string literals or
//! compile-time-resolvable string macros per spec §2.1.5.3.

use litmask::mask_concat;

fn main() {
    let _: String = mask_concat!(42);
}
