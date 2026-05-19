//! `mask_concat!()` with no arguments rejects per spec §2.1.5.4.

use litmask::mask_concat;

fn main() {
    let _: String = mask_concat!();
}
