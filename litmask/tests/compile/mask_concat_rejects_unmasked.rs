//! `mask_concat!` rejects `unmasked!(...)` nested invocations.
//! `unmasked!`'s purpose is to opt OUT of masking; using it inside
//! `mask_concat!` (whose job is to mask everything) is a logical
//! contradiction and must surface as the spec §2.1.5.3 INVALID_MSG
//! error.

use litmask::mask_concat;

fn main() {
    let _: String = mask_concat!("a-", unmasked!("plain"));
}
