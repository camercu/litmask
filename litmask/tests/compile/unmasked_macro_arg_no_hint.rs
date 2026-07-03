//! `unmasked!(include_str!(...))` keeps the plain non-literal detail:
//! suggesting `mask_include_str!` would contradict the caller's intent
//! to opt *out* of masking.

use litmask::unmasked;

fn main() {
    let _ = unmasked!(include_str!("examples/fixtures/noc_list.txt"));
}
