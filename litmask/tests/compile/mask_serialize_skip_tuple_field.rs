//! `skip` on a tuple (positional) field would shift the remaining
//! element indices — a shape the masking derives don't handle yet, so
//! it is reject-loud rather than silently divergent.

use litmask::MaskSerialize;

#[derive(MaskSerialize)]
struct ExfilTuple(#[serde(skip)] String, u32);

fn main() {}
