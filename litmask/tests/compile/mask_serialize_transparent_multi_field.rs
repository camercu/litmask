//! `#[serde(transparent)]` requires exactly one field — a multi-field
//! struct is reject-loud rather than silently divergent.

use litmask::MaskSerialize;

#[derive(MaskSerialize)]
#[serde(transparent)]
struct ExfilManifest {
    a: u8,
    b: u8,
}

fn main() {}
