//! `MaskSerialize` reject-loud on a not-yet-supported field-level
//! `#[serde(...)]` key: silently ignoring `flatten` would change the
//! wire format relative to the plain derive.

use litmask::MaskSerialize;

#[derive(MaskSerialize)]
struct ExfilManifest {
    #[serde(flatten)]
    endpoint: String,
}

fn main() {}
