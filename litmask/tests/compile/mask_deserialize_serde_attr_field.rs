//! `MaskDeserialize` reject-loud on a not-yet-supported field-level
//! `#[serde(...)]` key: silently ignoring `flatten` would accept
//! different inputs than the plain derive.

use litmask::MaskDeserialize;

#[derive(MaskDeserialize)]
struct ExfilManifest {
    #[serde(flatten)]
    endpoint: String,
}

fn main() {}
