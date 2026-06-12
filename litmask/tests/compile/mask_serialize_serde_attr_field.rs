//! `MaskSerialize` must reject field-level `#[serde(...)]`
//! attributes — a silently ignored `rename` would change the wire
//! format relative to the plain derive.

use litmask::MaskSerialize;

#[derive(MaskSerialize)]
struct ExfilManifest {
    #[serde(rename = "url")]
    endpoint: String,
}

fn main() {}
