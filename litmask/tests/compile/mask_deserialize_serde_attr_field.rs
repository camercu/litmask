//! `MaskDeserialize` must reject field-level `#[serde(...)]`
//! attributes — a silently ignored `rename` would reject inputs the
//! plain derive accepts.

use litmask::MaskDeserialize;

#[derive(MaskDeserialize)]
struct ExfilManifest {
    #[serde(rename = "url")]
    endpoint: String,
}

fn main() {}
