//! `MaskDeserialize` must reject container-level `#[serde(...)]`
//! attributes — honoring none of them silently (e.g. `rename_all`)
//! would accept different inputs than the plain derive.

use litmask::MaskDeserialize;

#[derive(MaskDeserialize)]
#[serde(rename_all = "camelCase")]
struct ExfilManifest {
    field_name: String,
}

fn main() {}
