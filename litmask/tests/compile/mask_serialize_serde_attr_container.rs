//! `MaskSerialize` must reject container-level `#[serde(...)]`
//! attributes — honoring none of them silently (e.g. `rename_all`)
//! would serialize under different names than the plain derive.

use litmask::MaskSerialize;

#[derive(MaskSerialize)]
#[serde(rename_all = "camelCase")]
struct ExfilManifest {
    field_name: String,
}

fn main() {}
