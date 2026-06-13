//! `MaskDeserialize` reject-loud on a not-yet-supported container-level
//! `#[serde(...)]` key: silently ignoring an alternate enum
//! representation (`tag`) would accept different inputs than the plain
//! derive.

use litmask::MaskDeserialize;

#[derive(MaskDeserialize)]
#[serde(tag = "type")]
struct ExfilManifest {
    field_name: String,
}

fn main() {}
