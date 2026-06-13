//! `MaskSerialize` reject-loud on a not-yet-supported container-level
//! `#[serde(...)]` key: silently ignoring an alternate enum
//! representation (`tag`) would change the wire format.

use litmask::MaskSerialize;

#[derive(MaskSerialize)]
#[serde(tag = "type")]
struct ExfilManifest {
    field_name: String,
}

fn main() {}
