//! `MaskDeserialize` reject-loud on a not-yet-supported variant-level
//! `#[serde(...)]` key: silently ignoring `other` would break the
//! behavior-identity contract without warning.

use litmask::MaskDeserialize;

#[derive(MaskDeserialize)]
enum CovertChannel {
    #[serde(other)]
    Dns { hostname: String },
}

fn main() {}
