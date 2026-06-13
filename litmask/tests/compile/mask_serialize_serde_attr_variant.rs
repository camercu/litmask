//! `MaskSerialize` reject-loud on a not-yet-supported variant-level
//! `#[serde(...)]` key: silently ignoring `other` would break the
//! wire-format-identity contract without warning.

use litmask::MaskSerialize;

#[derive(MaskSerialize)]
enum CovertChannel {
    #[serde(other)]
    Dns { hostname: String },
}

fn main() {}
