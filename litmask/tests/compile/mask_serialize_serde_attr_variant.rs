//! `MaskSerialize` must reject `#[serde(...)]` on an enum variant —
//! silently ignoring `rename` would break the wire-format-identity
//! contract without warning.

use litmask::MaskSerialize;

#[derive(MaskSerialize)]
enum CovertChannel {
    #[serde(rename = "dns")]
    Dns { hostname: String },
}

fn main() {}
