//! `MaskDeserialize` must reject `#[serde(...)]` on an enum variant —
//! silently ignoring `rename` would break the behavior-identity
//! contract without warning.

use litmask::MaskDeserialize;

#[derive(MaskDeserialize)]
enum CovertChannel {
    #[serde(rename = "dns")]
    Dns { hostname: String },
}

fn main() {}
