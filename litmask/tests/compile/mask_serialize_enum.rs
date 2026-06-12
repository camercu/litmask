//! `MaskSerialize` must reject enums loudly — silently degrading
//! to cleartext names would defeat the opt-in masking.

use litmask::MaskSerialize;

#[derive(MaskSerialize)]
enum CovertChannel {
    Dns { hostname: String },
}

fn main() {}
