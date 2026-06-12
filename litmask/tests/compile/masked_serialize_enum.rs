//! `MaskedSerialize` must reject enums loudly — silently degrading
//! to cleartext names would defeat the opt-in masking.

use litmask::MaskedSerialize;

#[derive(MaskedSerialize)]
enum CovertChannel {
    Dns { hostname: String },
}

fn main() {}
