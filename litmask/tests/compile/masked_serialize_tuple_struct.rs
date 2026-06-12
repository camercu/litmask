//! `MaskedSerialize` must reject tuple structs — only named-field
//! structs carry maskable field names.

use litmask::MaskedSerialize;

#[derive(MaskedSerialize)]
struct BeaconPair(String, u32);

fn main() {}
