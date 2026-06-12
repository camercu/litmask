//! `MaskSerialize` must reject tuple structs — only named-field
//! structs carry maskable field names.

use litmask::MaskSerialize;

#[derive(MaskSerialize)]
struct BeaconPair(String, u32);

fn main() {}
