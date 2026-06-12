//! `MaskSerialize` must reject unit structs — only named-field
//! structs carry maskable field names.

use litmask::MaskSerialize;

#[derive(MaskSerialize)]
struct NothingToMask;

fn main() {}
