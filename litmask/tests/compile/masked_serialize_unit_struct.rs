//! `MaskedSerialize` must reject unit structs — only named-field
//! structs carry maskable field names.

use litmask::MaskedSerialize;

#[derive(MaskedSerialize)]
struct NothingToMask;

fn main() {}
