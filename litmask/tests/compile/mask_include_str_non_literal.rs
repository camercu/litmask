//! `mask_include_str!` rejects non-string-literal paths with the
//! spec §2.1.3.3 substring "mask_include_str! requires a string
//! literal path".

use litmask::mask_include_str;

fn main() {
    let path = "examples/fixtures/noc_list.txt";
    let _ = mask_include_str!(path);
}
