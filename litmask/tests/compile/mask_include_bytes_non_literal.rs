//! `mask_include_bytes!` rejects non-string-literal paths with the
//! spec §2.1.4.3 substring "mask_include_bytes! requires a string
//! literal path".

use litmask::mask_include_bytes;

fn main() {
    let path = "examples/fixtures/binary_blob.bin";
    let _ = mask_include_bytes!(path);
}
