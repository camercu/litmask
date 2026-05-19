//! `mask_include_bytes!` rejects a missing file at proc-macro time
//! with the spec §2.1.4.4 substring "mask_include_bytes!: could not
//! read".

use litmask::mask_include_bytes;

fn main() {
    let _ = mask_include_bytes!("examples/fixtures/this_file_does_not_exist.bin");
}
