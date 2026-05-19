//! `mask_include_str!` rejects a missing file at proc-macro time
//! with the spec §2.1.3.4 substring "mask_include_str!: could not
//! read".

use litmask::mask_include_str;

fn main() {
    let _ = mask_include_str!("examples/fixtures/this_file_does_not_exist.txt");
}
