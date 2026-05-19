//! `mask_file!` accepts no arguments per spec §2.1.8.1.

use litmask::mask_file;

fn main() {
    let _: String = mask_file!(42);
}
