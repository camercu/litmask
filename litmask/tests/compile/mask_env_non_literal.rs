//! `mask_env!` rejects non-string-literal names per spec §2.1.6.4.

use litmask::mask_env;

fn main() {
    let name = "CARGO_PKG_NAME";
    let _: String = mask_env!(name);
}
