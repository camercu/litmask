//! `mask_option_env!` rejects non-string-literal names per spec
//! §2.1.7.4.

use litmask::mask_option_env;

fn main() {
    let name = "CARGO_PKG_NAME";
    let _: Option<String> = mask_option_env!(name);
}
