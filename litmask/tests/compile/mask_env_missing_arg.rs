//! An empty `mask_env!()` is `missing-arg`, not `non-literal` (§1.9.6).

use litmask::mask_env;

fn main() {
    let _: String = mask_env!();
}
