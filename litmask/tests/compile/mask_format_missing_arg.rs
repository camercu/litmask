//! An empty `mask_format!()` is `missing-arg`, not `non-literal` (§1.9.6).

use litmask::mask_format;

fn main() {
    let _ = mask_format!();
}
