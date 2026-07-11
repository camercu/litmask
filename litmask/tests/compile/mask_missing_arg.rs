//! An empty `mask!()` is `missing-arg`, not `non-literal` (§1.9.6): the
//! fix is to supply an argument, not to change an existing one's kind.

use litmask::mask;

fn main() {
    let _ = mask!();
}
