//! `mask!` accepts only `include_str!` and `concat!` as nested macro
//! invocations; any other macro must fall through to the standard
//! rejection.

use litmask::mask;

fn main() {
    let _ = mask!(vec![1, 2, 3]);
}
