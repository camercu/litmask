//! `mask!(include_str!(...))` propagates the underlying file-read
//! error so users see the exact path that could not be opened. The
//! snapshot below locks the error format; it must echo the user's
//! literal path (not the resolved absolute path) for portability.

use litmask::mask;

fn main() {
    let _ = mask!(include_str!("examples/fixtures/does_not_exist.txt"));
}
