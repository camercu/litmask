//! Demonstrates `mask!(b"...")` and `mask!(c"...")` (Task 6 /
//! §2.1.1.3, §2.1.1.4).
//!
//! Both fixtures are deliberately lexically unusual phrases so the
//! integration test that asserts each one is absent from the compiled
//! binary's `strings` output cannot false-positive against std /
//! dependency text.

use litmask::mask;
use std::ffi::CString;

fn main() {
    // The byte-literal fixture is a printable ASCII run wrapped in two
    // non-printable bytes so `strings(1)` extracts the middle as a
    // single token — making the absence assertion in
    // `tests/example_scrub.rs` precise.
    let bytes: Vec<u8> = mask!(b"\x01scarlet-onyx-narwhal-c8d7e9\x02");
    let cstr: CString = mask!(c"navy-velvet-quokka-3f1a7b — fixture");

    println!("bytes={bytes:?}");
    println!("cstr={cstr:?}");
}
