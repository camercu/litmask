//! Demonstrates `mask!(b"...")` and `mask!(c"...")`.
//!
//! Both fixtures use lexically unusual phrases so the integration
//! test that asserts each one is absent from the compiled binary
//! cannot false-positive against std / dependency text.

use litmask::mask;
use std::ffi::CString;

fn main() {
    // The byte-literal fixture is a printable ASCII run wrapped in two
    // non-printable bytes so `strings(1)` extracts the middle as a
    // single token, keeping the absence assertion precise.
    let bytes: Vec<u8> = mask!(b"\x01scarlet-onyx-narwhal-c8d7e9\x02");
    let cstr: CString = mask!(c"navy-velvet-quokka-3f1a7b — fixture");

    println!("bytes={bytes:?}");
    println!("cstr={cstr:?}");
}
