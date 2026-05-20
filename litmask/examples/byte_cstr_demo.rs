//! `mask!(b"...")` → `Vec<u8>` and `mask!(c"...")` → `CString`. Use
//! byte literals for embedded keys or non-UTF-8 payloads; C strings
//! for FFI calls that expect NUL-terminated data.
//!
//! Verify masking via the strings/grep recipe in `hello_world.rs`.

use litmask::mask;
use std::ffi::CString;

fn main() {
    // The byte fixture is wrapped in two non-printable bytes so
    // `strings(1)` extracts the middle as one token, keeping the
    // absence assertion precise.
    let bytes: Vec<u8> = mask!(b"\x01scarlet-onyx-narwhal-c8d7e9\x02");
    let cstr: CString = mask!(c"navy-velvet-quokka-3f1a7b — fixture");

    println!("bytes={bytes:?}");
    println!("cstr={cstr:?}");
}
