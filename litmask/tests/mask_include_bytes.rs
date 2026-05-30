//! `mask_include_bytes!` round-trips the file's raw bytes as a
//! `Vec<u8>`; bytes never appear in compiled binary plaintext.
//!
//! Path resolution mirrors stdlib `include_bytes!` exactly: relative
//! to the directory of the source file containing the invocation.

mod common;

use litmask::mask_include_bytes;

#[test]
fn mask_include_bytes_round_trips_to_vec() {
    common::init_once();
    let bytes: Vec<u8> = mask_include_bytes!("../examples/fixtures/binary_blob.bin");
    let expected = "cobalt-narwhal-9c4e72-bytes-fixture";
    let s = std::str::from_utf8(&bytes).expect("fixture is UTF-8");
    assert!(s.contains(expected));
}

#[test]
fn mask_include_bytes_two_call_sites_decode_independently() {
    common::init_once();
    let a: Vec<u8> = mask_include_bytes!("../examples/fixtures/binary_blob.bin");
    let b: Vec<u8> = mask_include_bytes!("../examples/fixtures/binary_blob.bin");
    assert_eq!(a, b);
}

#[test]
fn mask_include_bytes_resolves_like_stdlib_include_bytes() {
    common::init_once();
    // Masked result MUST equal stdlib `include_bytes!` for the same
    // path literal at the same call-site, proving file-relative parity.
    let masked: Vec<u8> = mask_include_bytes!("../examples/fixtures/binary_blob.bin");
    let std_bytes: &[u8] = include_bytes!("../examples/fixtures/binary_blob.bin");
    assert_eq!(masked, std_bytes);
}
