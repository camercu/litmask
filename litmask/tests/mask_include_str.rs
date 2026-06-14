//! `mask_include_str!` round-trips the file's UTF-8 content as a
//! `String` at runtime; the literal text never appears in the
//! compiled binary's plaintext (the scrub test in
//! `tests/example_scrub.rs` locks the absence half).
//!
//! Path resolution mirrors stdlib `include_str!` exactly: relative to
//! the directory of the source file containing the invocation. The
//! parity test below pins that contract.

mod common;

use litmask::mask_include_str;

#[test]
fn mask_include_str_round_trips_to_string() {
    let s: String = mask_include_str!("../examples/fixtures/noc_list.txt");
    assert!(s.contains("Non-Official Cover (NOC) List"));
}

#[test]
fn mask_include_str_two_call_sites_decode_independently() {
    let a: String = mask_include_str!("../examples/fixtures/noc_list.txt");
    let b: String = mask_include_str!("../examples/fixtures/noc_list.txt");
    assert_eq!(a, b);
}

#[test]
fn mask_include_str_resolves_like_stdlib_include_str() {
    // Same path literal, same call-site file: the masked result MUST
    // equal what stdlib `include_str!` produces, proving file-relative
    // resolution parity.
    let masked: String = mask_include_str!("../examples/fixtures/noc_list.txt");
    let std_str: &str = include_str!("../examples/fixtures/noc_list.txt");
    assert_eq!(masked, std_str);
}
