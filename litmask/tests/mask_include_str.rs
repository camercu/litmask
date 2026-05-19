//! `mask_include_str!` round-trips the file's UTF-8 content as a
//! `String` at runtime; the literal text never appears in the
//! compiled binary's plaintext (the scrub test in
//! `tests/example_scrub.rs` locks the absence half).

mod common;

use litmask::mask_include_str;

#[test]
fn mask_include_str_round_trips_to_string() {
    common::init_once();
    let s: String = mask_include_str!("examples/fixtures/quote.txt");
    assert!(s.contains("vermilion-axolotl-7e2d4a"));
}

#[test]
fn mask_include_str_two_call_sites_decode_independently() {
    common::init_once();
    let a: String = mask_include_str!("examples/fixtures/quote.txt");
    let b: String = mask_include_str!("examples/fixtures/quote.txt");
    assert_eq!(a, b);
}
