//! Integration tests for the public `weak_mask!()` macro.
//!
//! Verifies round-trip decoding of obfuscated string literals across
//! ASCII, empty, multi-byte UTF-8, and key-cycling-length cases, plus
//! the pointer-stability (`&'static str` returned by a per-call-site
//! cache) contract.

use litmask::weak_mask;

#[test]
fn weak_mask_ascii_round_trips() {
    let decoded = weak_mask!("LITMASK_TEST_ASCII");
    assert_eq!(decoded, "LITMASK_TEST_ASCII");
}

#[test]
fn weak_mask_empty_literal() {
    let decoded = weak_mask!("");
    assert_eq!(decoded, "");
}

#[test]
fn weak_mask_multibyte_utf8() {
    let decoded = weak_mask!("héllo — wörld 🦀");
    assert_eq!(decoded, "héllo — wörld 🦀");
}

#[test]
fn weak_mask_literal_longer_than_wrapper() {
    // Wrapper is 62 bytes; this literal is 96 bytes, forcing the
    // XOR-cycle path to wrap around. Decoded value must still match.
    let decoded = weak_mask!(
        "padding-test-padding-test-padding-test-padding-test-padding-test-padding-test-padding-test-aaaa"
    );
    assert_eq!(
        decoded,
        "padding-test-padding-test-padding-test-padding-test-padding-test-padding-test-padding-test-aaaa"
    );
}

#[test]
fn weak_mask_returns_static_str_stable_across_calls() {
    fn call() -> &'static str {
        weak_mask!("LITMASK_TEST_STABLE_REF")
    }
    let a: &'static str = call();
    let b: &'static str = call();
    // Caching contract: repeated expansion-of-the-same-call-site reuses
    // the OnceLock<String> backing storage, so the pointers match.
    assert_eq!(a.as_ptr(), b.as_ptr());
    assert_eq!(a, "LITMASK_TEST_STABLE_REF");
    assert_eq!(b, "LITMASK_TEST_STABLE_REF");
}
