//! Integration tests for the public `weak_mask!()` macro — the
//! pre-`init!()` obfuscation path for bootstrap-phase strings.
//!
//! These tests deliberately do NOT call `init!()`: `weak_mask!` must
//! decode independently of the AEAD runtime, using only the wrapper
//! bytes baked into the binary at compile time.
//!
//! Verifies round-trip decoding across ASCII, empty, multi-byte UTF-8,
//! and key-cycling-length cases, plus the pointer-stability
//! (`&'static str` returned by a per-call-site cache) contract.

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
    // The weak XOR key is 64 bytes; this literal is longer, so the
    // XOR-cycle path wraps the key around. Decoded value must still match.
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
    // the OnceLock<String> backing storage, so the pointers match. `b`'s
    // value needs no separate assertion — sharing `a`'s backing (asserted
    // here) means it holds the same bytes.
    assert_eq!(a.as_ptr(), b.as_ptr());
    assert_eq!(a, "LITMASK_TEST_STABLE_REF");
}
