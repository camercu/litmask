//! Integration tests for `weak_mask!(b"...")` — pre-`init!()` byte
//! string obfuscation returning `&'static [u8]`.
//!
//! Mirrors `weak_mask.rs` test structure. Does NOT call `init!()`
//! — `weak_mask!` must decode independently of the AEAD runtime.

use litmask::weak_mask;

#[test]
fn weak_mask_bytes_round_trips() {
    let decoded: &'static [u8] = weak_mask!(b"hello bytes");
    assert_eq!(decoded, b"hello bytes");
}

#[test]
fn weak_mask_bytes_empty() {
    let decoded = weak_mask!(b"");
    assert_eq!(decoded, b"");
}

#[test]
fn weak_mask_bytes_non_utf8() {
    let decoded = weak_mask!(b"\xff\x00\x01\xfe");
    assert_eq!(decoded, b"\xff\x00\x01\xfe");
}

#[test]
fn weak_mask_bytes_longer_than_wrapper() {
    let decoded = weak_mask!(
        b"padding-test-padding-test-padding-test-padding-test-padding-test-padding-test-padding-test-aaaa"
    );
    assert_eq!(
        decoded,
        b"padding-test-padding-test-padding-test-padding-test-padding-test-padding-test-padding-test-aaaa"
    );
}

#[test]
fn weak_mask_bytes_returns_static_ref_stable_across_calls() {
    fn call() -> &'static [u8] {
        weak_mask!(b"STABLE_BYTES_REF")
    }
    let a = call();
    let b = call();
    assert_eq!(a.as_ptr(), b.as_ptr());
    assert_eq!(a, b"STABLE_BYTES_REF");
}
