//! Integration tests for `weak_mask!(c"...")` — pre-`init!()` C string
//! obfuscation returning `&'static CStr`.
//!
//! Mirrors `weak_mask.rs` test structure. Does NOT call `init!()`
//! — `weak_mask!` must decode independently of the AEAD runtime.

use std::ffi::CStr;

use litmask::weak_mask;

#[test]
fn weak_mask_cstr_round_trips() {
    let decoded: &'static CStr = weak_mask!(c"hello cstr");
    assert_eq!(decoded, c"hello cstr");
}

#[test]
fn weak_mask_cstr_empty() {
    let decoded = weak_mask!(c"");
    assert_eq!(decoded, c"");
}

#[test]
fn weak_mask_cstr_multibyte_utf8() {
    let decoded = weak_mask!(c"héllo — wörld 🦀");
    assert_eq!(decoded, c"héllo — wörld 🦀");
}

#[test]
fn weak_mask_cstr_longer_than_wrapper() {
    let decoded = weak_mask!(
        c"padding-test-padding-test-padding-test-padding-test-padding-test-padding-test-padding-test-aaaa"
    );
    assert_eq!(
        decoded,
        c"padding-test-padding-test-padding-test-padding-test-padding-test-padding-test-padding-test-aaaa"
    );
}

#[test]
fn weak_mask_cstr_returns_static_ref_stable_across_calls() {
    fn call() -> &'static CStr {
        weak_mask!(c"STABLE_CSTR_REF")
    }
    let a = call();
    let b = call();
    assert_eq!(a.as_ptr(), b.as_ptr());
    assert_eq!(a, c"STABLE_CSTR_REF");
}
