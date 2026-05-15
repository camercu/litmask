//! Round-trip integration tests for `mask!` against byte string and
//! C string literals (Task 6 / spec §2.1.1.1, §2.1.1.3, §2.1.1.4).
//!
//! Tests are written test-first per the prove-it pattern: against the
//! pre-Task-6 macro, `mask!(b"...")` and `mask!(c"...")` fail at compile
//! time with `expected string literal`, so this file does not compile
//! against the old codebase. Once the macro dispatches on all three
//! literal kinds and the two runtime helpers exist, the file compiles
//! and the assertions hold.
//!
//! The tests use `init_with!` + a static `KeyProvider` so they do not
//! depend on `LITMASK_UNLOCK_KEY` being set in the test process's
//! environment.

mod common;

use litmask::{KeyError, KeyProvider, UnlockKey, init_with, mask};
use std::ffi::CString;
use std::sync::Once;

struct StaticProvider {
    key_b64: String,
}

impl KeyProvider for StaticProvider {
    fn unlock_key(&self) -> Result<UnlockKey, KeyError> {
        UnlockKey::from_base64url(&self.key_b64)
    }
}

static INIT: Once = Once::new();

fn setup() {
    INIT.call_once(|| {
        let key = common::read_unlock_key(&common::config_path(common::Profile::Debug));
        let provider = StaticProvider { key_b64: key };
        init_with!(provider).expect("init_with succeeded");
    });
}

#[test]
fn mask_byte_literal_returns_vec_of_bytes() {
    setup();
    let v: Vec<u8> = mask!(b"\x01\x02\x03");
    assert_eq!(v, vec![1, 2, 3]);
}

#[test]
fn mask_byte_literal_empty_round_trips() {
    setup();
    let v: Vec<u8> = mask!(b"");
    assert!(v.is_empty());
}

#[test]
fn mask_byte_literal_with_full_byte_range_including_nul() {
    setup();
    let v: Vec<u8> = mask!(b"\x00\xff\x7f\x80\xab");
    assert_eq!(v, vec![0x00, 0xff, 0x7f, 0x80, 0xab]);
}

#[test]
fn mask_c_string_literal_returns_cstring_with_terminator() {
    setup();
    let c: CString = mask!(c"hello");
    assert_eq!(c.to_bytes(), b"hello");
    assert_eq!(c.as_bytes_with_nul(), b"hello\0");
}

#[test]
fn mask_c_string_literal_with_multibyte_utf8() {
    setup();
    let c: CString = mask!(c"héllo — wörld 🦀");
    assert_eq!(c.to_bytes(), "héllo — wörld 🦀".as_bytes());
}

#[test]
fn mask_c_string_literal_empty_round_trips() {
    setup();
    let c: CString = mask!(c"");
    assert!(c.to_bytes().is_empty());
    assert_eq!(c.as_bytes_with_nul(), b"\0");
}

/// Locks the contract that raw byte / raw C string literals dispatch
/// through the same arms as their non-raw siblings. `syn::LitByteStr`
/// and `syn::LitCStr` strip the `r` prefix and de-escape uniformly, so
/// from the macro's perspective `br"..."` and `b"..."` are
/// indistinguishable — but a regression in syn or our `Parse` impl
/// could surface here.
#[test]
fn mask_raw_byte_and_c_string_literals_round_trip() {
    setup();
    let v: Vec<u8> = mask!(br"raw \n stays literal");
    assert_eq!(v, br"raw \n stays literal");

    let c: CString = mask!(cr"raw \n stays literal");
    assert_eq!(c.to_bytes(), br"raw \n stays literal");
}

#[test]
fn mask_string_literal_returns_string_unchanged() {
    // Regression net: §2.1.1.2 string-literal behavior is preserved by
    // the dispatch change.
    setup();
    let s: String = mask!("hello");
    assert_eq!(s, "hello");
}
