//! Integration tests for `unmasked!` (spec §2.1.2). The macro is an
//! identity over the three accepted literal kinds; this file proves
//! both the round-trip and the type-preservation guarantees, plus
//! the §2.1.2.4 zero-overhead property via const-context evaluation.

use litmask::unmasked;
use std::ffi::CStr;

#[test]
fn unmasked_string_literal_yields_static_str() {
    let s: &str = unmasked!("plain");
    assert_eq!(s, "plain");
}

#[test]
fn unmasked_byte_string_literal_yields_static_array_reference() {
    let b: &[u8; 3] = unmasked!(b"abc");
    assert_eq!(b, b"abc");
}

#[test]
fn unmasked_c_string_literal_yields_static_cstr() {
    let c: &CStr = unmasked!(c"hi");
    assert_eq!(c.to_bytes(), b"hi");
    assert_eq!(c.to_bytes_with_nul(), b"hi\0");
}

/// `const` context evaluation locks the §2.1.2.4 zero-overhead
/// contract: only an expression of `&'static str` (the bare literal)
/// can initialize a `const` of that type. Any runtime decoding or
/// allocation would fail to compile here.
#[test]
fn unmasked_string_literal_is_const_evaluable() {
    const X: &str = unmasked!("static");
    assert_eq!(X, "static");
}

/// Same const-context lock for byte string literals.
#[test]
fn unmasked_byte_string_literal_is_const_evaluable() {
    const X: &[u8; 5] = unmasked!(b"bytes");
    assert_eq!(X, b"bytes");
}

/// Raw forms (`r"…"`, `br"…"`, `cr"…"`) must dispatch through the
/// same arms as their non-raw siblings — the proc-macro should not
/// care whether the source spelling included the `r` prefix.
#[test]
fn unmasked_raw_string_byte_and_cstr_literals_work() {
    let s: &str = unmasked!(r"raw\nstays literal");
    assert_eq!(s, "raw\\nstays literal");

    let b: &[u8; 18] = unmasked!(br"raw\nstays literal");
    assert_eq!(b, b"raw\\nstays literal");

    let c: &CStr = unmasked!(cr"raw\nstays literal");
    assert_eq!(c.to_bytes(), b"raw\\nstays literal");
}

#[test]
fn unmasked_empty_string_literal_works() {
    let s: &str = unmasked!("");
    assert!(s.is_empty());
}

#[test]
fn unmasked_empty_byte_string_literal_yields_zero_length_array() {
    let b: &[u8; 0] = unmasked!(b"");
    assert_eq!(b, b"");
}

#[test]
fn unmasked_empty_c_string_literal_carries_only_terminator() {
    let c: &CStr = unmasked!(c"");
    assert!(c.to_bytes().is_empty());
    assert_eq!(c.to_bytes_with_nul(), b"\0");
}

#[test]
fn unmasked_multibyte_utf8_string_passes_through_unchanged() {
    let s: &str = unmasked!("héllo — wörld 🦀");
    assert_eq!(s, "héllo — wörld 🦀");
}
