//! `mask_concat!` resolves string literals and nested
//! `concat!` / `include_str!` / `env!` invocations at proc-macro
//! time, then masks the concatenated result as a single `String`.
//!
//! The zero-argument case mirrors stdlib `concat!()` → `""` (not an
//! error); pinned by `mask_concat_empty_matches_stdlib` below.

mod common;

use litmask::mask_concat;

#[test]
fn mask_concat_string_literals_round_trip() {
    let s: String = mask_concat!("a", "b", "c");
    assert_eq!(s, "abc");
}

#[test]
fn mask_concat_single_literal_round_trip() {
    let s: String = mask_concat!("solo");
    assert_eq!(s, "solo");
}

#[test]
fn mask_concat_nested_concat() {
    let s: String = mask_concat!("prefix-", concat!("inner-", "part"));
    assert_eq!(s, "prefix-inner-part");
}

#[test]
fn mask_concat_nested_include_str() {
    let s: String = mask_concat!("prefix:", include_str!("../examples/fixtures/noc_list.txt"));
    assert!(s.starts_with("prefix:"));
    assert!(s.contains("Non-Official Cover (NOC) List"));
}

#[test]
fn mask_concat_nested_env_var() {
    // CARGO_PKG_NAME is always set during cargo build for the
    // litmask crate.
    let s: String = mask_concat!("crate=", env!("CARGO_PKG_NAME"));
    assert_eq!(s, "crate=litmask");
}

#[test]
fn mask_concat_accepts_every_stdlib_literal_kind() {
    // Mirror stdlib `concat!` grammar: string + integer + float +
    // bool + char + nested concat / include_str / env. Each
    // primitive literal is stringified at proc-macro time.
    let s: String = mask_concat!("s=", "abc", " i=", 42, " f=", 2.5, " b=", true, " c=", 'X');
    assert_eq!(s, "s=abc i=42 f=2.5 b=true c=X");
}

#[test]
fn mask_concat_integer_only() {
    let s: String = mask_concat!(7);
    assert_eq!(s, "7");
}

#[test]
fn mask_concat_negative_integer() {
    let s: String = mask_concat!("n=", -3);
    assert_eq!(s, "n=-3");
}

#[test]
fn mask_concat_empty_matches_stdlib() {
    // Stdlib `concat!()` yields `""`; `mask_concat!()` mirrors that.
    let s: String = mask_concat!();
    assert_eq!(s, concat!());
    assert_eq!(s, "");
}

#[test]
fn mask_concat_integer_radixes_match_stdlib() {
    // Hex/octal/binary integer literals stringify to decimal, exactly
    // like stdlib `concat!`.
    let s: String = mask_concat!(0x10, "-", 0o17, "-", 0b101, "-", 1_000);
    assert_eq!(s, concat!(0x10, "-", 0o17, "-", 0b101, "-", 1_000));
    assert_eq!(s, "16-15-5-1000");
}

#[test]
fn mask_concat_float_forms_match_stdlib() {
    // Plain, fractional, and exponent float literals stringify
    // identically to stdlib `concat!`.
    let s: String = mask_concat!(1.0, "-", 1e3, "-", 1.5e2, "-", 2.5f64);
    assert_eq!(s, concat!(1.0, "-", 1e3, "-", 1.5e2, "-", 2.5f64));
    assert_eq!(s, "1.0-1e3-1.5e2-2.5");
}

#[test]
fn mask_concat_nested_empty_concat_matches_stdlib() {
    let s: String = mask_concat!("a", concat!(), "b");
    assert_eq!(s, concat!("a", concat!(), "b"));
    assert_eq!(s, "ab");
}
