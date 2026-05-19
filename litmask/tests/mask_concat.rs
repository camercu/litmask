//! `mask_concat!` resolves string literals and nested
//! `concat!` / `include_str!` / `env!` invocations at proc-macro
//! time, then masks the concatenated result as a single `String`.

mod common;

use litmask::mask_concat;

#[test]
fn mask_concat_string_literals_round_trip() {
    common::init_once();
    let s: String = mask_concat!("a", "b", "c");
    assert_eq!(s, "abc");
}

#[test]
fn mask_concat_single_literal_round_trip() {
    common::init_once();
    let s: String = mask_concat!("solo");
    assert_eq!(s, "solo");
}

#[test]
fn mask_concat_nested_concat() {
    common::init_once();
    let s: String = mask_concat!("prefix-", concat!("inner-", "part"));
    assert_eq!(s, "prefix-inner-part");
}

#[test]
fn mask_concat_nested_include_str() {
    common::init_once();
    let s: String = mask_concat!("prefix:", include_str!("examples/fixtures/quote.txt"));
    assert!(s.starts_with("prefix:"));
    assert!(s.contains("vermilion-axolotl-7e2d4a"));
}

#[test]
fn mask_concat_nested_env_var() {
    common::init_once();
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
    common::init_once();
    let s: String = mask_concat!("s=", "abc", " i=", 42, " f=", 2.5, " b=", true, " c=", 'X');
    assert_eq!(s, "s=abc i=42 f=2.5 b=true c=X");
}

#[test]
fn mask_concat_integer_only() {
    common::init_once();
    let s: String = mask_concat!(7);
    assert_eq!(s, "7");
}

#[test]
fn mask_concat_negative_integer() {
    common::init_once();
    let s: String = mask_concat!("n=", -3);
    assert_eq!(s, "n=-3");
}
