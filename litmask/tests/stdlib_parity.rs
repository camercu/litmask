//! Drop-in parity: every `mask_*!` macro produces the same value as
//! its stdlib counterpart for the same inputs. Each test asserts
//! `mask_*` byte-equals the stdlib equivalent, so any future
//! divergence from stdlib behavior fails here. Compile-time-error
//! parity (e.g. unused args, missing files) is locked separately by
//! the trybuild fixtures under `tests/compile/`.

mod common;

use std::ffi::CString;

use litmask::{
    mask, mask_concat, mask_env, mask_file, mask_format, mask_include_bytes, mask_include_str,
    mask_option_env,
};

#[test]
fn mask_matches_str_literal() {
    let s: String = mask!("vermilion-axolotl");
    assert_eq!(s, "vermilion-axolotl");
}

#[test]
fn mask_matches_byte_literal() {
    let v: Vec<u8> = mask!(b"\x00\xff\x7f-bytes");
    assert_eq!(v, b"\x00\xff\x7f-bytes");
}

#[test]
fn mask_matches_cstr_literal() {
    let c: CString = mask!(c"cobalt-narwhal");
    assert_eq!(c.as_c_str(), c"cobalt-narwhal");
}

#[test]
fn mask_format_matches_format() {
    let w = 6;
    let name = "rust";
    assert_eq!(
        mask_format!(
            "{name} | {:>width$} | {:.2} | {:#x}",
            42,
            1.23456,
            255u32,
            width = w
        ),
        format!(
            "{name} | {:>width$} | {:.2} | {:#x}",
            42,
            1.23456,
            255u32,
            width = w
        ),
    );
}

#[test]
fn mask_concat_matches_concat() {
    let s: String = mask_concat!(
        "s=", "a", " i=", 0x10, " f=", 1.5e2, " b=", true, " c=", 'X', -3
    );
    assert_eq!(
        s,
        concat!(
            "s=", "a", " i=", 0x10, " f=", 1.5e2, " b=", true, " c=", 'X', -3
        ),
    );
}

#[test]
fn mask_concat_empty_matches_concat() {
    let s: String = mask_concat!();
    assert_eq!(s, concat!());
}

#[test]
fn mask_env_matches_env() {
    // CARGO_PKG_NAME is always set during the build of this crate.
    let s: String = mask_env!("CARGO_PKG_NAME");
    assert_eq!(s, env!("CARGO_PKG_NAME"));
}

#[test]
fn mask_option_env_present_matches_option_env() {
    let s: Option<String> = mask_option_env!("CARGO_PKG_NAME");
    assert_eq!(s.as_deref(), option_env!("CARGO_PKG_NAME"));
}

#[test]
fn mask_option_env_absent_matches_option_env() {
    let s: Option<String> = mask_option_env!("LITMASK_PARITY_DEFINITELY_UNSET_Q9Z");
    assert_eq!(
        s.as_deref(),
        option_env!("LITMASK_PARITY_DEFINITELY_UNSET_Q9Z"),
    );
    assert_eq!(s, None);
}

#[test]
fn mask_file_matches_file() {
    let s: String = mask_file!();
    assert_eq!(s, file!());
}

#[test]
fn mask_include_str_matches_include_str() {
    let s: String = mask_include_str!("../examples/fixtures/noc_list.txt");
    assert_eq!(s, include_str!("../examples/fixtures/noc_list.txt"));
}

#[test]
fn mask_include_bytes_matches_include_bytes() {
    let v: Vec<u8> = mask_include_bytes!("../examples/fixtures/binary_blob.bin");
    assert_eq!(v, include_bytes!("../examples/fixtures/binary_blob.bin"));
}
