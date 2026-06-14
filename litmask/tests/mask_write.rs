//! Integration tests for `mask_write!` and `mask_writeln!`.
//!
//! These macros are thin wrappers around `mask_format!` that write to
//! an arbitrary `impl core::fmt::Write` or `impl std::io::Write`
//! destination. Format-string correctness is locked by `mask_format.rs`;
//! these tests verify compilation, runtime execution (no panic), output
//! equality with `write!`/`writeln!`, and argument-pattern coverage.

mod common;

use std::fmt::Write as _;

use litmask::{mask_write, mask_writeln};

// ── mask_writeln! with fmt::Write ───────────────────────────────

#[test]
fn mask_writeln_fmt_no_args() {
    let mut buf = String::new();
    mask_writeln!(buf).unwrap();
    assert_eq!(buf, "\n");
}

#[test]
fn mask_writeln_fmt_static_text() {
    let mut buf = String::new();
    mask_writeln!(buf, "hello world").unwrap();
    assert_eq!(buf, "hello world\n");
}

#[test]
fn mask_writeln_fmt_positional_args() {
    let mut buf = String::new();
    mask_writeln!(buf, "x={}, y={:.2}", 1, 2.5).unwrap();

    let mut expected = String::new();
    writeln!(expected, "x={}, y={:.2}", 1, 2.5).unwrap();
    assert_eq!(buf, expected);
}

#[test]
fn mask_writeln_fmt_named_args() {
    let mut buf = String::new();
    mask_writeln!(buf, "{x} {y}", x = 1, y = 2).unwrap();
    assert_eq!(buf, "1 2\n");
}

#[test]
fn mask_writeln_fmt_implicit_capture() {
    let var = 42;
    let mut buf = String::new();
    mask_writeln!(buf, "{var}").unwrap();
    assert_eq!(buf, "42\n");
}

#[test]
fn mask_writeln_fmt_debug_specifier() {
    let mut buf = String::new();
    mask_writeln!(buf, "v={:?}", vec![1, 2, 3]).unwrap();

    let mut expected = String::new();
    writeln!(expected, "v={:?}", vec![1, 2, 3]).unwrap();
    assert_eq!(buf, expected);
}

// ── mask_write! with fmt::Write ─────────────────────────────────

#[test]
fn mask_write_fmt_static_text() {
    let mut buf = String::new();
    mask_write!(buf, "hello").unwrap();
    assert_eq!(buf, "hello");
}

#[test]
fn mask_write_fmt_positional_args() {
    let mut buf = String::new();
    mask_write!(buf, "x={}, y={}", 1, 2).unwrap();
    assert_eq!(buf, "x=1, y=2");
}

#[test]
fn mask_write_fmt_named_args() {
    let mut buf = String::new();
    mask_write!(buf, "{name}", name = "test").unwrap();
    assert_eq!(buf, "test");
}

#[test]
fn mask_write_fmt_mixed_positional_and_named() {
    let mut buf = String::new();
    mask_write!(buf, "{x} {} {y}", "pos", x = 1, y = 2).unwrap();
    assert_eq!(buf, "1 pos 2");
}

#[test]
fn mask_write_fmt_empty_template() {
    let mut buf = String::new();
    mask_write!(buf, "").unwrap();
    assert_eq!(buf, "");
}

// ── mask_write! with io::Write ──────────────────────────────────

#[test]
fn mask_write_io_vec_buffer() {
    use std::io::Write as _;
    let mut buf: Vec<u8> = Vec::new();
    mask_write!(buf, "bytes={}", 42).unwrap();
    assert_eq!(buf, b"bytes=42");
}

#[test]
fn mask_writeln_io_vec_buffer() {
    use std::io::Write as _;
    let mut buf: Vec<u8> = Vec::new();
    mask_writeln!(buf, "line={}", 1).unwrap();
    assert_eq!(buf, b"line=1\n");
}

#[test]
fn mask_writeln_io_no_args() {
    use std::io::Write as _;
    let mut buf: Vec<u8> = Vec::new();
    mask_writeln!(buf).unwrap();
    assert_eq!(buf, b"\n");
}

// ── edge cases ──────────────────────────────────────────────────

#[test]
fn mask_writeln_fmt_empty_template() {
    let mut buf = String::new();
    mask_writeln!(buf, "").unwrap();
    assert_eq!(buf, "\n");
}

struct FailWriter;

impl std::fmt::Write for FailWriter {
    fn write_str(&mut self, _: &str) -> std::fmt::Result {
        Err(std::fmt::Error)
    }
}

#[test]
fn mask_write_fmt_fail_writer_propagates_error() {
    let result = mask_write!(FailWriter, "hello");
    assert!(result.is_err());
}

#[test]
fn mask_writeln_fmt_fail_writer_propagates_error() {
    let result = mask_writeln!(FailWriter, "hello");
    assert!(result.is_err());
}
