//! Integration tests for `mask_print!` and `mask_println!`.
//!
//! These macros are thin wrappers around `mask_format!` that print to
//! stdout. Format-string correctness is locked by `mask_format.rs`;
//! these tests verify compilation, runtime execution (no panic), and
//! argument-pattern coverage.

mod common;

use litmask::{mask_print, mask_println};

// ── mask_println! ───────────────────────────────────────────────

#[test]
fn mask_println_no_args() {
    common::init_once();
    mask_println!();
}

#[test]
fn mask_println_static_text() {
    common::init_once();
    mask_println!("static text only");
}

#[test]
fn mask_println_positional_args() {
    common::init_once();
    mask_println!("x={}, y={:.2}", 1, 2.5);
}

#[test]
fn mask_println_named_args() {
    common::init_once();
    mask_println!("{x} {y}", x = 1, y = 2);
}

#[test]
fn mask_println_implicit_capture() {
    common::init_once();
    let var = 42;
    mask_println!("{var}");
}

#[test]
fn mask_println_debug_specifier() {
    common::init_once();
    mask_println!("v={:?}", vec![1, 2, 3]);
}

#[test]
fn mask_println_mixed_positional_and_named() {
    common::init_once();
    mask_println!("{x} {} {y}", "pos", x = 1, y = 2);
}

#[test]
fn mask_println_empty_template() {
    common::init_once();
    mask_println!("");
}

// ── mask_print! ─────────────────────────────────────────────────

#[test]
fn mask_print_empty_template() {
    common::init_once();
    mask_print!("");
}

#[test]
fn mask_print_static_text() {
    common::init_once();
    mask_print!("hello");
}

#[test]
fn mask_print_positional_args() {
    common::init_once();
    mask_print!("x={}, y={}", 1, 2);
}

#[test]
fn mask_print_named_args() {
    common::init_once();
    mask_print!("{name}", name = "test");
}
