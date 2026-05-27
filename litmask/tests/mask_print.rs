//! Integration tests for `mask_print!` and `mask_println!`.
//!
//! These macros are thin wrappers around `mask_format!` that print to
//! stdout. Format-string correctness is locked by `mask_format.rs`;
//! these tests verify compilation, runtime execution (no panic),
//! argument-pattern coverage, and end-to-end stdout output via
//! subprocess capture.

mod common;

use std::process::Command;

use common::Profile;
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

// ── E2E subprocess stdout capture ──────────────────────────────

fn run_mask_print_e2e() -> String {
    common::build_example("mask_print_e2e", Profile::Debug);
    let bin = common::example_path("mask_print_e2e", Profile::Debug);
    let key = common::read_unlock_key(&common::config_path(Profile::Debug));
    let output = Command::new(&bin)
        .env("LITMASK_UNLOCK_KEY", &key)
        .output()
        .expect("mask_print_e2e invocation failed");
    assert!(
        output.status.success(),
        "mask_print_e2e exited non-zero: status={:?} stderr={}",
        output.status,
        String::from_utf8_lossy(&output.stderr),
    );
    String::from_utf8(output.stdout).expect("stdout is UTF-8")
}

#[test]
fn mask_println_e2e_static_text() {
    let stdout = run_mask_print_e2e();
    assert!(
        stdout.starts_with("celadon-wren-8f4a2d\n"),
        "first line mismatch: {stdout:?}",
    );
}

#[test]
fn mask_println_e2e_format_args() {
    let stdout = run_mask_print_e2e();
    let lines: Vec<&str> = stdout.lines().collect();
    assert_eq!(lines[1], "topaz-gecko-7", "formatted line mismatch");
}

#[test]
fn mask_print_e2e_no_trailing_newline() {
    let stdout = run_mask_print_e2e();
    assert!(
        stdout.ends_with("viridian-pika-3e9b1c"),
        "mask_print! must not append newline: {stdout:?}",
    );
}
