//! Integration tests for `mask_eprint!` and `mask_eprintln!`.
//!
//! These macros are thin wrappers around `mask_format!` that print to
//! stderr. Format-string correctness is locked by `mask_format.rs`;
//! these tests verify compilation, runtime execution (no panic),
//! argument-pattern coverage, and end-to-end stderr output via
//! subprocess capture.

mod common;

use std::process::Command;

use common::Profile;
use litmask::{mask_eprint, mask_eprintln};

// ── mask_eprintln! ──────────────────────────────────────────────

#[test]
fn mask_eprintln_no_args() {
    mask_eprintln!();
}

#[test]
fn mask_eprintln_static_text() {
    mask_eprintln!("static text only");
}

#[test]
fn mask_eprintln_positional_args() {
    mask_eprintln!("x={}, y={:.2}", 1, 2.5);
}

#[test]
fn mask_eprintln_named_args() {
    mask_eprintln!("{x} {y}", x = 1, y = 2);
}

#[test]
fn mask_eprintln_implicit_capture() {
    let var = 42;
    mask_eprintln!("{var}");
}

#[test]
fn mask_eprintln_debug_specifier() {
    mask_eprintln!("v={:?}", vec![1, 2, 3]);
}

#[test]
fn mask_eprintln_mixed_positional_and_named() {
    mask_eprintln!("{x} {} {y}", "pos", x = 1, y = 2);
}

#[test]
fn mask_eprintln_empty_template() {
    mask_eprintln!("");
}

// ── mask_eprint! ────────────────────────────────────────────────

#[test]
fn mask_eprint_empty_template() {
    mask_eprint!("");
}

#[test]
fn mask_eprint_static_text() {
    mask_eprint!("hello");
}

#[test]
fn mask_eprint_positional_args() {
    mask_eprint!("x={}, y={}", 1, 2);
}

#[test]
fn mask_eprint_named_args() {
    mask_eprint!("{name}", name = "test");
}

// ── E2E subprocess stderr capture ──────────────────────────────

fn run_mask_eprint_e2e() -> String {
    common::build_example("mask_eprint_e2e", Profile::Debug);
    let bin = common::example_path("mask_eprint_e2e", Profile::Debug);
    // The Embedded example self-initializes on its first mask_eprint!.
    let output = Command::new(&bin)
        .output()
        .expect("mask_eprint_e2e invocation failed");
    assert!(
        output.status.success(),
        "mask_eprint_e2e exited non-zero: status={:?} stdout={}",
        output.status,
        String::from_utf8_lossy(&output.stdout),
    );
    String::from_utf8(output.stderr).expect("stderr is UTF-8")
}

#[test]
fn mask_eprintln_e2e_static_text() {
    let stderr = run_mask_eprint_e2e();
    assert!(
        stderr.starts_with("nothing-to-see-here-officer\n"),
        "first line mismatch: {stderr:?}",
    );
}

#[test]
fn mask_eprintln_e2e_format_args() {
    let stderr = run_mask_eprint_e2e();
    let lines: Vec<&str> = stderr.lines().collect();
    assert_eq!(lines[1], "secret-level-7", "formatted line mismatch");
}

#[test]
fn mask_eprint_e2e_no_trailing_newline() {
    let stderr = run_mask_eprint_e2e();
    assert!(
        stderr.ends_with("end-of-transmission"),
        "mask_eprint! must not append newline: {stderr:?}",
    );
}
