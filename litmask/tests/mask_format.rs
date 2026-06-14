//! Integration tests for `mask_format!`. Covers positional placeholders,
//! named arguments, implicit captures, and dynamic width/precision.
//!
//! Each round-trip test asserts the produced `String` byte-equals
//! the output of an equivalent `format!()` invocation, locking
//! output identity directly.

mod common;

use litmask::mask_format;

#[test]
fn mask_format_basic_positional_round_trips() {
    let s = mask_format!("x={}, y={:.2}", 1, 2.5);
    assert_eq!(s, format!("x={}, y={:.2}", 1, 2.5));
    assert_eq!(s, "x=1, y=2.50");
}

#[test]
fn mask_format_debug_specifier_matches_format() {
    let v = vec![1, 2, 3];
    let plain = mask_format!("v={:?}", v);
    assert_eq!(plain, format!("v={:?}", vec![1, 2, 3]));

    let pretty = mask_format!("v={:#?}", vec![1, 2, 3]);
    assert_eq!(pretty, format!("v={:#?}", vec![1, 2, 3]));
}

#[test]
fn mask_format_hex_specifiers_match_format() {
    let s = mask_format!("hex={:#x} bin={:#b} oct={:#o}", 255u32, 255u32, 255u32);
    assert_eq!(
        s,
        format!("hex={:#x} bin={:#b} oct={:#o}", 255u32, 255u32, 255u32)
    );
}

#[test]
fn mask_format_padded_specifier_matches_format() {
    let s = mask_format!("[{:>10}] [{:<10}] [{:^10}]", "rt", "lt", "ctr");
    assert_eq!(s, format!("[{:>10}] [{:<10}] [{:^10}]", "rt", "lt", "ctr"));
}

#[test]
fn mask_format_precision_specifier_matches_format() {
    let s = mask_format!("pi={:.5}", std::f64::consts::PI);
    assert_eq!(s, format!("pi={:.5}", std::f64::consts::PI));
}

#[test]
fn mask_format_explicit_positional_indices_match_format() {
    let s = mask_format!("{1} {0} {1}", "a", "b");
    assert_eq!(s, format!("{1} {0} {1}", "a", "b"));
    assert_eq!(s, "b a b");
}

#[test]
fn mask_format_literal_braces_round_trip() {
    let s = mask_format!("{{escaped}} and {} live together", "real");
    assert_eq!(s, format!("{{escaped}} and {} live together", "real"));
    assert_eq!(s, "{escaped} and real live together");
}

#[test]
fn mask_format_no_args_returns_template_text() {
    let s = mask_format!("static text only");
    assert_eq!(s, "static text only");
}

#[test]
fn mask_format_empty_template_returns_empty_string() {
    let s = mask_format!("");
    assert!(s.is_empty());
}

#[test]
fn mask_format_evaluates_each_argument_exactly_once() {
    let calls = std::cell::Cell::new(0u32);
    let bump = || {
        calls.set(calls.get() + 1);
        calls.get()
    };
    // bump() returns 1, 2, 3 in left-to-right order — same as format!.
    let s = mask_format!("{} {} {}", bump(), bump(), bump());
    assert_eq!(calls.get(), 3, "each positional arg evaluated exactly once");
    assert_eq!(s, "1 2 3");
}

// ── Named args + implicit captures + dynamic width/precision ───

/// A named argument's RHS expression is evaluated exactly once even
/// if referenced multiple times in the template. Matches `format!`'s
/// single-evaluation guarantee for named args.
#[test]
fn mask_format_named_arg_evaluates_exactly_once() {
    let calls = std::cell::Cell::new(0u32);
    let bump = || {
        calls.set(calls.get() + 1);
        calls.get()
    };
    let s = mask_format!("{x} {x}", x = bump());
    assert_eq!(
        calls.get(),
        1,
        "named arg referenced twice must evaluate exactly once",
    );
    assert_eq!(s, "1 1");
}

/// A placeholder `{var}` with no corresponding named arg resolves
/// to the local `var` already in scope at the call site.
#[test]
fn mask_format_implicit_capture_reads_local() {
    let var = 7;
    let s = mask_format!("{var}");
    assert_eq!(s, "7");
    assert_eq!(s, format!("{var}"));
}

/// Dynamic width `{:>w$}` resolves `w` against the named arg with
/// the same name, producing identical output to `format!`.
#[test]
fn mask_format_dynamic_width_matches_format() {
    let s = mask_format!("{:>w$}", "hi", w = 5);
    assert_eq!(s, format!("{:>w$}", "hi", w = 5));
    assert_eq!(s, "   hi");
}

/// Dynamic precision `{:.p$}` resolves `p` against the named arg
/// with the same name, producing identical output to `format!`.
#[test]
fn mask_format_dynamic_precision_matches_format() {
    let pi = std::f64::consts::PI;
    let s = mask_format!("{:.p$}", pi, p = 3);
    assert_eq!(s, format!("{:.p$}", pi, p = 3));
    assert_eq!(s, "3.142");
}

/// Dynamic width via implicit capture (no named-arg declaration;
/// `w` is a local in scope).
#[test]
fn mask_format_dynamic_width_implicit_capture_matches_format() {
    let w = 8;
    let s = mask_format!("{:>w$}", "x");
    assert_eq!(s, format!("{:>w$}", "x"));
    assert_eq!(s, "       x");
}

/// Mixed positional + named placeholders produce identical output
/// to `format!` for the same input.
#[test]
fn mask_format_named_and_positional_mix_matches_format() {
    let s = mask_format!("{x} {} {y}", "pos", x = 1, y = 2);
    assert_eq!(s, format!("{x} {} {y}", "pos", x = 1, y = 2));
    assert_eq!(s, "1 pos 2");
}

/// An implicit capture of a non-Copy type works the same way as
/// `format!` — the reference is borrowed, the local stays usable
/// after the call.
#[test]
fn mask_format_implicit_capture_borrows_non_copy() {
    let var = String::from("hello");
    let s = mask_format!("{var}!");
    assert_eq!(s, "hello!");
    // `var` still usable — the implicit capture took it by reference.
    assert_eq!(var.len(), 5);
}
