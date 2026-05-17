//! Integration tests for `maskfmt!` (spec §2.2). Task 10 covers
//! positional placeholders; Task 11 adds named arguments
//! (§2.2.2.3), implicit captures (§2.2.2.4), and dynamic
//! width/precision (§2.2.2.6).
//!
//! Each round-trip test asserts the produced `String` byte-equals
//! the output of an equivalent `format!()` invocation, locking
//! §2.2.2.8 (output identity) directly.

mod common;

use litmask::maskfmt;

#[test]
fn maskfmt_basic_positional_round_trips() {
    common::init_once();
    let s = maskfmt!("x={}, y={:.2}", 1, 2.5);
    assert_eq!(s, format!("x={}, y={:.2}", 1, 2.5));
    assert_eq!(s, "x=1, y=2.50");
}

#[test]
fn maskfmt_debug_specifier_matches_format() {
    common::init_once();
    let v = vec![1, 2, 3];
    let plain = maskfmt!("v={:?}", v);
    assert_eq!(plain, format!("v={:?}", vec![1, 2, 3]));

    let pretty = maskfmt!("v={:#?}", vec![1, 2, 3]);
    assert_eq!(pretty, format!("v={:#?}", vec![1, 2, 3]));
}

#[test]
fn maskfmt_hex_specifiers_match_format() {
    common::init_once();
    let s = maskfmt!("hex={:#x} bin={:#b} oct={:#o}", 255u32, 255u32, 255u32);
    assert_eq!(
        s,
        format!("hex={:#x} bin={:#b} oct={:#o}", 255u32, 255u32, 255u32)
    );
}

#[test]
fn maskfmt_padded_specifier_matches_format() {
    common::init_once();
    let s = maskfmt!("[{:>10}] [{:<10}] [{:^10}]", "rt", "lt", "ctr");
    assert_eq!(s, format!("[{:>10}] [{:<10}] [{:^10}]", "rt", "lt", "ctr"));
}

#[test]
fn maskfmt_precision_specifier_matches_format() {
    common::init_once();
    let s = maskfmt!("pi={:.5}", std::f64::consts::PI);
    assert_eq!(s, format!("pi={:.5}", std::f64::consts::PI));
}

#[test]
fn maskfmt_explicit_positional_indices_match_format() {
    common::init_once();
    let s = maskfmt!("{1} {0} {1}", "a", "b");
    assert_eq!(s, format!("{1} {0} {1}", "a", "b"));
    assert_eq!(s, "b a b");
}

#[test]
fn maskfmt_literal_braces_round_trip() {
    common::init_once();
    let s = maskfmt!("{{escaped}} and {} live together", "real");
    assert_eq!(s, format!("{{escaped}} and {} live together", "real"));
    assert_eq!(s, "{escaped} and real live together");
}

#[test]
fn maskfmt_no_args_returns_template_text() {
    common::init_once();
    let s = maskfmt!("static text only");
    assert_eq!(s, "static text only");
}

#[test]
fn maskfmt_empty_template_returns_empty_string() {
    common::init_once();
    let s = maskfmt!("");
    assert!(s.is_empty());
}

#[test]
fn maskfmt_evaluates_each_argument_exactly_once() {
    common::init_once();
    let calls = std::cell::Cell::new(0u32);
    let bump = || {
        calls.set(calls.get() + 1);
        calls.get()
    };
    // bump() returns 1, 2, 3 in left-to-right order — same as format!.
    let s = maskfmt!("{} {} {}", bump(), bump(), bump());
    assert_eq!(calls.get(), 3, "each positional arg evaluated exactly once");
    assert_eq!(s, "1 2 3");
}

// ── Task 11: named args + implicit captures + dynamic width/precision ──

/// §2.2.2.3: a named argument's RHS expression is evaluated exactly
/// once even if referenced multiple times in the template. Matches
/// `format!`'s single-evaluation guarantee for named args.
#[test]
fn maskfmt_named_arg_evaluates_exactly_once() {
    common::init_once();
    let calls = std::cell::Cell::new(0u32);
    let bump = || {
        calls.set(calls.get() + 1);
        calls.get()
    };
    let s = maskfmt!("{x} {x}", x = bump());
    assert_eq!(
        calls.get(),
        1,
        "named arg referenced twice must evaluate exactly once",
    );
    assert_eq!(s, "1 1");
}

/// §2.2.2.4: a placeholder `{var}` with no corresponding named arg
/// resolves to the local `var` already in scope at the call site.
#[test]
fn maskfmt_implicit_capture_reads_local() {
    common::init_once();
    let var = 7;
    let s = maskfmt!("{var}");
    assert_eq!(s, "7");
    assert_eq!(s, format!("{var}"));
}

/// §2.2.2.6: dynamic width `{:>w$}` resolves `w` against the named
/// arg with the same name, producing identical output to `format!`.
#[test]
fn maskfmt_dynamic_width_matches_format() {
    common::init_once();
    let s = maskfmt!("{:>w$}", "hi", w = 5);
    assert_eq!(s, format!("{:>w$}", "hi", w = 5));
    assert_eq!(s, "   hi");
}

/// §2.2.2.6: dynamic precision `{:.p$}` resolves `p` against the
/// named arg with the same name, producing identical output to
/// `format!`.
#[test]
fn maskfmt_dynamic_precision_matches_format() {
    common::init_once();
    let pi = std::f64::consts::PI;
    let s = maskfmt!("{:.p$}", pi, p = 3);
    assert_eq!(s, format!("{:.p$}", pi, p = 3));
    assert_eq!(s, "3.142");
}

/// §2.2.2.6: dynamic width via implicit capture (no named-arg
/// declaration; `w` is a local in scope).
#[test]
fn maskfmt_dynamic_width_implicit_capture_matches_format() {
    common::init_once();
    let w = 8;
    let s = maskfmt!("{:>w$}", "x");
    assert_eq!(s, format!("{:>w$}", "x"));
    assert_eq!(s, "       x");
}

/// §2.2.2.8: mixed positional + named placeholders produce identical
/// output to `format!` for the same input.
#[test]
fn maskfmt_named_and_positional_mix_matches_format() {
    common::init_once();
    let s = maskfmt!("{x} {} {y}", "pos", x = 1, y = 2);
    assert_eq!(s, format!("{x} {} {y}", "pos", x = 1, y = 2));
    assert_eq!(s, "1 pos 2");
}

/// §2.2.2.4: an implicit capture of a non-Copy type works the same
/// way as `format!` — the reference is borrowed, the local stays
/// usable after the call.
#[test]
fn maskfmt_implicit_capture_borrows_non_copy() {
    common::init_once();
    let var = String::from("hello");
    let s = maskfmt!("{var}!");
    assert_eq!(s, "hello!");
    // `var` still usable — the implicit capture took it by reference.
    assert_eq!(var.len(), 5);
}
