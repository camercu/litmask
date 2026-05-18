//! Integration tests for `#[mask_all]`.
//!
//! The attribute walks the module's AST and rewrites bare string /
//! byte string / C string literal expressions to `mask!(literal)`,
//! plus a set of common macro families (`format!`, `println!` etc.,
//! `panic!` etc., `assert!` with custom message, `write!`/`writeln!`,
//! `include_str!`, `concat!`) to their masked equivalents. These
//! tests lock the round-trip — masked literals decrypt at runtime
//! to their plaintext — and the recursion contract — nested
//! modules, functions, blocks, and closures all get rewritten.

#![allow(dead_code)]
// Many fixture items are referenced only by the test bodies.
// `#[mask_all]` emits ghost-deprecation warnings for every skipped
// literal — the integration tests below intentionally exercise skip
// paths, so `-D warnings` (set by the workspace pre-push hook) would
// otherwise upgrade those warnings to errors. The warning *text* is
// locked separately in the trybuild fixtures under
// `tests/compile/mask_all_*_warning.rs` via `#[deny(deprecated)]`.
#![allow(deprecated)]

mod common;

use litmask::mask_all;

#[mask_all]
mod simple_bare_literal {
    pub fn fixture() -> String {
        let s = "iridium-falcon-7a2c9b";
        s.to_string()
    }
}

#[test]
fn bare_string_literal_round_trips_through_mask_all() {
    common::init_once();
    assert_eq!(simple_bare_literal::fixture(), "iridium-falcon-7a2c9b");
}

#[mask_all]
mod nested_function_with_block_and_closure {
    pub fn outer() -> String {
        let a = "platinum-koala-3e8f12";
        let block_val = {
            let b = "cinnabar-otter-6d4a91";
            format!("{a}+{b}")
        };
        let closure_val: String = (|| "carbon-marmot-9b1e57".to_string())();
        format!("{block_val}|{closure_val}")
    }
}

#[test]
fn mask_all_recurses_into_blocks_and_closures() {
    common::init_once();
    let s = nested_function_with_block_and_closure::outer();
    assert!(s.contains("platinum-koala-3e8f12"));
    assert!(s.contains("cinnabar-otter-6d4a91"));
    assert!(s.contains("carbon-marmot-9b1e57"));
}

#[mask_all]
mod nested_module {
    pub mod inner {
        pub fn lookup() -> String {
            let token = "graphite-toucan-4c7d28";
            token.to_string()
        }
    }
}

#[test]
fn mask_all_recurses_into_nested_modules() {
    common::init_once();
    assert_eq!(nested_module::inner::lookup(), "graphite-toucan-4c7d28");
}

#[mask_all]
mod respects_explicit_mask {
    use litmask::mask;
    pub fn fixture() -> String {
        let explicit: String = mask!("titanium-finch-2a6c40");
        let bare = "tungsten-ibis-1f9d63";
        format!("{explicit}|{bare}")
    }
}

#[test]
fn mask_all_does_not_double_mask_explicit_mask_invocation() {
    common::init_once();
    let s = respects_explicit_mask::fixture();
    assert!(s.contains("titanium-finch-2a6c40"));
    assert!(s.contains("tungsten-ibis-1f9d63"));
}

// ── Skip rules ─────────────────────────────────────────────────

#[mask_all]
mod pattern_position_left_unchanged {
    pub fn classify(x: &str) -> u32 {
        match x {
            "alpha" => 1,
            "beta" => 2,
            _ => 0,
        }
    }
}

#[test]
fn mask_all_skips_pattern_literals_match_arm() {
    common::init_once();
    // The pattern literals "alpha"/"beta" must NOT have been
    // rewritten — patterns can't accept `mask!()` expressions. RHS
    // values are integers so no rewriting risk on the arms.
    assert_eq!(pattern_position_left_unchanged::classify("alpha"), 1);
    assert_eq!(pattern_position_left_unchanged::classify("beta"), 2);
    assert_eq!(pattern_position_left_unchanged::classify("zzz"), 0);
}

#[mask_all]
mod if_let_pattern_left_unchanged {
    pub fn detect(input: Option<&str>) -> bool {
        if let Some("trigger") = input {
            return true;
        }
        false
    }
}

#[test]
fn mask_all_skips_pattern_literals_if_let() {
    common::init_once();
    assert!(if_let_pattern_left_unchanged::detect(Some("trigger")));
    assert!(!if_let_pattern_left_unchanged::detect(Some("other")));
    assert!(!if_let_pattern_left_unchanged::detect(None));
}

#[mask_all]
mod while_let_pattern_left_unchanged {
    pub fn count_until_sentinel<I: Iterator<Item = &'static str>>(iter: I) -> u32 {
        let mut n = 0;
        let mut it = iter.peekable();
        while let Some(&"STOP") = it.peek() {
            it.next();
            n += 1;
        }
        n
    }
}

#[test]
fn mask_all_skips_pattern_literals_while_let() {
    common::init_once();
    let items = vec!["STOP", "STOP", "go"];
    assert_eq!(
        while_let_pattern_left_unchanged::count_until_sentinel(items.into_iter()),
        2,
    );
}

// ── include_str! and concat! wrapping ──────────────────────────

#[mask_all]
mod include_str_wrapped {
    pub fn fixture() -> String {
        // Shares the fixture file with `mask_all_demo`; path resolves
        // relative to `CARGO_MANIFEST_DIR` (= `litmask/`).
        include_str!("examples/fixtures/mask_all_include_str.txt").to_string()
    }
}

#[test]
fn mask_all_wraps_include_str_in_mask() {
    common::init_once();
    let contents = include_str_wrapped::fixture();
    // The fixture file content (minus trailing newline normalization)
    // must round-trip through mask!() correctly.
    assert!(contents.contains("selenium-pangolin-3d8a91-mask-all-macro"));
}

#[mask_all]
mod concat_wrapped {
    pub fn fixture() -> String {
        concat!("rhodium-", "lemur-", "5c2a93-mask-all-macro").to_string()
    }
}

#[test]
fn mask_all_wraps_concat_in_mask() {
    common::init_once();
    assert_eq!(
        concat_wrapped::fixture(),
        "rhodium-lemur-5c2a93-mask-all-macro"
    );
}

// ── format! → maskfmt! ─────────────────────────────────────────

#[mask_all]
mod format_macro_rewritten {
    pub fn fixture() -> String {
        let n = 42;
        format!("x={n}")
    }
}

#[test]
fn mask_all_rewrites_format_with_literal_template() {
    common::init_once();
    assert_eq!(format_macro_rewritten::fixture(), "x=42");
}

#[mask_all]
mod format_macro_named_args {
    pub fn fixture() -> String {
        format!("a={a} b={b}", a = 1, b = 2)
    }
}

#[test]
fn mask_all_rewrites_format_with_named_args() {
    common::init_once();
    assert_eq!(format_macro_named_args::fixture(), "a=1 b=2");
}

// ── Panic family ───────────────────────────────────────────────

#[mask_all]
mod panic_message_rewritten {
    pub fn fixture() {
        panic!("titanium-yak-3a8e57-mask-all-macro");
    }
}

#[test]
fn mask_all_panic_message_round_trips() {
    common::init_once();
    let msg = common::catch_panic_msg(panic_message_rewritten::fixture).expect("expected panic");
    assert!(
        msg.contains("titanium-yak-3a8e57-mask-all-macro"),
        "panic message lost the fixture text; got: {msg:?}",
    );
}

// ── User-defined macros left alone ─────────────────────────────

macro_rules! my_user_macro {
    ($s:literal) => {
        $s
    };
}

#[mask_all]
mod user_macro_left_alone {
    pub fn fixture() -> &'static str {
        // `my_user_macro!` is user-defined; mask_all must leave its
        // literal argument intact (would otherwise type-mismatch the
        // `&'static str` return — `mask!()` returns `String`).
        my_user_macro!("hafnium-quokka-4d3e72-mask-all-macro")
    }
}

#[test]
fn mask_all_leaves_user_macro_literal_args_intact() {
    common::init_once();
    assert_eq!(
        user_macro_left_alone::fixture(),
        "hafnium-quokka-4d3e72-mask-all-macro",
    );
}

// ── write!/writeln! ────────────────────────────────────────────

#[mask_all]
mod write_macro_rewritten {
    use std::fmt::Write as _;
    pub fn fixture() -> String {
        let mut buf = String::new();
        write!(buf, "x={n}", n = 7).unwrap();
        buf
    }
}

#[test]
fn mask_all_rewrites_write_with_literal_template() {
    common::init_once();
    assert_eq!(write_macro_rewritten::fixture(), "x=7");
}

#[mask_all]
mod writeln_macro_rewritten {
    use std::fmt::Write as _;
    pub fn fixture() -> String {
        let mut buf = String::new();
        writeln!(buf, "tag={t}", t = "value").unwrap();
        buf
    }
}

#[test]
fn mask_all_rewrites_writeln_with_literal_template() {
    common::init_once();
    assert_eq!(writeln_macro_rewritten::fixture(), "tag=value\n");
}

// ── assert family with custom message ──────────────────────────

#[mask_all]
mod assert_with_message_rewritten {
    pub fn fixture_passing() {
        let x = 5;
        assert!(x > 0, "x must be positive, got x={x}");
    }

    pub fn fixture_failing() {
        let x = 5;
        let y = 6;
        assert_eq!(x, y, "expected equal, got x={x} y={y}");
    }
}

#[test]
fn mask_all_assert_with_message_round_trips_passing() {
    common::init_once();
    // No panic expected — assert!'s condition holds.
    assert_with_message_rewritten::fixture_passing();
}

#[test]
fn mask_all_assert_eq_with_message_panics_with_message() {
    common::init_once();
    let msg = common::catch_panic_msg(assert_with_message_rewritten::fixture_failing)
        .expect("expected panic");
    assert!(
        msg.contains("expected equal, got x=5 y=6"),
        "panic message lost the custom-message text; got: {msg:?}",
    );
}

// ── qualified macro paths ──────────────────────────────────────

#[mask_all]
mod qualified_macro_path_recognized {
    pub fn fixture() -> String {
        // `std::format!` resolves to the same builtin; the last-
        // segment match in `classify_macro` recognizes it as the
        // format family.
        std::format!("ytterbium-pika-2f9c83={n}", n = 11)
    }
}

#[test]
fn mask_all_recognizes_qualified_format_path() {
    common::init_once();
    assert_eq!(
        qualified_macro_path_recognized::fixture(),
        "ytterbium-pika-2f9c83=11",
    );
}

#[mask_all]
mod const_and_static_initializers {
    pub const SLUG: &str = "compile-time-only";
    pub static GREETING: &str = "static-also-compile-time";

    pub fn fixture() -> (String, String) {
        // Bare runtime literal — DOES get masked.
        let runtime = "runtime-eligible";
        (SLUG.to_string(), format!("{GREETING}+{runtime}"))
    }
}

#[test]
fn mask_all_skips_const_and_static_initializers() {
    common::init_once();
    let (slug, greeting) = const_and_static_initializers::fixture();
    // const/static round-trip unchanged (would not even compile if
    // `mask!()` had been substituted — `mask!()` is not const).
    assert_eq!(slug, "compile-time-only");
    assert!(greeting.contains("static-also-compile-time"));
    assert!(greeting.contains("runtime-eligible"));
}

// ── Byte-string + c-string coverage ────────────────────────────

#[mask_all]
mod byte_string_literal_round_trip {
    pub fn fixture() -> Vec<u8> {
        // After `#[mask_all]` rewrites `b"..."` → `mask!(b"...")`,
        // the tail expression evaluates directly to an owned
        // `Vec<u8>` and matches the return type without any
        // `.to_vec()` round-trip.
        b"chromium-bobcat-1c5e92"
    }
}

#[test]
fn mask_all_rewrites_byte_string_literals() {
    common::init_once();
    assert_eq!(
        byte_string_literal_round_trip::fixture(),
        b"chromium-bobcat-1c5e92".to_vec(),
    );
}

#[mask_all]
mod c_string_literal_round_trip {
    use std::ffi::CString;
    pub fn fixture() -> CString {
        // After `#[mask_all]` rewrites `c"..."` → `mask!(c"...")`,
        // the expression evaluates to an owned `CString`, no
        // intermediate borrow needed.
        c"radium-quetzal-8e3a51".to_owned()
    }
}

#[test]
fn mask_all_rewrites_c_string_literals() {
    common::init_once();
    let s = c_string_literal_round_trip::fixture();
    assert_eq!(s.to_bytes(), b"radium-quetzal-8e3a51");
}

// ── assert_ne! with custom message ─────────────────────────────

#[mask_all]
mod assert_ne_with_message_rewritten {
    pub fn fixture_failing() {
        let x = 5;
        let y = 5;
        assert_ne!(x, y, "expected unequal, got x={x} y={y}");
    }
}

#[test]
fn mask_all_assert_ne_with_message_panics_with_message() {
    common::init_once();
    let msg = common::catch_panic_msg(assert_ne_with_message_rewritten::fixture_failing)
        .expect("expected panic");
    assert!(
        msg.contains("expected unequal, got x=5 y=5"),
        "panic message lost the custom-message text; got: {msg:?}",
    );
}

// ── Output family (eprintln!, print!, eprint!) ─────────────────

#[mask_all]
mod eprintln_macro_rewritten {
    pub fn fixture() {
        eprintln!("zirconium-marten-1b8d47={n}", n = 3);
    }
}

#[test]
fn mask_all_rewrites_eprintln_with_literal_template() {
    common::init_once();
    eprintln_macro_rewritten::fixture();
}

#[mask_all]
mod print_macro_rewritten {
    pub fn fixture() {
        print!("vanadium-civet-4a2e83={n}", n = 5);
    }
}

#[test]
fn mask_all_rewrites_print_with_literal_template() {
    common::init_once();
    print_macro_rewritten::fixture();
}

#[mask_all]
mod eprint_macro_rewritten {
    pub fn fixture() {
        eprint!("niobium-coati-7c5f29={n}", n = 7);
    }
}

#[test]
fn mask_all_rewrites_eprint_with_literal_template() {
    common::init_once();
    eprint_macro_rewritten::fixture();
}

// ── Panic family (todo!, unimplemented!, unreachable!) ─────────

#[mask_all]
mod todo_macro_rewritten {
    pub fn fixture() {
        todo!("hafnium-aardvark-8d4e62: feature gating in progress");
    }
}

#[test]
fn mask_all_todo_message_round_trips() {
    common::init_once();
    let msg = common::catch_panic_msg(todo_macro_rewritten::fixture).expect("expected panic");
    assert!(
        msg.contains("hafnium-aardvark-8d4e62"),
        "todo! panic lost the fixture text; got: {msg:?}",
    );
}

#[mask_all]
mod unimplemented_macro_rewritten {
    pub fn fixture() {
        unimplemented!("tantalum-shrew-2a9f51: experimental path");
    }
}

#[test]
fn mask_all_unimplemented_message_round_trips() {
    common::init_once();
    let msg =
        common::catch_panic_msg(unimplemented_macro_rewritten::fixture).expect("expected panic");
    assert!(
        msg.contains("tantalum-shrew-2a9f51"),
        "unimplemented! panic lost the fixture text; got: {msg:?}",
    );
}

#[mask_all]
mod unreachable_macro_rewritten {
    pub fn fixture(x: u32) -> u32 {
        match x {
            0 => 0,
            _ => unreachable!("ruthenium-loris-3c8e74: x must be zero in this fixture, got {x}"),
        }
    }
}

#[test]
fn mask_all_unreachable_message_round_trips() {
    common::init_once();
    // Direct call with x != 0 trips the unreachable! and panics
    // with the masked message.
    let msg = common::catch_panic_msg(|| {
        let _ = unreachable_macro_rewritten::fixture(1);
    })
    .expect("expected panic");
    assert!(
        msg.contains("ruthenium-loris-3c8e74"),
        "unreachable! panic lost the fixture text; got: {msg:?}",
    );
}

// ── debug_assert family — left alone (SkipDiagnostic) ──────────
//
// The walker classifies `debug_assert!`, `debug_assert_eq!`, and
// `debug_assert_ne!` as `SkipDiagnostic` regardless of the message
// form: release builds dead-code-eliminate the body via
// `cfg!(debug_assertions)`, so masking the message would only add
// a `.rodata` blob and a runtime decrypt that's never observed in
// shipping binaries. These tests pin that classification by
// asserting the original (un-rewritten) panic-message behavior in
// the debug profile that `cargo test` uses.

#[mask_all]
mod debug_assert_left_alone {
    pub fn fixture_passing() {
        let x = 5;
        debug_assert!(x > 0, "x must be positive, got x={x}");
    }

    pub fn fixture_failing() {
        let x = 5;
        debug_assert!(x < 0, "x must be negative, got x={x}");
    }
}

#[test]
fn mask_all_leaves_debug_assert_untouched() {
    debug_assert_left_alone::fixture_passing();
    let msg = common::catch_panic_msg(debug_assert_left_alone::fixture_failing)
        .expect("expected panic in debug build");
    assert!(
        msg.contains("x must be negative, got x=5"),
        "debug_assert! panic message lost; got: {msg:?}",
    );
}

#[mask_all]
mod debug_assert_eq_left_alone {
    pub fn fixture_failing() {
        let x = 5;
        let y = 6;
        debug_assert_eq!(x, y, "expected equal, got x={x} y={y}");
    }
}

#[test]
fn mask_all_leaves_debug_assert_eq_untouched() {
    let msg = common::catch_panic_msg(debug_assert_eq_left_alone::fixture_failing)
        .expect("expected panic in debug build");
    assert!(
        msg.contains("expected equal, got x=5 y=6"),
        "debug_assert_eq! panic message lost; got: {msg:?}",
    );
}

#[mask_all]
mod debug_assert_ne_left_alone {
    pub fn fixture_failing() {
        let x = 5;
        let y = 5;
        debug_assert_ne!(x, y, "expected unequal, got x={x} y={y}");
    }
}

#[test]
fn mask_all_leaves_debug_assert_ne_untouched() {
    let msg = common::catch_panic_msg(debug_assert_ne_left_alone::fixture_failing)
        .expect("expected panic in debug build");
    assert!(
        msg.contains("expected unequal, got x=5 y=5"),
        "debug_assert_ne! panic message lost; got: {msg:?}",
    );
}
