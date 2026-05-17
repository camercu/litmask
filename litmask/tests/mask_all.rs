//! Integration tests for `#[mask_all]` (Task 12 / spec §2.3.1 +
//! §2.3.2.1 + §2.3.2.6).
//!
//! The attribute walks the module's AST and rewrites bare string /
//! byte string / C string literal expressions to `mask!(literal)`.
//! These tests lock the round-trip (the literal decrypts at runtime
//! to its plaintext) plus the recursion contract (nested modules,
//! functions, blocks, closures all get rewritten). The skip rules
//! and warning emission live in separate test modules.

#![allow(dead_code)]
// Many fixture items are referenced only by the test bodies.
// `#[mask_all]` emits ghost-deprecation warnings for every skipped
// literal (§2.3.1.4) — that's the spec contract. The integration
// tests below intentionally exercise skip paths; `-D warnings` (set
// by the workspace pre-push hook) would otherwise upgrade those
// warnings to errors. The warning *text* is locked separately in
// `tests/compile/mask_all_pattern_warning.rs` via trybuild +
// `#[deny(deprecated)]`.
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

// ── §2.3.1.3 skip rules ────────────────────────────────────────

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

// ── §2.3.2.1 byte-string + c-string coverage ──────────────────

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
