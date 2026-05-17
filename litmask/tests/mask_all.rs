//! Integration tests for `#[mask_all]` (Task 12 / spec §2.3.1 +
//! §2.3.2.1 + §2.3.2.6).
//!
//! The attribute walks the module's AST and rewrites bare string /
//! byte string / C string literal expressions to `mask!(literal)`.
//! These tests lock the round-trip (the literal decrypts at runtime
//! to its plaintext) plus the recursion contract (nested modules,
//! functions, blocks, closures all get rewritten). The skip rules
//! and warning emission live in separate test modules.

#![allow(dead_code)] // Many fixture items are referenced only by the test bodies.

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
