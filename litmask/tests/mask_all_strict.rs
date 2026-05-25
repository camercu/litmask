//! `#[mask_all(strict)]` round-trips when every literal is either
//! masked by the substitution table or explicitly opted out via
//! `unmasked!()` (§2.3.3.2). These tests pin the success path; the
//! failure paths are locked separately in the trybuild fixtures
//! (`tests/compile/mask_all_strict_*_error.rs`).

mod common;

use litmask::{mask_all, unmasked};

// Strict module — every literal is in a position the walker rewrites
// to `mask!(...)` (the bare runtime literal), or wrapped in
// `unmasked!()` to opt out where the walker would have warned.
#[mask_all(strict)]
mod strict_all_covered {
    use litmask::unmasked;

    // Pattern literal cannot be rewritten to `mask!(...)` — move the
    // comparison into expression position via `unmasked!()` so the
    // strict-mode check is satisfied.
    pub fn classify(x: &str) -> u32 {
        if x == unmasked!("alpha") {
            1
        } else if x == unmasked!("beta") {
            2
        } else {
            0
        }
    }

    pub fn greet() -> String {
        // Bare literal — rewritten to `mask!(...)` by the walker.
        let name = "iridium-falcon-7a2c9b";
        format!("hello, {name}")
    }
}

#[test]
fn strict_module_compiles_when_pattern_literal_is_opted_out_via_unmasked() {
    common::init_once();
    assert_eq!(strict_all_covered::classify("alpha"), 1);
    assert_eq!(strict_all_covered::classify("beta"), 2);
    assert_eq!(strict_all_covered::classify("zzz"), 0);
}

#[test]
fn strict_module_rewrites_eligible_literals_to_mask() {
    common::init_once();
    let s = strict_all_covered::greet();
    assert!(s.contains("iridium-falcon-7a2c9b"));
}

// Sanity: `unmasked!()` at item-position in a strict module also
// satisfies the strict requirement (the literal is explicitly opted
// out from masking).
#[mask_all(strict)]
mod strict_unmasked_const {
    use litmask::unmasked;
    pub const SLUG: &str = unmasked!("compile-time-only");
}

#[test]
fn strict_const_initializer_compiles_when_value_is_unmasked() {
    assert_eq!(strict_unmasked_const::SLUG, "compile-time-only");
}

// Sanity: an explicit `unmasked!()` invocation at expression position
// still expands to the bare literal — strict mode must not perturb
// the identity-wrapper contract.
#[test]
fn unmasked_expression_expands_to_bare_literal_under_strict_scope() {
    let s: &str = unmasked!("explicit-opt-out");
    assert_eq!(s, "explicit-opt-out");
}
