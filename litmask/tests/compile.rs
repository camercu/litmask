//! Compile-fail fixtures for `mask!` per §1.10.2 and §1.9.6. Each
//! rejection scenario gets a `compile/<name>.rs` source paired with
//! a `<name>.stderr` snapshot. Positive cases (round-tripping
//! `include_str!` / `concat!` outputs) are covered by the runtime
//! integration tests in `mask_macro_inputs.rs` — `trybuild` would
//! only verify they compile, not that they decrypt correctly.
//!
//! Regenerate `.stderr` snapshots after an intentional message change:
//! `TRYBUILD=overwrite cargo test --test compile`.

#[test]
fn compile_fixtures() {
    let t = trybuild::TestCases::new();
    t.compile_fail("tests/compile/mask_integer_literal.rs");
    t.compile_fail("tests/compile/mask_non_literal_expr.rs");
    t.compile_fail("tests/compile/mask_non_whitelisted_macro.rs");
    t.compile_fail("tests/compile/mask_concat_mixed_kinds.rs");
    t.compile_fail("tests/compile/mask_concat_only_bytes.rs");
    t.compile_fail("tests/compile/mask_concat_only_cstrs.rs");
    t.compile_fail("tests/compile/mask_const_context.rs");
    t.compile_fail("tests/compile/mask_static_context.rs");
    t.compile_fail("tests/compile/mask_pattern_position.rs");
    t.compile_fail("tests/compile/mask_if_let_pattern.rs");
    t.compile_fail("tests/compile/mask_include_str_missing.rs");
    t.compile_fail("tests/compile/mask_concat_with_failing_include_str.rs");
}
