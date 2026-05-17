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
    t.compile_fail("tests/compile/unmasked_invalid_literal.rs");
    t.compile_fail("tests/compile/unmasked_non_literal_expr.rs");
    t.compile_fail("tests/compile/unmasked_multi_arg.rs");
    t.compile_fail("tests/compile/maskfmt_non_literal_template.rs");
    t.compile_fail("tests/compile/maskfmt_too_many_args.rs");
    t.compile_fail("tests/compile/maskfmt_too_few_args.rs");
    t.compile_fail("tests/compile/maskfmt_type_incompatible_spec.rs");
    t.compile_fail("tests/compile/maskfmt_duplicate_named_arg.rs");
    t.compile_fail("tests/compile/maskfmt_positional_after_named.rs");
    t.compile_fail("tests/compile/mask_all_pattern_warning.rs");
    t.compile_fail("tests/compile/mask_all_non_module_target.rs");
    t.compile_fail("tests/compile/mask_all_const_initializer_warning.rs");
    t.compile_fail("tests/compile/mask_all_static_initializer_warning.rs");
}
