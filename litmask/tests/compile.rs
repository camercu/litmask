//! Compile-fail fixtures for the proc-macro crate. Each rejection
//! scenario gets a `compile/<name>.rs` source paired with a
//! `<name>.stderr` snapshot. Positive cases (round-tripping
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
    t.compile_fail("tests/compile/mask_const_context.rs");
    t.compile_fail("tests/compile/mask_static_context.rs");
    t.compile_fail("tests/compile/mask_pattern_position.rs");
    t.compile_fail("tests/compile/mask_if_let_pattern.rs");
    t.compile_fail("tests/compile/mask_while_let_pattern.rs");
    t.compile_fail("tests/compile/unmasked_invalid_literal.rs");
    t.compile_fail("tests/compile/unmasked_non_literal_expr.rs");
    t.compile_fail("tests/compile/unmasked_multi_arg.rs");
    t.compile_fail("tests/compile/mask_fmt_non_literal_template.rs");
    t.compile_fail("tests/compile/mask_fmt_too_many_args.rs");
    t.compile_fail("tests/compile/mask_fmt_too_few_args.rs");
    t.compile_fail("tests/compile/mask_fmt_type_incompatible_spec.rs");
    t.compile_fail("tests/compile/mask_fmt_duplicate_named_arg.rs");
    t.compile_fail("tests/compile/mask_fmt_positional_after_named.rs");
    t.compile_fail("tests/compile/mask_fmt_invalid_placeholder_name.rs");
    t.compile_fail("tests/compile/mask_all_pattern_warning.rs");
    t.compile_fail("tests/compile/mask_all_non_module_target.rs");
    t.compile_fail("tests/compile/mask_all_const_initializer_warning.rs");
    t.compile_fail("tests/compile/mask_all_static_initializer_warning.rs");
    t.compile_fail("tests/compile/mask_all_user_macro_warning.rs");
    t.compile_fail("tests/compile/mask_all_user_macro_raw_warning.rs");
    t.compile_fail("tests/compile/mask_all_nested_module_pattern_warning.rs");
    t.compile_fail("tests/compile/mask_include_str_non_literal.rs");
    t.compile_fail("tests/compile/mask_include_str_missing_file.rs");
    t.compile_fail("tests/compile/mask_include_bytes_non_literal.rs");
    t.compile_fail("tests/compile/mask_include_bytes_missing_file.rs");
    t.compile_fail("tests/compile/mask_concat_empty.rs");
    t.compile_fail("tests/compile/mask_concat_invalid_arg.rs");
    t.compile_fail("tests/compile/mask_env_non_literal.rs");
    t.compile_fail("tests/compile/mask_env_unset.rs");
    t.compile_fail("tests/compile/mask_option_env_non_literal.rs");
    t.compile_fail("tests/compile/mask_file_with_args.rs");
}
