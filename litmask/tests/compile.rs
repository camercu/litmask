//! Compile-fail fixtures for the proc-macro crate. Each rejection
//! scenario gets a `compile/<name>.rs` source paired with a
//! `<name>.stderr` snapshot. Positive cases (round-tripping
//! `include_str!` / `concat!` outputs) are covered by the runtime
//! integration tests in `mask_macro_inputs.rs` — `trybuild` would
//! only verify they compile, not that they decrypt correctly.
//!
//! Regenerate `.stderr` snapshots after an intentional message change:
//! `TRYBUILD=overwrite cargo test --test compile`. The
//! `mask_serialize_*` fixtures additionally need
//! `--features unstable-serde`.

#[test]
fn compile_fixtures() {
    let t = trybuild::TestCases::new();
    t.compile_fail("tests/compile/mask_debug_union.rs");
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
    t.compile_fail("tests/compile/mask_format_non_literal_template.rs");
    t.compile_fail("tests/compile/mask_format_too_many_args.rs");
    t.compile_fail("tests/compile/mask_format_too_few_args.rs");
    t.compile_fail("tests/compile/mask_format_type_incompatible_spec.rs");
    t.compile_fail("tests/compile/mask_format_duplicate_named_arg.rs");
    t.compile_fail("tests/compile/mask_format_positional_after_named.rs");
    t.compile_fail("tests/compile/mask_format_named_unused.rs");
    t.compile_fail("tests/compile/mask_format_invalid_placeholder_name.rs");
    t.compile_fail("tests/compile/mask_all_pattern_warning.rs");
    t.compile_fail("tests/compile/mask_all_non_module_target.rs");
    t.compile_fail("tests/compile/mask_all_const_initializer_warning.rs");
    t.compile_fail("tests/compile/mask_all_static_initializer_warning.rs");
    t.compile_fail("tests/compile/mask_all_user_macro_warning.rs");
    t.compile_fail("tests/compile/mask_all_user_macro_raw_warning.rs");
    t.compile_fail("tests/compile/mask_all_nested_module_pattern_warning.rs");
    t.compile_fail("tests/compile/mask_all_strict_pattern_error.rs");
    t.compile_fail("tests/compile/mask_all_strict_non_literal_template_error.rs");
    t.compile_fail("tests/compile/mask_include_str_non_literal.rs");
    t.compile_fail("tests/compile/mask_include_str_missing_file.rs");
    t.compile_fail("tests/compile/mask_include_bytes_non_literal.rs");
    t.compile_fail("tests/compile/mask_include_bytes_missing_file.rs");
    t.compile_fail("tests/compile/mask_concat_invalid_arg.rs");
    t.compile_fail("tests/compile/mask_concat_rejects_unmasked.rs");
    t.compile_fail("tests/compile/mask_env_non_literal.rs");
    t.compile_fail("tests/compile/mask_env_unset.rs");
    t.compile_fail("tests/compile/mask_env_unset_with_custom_message.rs");
    t.compile_fail("tests/compile/mask_option_env_non_literal.rs");
    t.compile_fail("tests/compile/mask_file_with_args.rs");
    t.compile_fail("tests/compile/mask_rejects_include_str_shim.rs");
    t.compile_fail("tests/compile/mask_rejects_concat_shim.rs");
    t.compile_fail("tests/compile/init_external_against_embedded_seal.rs");
    t.compile_fail("tests/compile/init_machine_external_grammar_missing_provider.rs");
    t.compile_fail("tests/compile/init_machine_external_against_embedded_seal.rs");
}

/// Rejection fixtures for `#[derive(MaskSerialize)]` (EXPERIMENTAL,
/// `unstable-serde`). Gated on the feature: trybuild propagates the
/// running test build's enabled features into the fixture project, so
/// without the gate the fixtures would fail on "cannot find derive
/// macro" instead of the intended grammar diagnostics.
#[cfg(feature = "unstable-serde")]
#[test]
fn mask_serialize_compile_fixtures() {
    let t = trybuild::TestCases::new();
    t.compile_fail("tests/compile/mask_serialize_enum.rs");
    t.compile_fail("tests/compile/mask_serialize_serde_attr_container.rs");
    t.compile_fail("tests/compile/mask_serialize_serde_attr_field.rs");
}
