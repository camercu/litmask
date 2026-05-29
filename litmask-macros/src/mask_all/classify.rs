//! Macro-classification logic for `#[mask_all]`.
//!
//! Pure function over `syn::Macro` — no walker state, no side
//! effects. The walker calls [`classify_macro`] once per macro
//! invocation; tests can construct arbitrary `syn::Macro` values and
//! assert the family directly.

use proc_macro2::TokenStream as TokenStream2;

/// Recognized macro families. Returned by [`classify_macro`] for each
/// macro invocation encountered during the walk. The classification
/// depends on the macro's path (last segment, so qualified paths like
/// `std::format!` are recognized) and, for the assert family, on the
/// argument count (the no-message form takes a different path from
/// the custom-message form).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(super) enum MacroFamily {
    /// `mask!`, `mask_format!`, `unmasked!`, `weak_mask!` — explicit user
    /// choice; never rewritten, never warned.
    SkipExplicit,
    /// `dbg!`, `stringify!`, `compile_error!`, `cfg!`, `file!`,
    /// `line!`, `column!`, `module_path!`; the no-message form of
    /// `assert!` / `assert_eq!` / `assert_ne!`; and **all** forms of
    /// the `debug_assert!` family (`debug_assert!`,
    /// `debug_assert_eq!`, `debug_assert_ne!`, with or without a
    /// message). Left alone with no warning. Release builds strip
    /// `debug_assert!` bodies via `cfg!(debug_assertions)`, so
    /// masking their messages would add a `.rodata` blob and a
    /// runtime decrypt that's never observed in shipping binaries.
    SkipDiagnostic,
    /// `format!` — rewritten to `mask_format!`.
    Format,
    /// `println!`, `eprintln!`, `print!`, `eprint!` — wrapped via
    /// `mask_format!` and re-emitted with a `"{}"` placeholder for the
    /// formatted result.
    Output,
    /// `write!`, `writeln!` — like [`Output`] but the writer occupies
    /// the first argument; the template starts at argument index 1.
    Write,
    /// `panic!`, `todo!`, `unimplemented!`, `unreachable!` — wrapped
    /// via `mask_format!`, preserving the unwinding behavior.
    Panic,
    /// `assert!` with a custom-message argument, or `assert_eq!` /
    /// `assert_ne!` with the equivalent custom-message form. The
    /// condition (and values, for the equality variants) stay
    /// positional; the message is masked. `head_arity` is 1 for
    /// `assert!` (just the condition) and 2 for the equality
    /// asserts (both operands). The `debug_assert!` family does
    /// **not** route here — see `SkipDiagnostic`.
    AssertWithMessage { head_arity: usize },
    /// One of the stdlib compile-time-resolving macros rewritten to
    /// its dedicated `mask_*!` counterpart in `litmask`:
    /// `include_str!` → `mask_include_str!`, `include_bytes!` →
    /// `mask_include_bytes!`, `concat!` → `mask_concat!`, `env!` →
    /// `mask_env!`, `option_env!` → `mask_option_env!`, `file!()` →
    /// `mask_file!()`. The macro path is swapped; the argument
    /// tokens flow through unchanged.
    RewriteToMasked { masked_name: &'static str },
    /// Anything not recognized above. Literal arguments fall through
    /// unmasked and the walker emits a warning per literal so the
    /// user is alerted.
    UserDefined,
}

/// Classify a macro invocation by its path. Qualified paths
/// (`std::format!`, `core::dbg!`, `::std::panic!`) are recognized by
/// matching the last path segment, so the stdlib paths interoperate
/// the same as their unqualified forms.
pub(super) fn classify_macro(mac: &syn::Macro) -> MacroFamily {
    let Some(name) = macro_last_segment(mac) else {
        return MacroFamily::UserDefined;
    };
    match name.as_str() {
        "mask" | "mask_format" | "unmasked" | "weak_mask" => MacroFamily::SkipExplicit,
        // `debug_assert!` / `_eq!` / `_ne!` expand to
        // `if cfg!(debug_assertions) { assert!(...) }`; release
        // builds dead-code-eliminate the body, so masking the
        // message would generate a `.rodata` blob and a runtime
        // decrypt that's discarded — pure cost for no release-
        // binary benefit. Treat the whole debug-assert family as
        // diagnostic-only regardless of the message form.
        "dbg" | "stringify" | "compile_error" | "cfg" | "line" | "column" | "module_path"
        | "debug_assert" | "debug_assert_eq" | "debug_assert_ne" => MacroFamily::SkipDiagnostic,
        "assert" => {
            // assert!(cond) — no message; assert!(cond, msg, ...) — with.
            if count_top_level_args(&mac.tokens) >= 2 {
                MacroFamily::AssertWithMessage { head_arity: 1 }
            } else {
                MacroFamily::SkipDiagnostic
            }
        }
        "assert_eq" | "assert_ne" => {
            // assert_eq!(a, b) — no message; assert_eq!(a, b, msg, ...) — with.
            if count_top_level_args(&mac.tokens) >= 3 {
                MacroFamily::AssertWithMessage { head_arity: 2 }
            } else {
                MacroFamily::SkipDiagnostic
            }
        }
        "format" => MacroFamily::Format,
        "println" | "eprintln" | "print" | "eprint" => MacroFamily::Output,
        "write" | "writeln" => MacroFamily::Write,
        "panic" | "todo" | "unimplemented" | "unreachable" => MacroFamily::Panic,
        "include_str" => MacroFamily::RewriteToMasked {
            masked_name: "mask_include_str",
        },
        "include_bytes" => MacroFamily::RewriteToMasked {
            masked_name: "mask_include_bytes",
        },
        "concat" => MacroFamily::RewriteToMasked {
            masked_name: "mask_concat",
        },
        "env" => MacroFamily::RewriteToMasked {
            masked_name: "mask_env",
        },
        "option_env" => MacroFamily::RewriteToMasked {
            masked_name: "mask_option_env",
        },
        "file" => MacroFamily::RewriteToMasked {
            masked_name: "mask_file",
        },
        _ => MacroFamily::UserDefined,
    }
}

fn macro_last_segment(mac: &syn::Macro) -> Option<String> {
    Some(mac.path.segments.last()?.ident.to_string())
}

/// Count top-level comma-separated arguments in a macro body.
/// Commas inside parenthesized or bracketed sub-expressions are
/// not counted as separators because `Punctuated::<Expr, _>::parse_terminated`
/// honors expression nesting. Returns 0 if the body is empty or
/// fails to parse as a comma-separated argument list.
fn count_top_level_args(tokens: &TokenStream2) -> usize {
    use syn::parse::Parser as _;
    let parser = |input: syn::parse::ParseStream| -> syn::Result<usize> {
        let punct: syn::punctuated::Punctuated<syn::Expr, syn::Token![,]> =
            syn::punctuated::Punctuated::parse_terminated(input)?;
        Ok(punct.len())
    };
    parser.parse2(tokens.clone()).unwrap_or(0)
}

#[cfg(test)]
mod tests {
    use super::*;
    use quote::quote;

    fn mac(src: proc_macro2::TokenStream) -> syn::Macro {
        syn::parse2::<syn::ExprMacro>(src).expect("parse macro").mac
    }

    #[test]
    fn explicit_litmask_macros_classify_as_skip_explicit() {
        for name in ["mask", "mask_format", "unmasked", "weak_mask"] {
            let ident = syn::Ident::new(name, proc_macro2::Span::call_site());
            let m = mac(quote! { #ident!("x") });
            assert_eq!(
                classify_macro(&m),
                MacroFamily::SkipExplicit,
                "{name}! must skip-explicit"
            );
        }
    }

    #[test]
    fn debug_assert_family_skips_regardless_of_message() {
        // Release builds dead-code-eliminate debug_assert! bodies,
        // so masking would add cost for no observable benefit.
        for src in [
            quote! { debug_assert!(x) },
            quote! { debug_assert!(x, "msg") },
            quote! { debug_assert_eq!(a, b) },
            quote! { debug_assert_eq!(a, b, "msg") },
            quote! { debug_assert_ne!(a, b, "msg") },
        ] {
            assert_eq!(classify_macro(&mac(src)), MacroFamily::SkipDiagnostic);
        }
    }

    #[test]
    fn assert_classifies_on_arg_count() {
        // assert!(cond) → diagnostic-only; assert!(cond, msg) → rewrite the msg.
        assert_eq!(
            classify_macro(&mac(quote! { assert!(x) })),
            MacroFamily::SkipDiagnostic
        );
        assert_eq!(
            classify_macro(&mac(quote! { assert!(x, "msg") })),
            MacroFamily::AssertWithMessage { head_arity: 1 }
        );
    }

    #[test]
    fn assert_eq_ne_route_through_head_arity_two() {
        assert_eq!(
            classify_macro(&mac(quote! { assert_eq!(a, b) })),
            MacroFamily::SkipDiagnostic
        );
        assert_eq!(
            classify_macro(&mac(quote! { assert_eq!(a, b, "msg") })),
            MacroFamily::AssertWithMessage { head_arity: 2 }
        );
        assert_eq!(
            classify_macro(&mac(quote! { assert_ne!(a, b, "msg") })),
            MacroFamily::AssertWithMessage { head_arity: 2 }
        );
    }

    #[test]
    fn stdlib_rewrite_macros_carry_masked_name() {
        let cases = [
            ("include_str", "mask_include_str"),
            ("include_bytes", "mask_include_bytes"),
            ("concat", "mask_concat"),
            ("env", "mask_env"),
            ("option_env", "mask_option_env"),
            ("file", "mask_file"),
        ];
        for (stdlib, masked) in cases {
            let ident = syn::Ident::new(stdlib, proc_macro2::Span::call_site());
            let m = mac(quote! { #ident!("x") });
            assert_eq!(
                classify_macro(&m),
                MacroFamily::RewriteToMasked {
                    masked_name: masked
                },
            );
        }
    }

    #[test]
    fn qualified_paths_match_on_last_segment() {
        // std::format!, core::dbg!, ::std::panic! must classify as
        // their unqualified counterparts so users can write either form.
        assert_eq!(
            classify_macro(&mac(quote! { std::format!("x") })),
            MacroFamily::Format,
        );
        assert_eq!(
            classify_macro(&mac(quote! { core::dbg!(x) })),
            MacroFamily::SkipDiagnostic,
        );
        assert_eq!(
            classify_macro(&mac(quote! { ::std::panic!("boom") })),
            MacroFamily::Panic,
        );
    }

    #[test]
    fn unknown_macros_classify_as_user_defined() {
        assert_eq!(
            classify_macro(&mac(quote! { my_macro!("x") })),
            MacroFamily::UserDefined,
        );
    }
}
