//! `mask_concat!` proc-macro: accept string literals plus nested
//! `concat!` / `include_str!` / `env!` invocations, resolve every
//! argument at proc-macro time, then AEAD-encrypt the concatenated
//! string and expand to a runtime decrypt call returning `String`.
//!
//! Replaces the prior `mask!(concat!(...))` shim with a dedicated
//! grammar that's directly addressable by `#[mask_all]`'s
//! substitution table.

use std::fs;

use proc_macro::TokenStream;
use syn::parse::{Parse, ParseStream};
use syn::punctuated::Punctuated;
use syn::spanned::Spanned;
use syn::{LitStr, Token, parse_macro_input};

use crate::common::{FailTag, compile_error, env_failure, include_relative_path, mask_str};

const MACRO_NAME: &str = "mask_concat";
const INVALID_DETAIL: &str =
    "arguments must be string literals or compile-time-resolvable string macros";

pub(crate) fn expand(input: TokenStream) -> TokenStream {
    let MaskConcatArgs(args) = parse_macro_input!(input as MaskConcatArgs);
    // Empty argument list mirrors stdlib `concat!()` → `""` (no error).
    let span = args
        .first()
        .map_or_else(proc_macro2::Span::call_site, MaskConcatArg::span);
    // Nested `include_str!` resolves relative to the file containing
    // the `mask_concat!` invocation, matching stdlib `include_str!`.
    let call_file = proc_macro::Span::call_site().file();
    let mut acc = String::new();
    for arg in &args {
        match arg.resolve(&call_file) {
            Ok(s) => acc.push_str(&s),
            Err(e) => return e.to_compile_error().into(),
        }
    }
    mask_str(span, acc.into_bytes()).into()
}

struct MaskConcatArgs(Punctuated<MaskConcatArg, Token![,]>);

impl Parse for MaskConcatArgs {
    fn parse(input: ParseStream) -> syn::Result<Self> {
        Punctuated::parse_terminated(input).map(MaskConcatArgs)
    }
}

enum MaskConcatArg {
    /// Pre-resolved literal value (string, integer, float, bool,
    /// char, or negative numeric) plus its source span. All five
    /// stdlib-`concat!`-compatible primitive kinds collapse here.
    Resolved(String, proc_macro2::Span),
    Concat(Punctuated<MaskConcatArg, Token![,]>, proc_macro2::Span),
    IncludeStr(LitStr, proc_macro2::Span),
    Env(LitStr, proc_macro2::Span),
}

impl MaskConcatArg {
    fn span(&self) -> proc_macro2::Span {
        match self {
            Self::Resolved(_, span)
            | Self::Concat(_, span)
            | Self::IncludeStr(_, span)
            | Self::Env(_, span) => *span,
        }
    }

    fn resolve(&self, call_file: &str) -> syn::Result<String> {
        match self {
            Self::Resolved(value, _) => Ok(value.clone()),
            Self::Concat(args, _) => {
                let mut s = String::new();
                for arg in args {
                    s.push_str(&arg.resolve(call_file)?);
                }
                Ok(s)
            }
            Self::IncludeStr(path_lit, _) => {
                let path_str = path_lit.value();
                let resolved = include_relative_path(call_file, &path_str);
                fs::read_to_string(&resolved).map_err(|e| {
                    compile_error(
                        path_lit.span(),
                        MACRO_NAME,
                        FailTag::ReadFailure,
                        &format!("nested include_str!: could not read `{path_str}`: {e}"),
                    )
                })
            }
            Self::Env(name_lit, _) => {
                let name = name_lit.value();
                std::env::var(&name).map_err(|e| {
                    let (tag, detail) = env_failure(&e, &name, "nested env!: ");
                    compile_error(name_lit.span(), MACRO_NAME, tag, &detail)
                })
            }
        }
    }
}

impl Parse for MaskConcatArg {
    fn parse(input: ParseStream) -> syn::Result<Self> {
        // Only the three stdlib compile-time-resolving forms are
        // recursed into. `unmasked!` and any user-defined macro are
        // rejected so the concatenated output cannot silently
        // include text that bypassed the masking pipeline.
        if input.peek(syn::Ident) && input.peek2(Token![!]) {
            let mac: syn::Macro = input.parse()?;
            let name = mac.path.get_ident().map(syn::Ident::to_string);
            let span = mac.path.span();
            return match name.as_deref() {
                Some("concat") => {
                    let args: Punctuated<MaskConcatArg, Token![,]> =
                        mac.parse_body_with(Punctuated::parse_terminated)?;
                    Ok(Self::Concat(args, span))
                }
                Some("include_str") => {
                    let lit: LitStr = mac.parse_body().map_err(|e| invalid_arg(e.span()))?;
                    Ok(Self::IncludeStr(lit, span))
                }
                Some("env") => {
                    let lit: LitStr = mac.parse_body().map_err(|e| invalid_arg(e.span()))?;
                    Ok(Self::Env(lit, span))
                }
                _ => Err(invalid_arg(span)),
            };
        }
        // Anything else: parse as an expression and check it's a
        // stdlib-`concat!`-style primitive literal (string, int,
        // float, bool, char, or unary-negated numeric).
        let expr: syn::Expr = input.parse().map_err(|e| invalid_arg(e.span()))?;
        let span = expr.span();
        let value = resolve_expr_literal(&expr).ok_or_else(|| invalid_arg(span))?;
        Ok(Self::Resolved(value, span))
    }
}

fn invalid_arg(span: proc_macro2::Span) -> syn::Error {
    compile_error(span, MACRO_NAME, FailTag::InvalidArg, INVALID_DETAIL)
}

/// Stringify the supported primitive-literal expressions accepted by
/// stdlib `concat!`. Returns `None` for anything else (paths, calls,
/// byte/cstr literals, etc.) so the caller can surface the standard
/// `invalid-arg` rejection via [`invalid_arg`].
fn resolve_expr_literal(expr: &syn::Expr) -> Option<String> {
    match expr {
        syn::Expr::Lit(le) => stringify_lit(&le.lit, false),
        // Stdlib `concat!(-3, -2.5)` accepts unary-negated numeric
        // literals; rustc parses `-3` as `Neg(LitInt(3))` rather
        // than a single LitInt, so we handle the unary wrapping
        // here.
        syn::Expr::Unary(syn::ExprUnary {
            op: syn::UnOp::Neg(_),
            expr: inner,
            ..
        }) => {
            let syn::Expr::Lit(le) = inner.as_ref() else {
                return None;
            };
            stringify_lit(&le.lit, true)
        }
        _ => None,
    }
}

/// Stringify one literal for `concat!`-compatible output. `negated`
/// is true when the literal was wrapped in unary `-`; only numeric
/// kinds accept negation — string/bool/char do not.
fn stringify_lit(lit: &syn::Lit, negated: bool) -> Option<String> {
    match lit {
        syn::Lit::Str(s) if !negated => Some(s.value()),
        syn::Lit::Int(n) if negated => Some(format!("-{}", n.base10_digits())),
        syn::Lit::Int(n) => Some(n.base10_digits().to_string()),
        syn::Lit::Float(f) if negated => Some(format!("-{}", f.base10_digits())),
        syn::Lit::Float(f) => Some(f.base10_digits().to_string()),
        syn::Lit::Bool(b) if !negated => Some(b.value.to_string()),
        syn::Lit::Char(c) if !negated => Some(c.value().to_string()),
        _ => None,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use syn::parse_quote;

    #[test]
    fn stringify_lit_accepts_unnegated_primitives() {
        assert_eq!(
            stringify_lit(&parse_quote!("hi"), false).as_deref(),
            Some("hi")
        );
        assert_eq!(
            stringify_lit(&parse_quote!(42), false).as_deref(),
            Some("42")
        );
        assert_eq!(
            stringify_lit(&parse_quote!(2.5), false).as_deref(),
            Some("2.5")
        );
        assert_eq!(
            stringify_lit(&parse_quote!(true), false).as_deref(),
            Some("true")
        );
        assert_eq!(
            stringify_lit(&parse_quote!('z'), false).as_deref(),
            Some("z")
        );
    }

    #[test]
    fn stringify_lit_negates_only_numeric_kinds() {
        // Numeric literals carry the leading `-` through.
        assert_eq!(
            stringify_lit(&parse_quote!(42), true).as_deref(),
            Some("-42")
        );
        assert_eq!(
            stringify_lit(&parse_quote!(2.5), true).as_deref(),
            Some("-2.5")
        );
        // The un-negated numeric arms must not prepend a `-`.
        assert_eq!(
            stringify_lit(&parse_quote!(42), false).as_deref(),
            Some("42")
        );
        assert_eq!(
            stringify_lit(&parse_quote!(2.5), false).as_deref(),
            Some("2.5")
        );
    }

    #[test]
    fn stringify_lit_rejects_negated_non_numeric_kinds() {
        // `-"s"`, `-true`, `-'c'` are not valid `concat!` literals: the
        // negation guard must reject them (→ None), not silently drop the
        // `-` and accept the underlying value.
        assert_eq!(stringify_lit(&parse_quote!("s"), true), None);
        assert_eq!(stringify_lit(&parse_quote!(true), true), None);
        assert_eq!(stringify_lit(&parse_quote!('c'), true), None);
    }

    #[test]
    fn resolve_expr_literal_handles_unary_negated_numbers() {
        // End-to-end through the unary-`Neg` unwrapping: `-3` resolves,
        // `-"x"` does not.
        assert_eq!(
            resolve_expr_literal(&parse_quote!(-3)).as_deref(),
            Some("-3")
        );
        assert_eq!(resolve_expr_literal(&parse_quote!(3)).as_deref(), Some("3"));
        assert_eq!(resolve_expr_literal(&parse_quote!(-"x")), None);
        // A non-literal expression is not a concat primitive.
        assert_eq!(resolve_expr_literal(&parse_quote!(foo())), None);
    }
}
