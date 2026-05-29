//! `mask_concat!` proc-macro: accept string literals plus nested
//! `concat!` / `include_str!` / `env!` invocations, resolve every
//! argument at proc-macro time, then AEAD-encrypt the concatenated
//! string and expand to a runtime decrypt call returning `String`.
//!
//! Replaces the prior `mask!(concat!(...))` shim with a dedicated
//! grammar that's directly addressable by `#[mask_all]`'s
//! substitution table.

use std::fs;
use std::path::PathBuf;

use proc_macro::TokenStream;
use syn::parse::{Parse, ParseStream};
use syn::punctuated::Punctuated;
use syn::spanned::Spanned;
use syn::{LitStr, Token, parse_macro_input};

use crate::common::{FailTag, compile_error, mask_str};

const MACRO_NAME: &str = "mask_concat";
const INVALID_DETAIL: &str =
    "arguments must be string literals or compile-time-resolvable string macros";

pub(crate) fn expand(input: TokenStream) -> TokenStream {
    let MaskConcatArgs(args) = parse_macro_input!(input as MaskConcatArgs);
    if args.is_empty() {
        return compile_error(
            proc_macro2::Span::call_site(),
            MACRO_NAME,
            FailTag::EmptyArgs,
            "requires at least one argument",
        )
        .to_compile_error()
        .into();
    }
    let span = args.first().expect("non-empty").span();
    let mut acc = String::new();
    for arg in &args {
        match arg.resolve() {
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

    fn resolve(&self) -> syn::Result<String> {
        match self {
            Self::Resolved(value, _) => Ok(value.clone()),
            Self::Concat(args, _) => {
                let mut s = String::new();
                for arg in args {
                    s.push_str(&arg.resolve()?);
                }
                Ok(s)
            }
            Self::IncludeStr(path_lit, _) => {
                let path_str = path_lit.value();
                let dir = crate::common::manifest_dir().ok_or_else(|| {
                    compile_error(
                        path_lit.span(),
                        MACRO_NAME,
                        FailTag::ReadFailure,
                        "nested include_str!: CARGO_MANIFEST_DIR not set",
                    )
                })?;
                let resolved = PathBuf::from(dir).join(&path_str);
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
                    let (tag, detail) = match e {
                        std::env::VarError::NotPresent => (
                            FailTag::Unset,
                            format!("nested env!: environment variable `{name}` is not set"),
                        ),
                        std::env::VarError::NotUnicode(_) => (
                            FailTag::UnicodeFailure,
                            format!(
                                "nested env!: environment variable `{name}` is set but its value is not valid UTF-8"
                            ),
                        ),
                    };
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
