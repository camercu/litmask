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

use crate::common::{MaskKind, mask_plaintext};

const EMPTY_MSG: &str = "mask_concat! requires at least one argument";
const INVALID_MSG: &str =
    "mask_concat! arguments must be string literals or compile-time-resolvable string macros";

pub(crate) fn expand(input: TokenStream) -> TokenStream {
    let MaskConcatArgs(args) = parse_macro_input!(input as MaskConcatArgs);
    if args.is_empty() {
        return syn::Error::new(proc_macro2::Span::call_site(), EMPTY_MSG)
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
    mask_plaintext(acc.into_bytes(), span, MaskKind::Str).into()
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
                let manifest_dir = std::env::var_os("CARGO_MANIFEST_DIR").ok_or_else(|| {
                    syn::Error::new(
                        path_lit.span(),
                        "mask_concat! include_str!: CARGO_MANIFEST_DIR not set",
                    )
                })?;
                let resolved = PathBuf::from(manifest_dir).join(&path_str);
                fs::read_to_string(&resolved).map_err(|e| {
                    syn::Error::new(
                        path_lit.span(),
                        format!("mask_concat! include_str!: could not read `{path_str}`: {e}"),
                    )
                })
            }
            Self::Env(name_lit, _) => {
                let name = name_lit.value();
                std::env::var(&name).map_err(|e| {
                    let detail = match e {
                        std::env::VarError::NotPresent => "is not set",
                        std::env::VarError::NotUnicode(_) => {
                            "is set but its value is not valid UTF-8"
                        }
                    };
                    syn::Error::new(
                        name_lit.span(),
                        format!("mask_concat! env!: environment variable `{name}` {detail}"),
                    )
                })
            }
        }
    }
}

impl Parse for MaskConcatArg {
    fn parse(input: ParseStream) -> syn::Result<Self> {
        // Macro-invocation arms (recursive into stdlib-equivalent
        // compile-time-resolvable forms). `unmasked!`, user macros,
        // and any other macro path fall through to INVALID_MSG.
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
                    let lit: LitStr = mac
                        .parse_body()
                        .map_err(|e| syn::Error::new(e.span(), INVALID_MSG))?;
                    Ok(Self::IncludeStr(lit, span))
                }
                Some("env") => {
                    let lit: LitStr = mac
                        .parse_body()
                        .map_err(|e| syn::Error::new(e.span(), INVALID_MSG))?;
                    Ok(Self::Env(lit, span))
                }
                _ => Err(syn::Error::new(span, INVALID_MSG)),
            };
        }
        // Anything else: parse as an expression and check it's a
        // stdlib-`concat!`-style primitive literal (string, int,
        // float, bool, char, or unary-negated numeric).
        let expr: syn::Expr = input
            .parse()
            .map_err(|e| syn::Error::new(e.span(), INVALID_MSG))?;
        let span = expr.span();
        let value =
            resolve_expr_literal(&expr).ok_or_else(|| syn::Error::new(span, INVALID_MSG))?;
        Ok(Self::Resolved(value, span))
    }
}

/// Stringify the supported primitive-literal expressions accepted by
/// stdlib `concat!`. Returns `None` for anything else (paths, calls,
/// byte/cstr literals, etc.) so the caller can surface
/// [`INVALID_MSG`].
fn resolve_expr_literal(expr: &syn::Expr) -> Option<String> {
    match expr {
        syn::Expr::Lit(lit_expr) => match &lit_expr.lit {
            syn::Lit::Str(s) => Some(s.value()),
            syn::Lit::Int(n) => Some(n.base10_digits().to_string()),
            syn::Lit::Float(f) => Some(f.base10_digits().to_string()),
            syn::Lit::Bool(b) => Some(b.value.to_string()),
            syn::Lit::Char(c) => Some(c.value().to_string()),
            // LitByteStr / LitByte / LitCStr / Verbatim: stdlib
            // `concat!` rejects byte-shaped literals at top level;
            // mirror that.
            _ => None,
        },
        // Stdlib `concat!(-3, -2.5)` accepts unary-negated numeric
        // literals; rustc parses `-3` as `Neg(LitInt(3))` rather
        // than a single LitInt, so we handle the unary wrapping
        // here.
        syn::Expr::Unary(syn::ExprUnary {
            op: syn::UnOp::Neg(_),
            expr: inner,
            ..
        }) => match inner.as_ref() {
            syn::Expr::Lit(lit_expr) => match &lit_expr.lit {
                syn::Lit::Int(n) => Some(format!("-{}", n.base10_digits())),
                syn::Lit::Float(f) => Some(format!("-{}", f.base10_digits())),
                _ => None,
            },
            _ => None,
        },
        _ => None,
    }
}
