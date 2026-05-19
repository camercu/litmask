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
    Str(LitStr),
    Concat(Punctuated<MaskConcatArg, Token![,]>, proc_macro2::Span),
    IncludeStr(LitStr, proc_macro2::Span),
    Env(LitStr, proc_macro2::Span),
}

impl MaskConcatArg {
    fn span(&self) -> proc_macro2::Span {
        match self {
            Self::Str(lit) => lit.span(),
            Self::Concat(_, span) | Self::IncludeStr(_, span) | Self::Env(_, span) => *span,
        }
    }

    fn resolve(&self) -> syn::Result<String> {
        match self {
            Self::Str(lit) => Ok(lit.value()),
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
                std::env::var(&name).map_err(|_| {
                    syn::Error::new(
                        name_lit.span(),
                        format!("mask_concat! env!: environment variable `{name}` is not set"),
                    )
                })
            }
        }
    }
}

impl Parse for MaskConcatArg {
    fn parse(input: ParseStream) -> syn::Result<Self> {
        if input.peek(LitStr) {
            return Ok(Self::Str(input.parse()?));
        }
        if input.peek(syn::Ident) && input.peek2(Token![!]) {
            let mac: syn::Macro = input.parse()?;
            let name = mac.path.get_ident().map(syn::Ident::to_string);
            let span = mac.path.span();
            match name.as_deref() {
                Some("concat") => {
                    let args: Punctuated<MaskConcatArg, Token![,]> =
                        mac.parse_body_with(Punctuated::parse_terminated)?;
                    return Ok(Self::Concat(args, span));
                }
                Some("include_str") => {
                    let lit: LitStr = mac.parse_body()?;
                    return Ok(Self::IncludeStr(lit, span));
                }
                Some("env") => {
                    let lit: LitStr = mac.parse_body()?;
                    return Ok(Self::Env(lit, span));
                }
                _ => return Err(syn::Error::new(span, INVALID_MSG)),
            }
        }
        Err(syn::Error::new(input.span(), INVALID_MSG))
    }
}
