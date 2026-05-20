//! `unmasked!` proc-macro: identity wrapper for an explicitly opt-out
//! literal. Exists so the deep-rewriting `#[mask_all]` attribute can
//! recognize a literal as deliberately not-to-be-masked, while
//! expanding to the bare literal token at compile time.

use proc_macro::TokenStream;
use proc_macro2::TokenStream as TokenStream2;
use quote::quote;
use syn::parse::{Parse, ParseStream};
use syn::{LitByteStr, LitCStr, LitStr, parse_macro_input};

use crate::common::{FailTag, compile_error};

const MACRO_NAME: &str = "unmasked";

/// Implementation of the `#[proc_macro] unmasked` entry point.
///
/// Zero runtime overhead: the expansion is the bare literal token,
/// so the result is `&'static str` / `&'static [u8; N]` /
/// `&'static CStr` exactly as if the wrapper macro were absent.
pub(crate) fn expand(input: TokenStream) -> TokenStream {
    let kind = parse_macro_input!(input as UnmaskedInput);
    quote!(#kind).into()
}

/// Parsed `unmasked!` input. Mirrors `mask::MaskInput`'s grammar
/// (string / byte string / C string literal) but emits the literal
/// verbatim instead of running the encryption pipeline. The `ToTokens`
/// impl delegates to the inner literal so `quote!(#kind)` produces the
/// same token the caller wrote.
enum UnmaskedInput {
    Str(LitStr),
    ByteStr(LitByteStr),
    CStr(LitCStr),
}

impl quote::ToTokens for UnmaskedInput {
    fn to_tokens(&self, tokens: &mut TokenStream2) {
        match self {
            Self::Str(lit) => lit.to_tokens(tokens),
            Self::ByteStr(lit) => lit.to_tokens(tokens),
            Self::CStr(lit) => lit.to_tokens(tokens),
        }
    }
}

impl Parse for UnmaskedInput {
    fn parse(input: ParseStream) -> syn::Result<Self> {
        if input.peek(LitStr) {
            return input.parse().map(Self::Str);
        }
        if input.peek(LitByteStr) {
            return input.parse().map(Self::ByteStr);
        }
        if input.peek(LitCStr) {
            return input.parse().map(Self::CStr);
        }
        Err(compile_error(
            input.span(),
            MACRO_NAME,
            FailTag::NonLiteral,
            "accepts string, byte string, or C string literals",
        ))
    }
}
