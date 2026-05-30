//! `unmasked!` proc-macro: identity wrapper for an explicitly opt-out
//! literal. Exists so the deep-rewriting `#[mask_all]` attribute can
//! recognize a literal as deliberately not-to-be-masked, while
//! expanding to the bare literal token at compile time.

use proc_macro::TokenStream;
use quote::quote;

use crate::common::parse_string_literal;

const MACRO_NAME: &str = "unmasked";

/// Implementation of the `#[proc_macro] unmasked` entry point.
///
/// Zero runtime overhead: the expansion is the bare literal token,
/// so the result is `&'static str` / `&'static [u8; N]` /
/// `&'static CStr` exactly as if the wrapper macro were absent.
pub(crate) fn expand(input: TokenStream) -> TokenStream {
    let lit = match parse_string_literal(input, MACRO_NAME) {
        Ok(lit) => lit,
        Err(e) => return e.to_compile_error().into(),
    };
    quote!(#lit).into()
}
