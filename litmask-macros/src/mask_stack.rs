//! `mask_stack!` proc-macro: AEAD-encrypt a string / byte-string /
//! C-string literal at compile time and expand to a **stack-resident**,
//! zero-alloc runtime decrypt — the stack counterpart of `mask!`.
//!
//! Same literal-kind acceptance as `mask!` (string, byte-string,
//! C-string); the output is a `MaskStr<N>` / `MaskBytes<N>` /
//! `MaskCStr<N>` guard that decrypts into an inline `[u8; N]` and
//! zeroizes on drop, rather than a heap `String` / `Vec` / `CString`.

use proc_macro::TokenStream;

use crate::common::{StringLiteral, mask_stack_str, parse_string_literal};

const MACRO_NAME: &str = "mask_stack";

pub(crate) fn expand(input: TokenStream) -> TokenStream {
    let parsed = match parse_string_literal(input, MACRO_NAME) {
        Ok(lit) => lit,
        Err(e) => return e.to_compile_error().into(),
    };
    match parsed {
        StringLiteral::Str(lit) => mask_stack_str(lit.span(), lit.value().into_bytes()),
        StringLiteral::ByteStr(lit) => syn::Error::new(
            lit.span(),
            "mask_stack!(b\"...\") is not yet implemented; use mask!(b\"...\") for now",
        )
        .to_compile_error(),
        StringLiteral::CStr(lit) => syn::Error::new(
            lit.span(),
            "mask_stack!(c\"...\") is not yet implemented; use mask!(c\"...\") for now",
        )
        .to_compile_error(),
    }
    .into()
}
