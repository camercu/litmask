//! `mask_stack!` proc-macro: AEAD-encrypt a string / byte-string /
//! C-string literal at compile time and expand to a **stack-resident**,
//! zero-alloc runtime decrypt — the stack counterpart of `mask!`.
//!
//! Same literal-kind acceptance as `mask!` (string, byte-string,
//! C-string); the output is a `MaskStr<N>` / `MaskBytes<N>` /
//! `MaskCStr<N>` guard that decrypts into an inline `[u8; N]` and
//! zeroizes on drop, rather than a heap `String` / `Vec` / `CString`.

use proc_macro::TokenStream;

use crate::common::{
    StringLiteral, mask_stack_bytes, mask_stack_cstr, mask_stack_str, parse_string_literal,
};

const MACRO_NAME: &str = "mask_stack";

pub(crate) fn expand(input: TokenStream) -> TokenStream {
    let parsed = match parse_string_literal(input, MACRO_NAME) {
        Ok(lit) => lit,
        Err(e) => return e.to_compile_error().into(),
    };
    match parsed {
        StringLiteral::Str(lit) => mask_stack_str(lit.span(), lit.value().into_bytes()),
        StringLiteral::ByteStr(lit) => mask_stack_bytes(lit.span(), lit.value()),
        // `LitCStr::value` yields a `CString`; `into_bytes()` drops the
        // NUL terminator so the sealed blob holds only the payload, the
        // same contract heap `mask!(c"...")` uses (the seam re-adds the
        // terminator into the stack buffer).
        StringLiteral::CStr(lit) => mask_stack_cstr(lit.span(), lit.value().into_bytes()),
    }
    .into()
}
