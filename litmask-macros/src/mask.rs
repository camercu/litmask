//! `mask!` proc-macro: AEAD-encrypt a string / byte-string / C-string
//! literal at compile time and expand to a runtime decrypt call.
//!
//! Per spec Amendment 2026-05-17(b), `mask!` accepts only the three
//! literal kinds enumerated in §2.1.1.1–§2.1.1.4. Compile-time-
//! resolvable macros (`include_str!`, `concat!`, `env!`,
//! `option_env!`, `include_bytes!`, `file!`) have dedicated
//! `mask_*!` counterparts (§2.1.3–§2.1.8); the prior
//! `mask!(include_str!(...))` / `mask!(concat!(...))` whitelist is
//! removed.

use proc_macro::TokenStream;

use crate::common::{StringLiteral, mask_bytes, mask_cstr, mask_str, parse_string_literal};

const MACRO_NAME: &str = "mask";

/// Implementation of the `#[proc_macro] mask` entry point. Re-exported
/// at the crate root via a one-line wrapper.
///
/// Dispatches to a per-literal-kind helper from
/// [`crate::common`]. The c-string arm relies on the
/// `__decrypt_cstring_call!` `macro_rules` dispatcher in
/// `litmask::lib.rs`, which surfaces a clean `compile_error!` for
/// the `no-std` feature combination instead of a downstream
/// "`CString` not found" diagnostic.
pub(crate) fn expand(input: TokenStream) -> TokenStream {
    let parsed = match parse_string_literal(input, MACRO_NAME) {
        Ok(lit) => lit,
        Err(e) => return e.to_compile_error().into(),
    };
    match parsed {
        // `LitCStr::value` returns a `CString`; into_bytes() drops the
        // NUL terminator. We re-add the NUL at decode time via
        // `CString::new` so the encrypted blob holds only the payload,
        // not the terminator.
        StringLiteral::Str(lit) => mask_str(lit.span(), lit.value().into_bytes()),
        StringLiteral::ByteStr(lit) => mask_bytes(lit.span(), lit.value()),
        StringLiteral::CStr(lit) => mask_cstr(lit.span(), lit.value().into_bytes()),
    }
    .into()
}
