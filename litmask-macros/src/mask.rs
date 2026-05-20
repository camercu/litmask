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
use syn::parse::{Parse, ParseStream};
use syn::{LitByteStr, LitCStr, LitStr, parse_macro_input};

use crate::common::{FailTag, compile_error, mask_bytes, mask_cstr, mask_str};

const MACRO_NAME: &str = "mask";
const INVALID_LITERAL_DETAIL: &str = "accepts string, byte string, or C string literals";

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
    let parsed = parse_macro_input!(input as MaskInput);
    match parsed {
        // `LitCStr::value` returns a `CString`; into_bytes() drops the
        // NUL terminator. We re-add the NUL at decode time via
        // `CString::new` so the encrypted blob holds only the payload,
        // not the terminator.
        MaskInput::Str(lit) => mask_str(lit.span(), lit.value().into_bytes()),
        MaskInput::ByteStr(lit) => mask_bytes(lit.span(), lit.value()),
        MaskInput::CStr(lit) => mask_cstr(lit.span(), lit.value().into_bytes()),
    }
    .into()
}

/// Parsed `mask!` input: one of the three accepted literal kinds.
/// The per-literal span is preserved through `quote!` interpolation,
/// so a `mask!()` invocation synthesized by `#[mask_all]` carries the
/// user's source span (not the attribute's), even when several
/// synthesized calls share an outer span — the per-literal span gives
/// the most granular `(file, line, column)` available.
enum MaskInput {
    Str(LitStr),
    ByteStr(LitByteStr),
    CStr(LitCStr),
}

impl Parse for MaskInput {
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
            INVALID_LITERAL_DETAIL,
        ))
    }
}
