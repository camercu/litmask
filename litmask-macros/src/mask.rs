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

use crate::common::{FailTag, MaskKind, compile_error, mask_plaintext};

const MACRO_NAME: &str = "mask";
const INVALID_LITERAL_DETAIL: &str = "accepts string, byte string, or C string literals";

/// Implementation of the `#[proc_macro] mask` entry point. Re-exported
/// at the crate root via a one-line wrapper.
pub(crate) fn expand(input: TokenStream) -> TokenStream {
    let parsed = parse_macro_input!(input as MaskInput);
    let span = parsed.span();
    let kind = parsed.mask_kind();
    let plaintext = parsed.plaintext();
    mask_plaintext(plaintext, span, kind).into()
}

/// Parsed `mask!` input: one of the three accepted literal kinds.
enum MaskInput {
    Str(LitStr),
    ByteStr(LitByteStr),
    CStr(LitCStr),
}

impl MaskInput {
    /// `proc_macro2::Span` of the underlying literal. Preserved
    /// through `quote!` interpolation, so a `mask!()` invocation
    /// synthesized by `#[mask_all]` carries the user's source span
    /// (not the attribute's), even when several synthesized calls
    /// share an outer span — the per-literal span gives the most
    /// granular `(file, line, column)` available.
    fn span(&self) -> proc_macro2::Span {
        match self {
            Self::Str(lit) => lit.span(),
            Self::ByteStr(lit) => lit.span(),
            Self::CStr(lit) => lit.span(),
        }
    }

    fn plaintext(&self) -> Vec<u8> {
        match self {
            Self::Str(lit) => lit.value().into_bytes(),
            Self::ByteStr(lit) => lit.value(),
            // `LitCStr::value` returns a `CString`; into_bytes() drops
            // the NUL terminator. We re-add the NUL at decode time via
            // `CString::new` so the encrypted blob holds only the
            // payload, not the terminator.
            Self::CStr(lit) => lit.value().into_bytes(),
        }
    }

    /// Map literal kind to the `MaskKind` driving `mask_plaintext`'s
    /// runtime decrypt expression. The c-string arm relies on the
    /// `__decrypt_cstring_call!` `macro_rules` dispatcher in
    /// `litmask::lib.rs`, which surfaces a clean `compile_error!` for
    /// the `no-std` feature combination instead of a downstream
    /// "`CString` not found" diagnostic.
    fn mask_kind(&self) -> MaskKind {
        match self {
            Self::Str(_) => MaskKind::Str,
            Self::ByteStr(_) => MaskKind::Bytes,
            Self::CStr(_) => MaskKind::CStr,
        }
    }
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
