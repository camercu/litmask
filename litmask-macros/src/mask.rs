//! `mask!` proc-macro: AEAD-encrypt a string / byte-string / C-string
//! literal at compile time and expand to a runtime decrypt call.
//!
//! Also accepts `include_str!(...)` and `concat!(...)` as inputs:
//! both expand at proc-macro time to a synthetic string literal, so
//! the encryption pipeline sees a uniform literal input regardless
//! of which surface form the user wrote.

use std::fs;
use std::path::PathBuf;

use proc_macro::TokenStream;
use syn::parse::{Parse, ParseStream};
use syn::punctuated::Punctuated;
use syn::spanned::Spanned;
use syn::{LitByteStr, LitCStr, LitStr, Token, parse_macro_input};

use crate::common::{MaskKind, mask_plaintext};

/// Error text emitted for any `mask!` input that isn't a supported
/// literal kind or one of the two accepted built-in macro inputs.
/// Single source of truth — change here and regenerate trybuild
/// snapshots with `TRYBUILD=overwrite`.
const INVALID_LITERAL_MSG: &str = "mask! accepts string, byte string, or C string literals";

/// Error text emitted when a `concat!` argument inside `mask!` is
/// neither a supported literal kind nor a further nested
/// `concat!`/`include_str!`, or when the arguments mix literal kinds.
const CONCAT_ARG_MSG: &str =
    "concat! arguments inside mask! must be string, byte string, or C string literals";

/// Implementation of the `#[proc_macro] mask` entry point. Re-exported
/// at the crate root via a one-line wrapper.
pub(crate) fn expand(input: TokenStream) -> TokenStream {
    let parsed = parse_macro_input!(input as MaskInput);
    let span = parsed.span();
    let kind = parsed.mask_kind();
    let plaintext = parsed.plaintext();
    mask_plaintext(plaintext, span, kind).into()
}

/// Parsed `mask!` input. After accepting `include_str!`/`concat!`
/// (both resolve to synthetic `LitStr` values during parsing), the
/// input always reduces to one of three literal kinds — the runtime
/// path is uniform across every accepted input form.
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
    /// `__decrypt_cstring_call!` macro_rules dispatcher in
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
        if input.peek(syn::Ident) && input.peek2(Token![!]) {
            return parse_macro_input_arg(input);
        }
        Err(syn::Error::new(input.span(), INVALID_LITERAL_MSG))
    }
}

/// Resolve the two macro inputs `mask!` accepts: `include_str!(...)`
/// and `concat!(...)`. Any other macro invocation falls back to the
/// standard rejection so `mask!(println!(...))` and friends produce
/// the [`INVALID_LITERAL_MSG`] error.
fn parse_macro_input_arg(input: ParseStream) -> syn::Result<MaskInput> {
    let mac: syn::Macro = input.parse()?;
    let name = mac.path.get_ident().map(syn::Ident::to_string);
    match name.as_deref() {
        Some("include_str") => resolve_include_str(&mac),
        Some("concat") => resolve_concat(&mac),
        _ => Err(syn::Error::new(mac.path.span(), INVALID_LITERAL_MSG)),
    }
}

/// `mask!(include_str!("path"))` — read the file at proc-macro time
/// and treat its contents as if the user had written a string literal
/// at the call site. Path is resolved relative to the consumer
/// crate's `CARGO_MANIFEST_DIR`.
///
/// Note: stable Rust does not expose a proc-macro API for marking
/// arbitrary files as build inputs, so edits to the included file
/// do NOT trigger an automatic rebuild — users must `cargo clean`
/// or touch a tracked source file.
fn resolve_include_str(mac: &syn::Macro) -> syn::Result<MaskInput> {
    let path_lit: LitStr = mac.parse_body()?;
    let manifest_dir = std::env::var_os("CARGO_MANIFEST_DIR").ok_or_else(|| {
        syn::Error::new(
            path_lit.span(),
            "mask!(include_str!(...)): CARGO_MANIFEST_DIR is not set",
        )
    })?;
    let user_path = path_lit.value();
    let resolved = PathBuf::from(manifest_dir).join(&user_path);
    // Error message echoes the user's literal path, not the resolved
    // absolute path. Resolved paths embed the user's home directory
    // and the consumer crate's checkout location, both of which break
    // trybuild snapshot portability and leak local FS layout into
    // diagnostics.
    let content = fs::read_to_string(&resolved).map_err(|e| {
        syn::Error::new(
            path_lit.span(),
            format!("mask!(include_str!(\"{user_path}\")): {e}"),
        )
    })?;
    Ok(MaskInput::Str(LitStr::new(&content, path_lit.span())))
}

/// `mask!(concat!(args...))` — recursively resolve each argument as a
/// `MaskInput`, reject mixed literal kinds, and emit a synthetic
/// literal of the unified kind. Currently only string-literal concat
/// is reachable: byte/c-string concat is rejected with
/// [`CONCAT_ARG_MSG`] because the stdlib `concat!` doesn't accept
/// those forms anyway.
fn resolve_concat(mac: &syn::Macro) -> syn::Result<MaskInput> {
    let span = mac.path.span();
    let args: Punctuated<MaskInput, Token![,]> = mac.parse_body_with(|input: ParseStream| {
        Punctuated::parse_terminated_with(input, |arg_input| {
            // The "argument is neither a supported literal nor a
            // whitelisted macro" case surfaces from inner parsing as
            // INVALID_LITERAL_MSG. Inside `concat!` the spec mandates
            // CONCAT_ARG_MSG for that case — but downstream errors
            // (file-not-found from include_str!, nested concat
            // failures with their own context) must reach the user
            // unchanged, otherwise diagnostics like "failed to read
            // /path/to/missing.txt" get masked behind the generic
            // concat substring.
            //
            // Equality (not `contains`) is intentional: it locks the
            // rewrite to the one well-defined catch-all branch of
            // MaskInput::parse and avoids false-firing on downstream
            // errors whose messages happen to embed the substring.
            // If MaskInput::parse ever decorates this error with
            // span hints or extra notes, this comparison flips
            // silently to false — update both sites in lockstep.
            MaskInput::parse(arg_input).map_err(|e| {
                if e.to_string() == INVALID_LITERAL_MSG {
                    syn::Error::new(e.span(), CONCAT_ARG_MSG)
                } else {
                    e
                }
            })
        })
    })?;

    let mut acc = String::new();
    for arg in &args {
        match arg {
            MaskInput::Str(s) => acc.push_str(&s.value()),
            _ => return Err(syn::Error::new(span, CONCAT_ARG_MSG)),
        }
    }
    Ok(MaskInput::Str(LitStr::new(&acc, span)))
}
