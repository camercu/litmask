//! String-literal parsing for the `mask_*!` grammars: the single
//! `LitStr` requirement, the path-argument reader, and the three-kind
//! [`StringLiteral`] accepted by `mask!` / `unmasked!` / `weak_mask!`.

use proc_macro2::TokenStream;
use quote::ToTokens;
use syn::parse::ParseStream;
use syn::{LitByteStr, LitCStr, LitStr};

use super::diagnostics::{FailTag, compile_error};
use super::path::include_relative_path;

/// Parse a `proc_macro::TokenStream` as a single `LitStr` argument,
/// or return a §1.9.6 `non-literal` compile error. Used by every
/// path-or-name-shaped mask_*! macro that takes one string literal.
pub(crate) fn require_lit_str(
    input: proc_macro::TokenStream,
    macro_name: &str,
    detail: &str,
) -> Result<LitStr, syn::Error> {
    match syn::parse::<LitStr>(input) {
        Ok(lit) => Ok(lit),
        Err(e) => Err(compile_error(
            e.span(),
            macro_name,
            FailTag::NonLiteral,
            detail,
        )),
    }
}

/// Parse `input` as a single-string-literal path argument, resolve it
/// the way stdlib `include_str!` does — relative to the source file
/// containing the invocation (see [`include_relative_path`]) — and
/// read the file via `reader`. Returns the parsed `LitStr` (for
/// span-preserving downstream emission) plus the read content on
/// success.
///
/// `reader` decides the read shape: pass `std::fs::read_to_string` for
/// `mask_include_str!` (UTF-8 validated at proc-macro time) or
/// `std::fs::read` for `mask_include_bytes!` (raw bytes). The signature
/// preserves UTF-8 fail-fast semantics — invalid UTF-8 in an
/// `include_str!`-shaped file fails the compile, not the user's
/// runtime.
///
/// Error detail echoes the user's literal path, not the resolved
/// path, so trybuild snapshots stay portable and local FS layout
/// doesn't leak into diagnostics.
pub(crate) fn read_lit_str_path<T>(
    input: proc_macro::TokenStream,
    macro_name: &'static str,
    reader: impl FnOnce(&std::path::Path) -> std::io::Result<T>,
) -> Result<(LitStr, T), syn::Error> {
    let path_lit = require_lit_str(input, macro_name, "requires a string literal path")?;
    let path_str = path_lit.value();
    let call_file = proc_macro::Span::call_site().file();
    let resolved = include_relative_path(&call_file, &path_str);
    let content = reader(&resolved).map_err(|e| {
        compile_error(
            path_lit.span(),
            macro_name,
            FailTag::ReadFailure,
            &format!("could not read `{path_str}`: {e}"),
        )
    })?;
    Ok((path_lit, content))
}

/// The three string-like literal kinds accepted by `mask!`,
/// `unmasked!`, and `weak_mask!`. Each variant preserves the
/// literal's source span so per-call-site nonce derivation works
/// even when `#[mask_all]` synthesizes multiple `mask!` calls
/// within one expansion.
pub(crate) enum StringLiteral {
    Str(LitStr),
    ByteStr(LitByteStr),
    CStr(LitCStr),
}

impl StringLiteral {
    pub(crate) fn parse_from(input: ParseStream, macro_name: &str) -> syn::Result<Self> {
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
            macro_name,
            FailTag::NonLiteral,
            "accepts string, byte string, or C string literals",
        ))
    }
}

impl ToTokens for StringLiteral {
    fn to_tokens(&self, tokens: &mut TokenStream) {
        match self {
            Self::Str(lit) => lit.to_tokens(tokens),
            Self::ByteStr(lit) => lit.to_tokens(tokens),
            Self::CStr(lit) => lit.to_tokens(tokens),
        }
    }
}

/// Parse a `proc_macro::TokenStream` as a [`StringLiteral`]. Returns a
/// `syn::Error` on failure; callers lower it to a token stream at the
/// `expand` boundary via `.to_compile_error().into()`, matching the
/// error-handling idiom used by every other `mask_*!` macro.
pub(crate) fn parse_string_literal(
    input: proc_macro::TokenStream,
    macro_name: &str,
) -> syn::Result<StringLiteral> {
    syn::parse::Parser::parse(
        |stream: ParseStream| StringLiteral::parse_from(stream, macro_name),
        input,
    )
}
