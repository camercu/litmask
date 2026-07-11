//! `mask_env!` proc-macro: read a build-time environment variable
//! at proc-macro time, AEAD-encrypt the value, and expand to a
//! runtime decrypt call returning `String`. Grammar mirrors stdlib
//! `env!`: `mask_env!("NAME")` or `mask_env!("NAME", "custom error
//! message")`. An unset variable is a compile error; the optional
//! second arg, when provided, is used as the error text.

use std::env::VarError;

use proc_macro::TokenStream;
use proc_macro2::TokenStream as TokenStream2;
use syn::parse::{Parse, ParseStream};
use syn::{LitStr, Token, parse_macro_input};

use crate::common::{FailTag, compile_error, env_failure, mask_str};

const MACRO_NAME: &str = "mask_env";
const NON_LITERAL_DETAIL: &str = "requires a string literal name";

struct MaskEnvInput {
    name: LitStr,
    custom_msg: Option<LitStr>,
}

impl Parse for MaskEnvInput {
    fn parse(input: ParseStream) -> syn::Result<Self> {
        let non_literal = |span: proc_macro2::Span| {
            compile_error(span, MACRO_NAME, FailTag::NonLiteral, NON_LITERAL_DETAIL)
        };
        // Nothing supplied is missing-arg, not non-literal (§1.9.6).
        if input.is_empty() {
            return Err(compile_error(
                input.span(),
                MACRO_NAME,
                FailTag::MissingArg,
                NON_LITERAL_DETAIL,
            ));
        }
        let name: LitStr = input.parse().map_err(|e| non_literal(e.span()))?;
        let custom_msg = if input.peek(Token![,]) {
            input.parse::<Token![,]>()?;
            // Trailing comma after the name (`mask_env!("X",)`) is
            // legal and produces no custom message.
            if input.is_empty() {
                None
            } else {
                Some(input.parse::<LitStr>().map_err(|e| non_literal(e.span()))?)
            }
        } else {
            None
        };
        if !input.is_empty() {
            return Err(non_literal(input.span()));
        }
        Ok(Self { name, custom_msg })
    }
}

pub(crate) fn expand(input: TokenStream) -> TokenStream {
    let MaskEnvInput { name, custom_msg } = parse_macro_input!(input as MaskEnvInput);
    // Imperative shell: read the environment, then hand the lookup result
    // to the pure branch selector below. Only the `Ok` arm needs the
    // build-time keys (via `mask_str`), so it stays here; the error
    // diagnostics are decided in `env_error_tokens`, which is testable
    // without touching the process environment.
    match std::env::var(name.value()) {
        Ok(value) => mask_str(name.span(), value.into_bytes()).into(),
        Err(err) => env_error_tokens(&err, &name, custom_msg.as_ref()).into(),
    }
}

/// Compile-error tokens for a failed `mask_env!` lookup. Pure — depends
/// only on the `VarError` and the parsed name/message, not the
/// environment — so the diagnostic-selection branch is unit testable.
///
/// A user-supplied custom message is emitted verbatim for the unset case,
/// exactly mirroring stdlib `env!("NAME", "msg")` (§2.1.6.3): no §1.9.6
/// macro-name/tag prefix, since the user owns the entire diagnostic text.
/// Every other failure (unset-without-message, non-UTF-8) keeps the
/// §1.9.6 format.
fn env_error_tokens(err: &VarError, name: &LitStr, custom_msg: Option<&LitStr>) -> TokenStream2 {
    if let (VarError::NotPresent, Some(msg)) = (err, custom_msg) {
        return syn::Error::new(name.span(), msg.value()).to_compile_error();
    }
    let (tag, detail) = env_failure(err, &name.value(), "");
    compile_error(name.span(), MACRO_NAME, tag, &detail).to_compile_error()
}

#[cfg(test)]
mod tests {
    use super::*;
    use syn::parse_quote;

    fn err_text(err: &VarError, custom: Option<&LitStr>) -> String {
        let name: LitStr = parse_quote!("MY_VAR");
        env_error_tokens(err, &name, custom).to_string()
    }

    #[test]
    fn unset_with_custom_message_emits_it_verbatim() {
        let custom: LitStr = parse_quote!("please set MY_VAR");
        let text = err_text(&VarError::NotPresent, Some(&custom));
        assert!(
            text.contains("please set MY_VAR"),
            "user message verbatim: {text}"
        );
        // The user owns the whole text — no §1.9.6 `mask_env:` prefix.
        assert!(
            !text.contains("mask_env"),
            "no macro prefix on custom message: {text}"
        );
    }

    #[test]
    fn unset_without_custom_message_uses_the_formatted_diagnostic() {
        let text = err_text(&VarError::NotPresent, None);
        assert!(
            text.contains("mask_env"),
            "falls back to the §1.9.6 format: {text}"
        );
    }

    #[test]
    fn non_utf8_ignores_the_custom_message_and_stays_formatted() {
        // The custom message only applies to the unset case; a non-UTF-8
        // value is a different failure and keeps the §1.9.6 format.
        let custom: LitStr = parse_quote!("please set MY_VAR");
        let text = err_text(&VarError::NotUnicode("x".into()), Some(&custom));
        assert!(
            text.contains("mask_env"),
            "non-utf8 stays formatted: {text}"
        );
        assert!(
            !text.contains("please set MY_VAR"),
            "custom message not used: {text}"
        );
    }
}
