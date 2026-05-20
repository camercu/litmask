//! `mask_env!` proc-macro: read a build-time environment variable
//! at proc-macro time, AEAD-encrypt the value, and expand to a
//! runtime decrypt call returning `String`. Grammar mirrors stdlib
//! `env!`: `mask_env!("NAME")` or `mask_env!("NAME", "custom error
//! message")`. An unset variable is a compile error; the optional
//! second arg, when provided, is used as the error text.

use std::env::VarError;

use proc_macro::TokenStream;
use syn::parse::{Parse, ParseStream};
use syn::{LitStr, Token, parse_macro_input};

use crate::common::{FailTag, compile_error, mask_str};

const MACRO_NAME: &str = "mask_env";
const NON_LITERAL_DETAIL: &str = "requires a string literal name";

struct MaskEnvInput {
    name: LitStr,
    custom_msg: Option<LitStr>,
}

impl Parse for MaskEnvInput {
    fn parse(input: ParseStream) -> syn::Result<Self> {
        let name: LitStr = input.parse().map_err(|e| {
            compile_error(
                e.span(),
                MACRO_NAME,
                FailTag::NonLiteral,
                NON_LITERAL_DETAIL,
            )
        })?;
        let custom_msg = if input.peek(Token![,]) {
            input.parse::<Token![,]>()?;
            // Allow trailing comma after the name: `mask_env!("X",)`.
            if input.is_empty() {
                None
            } else {
                Some(input.parse::<LitStr>().map_err(|e| {
                    compile_error(
                        e.span(),
                        MACRO_NAME,
                        FailTag::NonLiteral,
                        NON_LITERAL_DETAIL,
                    )
                })?)
            }
        } else {
            None
        };
        if !input.is_empty() {
            return Err(compile_error(
                input.span(),
                MACRO_NAME,
                FailTag::NonLiteral,
                NON_LITERAL_DETAIL,
            ));
        }
        Ok(Self { name, custom_msg })
    }
}

pub(crate) fn expand(input: TokenStream) -> TokenStream {
    let MaskEnvInput { name, custom_msg } = parse_macro_input!(input as MaskEnvInput);
    let name_value = name.value();
    match std::env::var(&name_value) {
        Ok(value) => mask_str(name.span(), value.into_bytes()).into(),
        Err(VarError::NotPresent) => {
            let err = match &custom_msg {
                // A user-supplied custom message replaces the prose
                // entirely (mirrors stdlib `env!`'s contract). The
                // §1.9.6 macro-name + tag prefix is still emitted so
                // tooling can pattern-match on `mask_env! unset:`.
                Some(m) => compile_error(name.span(), MACRO_NAME, FailTag::Unset, &m.value()),
                None => compile_error(
                    name.span(),
                    MACRO_NAME,
                    FailTag::Unset,
                    &format!("environment variable `{name_value}` is not set"),
                ),
            };
            err.to_compile_error().into()
        }
        Err(VarError::NotUnicode(_)) => compile_error(
            name.span(),
            MACRO_NAME,
            FailTag::UnicodeFailure,
            &format!("environment variable `{name_value}` is set but its value is not valid UTF-8"),
        )
        .to_compile_error()
        .into(),
    }
}
