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

use crate::common::{MaskKind, mask_plaintext};

const NON_LITERAL_MSG: &str = "mask_env! requires a string literal name";

struct MaskEnvInput {
    name: LitStr,
    custom_msg: Option<LitStr>,
}

impl Parse for MaskEnvInput {
    fn parse(input: ParseStream) -> syn::Result<Self> {
        let name: LitStr = input
            .parse()
            .map_err(|e| syn::Error::new(e.span(), NON_LITERAL_MSG))?;
        let custom_msg = if input.peek(Token![,]) {
            input.parse::<Token![,]>()?;
            // Allow trailing comma after the name: `mask_env!("X",)`.
            if input.is_empty() {
                None
            } else {
                Some(
                    input
                        .parse::<LitStr>()
                        .map_err(|e| syn::Error::new(e.span(), NON_LITERAL_MSG))?,
                )
            }
        } else {
            None
        };
        if !input.is_empty() {
            return Err(syn::Error::new(input.span(), NON_LITERAL_MSG));
        }
        Ok(Self { name, custom_msg })
    }
}

pub(crate) fn expand(input: TokenStream) -> TokenStream {
    let MaskEnvInput { name, custom_msg } = parse_macro_input!(input as MaskEnvInput);
    let name_value = name.value();
    match std::env::var(&name_value) {
        Ok(value) => mask_plaintext(value.into_bytes(), name.span(), MaskKind::Str).into(),
        Err(VarError::NotPresent) => {
            let msg = match &custom_msg {
                Some(m) => m.value(),
                None => format!("mask_env!: environment variable `{name_value}` is not set"),
            };
            syn::Error::new(name.span(), msg).to_compile_error().into()
        }
        Err(VarError::NotUnicode(_)) => syn::Error::new(
            name.span(),
            format!(
                "mask_env!: environment variable `{name_value}` is set but its value is not valid UTF-8"
            ),
        )
        .to_compile_error()
        .into(),
    }
}
