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
    let name_value = name.value();
    match std::env::var(&name_value) {
        Ok(value) => mask_str(name.span(), value.into_bytes()).into(),
        // A user-supplied custom message is emitted verbatim for the
        // unset case, exactly mirroring stdlib `env!("NAME", "msg")`
        // (per spec §2.1.6.3): no §1.9.6 macro-name/tag prefix, since
        // the user owns the entire diagnostic text. All other failures
        // (unset-without-message, non-UTF-8) keep the §1.9.6 format.
        Err(VarError::NotPresent) if custom_msg.is_some() => {
            let msg = custom_msg.expect("checked is_some").value();
            syn::Error::new(name.span(), msg).to_compile_error().into()
        }
        Err(err) => {
            let (tag, detail) = env_failure(&err, &name_value, "");
            compile_error(name.span(), MACRO_NAME, tag, &detail)
                .to_compile_error()
                .into()
        }
    }
}
