//! `mask_env!` proc-macro: read a build-time environment variable
//! at proc-macro time, AEAD-encrypt the value, and expand to a
//! runtime decrypt call returning `String`. Mirrors stdlib `env!`'s
//! must-succeed contract: an unset variable is a compile error.

use proc_macro::TokenStream;
use syn::LitStr;

use crate::common::{MaskKind, mask_plaintext};

const NON_LITERAL_MSG: &str = "mask_env! requires a string literal name";

pub(crate) fn expand(input: TokenStream) -> TokenStream {
    let name_lit: LitStr = match syn::parse(input) {
        Ok(lit) => lit,
        Err(e) => {
            return syn::Error::new(e.span(), NON_LITERAL_MSG)
                .to_compile_error()
                .into();
        }
    };
    let name = name_lit.value();
    let Ok(value) = std::env::var(&name) else {
        return syn::Error::new(
            name_lit.span(),
            format!("mask_env!: environment variable `{name}` is not set"),
        )
        .to_compile_error()
        .into();
    };
    mask_plaintext(value.into_bytes(), name_lit.span(), MaskKind::Str).into()
}
