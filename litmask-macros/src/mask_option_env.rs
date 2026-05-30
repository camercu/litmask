//! `mask_option_env!` proc-macro: like `mask_env!` but the *unset*
//! case is a runtime `None` rather than a compile error. A present-
//! but-non-UTF-8 value remains a compile error, mirroring stdlib
//! `option_env!`'s contract exactly (only "not present" is `None`).

use std::env::VarError;

use proc_macro::TokenStream;
use quote::quote;

use crate::common::{compile_error, env_failure, mask_str, require_lit_str};

const MACRO_NAME: &str = "mask_option_env";

pub(crate) fn expand(input: TokenStream) -> TokenStream {
    let name_lit = match require_lit_str(input, MACRO_NAME, "requires a string literal name") {
        Ok(lit) => lit,
        Err(e) => return e.to_compile_error().into(),
    };
    let name = name_lit.value();
    let expansion = match std::env::var(&name) {
        Ok(v) => {
            let masked = mask_str(name_lit.span(), v.into_bytes());
            quote! { ::core::option::Option::Some(#masked) }
        }
        // Only a genuinely-absent variable is a runtime `None` (mirrors
        // stdlib `option_env!`). A present-but-non-UTF-8 value is a
        // compile error, matching `mask_env!` and stdlib `option_env!`.
        Err(VarError::NotPresent) => {
            quote! { ::core::option::Option::<::litmask::__internal::__String>::None }
        }
        Err(err @ VarError::NotUnicode(_)) => {
            let (tag, detail) = env_failure(&err, &name, "");
            return compile_error(name_lit.span(), MACRO_NAME, tag, &detail)
                .to_compile_error()
                .into();
        }
    };
    expansion.into()
}
