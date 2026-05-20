//! `mask_option_env!` proc-macro: like `mask_env!` but the unset
//! case is a runtime `None` rather than a compile error, mirroring
//! stdlib `option_env!`'s contract.

use proc_macro::TokenStream;
use quote::quote;

use crate::common::{mask_str, require_lit_str};

const MACRO_NAME: &str = "mask_option_env";

pub(crate) fn expand(input: TokenStream) -> TokenStream {
    let name_lit = match require_lit_str(input, MACRO_NAME, "requires a string literal name") {
        Ok(lit) => lit,
        Err(e) => return e.to_compile_error().into(),
    };
    let name = name_lit.value();
    let expansion = if let Ok(v) = std::env::var(&name) {
        let masked = mask_str(name_lit.span(), v.into_bytes());
        quote! { ::core::option::Option::Some(#masked) }
    } else {
        quote! { ::core::option::Option::<::litmask::__internal::__String>::None }
    };
    expansion.into()
}
