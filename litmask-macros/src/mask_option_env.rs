//! `mask_option_env!` proc-macro: like `mask_env!` but the unset
//! case is a runtime `None` rather than a compile error, mirroring
//! stdlib `option_env!`'s contract.

use proc_macro::TokenStream;
use quote::quote;
use syn::LitStr;

use crate::common::{MaskKind, mask_plaintext};

const NON_LITERAL_MSG: &str = "mask_option_env! requires a string literal name";

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
    let expansion = match std::env::var(&name) {
        Ok(v) => {
            let masked = mask_plaintext(v.into_bytes(), name_lit.span(), MaskKind::Str);
            quote! { ::core::option::Option::Some(#masked) }
        }
        Err(_) => quote! {
            ::core::option::Option::<::litmask::__internal::__String>::None
        },
    };
    expansion.into()
}
