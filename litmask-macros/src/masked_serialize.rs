//! `#[derive(MaskedSerialize)]`: a `serde::Serialize` impl whose
//! struct and field names are AEAD-masked at compile time (EXPERIMENTAL,
//! `unstable-serde` feature).
//!
//! Plain `#[derive(serde::Serialize)]` embeds every field name as a
//! cleartext `&'static str` in `.rodata` via
//! `SerializeStruct::serialize_field("name", ...)`. This derive routes
//! each name through the same AEAD blob pipeline as `mask!` and
//! decrypts on first serialization.
//!
//! Wire-format contract: output is byte-identical to the plain derive
//! for every serde format. That is why the expansion uses
//! `serialize_struct` (not `serialize_map`) — non-self-describing
//! formats (bincode, postcard) serialize structs positionally without
//! names, and a map-based impl would both change their wire shape and
//! re-introduce the names on the wire. `serialize_struct` requires
//! `&'static str` names, so each decrypted name is leaked once and
//! cached in a `OnceLock`. The leak is bounded (one allocation per
//! name per process) and consistent with litmask's threat model: the
//! protected asset is the binary at rest, not process memory.

use proc_macro::TokenStream;
use proc_macro2::TokenStream as TokenStream2;
use quote::quote;
use syn::ext::IdentExt;
use syn::spanned::Spanned;
use syn::{Data, DeriveInput, Fields};

use crate::common::{FailTag, compile_error, mask_str};

const MACRO_NAME: &str = "MaskedSerialize";

/// Implementation of the `#[proc_macro_derive] MaskedSerialize` entry
/// point. Re-exported at the crate root via a one-line wrapper.
pub(crate) fn expand(input: TokenStream) -> TokenStream {
    let derive_input: DeriveInput = match syn::parse(input) {
        Ok(parsed) => parsed,
        Err(e) => return e.to_compile_error().into(),
    };
    match try_expand(&derive_input) {
        Ok(tokens) => tokens.into(),
        Err(e) => e.to_compile_error().into(),
    }
}

fn try_expand(input: &DeriveInput) -> syn::Result<TokenStream2> {
    let fields = named_fields(input)?;

    let struct_ident = &input.ident;
    let struct_name = masked_name_expr(struct_ident.unraw().to_string(), struct_ident.span());
    let field_count = fields.named.len();

    let serialize_fields = fields.named.iter().map(|field| {
        let ident = field.ident.as_ref().expect("named field has an ident");
        // `unraw` matches serde's own naming: `r#type` serializes as
        // "type", and the raw-ident prefix must not reach the wire.
        let name = masked_name_expr(ident.unraw().to_string(), ident.span());
        quote! {
            ::litmask::__serde::ser::SerializeStruct::serialize_field(
                &mut __state,
                #name,
                &self.#ident,
            )?;
        }
    });

    Ok(quote! {
        #[automatically_derived]
        impl ::litmask::__serde::Serialize for #struct_ident {
            fn serialize<__S>(
                &self,
                serializer: __S,
            ) -> ::core::result::Result<__S::Ok, __S::Error>
            where
                __S: ::litmask::__serde::Serializer,
            {
                let mut __state = ::litmask::__serde::Serializer::serialize_struct(
                    serializer,
                    #struct_name,
                    #field_count,
                )?;
                #(#serialize_fields)*
                ::litmask::__serde::ser::SerializeStruct::end(__state)
            }
        }
    })
}

/// Extract the named fields, rejecting every shape the prototype does
/// not mask. Each rejection is loud: silently falling back to the
/// plain-derive behavior would embed cleartext names — the exact leak
/// the user opted in to prevent.
fn named_fields(input: &DeriveInput) -> syn::Result<&syn::FieldsNamed> {
    if !input.generics.params.is_empty() {
        return Err(compile_error(
            input.generics.span(),
            MACRO_NAME,
            FailTag::Grammar,
            "generic structs are not yet supported",
        ));
    }
    let Data::Struct(data) = &input.data else {
        return Err(compile_error(
            input.ident.span(),
            MACRO_NAME,
            FailTag::Grammar,
            "supports structs with named fields only",
        ));
    };
    let Fields::Named(fields) = &data.fields else {
        return Err(compile_error(
            input.ident.span(),
            MACRO_NAME,
            FailTag::Grammar,
            "supports structs with named fields only",
        ));
    };
    Ok(fields)
}

/// Emit a `&'static str` expression yielding `name` at runtime:
/// decrypt the AEAD blob once, leak the `String`, cache in a
/// `OnceLock`. serde's `serialize_struct` / `serialize_field` take
/// `&'static str`, which a runtime-decrypted name can only satisfy by
/// leaking; the cache bounds the leak to one allocation per name.
fn masked_name_expr(name: String, span: proc_macro2::Span) -> TokenStream2 {
    let decrypt = mask_str(span, name.into_bytes());
    quote! {
        {
            static __LITMASK_NAME: ::std::sync::OnceLock<&'static str> =
                ::std::sync::OnceLock::new();
            *__LITMASK_NAME.get_or_init(|| ::std::boxed::Box::leak(
                (#decrypt).into_boxed_str(),
            ))
        }
    }
}
