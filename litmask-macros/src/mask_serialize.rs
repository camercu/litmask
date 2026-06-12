//! `#[derive(MaskSerialize)]`: a `serde::Serialize` impl whose
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
use syn::spanned::Spanned;
use syn::{Data, DeriveInput, Fields};

use crate::common::{FailTag, compile_error, expand_derive, mask_ident, with_trait_bounds};

const MACRO_NAME: &str = "MaskSerialize";

/// Implementation of the `#[proc_macro_derive] MaskSerialize` entry
/// point. Re-exported at the crate root via a one-line wrapper.
pub(crate) fn expand(input: TokenStream) -> TokenStream {
    expand_derive(input, try_expand)
}

fn try_expand(input: &DeriveInput) -> syn::Result<TokenStream2> {
    let body = serialize_body(input)?;

    let struct_ident = &input.ident;
    // Bound every type param with `Serialize`, mirroring the plain
    // serde derive's bound model: `Envelope<T>` serializes iff
    // `T: Serialize`.
    let generics = with_trait_bounds(
        input.generics.clone(),
        &syn::parse_quote!(::litmask::__serde::Serialize),
    );
    let (impl_generics, ty_generics, where_clause) = generics.split_for_impl();

    Ok(quote! {
        #[automatically_derived]
        impl #impl_generics ::litmask::__serde::Serialize
            for #struct_ident #ty_generics #where_clause
        {
            fn serialize<__S>(
                &self,
                serializer: __S,
            ) -> ::core::result::Result<__S::Ok, __S::Error>
            where
                __S: ::litmask::__serde::Serializer,
            {
                #body
            }
        }
    })
}

/// Dispatch on the input's shape, mirroring serde's own
/// classification: each shape maps to the dedicated `Serializer`
/// entry point the plain derive would call, which is what keeps the
/// wire format byte-identical (§E.2.1).
fn serialize_body(input: &DeriveInput) -> syn::Result<TokenStream2> {
    let data = match &input.data {
        Data::Struct(data) => data,
        Data::Enum(_) | Data::Union(_) => {
            return Err(compile_error(
                input.ident.span(),
                MACRO_NAME,
                FailTag::Grammar,
                "supports structs only",
            ));
        }
    };
    reject_serde_attrs(input, &data.fields)?;
    let name = masked_name_expr(&input.ident);
    match &data.fields {
        Fields::Named(fields) => Ok(named_struct_body(&name, fields)),
        Fields::Unit => Ok(quote! {
            ::litmask::__serde::Serializer::serialize_unit_struct(serializer, #name)
        }),
        Fields::Unnamed(_) => Err(compile_error(
            input.ident.span(),
            MACRO_NAME,
            FailTag::Grammar,
            "supports structs only",
        )),
    }
}

fn named_struct_body(name: &TokenStream2, fields: &syn::FieldsNamed) -> TokenStream2 {
    let field_count = fields.named.len();
    let serialize_fields = fields.named.iter().map(|field| {
        let ident = field.ident.as_ref().expect("named field has an ident");
        let field_name = masked_name_expr(ident);
        quote! {
            ::litmask::__serde::ser::SerializeStruct::serialize_field(
                &mut __state,
                #field_name,
                &self.#ident,
            )?;
        }
    });
    quote! {
        let mut __state = ::litmask::__serde::Serializer::serialize_struct(
            serializer,
            #name,
            #field_count,
        )?;
        #(#serialize_fields)*
        ::litmask::__serde::ser::SerializeStruct::end(__state)
    }
}

/// Reject any `#[serde(...)]` attribute on the container or a field.
/// The derive honors none of them; silently ignoring `rename` /
/// `rename_all` / `skip` would serialize under different names (or a
/// different shape) than the plain derive — the wire-format-identity
/// contract would break without warning.
fn reject_serde_attrs(input: &DeriveInput, fields: &Fields) -> syn::Result<()> {
    let container_attrs = input.attrs.iter();
    let field_attrs = fields.iter().flat_map(|field| field.attrs.iter());
    for attr in container_attrs.chain(field_attrs) {
        if attr.path().is_ident("serde") {
            return Err(compile_error(
                attr.span(),
                MACRO_NAME,
                FailTag::InvalidArg,
                "`#[serde(...)]` attributes are not supported",
            ));
        }
    }
    Ok(())
}

/// Emit a `&'static str` expression yielding the masked identifier's
/// name at runtime: decrypt the AEAD blob once, leak the `String`,
/// cache in a `OnceLock`. serde's `serialize_struct` /
/// `serialize_field` take `&'static str`, which a runtime-decrypted
/// name can only satisfy by leaking; the cache bounds the leak to one
/// allocation per name. (`MaskDebug` uses bare `mask_ident` instead —
/// the `Formatter` API takes `&str`, so it never needs the leak.)
fn masked_name_expr(ident: &syn::Ident) -> TokenStream2 {
    let decrypt = mask_ident(ident);
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
