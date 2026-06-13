//! `#[derive(MaskSerialize)]`: a `serde::Serialize` impl whose type,
//! field, and enum variant names are AEAD-masked at compile time
//! (EXPERIMENTAL, `unstable-serde` feature).
//!
//! Plain `#[derive(serde::Serialize)]` embeds every name as a
//! cleartext `&'static str` in `.rodata` via
//! `SerializeStruct::serialize_field("name", ...)` and friends. This
//! derive routes each name through the same AEAD blob pipeline as
//! `mask!` and decrypts on first serialization.
//!
//! Wire-format contract: output is byte-identical to the plain derive
//! for every serde format. That is why the expansion mirrors serde's
//! shape dispatch — each struct shape and variant kind calls the
//! dedicated `Serializer` entry point the plain derive would, never
//! `serialize_map` — because non-self-describing formats (bincode,
//! postcard) serialize structs positionally and enums by
//! declaration-order variant index; a map-based impl would both change
//! their wire shape and re-introduce the names on the wire. The serde
//! entry points require `&'static str` names, so each decrypted name
//! is leaked once and cached in a `OnceLock`. The leak is bounded (one
//! allocation per name per process) and consistent with litmask's
//! threat model: the protected asset is the binary at rest, not
//! process memory.

use proc_macro::TokenStream;
use proc_macro2::TokenStream as TokenStream2;
use quote::quote;
use syn::{Data, DeriveInput, Fields};

use crate::common::{FailTag, compile_error, expand_derive, masked_static_name, with_trait_bounds};
use crate::serde_attrs::{self, ContainerAttrs, RenameRule};

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
    let container = serde_attrs::parse_container(MACRO_NAME, &input.attrs)?;
    let name = masked_static_name(input.ident.span(), &container.serialize_name(&input.ident));
    match &input.data {
        Data::Struct(data) => match &data.fields {
            Fields::Named(fields) => {
                named_struct_body(&name, fields, container.rename_all.serialize)
            }
            Fields::Unit => Ok(quote! {
                ::litmask::__serde::Serializer::serialize_unit_struct(serializer, #name)
            }),
            Fields::Unnamed(fields) => tuple_struct_body(&name, fields),
        },
        Data::Enum(data) => enum_body(&name, data, &container),
        Data::Union(_) => Err(compile_error(
            input.ident.span(),
            MACRO_NAME,
            FailTag::Grammar,
            "supports structs and enums only",
        )),
    }
}

/// One match arm per variant, each calling the `*_variant` entry
/// point the plain derive would. The variant *index* (declaration
/// order, `u32`) is what non-self-describing formats put on the wire;
/// the masked *name* is what self-describing formats print.
fn enum_body(
    name: &TokenStream2,
    data: &syn::DataEnum,
    container: &ContainerAttrs,
) -> syn::Result<TokenStream2> {
    if data.variants.is_empty() {
        // An uninhabited enum has no arms; `match *self {}` is how the
        // plain derive proves exhaustiveness (`&Self` would not).
        return Ok(quote! { match *self {} });
    }
    let arms = data
        .variants
        .iter()
        .enumerate()
        .map(|(index, variant)| variant_arm(name, index, variant, container))
        .collect::<syn::Result<Vec<_>>>()?;
    Ok(quote! {
        match self {
            #(#arms)*
        }
    })
}

fn variant_arm(
    name: &TokenStream2,
    index: usize,
    variant: &syn::Variant,
    container: &ContainerAttrs,
) -> syn::Result<TokenStream2> {
    let vident = &variant.ident;
    let vattrs = serde_attrs::parse_variant(MACRO_NAME, &variant.attrs)?;
    let vname = masked_static_name(
        vident.span(),
        &vattrs.serialize_name(vident, container.rename_all.serialize),
    );
    let vindex = u32::try_from(index).expect("variant count exceeds u32");
    // Bindings are mangled, never the user's field idents: a field
    // named `serializer` or `__state` would otherwise shadow the
    // generated locals and break compilation.
    let bindings: Vec<syn::Ident> = (0..variant.fields.len())
        .map(|i| quote::format_ident!("__field{i}"))
        .collect();
    match &variant.fields {
        Fields::Unit => Ok(quote! {
            Self::#vident => ::litmask::__serde::Serializer::serialize_unit_variant(
                serializer,
                #name,
                #vindex,
                #vname,
            ),
        }),
        Fields::Unnamed(fields) if fields.unnamed.len() == 1 => {
            check_unnamed_field_attrs(fields)?;
            Ok(quote! {
                Self::#vident(__field0) =>
                    ::litmask::__serde::Serializer::serialize_newtype_variant(
                        serializer,
                        #name,
                        #vindex,
                        #vname,
                        __field0,
                    ),
            })
        }
        Fields::Unnamed(fields) => {
            check_unnamed_field_attrs(fields)?;
            let field_count = fields.unnamed.len();
            let serialize_fields = bindings.iter().map(|binding| {
                quote! {
                    ::litmask::__serde::ser::SerializeTupleVariant::serialize_field(
                        &mut __state,
                        #binding,
                    )?;
                }
            });
            Ok(quote! {
                Self::#vident( #(#bindings),* ) => {
                    let mut __state =
                        ::litmask::__serde::Serializer::serialize_tuple_variant(
                            serializer,
                            #name,
                            #vindex,
                            #vname,
                            #field_count,
                        )?;
                    #(#serialize_fields)*
                    ::litmask::__serde::ser::SerializeTupleVariant::end(__state)
                }
            })
        }
        Fields::Named(fields) => {
            // Pattern-bind every field (skipped ones to `_`), but only
            // serialize and count the non-`skip_serializing` ones.
            let mut pattern_binds = Vec::with_capacity(fields.named.len());
            let mut serialize_fields = Vec::new();
            let mut field_count = 0usize;
            for field in &fields.named {
                let ident = field.ident.as_ref().expect("named field has an ident");
                let attrs = serde_attrs::parse_field(MACRO_NAME, &field.attrs)?;
                if attrs.skip_serializing {
                    pattern_binds.push(quote! { #ident: _ });
                    continue;
                }
                let binding = quote::format_ident!("__field{field_count}");
                field_count += 1;
                let field_name = masked_static_name(
                    ident.span(),
                    &attrs.serialize_name(ident, vattrs.rename_all.serialize),
                );
                pattern_binds.push(quote! { #ident: #binding });
                serialize_fields.push(quote! {
                    ::litmask::__serde::ser::SerializeStructVariant::serialize_field(
                        &mut __state,
                        #field_name,
                        #binding,
                    )?;
                });
            }
            Ok(quote! {
                Self::#vident { #(#pattern_binds),* } => {
                    let mut __state =
                        ::litmask::__serde::Serializer::serialize_struct_variant(
                            serializer,
                            #name,
                            #vindex,
                            #vname,
                            #field_count,
                        )?;
                    #(#serialize_fields)*
                    ::litmask::__serde::ser::SerializeStructVariant::end(__state)
                }
            })
        }
    }
}

/// Tuple-struct dispatch mirrors serde's: exactly one field is a
/// newtype (`serialize_newtype_struct`), any other arity — including
/// zero — goes through `serialize_tuple_struct`. Collapsing the two
/// would change the wire shape in self-describing formats (`"v"` vs
/// `["v"]`).
fn tuple_struct_body(
    name: &TokenStream2,
    fields: &syn::FieldsUnnamed,
) -> syn::Result<TokenStream2> {
    check_unnamed_field_attrs(fields)?;
    let field_count = fields.unnamed.len();
    if field_count == 1 {
        return Ok(quote! {
            ::litmask::__serde::Serializer::serialize_newtype_struct(serializer, #name, &self.0)
        });
    }
    let serialize_fields = (0..field_count).map(|i| {
        let index = syn::Index::from(i);
        quote! {
            ::litmask::__serde::ser::SerializeTupleStruct::serialize_field(
                &mut __state,
                &self.#index,
            )?;
        }
    });
    Ok(quote! {
        let mut __state = ::litmask::__serde::Serializer::serialize_tuple_struct(
            serializer,
            #name,
            #field_count,
        )?;
        #(#serialize_fields)*
        ::litmask::__serde::ser::SerializeTupleStruct::end(__state)
    })
}

/// Reject-loud any unsupported `#[serde(...)]` on unnamed (tuple)
/// fields. Tuple fields have no names to mask, but they can still carry
/// serde attributes; parsing enforces the same subset boundary so an
/// unsupported key fails instead of silently diverging from serde.
/// `skip` on a positional field would shift the remaining indices, a
/// shape the masking derives don't handle yet — reject it loud.
fn check_unnamed_field_attrs(fields: &syn::FieldsUnnamed) -> syn::Result<()> {
    for field in &fields.unnamed {
        let attrs = serde_attrs::parse_field(MACRO_NAME, &field.attrs)?;
        if attrs.has_skip() {
            return Err(compile_error(
                syn::spanned::Spanned::span(field),
                MACRO_NAME,
                FailTag::InvalidArg,
                "`#[serde(skip)]` on a tuple field is not yet supported",
            ));
        }
    }
    Ok(())
}

fn named_struct_body(
    name: &TokenStream2,
    fields: &syn::FieldsNamed,
    rename_all: Option<RenameRule>,
) -> syn::Result<TokenStream2> {
    let mut serialize_fields = Vec::with_capacity(fields.named.len());
    let mut field_count = 0usize;
    for field in &fields.named {
        let ident = field.ident.as_ref().expect("named field has an ident");
        let attrs = serde_attrs::parse_field(MACRO_NAME, &field.attrs)?;
        if attrs.skip_serializing {
            continue;
        }
        field_count += 1;
        let field_name = masked_static_name(ident.span(), &attrs.serialize_name(ident, rename_all));
        serialize_fields.push(quote! {
            ::litmask::__serde::ser::SerializeStruct::serialize_field(
                &mut __state,
                #field_name,
                &self.#ident,
            )?;
        });
    }
    Ok(quote! {
        let mut __state = ::litmask::__serde::Serializer::serialize_struct(
            serializer,
            #name,
            #field_count,
        )?;
        #(#serialize_fields)*
        ::litmask::__serde::ser::SerializeStruct::end(__state)
    })
}
