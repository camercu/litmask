//! `#[derive(MaskDeserialize)]`: a `serde::Deserialize` impl whose
//! type, field, and enum variant names are AEAD-masked at compile time
//! (`unstable-serde` feature).
//!
//! Plain `#[derive(serde::Deserialize)]` embeds every name as
//! cleartext in `.rodata` — the `FIELDS`/`VARIANTS` arrays, the
//! field-visitor match-arm literals, the `expecting()` texts
//! (`"struct Config"`), and the `missing_field`/`unknown_variant`
//! diagnostics. This derive routes each name through the same AEAD
//! blob pipeline as `mask!` and decrypts on first deserialization.
//!
//! Behavior-identity contract: the impl accepts exactly the inputs
//! the plain derive accepts, produces equal values, and produces
//! byte-identical error messages, for every serde format. The
//! expansion mirrors serde's shape dispatch — each shape calls the
//! dedicated `Deserializer` entry point the plain derive would, and
//! the generated visitors implement the same `visit_*` set (notably
//! `visit_seq` alongside `visit_map`, which is how non-self-describing
//! formats deserialize structs positionally; the variant-identifier
//! `visit_u64` is how they select enum variants by declaration-order
//! index). Identifier matching compares against decrypted names at
//! runtime instead of literal match arms; everything serde's
//! expansion takes from `serde::__private` (semver-exempt, so
//! off-limits here) is replicated against public API in
//! `litmask::__serde_support`.
//!
//! serde's identifier entry points and error constructors require
//! `&'static str` / `&'static [&'static str]`, so each decrypted name
//! is leaked once and cached in a `OnceLock`. The leak is bounded
//! (one allocation per name per process) and consistent with
//! litmask's threat model: the protected asset is the binary at
//! rest, not process memory.

use proc_macro::TokenStream;
use proc_macro2::TokenStream as TokenStream2;
use quote::quote;
use syn::{Data, DeriveInput, Fields};

use crate::common::{FailTag, compile_error, masked_static_name};
use crate::derive_support::{expand_derive, transparent_field};
use crate::serde_attrs::{self, ContainerAttrs, RenameRule, VariantAttrs};

mod generics;
mod identifier;
mod named_fields;

use generics::{DeGenerics, split_de_generics, visitor_decl, visitor_expr};
use identifier::{
    AliasMatch, IdentifierKind, build_alias_match, identifier_block, names_list_fn, type_name_fn,
};
use named_fields::{
    NamedFieldsCx, build_aliases, de_names_of, named_field_infos, named_fields_visitor,
};

const MACRO_NAME: &str = "MaskDeserialize";

/// Implementation of the `#[proc_macro_derive] MaskDeserialize` entry
/// point. Re-exported at the crate root via a one-line wrapper.
pub(crate) fn expand(input: TokenStream) -> TokenStream {
    expand_derive(input, try_expand)
}

fn try_expand(input: &DeriveInput) -> syn::Result<TokenStream2> {
    // Parse the container's `#[serde(...)]` once and compute the
    // `'de`-threaded generics once, then thread both through every shape
    // body and visitor builder rather than re-deriving them at each. The
    // parse is idempotent, so re-deriving only risked drift between sites
    // and wasted expansion work. Mirrors `mask_serialize`'s threading.
    let container = serde_attrs::parse_container(MACRO_NAME, &input.attrs)?;
    let generics = split_de_generics(input, &container);
    let body = deserialize_body(input, &container, &generics)?;
    let struct_ident = &input.ident;
    let DeGenerics {
        de_impl,
        ty,
        where_clause,
        ..
    } = &generics;

    Ok(quote! {
        #[automatically_derived]
        impl #de_impl ::litmask::__serde::Deserialize<'de>
            for #struct_ident #ty #where_clause
        {
            fn deserialize<__D>(
                __deserializer: __D,
            ) -> ::core::result::Result<Self, __D::Error>
            where
                __D: ::litmask::__serde::Deserializer<'de>,
            {
                #body
            }
        }
    })
}

/// Dispatch on the input's shape, mirroring serde's own
/// classification: each shape maps to the dedicated `Deserializer`
/// entry point the plain derive would call, which is what keeps
/// accepted inputs and wire shapes identical.
fn deserialize_body(
    input: &DeriveInput,
    container: &ContainerAttrs,
    generics: &DeGenerics,
) -> syn::Result<TokenStream2> {
    if container.transparent {
        return transparent_deserialize_body(input);
    }
    match &input.data {
        Data::Struct(data) => match &data.fields {
            Fields::Named(fields) => named_struct_body(input, container, generics, fields),
            Fields::Unit => Ok(unit_struct_body(input, container, generics)),
            Fields::Unnamed(fields) => tuple_struct_body(input, container, generics, fields),
        },
        Data::Enum(data) => enum_body(input, container, generics, data),
        Data::Union(_) => Err(compile_error(
            input.ident.span(),
            MACRO_NAME,
            FailTag::Grammar,
            "supports structs and enums only",
        )),
    }
}

/// `#[serde(transparent)]`: delegate to the single field's `Deserialize`
/// and wrap the result in the struct — no field names on the wire.
fn transparent_deserialize_body(input: &DeriveInput) -> syn::Result<TokenStream2> {
    let struct_ident = &input.ident;
    let field = transparent_field(input, MACRO_NAME)?;
    let ty = field.ty;
    let decode = quote! {
        <#ty as ::litmask::__serde::Deserialize<'de>>::deserialize(__deserializer)?
    };
    let construct = if let Some(ident) = field.named_ident {
        quote! { #struct_ident { #ident: #decode } }
    } else {
        quote! { #struct_ident(#decode) }
    };
    Ok(quote! {
        ::core::result::Result::Ok(#construct)
    })
}

/// Resolve each variant's deserialize-side name. `parent` is the
/// container's `rename_all` rule, applied unless the variant has its
/// own `rename`.
fn variant_de_names(
    data: &syn::DataEnum,
    parent: Option<RenameRule>,
) -> syn::Result<Vec<(proc_macro2::Span, String)>> {
    data.variants
        .iter()
        .map(|variant| {
            let attrs = serde_attrs::parse_variant(MACRO_NAME, &variant.attrs)?;
            Ok((
                variant.ident.span(),
                attrs.deserialize_name(&variant.ident, parent),
            ))
        })
        .collect()
}

/// Build the variant-level `#[serde(alias)]` match data: a (possibly
/// empty) masked alias-name function plus the [`AliasMatch`] mapping each
/// alias back to its variant's `__Field` arm (indexed by declaration
/// order, matching [`identifier_block`](identifier)'s variant numbering).
/// Aliases are deserialize-only and unaffected by `rename_all`, mirroring
/// the field-alias builder.
fn variant_aliases(
    data: &syn::DataEnum,
    names_fn: &syn::Ident,
) -> syn::Result<(TokenStream2, Option<AliasMatch>)> {
    // Variants have no skip concept, so the alias target is the variant's
    // declaration-order index directly. Aliases are owned by the parsed
    // `VariantAttrs`, so collect them before borrowing into the builder.
    let owned: Vec<(usize, proc_macro2::Span, Vec<String>)> = data
        .variants
        .iter()
        .enumerate()
        .map(|(variant_index, variant)| {
            let attrs = serde_attrs::parse_variant(MACRO_NAME, &variant.attrs)?;
            Ok((variant_index, variant.ident.span(), attrs.aliases))
        })
        .collect::<syn::Result<_>>()?;
    let groups = owned
        .iter()
        .map(|(index, span, aliases)| (*index, *span, aliases.as_slice()));
    Ok(build_alias_match(names_fn, groups))
}

/// The container's deserialize type-name tuple `(span, resolved name)`.
fn type_name_tuple(input: &DeriveInput, container: &ContainerAttrs) -> (proc_macro2::Span, String) {
    (input.ident.span(), container.deserialize_name(&input.ident))
}

/// `Option<&'static str>` tokens for `ExpectedElements.variant`.
fn variant_option(variant_name: Option<&TokenStream2>) -> TokenStream2 {
    if let Some(call) = variant_name {
        quote! { ::core::option::Option::Some(#call) }
    } else {
        quote! { ::core::option::Option::None }
    }
}

/// The `visit_seq` accessor binding. A struct/variant with no readable
/// fields never touches its `SeqAccess`, so bind it `_` (binding `mut`
/// would warn); otherwise bind `mut __seq`. Mirrors serde's expansion.
fn seq_access_binding(field_count: usize) -> TokenStream2 {
    if field_count == 0 {
        quote! { _ }
    } else {
        quote! { mut __seq }
    }
}

/// `expecting()` body rendering `"<shape> <Name>"` (structs) or
/// `"<shape> <Name>::<Variant>"` (variants) from decrypted names.
fn expecting_body(shape: &str, variant_name: Option<&TokenStream2>) -> TokenStream2 {
    if let Some(call) = variant_name {
        quote! {
            ::core::write!(
                __formatter,
                "{} {}::{}",
                #shape,
                __litmask_type_name(),
                #call,
            )
        }
    } else {
        quote! {
            ::core::write!(__formatter, "{} {}", #shape, __litmask_type_name())
        }
    }
}

/// Per-field `let` statements for a `visit_seq` body: each pulls the
/// next element or fails with the plain derive's `invalid_length`
/// message (`"<shape> <Name> with N element(s)"`, composed at runtime
/// from the decrypted names).
fn seq_field_lets<'a>(
    bindings: &'a [syn::Ident],
    field_tys: &'a [&'a syn::Type],
    shape: &'a str,
    variant_name: Option<&'a TokenStream2>,
    field_count: usize,
) -> impl Iterator<Item = TokenStream2> + 'a {
    let variant = variant_option(variant_name);
    bindings.iter().enumerate().map(move |(i, binding)| {
        let fty = field_tys[i];
        let variant = &variant;
        quote! {
            let #binding = match ::litmask::__serde::de::SeqAccess::next_element::<#fty>(
                &mut __seq,
            )? {
                ::core::option::Option::Some(__value) => __value,
                ::core::option::Option::None => {
                    return ::core::result::Result::Err(
                        ::litmask::__serde::de::Error::invalid_length(
                            #i,
                            &::litmask::__serde_support::ExpectedElements {
                                shape: #shape,
                                name: __litmask_type_name(),
                                variant: #variant,
                                count: #field_count,
                            },
                        ),
                    );
                }
            };
        }
    })
}

fn named_struct_body(
    input: &DeriveInput,
    container: &ContainerAttrs,
    generics: &DeGenerics,
    fields: &syn::FieldsNamed,
) -> syn::Result<TokenStream2> {
    let struct_ident = &input.ident;
    let infos = named_field_infos(fields, container.rename_all.deserialize)?;
    let de_names = de_names_of(&infos);
    let names_fn = quote::format_ident!("__litmask_names");
    let aliases_fn = quote::format_ident!("__litmask_aliases");
    let type_name_fn = type_name_fn(&type_name_tuple(input, container));
    let names_fn_decl = names_list_fn(&names_fn, &de_names);
    let (aliases_decl, alias_match) = build_aliases(&aliases_fn, &infos);
    let field_identifier = identifier_block(
        &names_fn,
        de_names.len(),
        &IdentifierKind::StructField,
        alias_match.as_ref(),
        container.deny_unknown_fields,
    );
    let visitor_ident = quote::format_ident!("__Visitor");
    let visitor = named_fields_visitor(
        input,
        generics,
        &infos,
        &NamedFieldsCx {
            construct: quote! { #struct_ident },
            names_fn,
            shape: "struct",
            variant_name: None,
            visitor: visitor_ident,
        },
    );
    let visitor_expr = visitor_expr();

    Ok(quote! {
        #type_name_fn
        #names_fn_decl
        #aliases_decl
        #field_identifier
        #visitor

        ::litmask::__serde::Deserializer::deserialize_struct(
            __deserializer,
            __litmask_type_name(),
            __litmask_names(),
            #visitor_expr,
        )
    })
}

fn unit_struct_body(
    input: &DeriveInput,
    container: &ContainerAttrs,
    generics: &DeGenerics,
) -> TokenStream2 {
    let struct_ident = &input.ident;
    let type_name_fn = type_name_fn(&type_name_tuple(input, container));
    let visitor = visitor_decl(input, generics);
    let visitor_expr = visitor_expr();
    let DeGenerics {
        de_impl,
        de_ty,
        ty,
        where_clause,
    } = generics;
    quote! {
        #type_name_fn

        #visitor

        #[automatically_derived]
        impl #de_impl ::litmask::__serde::de::Visitor<'de>
            for __Visitor #de_ty #where_clause
        {
            type Value = #struct_ident #ty;

            fn expecting(
                &self,
                __formatter: &mut ::core::fmt::Formatter,
            ) -> ::core::fmt::Result {
                ::core::write!(__formatter, "unit struct {}", __litmask_type_name())
            }

            #[inline]
            fn visit_unit<__E>(self) -> ::core::result::Result<Self::Value, __E>
            where
                __E: ::litmask::__serde::de::Error,
            {
                ::core::result::Result::Ok(#struct_ident)
            }
        }

        ::litmask::__serde::Deserializer::deserialize_unit_struct(
            __deserializer,
            __litmask_type_name(),
            #visitor_expr,
        )
    }
}

/// Tuple-struct dispatch mirrors serde's: exactly one field is a
/// newtype (`deserialize_newtype_struct` + a `visit_newtype_struct`
/// method), any other arity — including zero — goes through
/// `deserialize_tuple_struct`. Both visitors share the `visit_seq`
/// path, which is what non-self-describing formats call.
fn tuple_struct_body(
    input: &DeriveInput,
    container: &ContainerAttrs,
    generics: &DeGenerics,
    fields: &syn::FieldsUnnamed,
) -> syn::Result<TokenStream2> {
    let struct_ident = &input.ident;
    serde_attrs::reject_tuple_field_attrs(MACRO_NAME, fields)?;
    let type_name_fn = type_name_fn(&type_name_tuple(input, container));
    let field_tys: Vec<&syn::Type> = fields.unnamed.iter().map(|field| &field.ty).collect();
    let field_count = field_tys.len();
    let bindings: Vec<syn::Ident> = (0..field_count)
        .map(|i| quote::format_ident!("__field{i}"))
        .collect();

    let seq_lets = seq_field_lets(&bindings, &field_tys, "tuple struct", None, field_count);
    let seq_binding = seq_access_binding(field_count);

    let visit_newtype = (field_count == 1).then(|| {
        let fty = field_tys[0];
        quote! {
            #[inline]
            fn visit_newtype_struct<__E>(
                self,
                __e: __E,
            ) -> ::core::result::Result<Self::Value, __E::Error>
            where
                __E: ::litmask::__serde::Deserializer<'de>,
            {
                let __field0: #fty = <#fty as ::litmask::__serde::Deserialize>::deserialize(__e)?;
                ::core::result::Result::Ok(#struct_ident(__field0))
            }
        }
    });

    let visitor_expr = visitor_expr();
    let dispatch = if field_count == 1 {
        quote! {
            ::litmask::__serde::Deserializer::deserialize_newtype_struct(
                __deserializer,
                __litmask_type_name(),
                #visitor_expr,
            )
        }
    } else {
        quote! {
            ::litmask::__serde::Deserializer::deserialize_tuple_struct(
                __deserializer,
                __litmask_type_name(),
                #field_count,
                #visitor_expr,
            )
        }
    };

    let visitor = visitor_decl(input, generics);
    let DeGenerics {
        de_impl,
        de_ty,
        ty,
        where_clause,
    } = generics;
    Ok(quote! {
        #type_name_fn

        #visitor

        #[automatically_derived]
        impl #de_impl ::litmask::__serde::de::Visitor<'de>
            for __Visitor #de_ty #where_clause
        {
            type Value = #struct_ident #ty;

            fn expecting(
                &self,
                __formatter: &mut ::core::fmt::Formatter,
            ) -> ::core::fmt::Result {
                ::core::write!(__formatter, "tuple struct {}", __litmask_type_name())
            }

            #visit_newtype

            #[inline]
            fn visit_seq<__A>(
                self,
                #seq_binding: __A,
            ) -> ::core::result::Result<Self::Value, __A::Error>
            where
                __A: ::litmask::__serde::de::SeqAccess<'de>,
            {
                #(#seq_lets)*
                ::core::result::Result::Ok(#struct_ident( #(#bindings),* ))
            }
        }

        #dispatch
    })
}

/// Externally tagged enum (serde's no-attrs default): the
/// variant-identifier enum selects by decrypted name or by
/// declaration-order index (`visit_u64` — the non-self-describing
/// wire form), then each match arm calls the `VariantAccess` entry
/// point for its variant kind. Tuple and struct variants declare
/// their own visitor inside the arm's block, exactly as serde's
/// expansion scopes them.
fn enum_body(
    input: &DeriveInput,
    container: &ContainerAttrs,
    generics: &DeGenerics,
    data: &syn::DataEnum,
) -> syn::Result<TokenStream2> {
    let enum_ident = &input.ident;
    let de_names = variant_de_names(data, container.rename_all.deserialize)?;
    let names_fn = quote::format_ident!("__litmask_names");
    let type_name_fn = type_name_fn(&type_name_tuple(input, container));
    let names_fn_decl = names_list_fn(&names_fn, &de_names);
    let valiases_fn = quote::format_ident!("__litmask_variant_aliases");
    let (valiases_decl, valias_match) = variant_aliases(data, &valiases_fn)?;
    let variant_identifier = identifier_block(
        &names_fn,
        de_names.len(),
        &IdentifierKind::EnumVariant,
        valias_match.as_ref(),
        false,
    );

    let match_variant = if data.variants.is_empty() {
        // An uninhabited enum still derives: the identifier enum is
        // itself uninhabited, so a successful `variant()` is
        // unreachable and `match __impossible {}` proves it — the
        // same construction as the plain derive.
        quote! {
            ::core::result::Result::map(
                ::litmask::__serde::de::EnumAccess::variant::<__Field>(__data),
                |(__impossible, _)| match __impossible {},
            )
        }
    } else {
        let arms = data
            .variants
            .iter()
            .enumerate()
            .map(|(index, variant)| variant_arm(input, container, generics, index, variant))
            .collect::<syn::Result<Vec<_>>>()?;
        quote! {
            match ::litmask::__serde::de::EnumAccess::variant(__data)? {
                #(#arms)*
            }
        }
    };

    let visitor = visitor_decl(input, generics);
    let visitor_expr = visitor_expr();
    let DeGenerics {
        de_impl,
        de_ty,
        ty,
        where_clause,
    } = generics;

    Ok(quote! {
        #type_name_fn
        #names_fn_decl
        #valiases_decl
        #variant_identifier

        #visitor

        #[automatically_derived]
        impl #de_impl ::litmask::__serde::de::Visitor<'de>
            for __Visitor #de_ty #where_clause
        {
            type Value = #enum_ident #ty;

            fn expecting(
                &self,
                __formatter: &mut ::core::fmt::Formatter,
            ) -> ::core::fmt::Result {
                ::core::write!(__formatter, "enum {}", __litmask_type_name())
            }

            fn visit_enum<__A>(
                self,
                __data: __A,
            ) -> ::core::result::Result<Self::Value, __A::Error>
            where
                __A: ::litmask::__serde::de::EnumAccess<'de>,
            {
                #match_variant
            }
        }

        ::litmask::__serde::Deserializer::deserialize_enum(
            __deserializer,
            __litmask_type_name(),
            __litmask_names(),
            #visitor_expr,
        )
    })
}

/// One `visit_enum` match arm per variant. The arm's block declares
/// everything the variant kind needs (an inner visitor for tuple and
/// struct variants, a field-identifier enum for struct variants) —
/// block scoping keeps each variant's generated items, including a
/// shadowed inner `__Field`, from colliding with the enum-level ones.
fn variant_arm(
    input: &DeriveInput,
    container: &ContainerAttrs,
    generics: &DeGenerics,
    index: usize,
    variant: &syn::Variant,
) -> syn::Result<TokenStream2> {
    let enum_ident = &input.ident;
    let vident = &variant.ident;
    let field_variant = quote::format_ident!("__field{index}");
    let vattrs = serde_attrs::parse_variant(MACRO_NAME, &variant.attrs)?;
    let variant_name = masked_static_name(
        vident.span(),
        &vattrs.deserialize_name(vident, container.rename_all.deserialize),
    );
    let variant_name_fn = quote! {
        fn __litmask_variant_name() -> &'static str {
            #variant_name
        }
    };
    let variant_name_call = quote! { __litmask_variant_name() };

    match &variant.fields {
        Fields::Unit => Ok(quote! {
            (__Field::#field_variant, __variant) => {
                ::litmask::__serde::de::VariantAccess::unit_variant(__variant)?;
                ::core::result::Result::Ok(#enum_ident::#vident)
            }
        }),
        Fields::Unnamed(fields) if fields.unnamed.len() == 1 => {
            serde_attrs::reject_tuple_field_attrs(MACRO_NAME, fields)?;
            let fty = &fields.unnamed[0].ty;
            Ok(quote! {
                (__Field::#field_variant, __variant) => ::core::result::Result::map(
                    ::litmask::__serde::de::VariantAccess::newtype_variant::<#fty>(__variant),
                    #enum_ident::#vident,
                ),
            })
        }
        Fields::Unnamed(fields) => tuple_variant_arm(
            input,
            generics,
            vident,
            &field_variant,
            &variant_name_fn,
            &variant_name_call,
            fields,
        ),
        Fields::Named(fields) => struct_variant_arm(
            input,
            generics,
            fields,
            &StructVariantCx {
                vident,
                field_variant: &field_variant,
                variant_name_fn: &variant_name_fn,
                variant_name_call: &variant_name_call,
                vattrs: &vattrs,
                deny_unknown: container.deny_unknown_fields,
            },
        ),
    }
}

/// `visit_enum` arm for a multi-field (or zero-arity) tuple variant: a
/// dedicated inner visitor whose `visit_seq` pulls each field
/// positionally, dispatched via `tuple_variant`.
fn tuple_variant_arm(
    input: &DeriveInput,
    generics: &DeGenerics,
    vident: &syn::Ident,
    field_variant: &syn::Ident,
    variant_name_fn: &TokenStream2,
    variant_name_call: &TokenStream2,
    fields: &syn::FieldsUnnamed,
) -> syn::Result<TokenStream2> {
    serde_attrs::reject_tuple_field_attrs(MACRO_NAME, fields)?;
    let enum_ident = &input.ident;
    let field_tys: Vec<&syn::Type> = fields.unnamed.iter().map(|field| &field.ty).collect();
    let field_count = field_tys.len();
    let bindings: Vec<syn::Ident> = (0..field_count)
        .map(|i| quote::format_ident!("__field{i}"))
        .collect();
    let seq_lets = seq_field_lets(
        &bindings,
        &field_tys,
        "tuple variant",
        Some(variant_name_call),
        field_count,
    );
    let seq_binding = seq_access_binding(field_count);
    let expecting = expecting_body("tuple variant", Some(variant_name_call));
    let DeGenerics {
        de_impl,
        de_ty,
        ty,
        where_clause,
    } = generics;
    Ok(quote! {
        (__Field::#field_variant, __variant) => {
            #variant_name_fn

            struct __VariantVisitor #de_impl #where_clause {
                marker: ::core::marker::PhantomData<#enum_ident #ty>,
                lifetime: ::core::marker::PhantomData<&'de ()>,
            }

            #[automatically_derived]
            impl #de_impl ::litmask::__serde::de::Visitor<'de>
                for __VariantVisitor #de_ty #where_clause
            {
                type Value = #enum_ident #ty;

                fn expecting(
                    &self,
                    __formatter: &mut ::core::fmt::Formatter,
                ) -> ::core::fmt::Result {
                    #expecting
                }

                #[inline]
                fn visit_seq<__A>(
                    self,
                    #seq_binding: __A,
                ) -> ::core::result::Result<Self::Value, __A::Error>
                where
                    __A: ::litmask::__serde::de::SeqAccess<'de>,
                {
                    #(#seq_lets)*
                    ::core::result::Result::Ok(
                        #enum_ident::#vident( #(#bindings),* ),
                    )
                }
            }

            ::litmask::__serde::de::VariantAccess::tuple_variant(
                __variant,
                #field_count,
                __VariantVisitor {
                    marker: ::core::marker::PhantomData,
                    lifetime: ::core::marker::PhantomData,
                },
            )
        }
    })
}

/// `visit_enum` arm for a struct variant: an inner field-identifier
/// enum plus a named-fields visitor, dispatched via `struct_variant`.
/// The per-variant context a struct-variant arm needs beyond the input
/// and its fields.
struct StructVariantCx<'a> {
    vident: &'a syn::Ident,
    field_variant: &'a syn::Ident,
    variant_name_fn: &'a TokenStream2,
    variant_name_call: &'a TokenStream2,
    vattrs: &'a VariantAttrs,
    deny_unknown: bool,
}

fn struct_variant_arm(
    input: &DeriveInput,
    generics: &DeGenerics,
    fields: &syn::FieldsNamed,
    cx: &StructVariantCx,
) -> syn::Result<TokenStream2> {
    let vident = cx.vident;
    let field_variant = cx.field_variant;
    let variant_name_fn = cx.variant_name_fn;
    let variant_name_call = cx.variant_name_call;
    let vattrs = cx.vattrs;
    let deny_unknown = cx.deny_unknown;
    let enum_ident = &input.ident;
    let infos = named_field_infos(fields, vattrs.rename_all.deserialize)?;
    let de_names = de_names_of(&infos);
    let vfields_fn = quote::format_ident!("__litmask_vfields");
    let valiases_fn = quote::format_ident!("__litmask_valiases");
    let vfields_decl = names_list_fn(&vfields_fn, &de_names);
    let (valiases_decl, alias_match) = build_aliases(&valiases_fn, &infos);
    // The inner `__Field` shadows the enum-level variant identifier
    // inside this arm's block — intentional, and exactly how serde
    // scopes its per-variant expansion.
    let field_identifier = identifier_block(
        &vfields_fn,
        de_names.len(),
        &IdentifierKind::StructField,
        alias_match.as_ref(),
        deny_unknown,
    );
    let visitor_ident = quote::format_ident!("__VariantVisitor");
    let visitor = named_fields_visitor(
        input,
        generics,
        &infos,
        &NamedFieldsCx {
            construct: quote! { #enum_ident::#vident },
            names_fn: vfields_fn.clone(),
            shape: "struct variant",
            variant_name: Some(variant_name_call.clone()),
            visitor: visitor_ident,
        },
    );
    Ok(quote! {
        (__Field::#field_variant, __variant) => {
            #variant_name_fn
            #vfields_decl
            #valiases_decl
            #field_identifier
            #visitor

            ::litmask::__serde::de::VariantAccess::struct_variant(
                __variant,
                #vfields_fn(),
                __VariantVisitor {
                    marker: ::core::marker::PhantomData,
                    lifetime: ::core::marker::PhantomData,
                },
            )
        }
    })
}
