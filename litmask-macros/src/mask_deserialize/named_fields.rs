//! Named-fields visitor codegen for the `MaskDeserialize` expansion: the
//! per-field model, the `visit_map` / `visit_seq` bodies, and the
//! `Visitor` carrier shared by a top-level named struct and a struct
//! variant. Self-contained — depends on the parent's shape-agnostic
//! helpers (`expecting_body`, `variant_option`) and the sibling
//! `generics` / `identifier` submodules, never on the body/dispatch
//! builders that call it.

use proc_macro2::TokenStream as TokenStream2;
use quote::quote;
use syn::DeriveInput;

use super::generics::{DeGenerics, split_de_generics};
use super::identifier::{AliasMatch, build_alias_match};
use super::{MACRO_NAME, expecting_body, variant_option};
use crate::serde_attrs::{self, RenameRule};

/// Per-named-field deserialize info: the construction ident/type plus
/// whether the field is `skip_deserializing` (filled from `Default`
/// instead of read) and its resolved deserialize name (meaningful only
/// when not skipped — skipped fields are absent from the wire).
pub(super) struct NamedFieldInfo<'a> {
    ident: &'a syn::Ident,
    ty: &'a syn::Type,
    skip_de: bool,
    de_name: (proc_macro2::Span, String),
    default: Option<serde_attrs::DefaultSource>,
    aliases: Vec<String>,
    deserialize_with: Option<syn::Path>,
}

/// The value a field takes when absent from the input: its
/// `#[serde(default)]` source, or `Default::default()` as the implicit
/// fallback for a `skip_deserializing` field with no explicit default.
fn default_value_expr(default: Option<&serde_attrs::DefaultSource>) -> TokenStream2 {
    if let Some(serde_attrs::DefaultSource::Path(path)) = default {
        quote! { #path() }
    } else {
        quote! { ::core::default::Default::default() }
    }
}

/// The container context a `deserialize_with` adapter needs to name the
/// impl's generics (a local item cannot capture an outer `T`). Carries the
/// container's `'de`-threaded, `Deserialize<'de>`-bounded generics fragments
/// (see [`DeGenerics`]) so the adapter can be generic over the same params.
pub(super) struct DeWithCtx<'a> {
    ident: &'a syn::Ident,
    de_impl: &'a TokenStream2,
    de_ty: &'a TokenStream2,
    ty: &'a TokenStream2,
    where_clause: &'a TokenStream2,
}

/// A local `Deserialize` adapter wrapping `fty`, whose `deserialize` calls
/// the `deserialize_with` function `path(deserializer)`. Block-scoped at
/// each use site, so the fixed name never collides. Generic over the
/// container's parameters (see [`DeWithCtx`]) so the field type may itself
/// be one of them; the value is read back through the `__value` field.
fn de_with_wrapper(ctx: &DeWithCtx, fty: &syn::Type, path: &syn::Path) -> TokenStream2 {
    let DeWithCtx {
        ident,
        de_impl,
        de_ty,
        ty,
        where_clause,
    } = ctx;
    quote! {
        struct __DeserializeWith #de_impl #where_clause {
            __value: #fty,
            __marker: ::core::marker::PhantomData<#ident #ty>,
            __lifetime: ::core::marker::PhantomData<&'de ()>,
        }
        impl #de_impl ::litmask::__serde::Deserialize<'de> for __DeserializeWith #de_ty #where_clause {
            fn deserialize<__D>(__d: __D) -> ::core::result::Result<Self, __D::Error>
            where
                __D: ::litmask::__serde::Deserializer<'de>,
            {
                ::core::result::Result::Ok(__DeserializeWith {
                    __value: #path(__d)?,
                    __marker: ::core::marker::PhantomData,
                    __lifetime: ::core::marker::PhantomData,
                })
            }
        }
    }
}

/// Parse every named field into a [`NamedFieldInfo`] (reject-loud on
/// unsupported `#[serde(...)]` keys). `parent` is the applicable
/// `rename_all` rule, applied unless the field has its own `rename`.
pub(super) fn named_field_infos(
    fields: &syn::FieldsNamed,
    parent: Option<RenameRule>,
) -> syn::Result<Vec<NamedFieldInfo<'_>>> {
    fields
        .named
        .iter()
        .map(|field| {
            let ident = field.ident.as_ref().expect("named field has an ident");
            let attrs = serde_attrs::parse_field(MACRO_NAME, &field.attrs)?;
            Ok(NamedFieldInfo {
                ident,
                ty: &field.ty,
                skip_de: attrs.skip_deserializing,
                de_name: (ident.span(), attrs.deserialize_name(ident, parent)),
                default: attrs.default,
                aliases: attrs.aliases,
                deserialize_with: attrs.deserialize_with,
            })
        })
        .collect()
}

/// The masked-name list for the fields actually read from the wire
/// (`skip_deserializing` fields are absent from the identifier set).
pub(super) fn de_names_of(infos: &[NamedFieldInfo]) -> Vec<(proc_macro2::Span, String)> {
    infos
        .iter()
        .filter(|info| !info.skip_de)
        .map(|info| info.de_name.clone())
        .collect()
}

/// Build the `#[serde(alias)]` match data for a set of named fields: a
/// (possibly empty) declaration of the masked alias-name function and,
/// when any aliases exist, the [`AliasMatch`] mapping each alias to its
/// field's `__Field` variant (indexed among the non-skipped fields, to
/// align with [`identifier_block`](super::identifier)'s variant numbering).
pub(super) fn build_aliases(
    names_fn: &syn::Ident,
    infos: &[NamedFieldInfo],
) -> (TokenStream2, Option<AliasMatch>) {
    // Skipped fields are absent from the identifier set, so the alias
    // target is the field's index *among the non-skipped fields*.
    let groups = infos
        .iter()
        .filter(|info| !info.skip_de)
        .enumerate()
        .map(|(field_index, info)| (field_index, info.de_name.0, info.aliases.as_slice()));
    build_alias_match(names_fn, groups)
}

/// Configuration distinguishing the two named-fields contexts: a
/// top-level struct and one struct variant of an enum. Everything
/// else about their visitors (map/seq bodies, duplicate/missing
/// field handling) is identical.
pub(super) struct NamedFieldsCx {
    /// `Type` or `Type::Variant` — the construction path.
    pub(super) construct: TokenStream2,
    /// Generated fn resolving this context's field-name group.
    pub(super) names_fn: syn::Ident,
    /// serde's expecting wording: `"struct"` or `"struct variant"`.
    pub(super) shape: &'static str,
    /// Call yielding the decrypted variant name, for variants only.
    pub(super) variant_name: Option<TokenStream2>,
    /// Visitor type name — distinct per scope so a struct-variant
    /// visitor never collides with the enum's own `__Visitor`.
    pub(super) visitor: syn::Ident,
}

/// Visitor declaration + `Visitor` impl for a named-fields context
/// (top-level struct or struct variant): `visit_map` with
/// duplicate/missing-field handling and unknown-field skipping, plus
/// `visit_seq` for positional formats. The caller emits the matching
/// identifier block and dispatch call. `skip_deserializing` fields are
/// absent from the wire and filled with `Default::default()`.
pub(super) fn named_fields_visitor(
    input: &DeriveInput,
    infos: &[NamedFieldInfo],
    cx: &NamedFieldsCx,
) -> TokenStream2 {
    let struct_ident = &input.ident;
    let NamedFieldsCx {
        construct,
        names_fn,
        shape,
        variant_name,
        visitor,
    } = cx;

    let generics = split_de_generics(input);
    let DeGenerics {
        de_impl,
        de_ty,
        ty,
        where_clause,
    } = &generics;
    let with_ctx = DeWithCtx {
        ident: struct_ident,
        de_impl,
        de_ty,
        ty,
        where_clause,
    };

    let expecting = expecting_body(shape, variant_name.as_ref());
    let visit_seq = named_visit_seq(infos, construct, shape, variant_name.as_ref(), &with_ctx);
    let visit_map = named_visit_map(infos, names_fn, construct, &with_ctx);

    quote! {
        struct #visitor #de_impl #where_clause {
            marker: ::core::marker::PhantomData<#struct_ident #ty>,
            lifetime: ::core::marker::PhantomData<&'de ()>,
        }

        #[automatically_derived]
        impl #de_impl ::litmask::__serde::de::Visitor<'de>
            for #visitor #de_ty #where_clause
        {
            type Value = #struct_ident #ty;

            fn expecting(
                &self,
                __formatter: &mut ::core::fmt::Formatter,
            ) -> ::core::fmt::Result {
                #expecting
            }

            #visit_seq
            #visit_map
        }
    }
}

/// The `visit_seq` method of a named-fields visitor: pull each
/// non-skipped field positionally; `skip_deserializing` fields consume
/// no element and take `Default::default()`. The `invalid_length`
/// index/count count only the fields actually read, matching serde.
fn named_visit_seq(
    infos: &[NamedFieldInfo],
    construct: &TokenStream2,
    shape: &str,
    variant_name: Option<&TokenStream2>,
    with_ctx: &DeWithCtx,
) -> TokenStream2 {
    let de_count = infos.iter().filter(|info| !info.skip_de).count();
    let variant = variant_option(variant_name);
    let mut lets = Vec::with_capacity(infos.len());
    let mut field_inits = Vec::with_capacity(infos.len());
    let mut read_index = 0usize;
    for (decl, info) in infos.iter().enumerate() {
        let ident = info.ident;
        let local = quote::format_ident!("__seqf{decl}");
        if info.skip_de {
            let default = default_value_expr(info.default.as_ref());
            lets.push(quote! { let #local = #default; });
        } else {
            let fty = info.ty;
            // A defaulted field uses its default when the sequence runs
            // out instead of erroring with `invalid_length`.
            let on_missing = if info.default.is_some() {
                default_value_expr(info.default.as_ref())
            } else {
                quote! {
                    return ::core::result::Result::Err(
                        ::litmask::__serde::de::Error::invalid_length(
                            #read_index,
                            &::litmask::__serde_support::ExpectedElements {
                                shape: #shape,
                                name: __litmask_type_name(),
                                variant: #variant,
                                count: #de_count,
                            },
                        ),
                    );
                }
            };
            let next_element = if let Some(path) = &info.deserialize_with {
                let wrapper = de_with_wrapper(with_ctx, fty, path);
                let de_ty = with_ctx.de_ty;
                quote! {
                    {
                        #wrapper
                        ::core::option::Option::map(
                            ::litmask::__serde::de::SeqAccess::next_element::<
                                __DeserializeWith #de_ty
                            >(
                                &mut __seq,
                            )?,
                            |__w| __w.__value,
                        )
                    }
                }
            } else {
                quote! {
                    ::litmask::__serde::de::SeqAccess::next_element::<#fty>(&mut __seq)?
                }
            };
            lets.push(quote! {
                let #local = match #next_element {
                    ::core::option::Option::Some(__value) => __value,
                    ::core::option::Option::None => { #on_missing }
                };
            });
            read_index += 1;
        }
        field_inits.push(quote! { #ident: #local });
    }
    // A struct with no readable fields never touches its SeqAccess;
    // binding it `mut` would warn, `_` mirrors serde's expansion.
    let seq_binding = if de_count == 0 {
        quote! { _ }
    } else {
        quote! { mut __seq }
    };
    quote! {
        #[inline]
        fn visit_seq<__A>(
            self,
            #seq_binding: __A,
        ) -> ::core::result::Result<Self::Value, __A::Error>
        where
            __A: ::litmask::__serde::de::SeqAccess<'de>,
        {
            #(#lets)*
            ::core::result::Result::Ok(#construct {
                #(#field_inits),*
            })
        }
    }
}

/// The `visit_map` method of a named-fields visitor: duplicate-field
/// detection, unknown-field skipping, and missing-field resolution.
/// `skip_deserializing` fields are never keyed and take `Default`.
fn named_visit_map(
    infos: &[NamedFieldInfo],
    names_fn: &syn::Ident,
    construct: &TokenStream2,
    with_ctx: &DeWithCtx,
) -> TokenStream2 {
    let mut lets = Vec::new();
    let mut arms = Vec::new();
    let mut extracts = Vec::new();
    let mut field_inits = Vec::with_capacity(infos.len());
    let mut read_index = 0usize;
    for info in infos {
        let ident = info.ident;
        if info.skip_de {
            let default = default_value_expr(info.default.as_ref());
            field_inits.push(quote! { #ident: #default });
            continue;
        }
        let fty = info.ty;
        let value = quote::format_ident!("__v{read_index}");
        let field_variant = quote::format_ident!("__field{read_index}");
        lets.push(quote! {
            let mut #value: ::core::option::Option<#fty> = ::core::option::Option::None;
        });
        let next_value = if let Some(path) = &info.deserialize_with {
            let wrapper = de_with_wrapper(with_ctx, fty, path);
            let de_ty = with_ctx.de_ty;
            quote! {
                {
                    #wrapper
                    ::litmask::__serde::de::MapAccess::next_value::<
                        __DeserializeWith #de_ty
                    >(&mut __map)?.__value
                }
            }
        } else {
            quote! { ::litmask::__serde::de::MapAccess::next_value::<#fty>(&mut __map)? }
        };
        arms.push(quote! {
            __Field::#field_variant => {
                if ::core::option::Option::is_some(&#value) {
                    return ::core::result::Result::Err(
                        <__A::Error as ::litmask::__serde::de::Error>::duplicate_field(
                            #names_fn()[#read_index],
                        ),
                    );
                }
                #value = ::core::option::Option::Some(#next_value);
            }
        });
        let on_missing = if info.default.is_some() {
            default_value_expr(info.default.as_ref())
        } else {
            quote! { ::litmask::__serde_support::missing_field(#names_fn()[#read_index])? }
        };
        extracts.push(quote! {
            let #value = match #value {
                ::core::option::Option::Some(#value) => #value,
                ::core::option::Option::None => { #on_missing }
            };
        });
        field_inits.push(quote! { #ident: #value });
        read_index += 1;
    }
    quote! {
        #[inline]
        fn visit_map<__A>(
            self,
            mut __map: __A,
        ) -> ::core::result::Result<Self::Value, __A::Error>
        where
            __A: ::litmask::__serde::de::MapAccess<'de>,
        {
            #(#lets)*
            while let ::core::option::Option::Some(__key) =
                ::litmask::__serde::de::MapAccess::next_key::<__Field>(&mut __map)?
            {
                match __key {
                    #(#arms)*
                    _ => {
                        let _ = ::litmask::__serde::de::MapAccess::next_value::<
                            ::litmask::__serde::de::IgnoredAny,
                        >(&mut __map)?;
                    }
                }
            }
            #(#extracts)*
            ::core::result::Result::Ok(#construct {
                #(#field_inits),*
            })
        }
    }
}
