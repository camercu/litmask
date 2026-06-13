//! `#[derive(MaskDeserialize)]`: a `serde::Deserialize` impl whose
//! type, field, and enum variant names are AEAD-masked at compile time
//! (EXPERIMENTAL, `unstable-serde` feature).
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

use crate::common::{
    FailTag, apply_bounds, compile_error, expand_derive, mask_name, masked_static_name,
    transparent_field,
};
use crate::serde_attrs::{self, ContainerAttrs, RenameRule, VariantAttrs};

const MACRO_NAME: &str = "MaskDeserialize";

/// Implementation of the `#[proc_macro_derive] MaskDeserialize` entry
/// point. Re-exported at the crate root via a one-line wrapper.
pub(crate) fn expand(input: TokenStream) -> TokenStream {
    expand_derive(input, try_expand)
}

fn try_expand(input: &DeriveInput) -> syn::Result<TokenStream2> {
    serde_attrs::reject_with_on_generic(input, MACRO_NAME)?;
    let body = deserialize_body(input)?;
    let struct_ident = &input.ident;
    let DeGenerics {
        de_impl,
        ty,
        where_clause,
        ..
    } = split_de_generics(input);

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
fn deserialize_body(input: &DeriveInput) -> syn::Result<TokenStream2> {
    let container = serde_attrs::parse_container(MACRO_NAME, &input.attrs)?;
    if container.transparent {
        return transparent_deserialize_body(input);
    }
    match &input.data {
        Data::Struct(data) => match &data.fields {
            Fields::Named(fields) => named_struct_body(input, fields),
            Fields::Unit => unit_struct_body(input),
            Fields::Unnamed(fields) => tuple_struct_body(input, fields),
        },
        Data::Enum(data) => enum_body(input, data),
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

/// Resolve the container's deserialize-side name (after `#[serde(rename
/// = ...)]`) plus the span to key its masking blob on.
fn container_de_name(input: &DeriveInput) -> syn::Result<(proc_macro2::Span, String)> {
    let container = serde_attrs::parse_container(MACRO_NAME, &input.attrs)?;
    Ok((input.ident.span(), container.deserialize_name(&input.ident)))
}

/// Per-named-field deserialize info: the construction ident/type plus
/// whether the field is `skip_deserializing` (filled from `Default`
/// instead of read) and its resolved deserialize name (meaningful only
/// when not skipped — skipped fields are absent from the wire).
struct NamedFieldInfo<'a> {
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

/// A local `Deserialize` adapter wrapping `ty`, whose `deserialize`
/// calls the `deserialize_with` function `path(deserializer)`. Block-
/// scoped at each use site, so the fixed name never collides. Non-
/// generic only (a local item cannot name outer generic params).
fn de_with_wrapper(ty: &syn::Type, path: &syn::Path) -> TokenStream2 {
    quote! {
        struct __DeserializeWith(#ty);
        impl<'de> ::litmask::__serde::Deserialize<'de> for __DeserializeWith {
            fn deserialize<__D>(__d: __D) -> ::core::result::Result<Self, __D::Error>
            where
                __D: ::litmask::__serde::Deserializer<'de>,
            {
                ::core::result::Result::Ok(__DeserializeWith(#path(__d)?))
            }
        }
    }
}

/// Parse every named field into a [`NamedFieldInfo`] (reject-loud on
/// unsupported `#[serde(...)]` keys). `parent` is the applicable
/// `rename_all` rule, applied unless the field has its own `rename`.
fn named_field_infos(
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
fn de_names_of(infos: &[NamedFieldInfo]) -> Vec<(proc_macro2::Span, String)> {
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
/// align with [`identifier_block`]'s variant numbering).
fn build_aliases(
    names_fn: &syn::Ident,
    infos: &[NamedFieldInfo],
) -> (TokenStream2, Option<AliasMatch>) {
    let mut flat: Vec<(proc_macro2::Span, String)> = Vec::new();
    let mut entries: Vec<(usize, usize)> = Vec::new();
    let mut field_index = 0usize;
    for info in infos {
        if info.skip_de {
            continue;
        }
        for alias in &info.aliases {
            entries.push((field_index, flat.len()));
            flat.push((info.de_name.0, alias.clone()));
        }
        field_index += 1;
    }
    if flat.is_empty() {
        return (TokenStream2::new(), None);
    }
    let decl = names_list_fn(names_fn, &flat);
    (
        decl,
        Some(AliasMatch {
            names_fn: names_fn.clone(),
            entries,
        }),
    )
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

/// The container's deserialize type-name tuple `(span, resolved name)`.
fn type_name_tuple(input: &DeriveInput, container: &ContainerAttrs) -> (proc_macro2::Span, String) {
    (input.ident.span(), container.deserialize_name(&input.ident))
}

/// Reject-loud any `#[serde(...)]` on unnamed (tuple) fields. The
/// masking derives don't yet apply field attributes positionally, so
/// honoring one silently (e.g. `deserialize_with`, `default`) would
/// diverge from serde without warning.
fn check_unnamed_field_attrs(fields: &syn::FieldsUnnamed) -> syn::Result<()> {
    for field in &fields.unnamed {
        let attrs = serde_attrs::parse_field(MACRO_NAME, &field.attrs)?;
        if attrs.is_set() {
            return Err(compile_error(
                syn::spanned::Spanned::span(field),
                MACRO_NAME,
                FailTag::InvalidArg,
                "`#[serde(...)]` on a tuple field is not yet supported",
            ));
        }
    }
    Ok(())
}

/// The four generics fragments every generated visitor needs, with
/// the `'de` lifetime threaded ahead of the type's own params and
/// each type param bounded `Deserialize<'de>` (the plain derive's
/// bound model). Token streams rather than `syn` borrows so body
/// builders can own them without lifetime plumbing.
struct DeGenerics {
    /// `<'de, T>` — impl-position generics including `'de`.
    de_impl: TokenStream2,
    /// `<'de, T>` — type-position generics for `__Visitor`.
    de_ty: TokenStream2,
    /// `<T>` — the input type's own type-position generics.
    ty: TokenStream2,
    /// `where T: Deserialize<'de>` (empty when no type params).
    where_clause: TokenStream2,
}

fn split_de_generics(input: &DeriveInput) -> DeGenerics {
    // A `#[serde(bound)]` override replaces the default `T:
    // Deserialize<'de>` predicate. Parsing here keeps every generated
    // visitor's generics consistent without threading the bound through
    // each builder; the container is already validated by the time this
    // runs (a bad bound surfaces from the body parse first).
    let bound = serde_attrs::parse_container(MACRO_NAME, &input.attrs)
        .unwrap_or_default()
        .bound
        .deserialize;
    let generics = apply_bounds(
        input.generics.clone(),
        &syn::parse_quote!(::litmask::__serde::Deserialize<'de>),
        bound.as_deref(),
    );
    let mut de_generics = generics.clone();
    let borrowed = borrowed_lifetimes(input);
    let de_param: syn::GenericParam = if borrowed.is_empty() {
        syn::parse_quote!('de)
    } else {
        syn::parse_quote!('de: #(#borrowed)+*)
    };
    de_generics.params.insert(0, de_param);
    let (de_impl, de_ty, _) = de_generics.split_for_impl();
    let (de_impl, de_ty) = (quote!(#de_impl), quote!(#de_ty));
    let (_, ty, where_clause) = generics.split_for_impl();
    DeGenerics {
        de_impl,
        de_ty,
        ty: quote!(#ty),
        where_clause: quote!(#where_clause),
    }
}

/// Lifetimes the deserialized value borrows from the input, mirroring
/// serde's implicit-borrow rule: only fields typed exactly `&str` /
/// `&[u8]` (optionally `Option`-wrapped) borrow, and each contributes
/// its reference lifetime as a `'de: 'a` bound on the impl. The check
/// is syntactic — type aliases don't borrow — matching serde's own
/// false-negative behavior.
fn borrowed_lifetimes(input: &DeriveInput) -> Vec<syn::Lifetime> {
    let fields: Vec<&syn::Field> = match &input.data {
        Data::Struct(data) => data.fields.iter().collect(),
        Data::Enum(data) => data
            .variants
            .iter()
            .flat_map(|variant| variant.fields.iter())
            .collect(),
        Data::Union(_) => Vec::new(),
    };
    let mut seen = std::collections::BTreeSet::new();
    let mut lifetimes = Vec::new();
    for field in fields {
        let Some(reference) = implicitly_borrowed_reference(&field.ty) else {
            continue;
        };
        if let Some(lifetime) = &reference.lifetime {
            if seen.insert(lifetime.to_string()) {
                lifetimes.push(lifetime.clone());
            }
        }
    }
    lifetimes
}

/// `&str` / `&[u8]`, directly or as `Option<&str>` / `Option<&[u8]>`
/// — the only shapes serde implicitly borrows.
fn implicitly_borrowed_reference(ty: &syn::Type) -> Option<&syn::TypeReference> {
    if let syn::Type::Reference(reference) = ty {
        return (is_str(&reference.elem) || is_slice_u8(&reference.elem)).then_some(reference);
    }
    option_inner(ty).and_then(implicitly_borrowed_reference)
}

fn is_str(ty: &syn::Type) -> bool {
    matches!(ty, syn::Type::Path(path) if path.qself.is_none() && path.path.is_ident("str"))
}

fn is_slice_u8(ty: &syn::Type) -> bool {
    match ty {
        syn::Type::Slice(slice) => {
            matches!(&*slice.elem, syn::Type::Path(path)
                if path.qself.is_none() && path.path.is_ident("u8"))
        }
        _ => false,
    }
}

/// `Option<T>` (sole path segment, single type argument) → `T`.
fn option_inner(ty: &syn::Type) -> Option<&syn::Type> {
    let syn::Type::Path(path) = ty else {
        return None;
    };
    if path.qself.is_some() || path.path.segments.len() != 1 {
        return None;
    }
    let segment = &path.path.segments[0];
    if segment.ident != "Option" {
        return None;
    }
    let syn::PathArguments::AngleBracketed(args) = &segment.arguments else {
        return None;
    };
    if args.args.len() != 1 {
        return None;
    }
    match &args.args[0] {
        syn::GenericArgument::Type(inner) => Some(inner),
        _ => None,
    }
}

/// `__Visitor` carrier struct declaration — the `PhantomData` pair
/// mirrors serde's expansion (`marker` pins the output type so the
/// impl's generics are used; `lifetime` pins `'de`).
fn visitor_decl(input: &DeriveInput, generics: &DeGenerics) -> TokenStream2 {
    let struct_ident = &input.ident;
    let DeGenerics {
        de_impl,
        ty,
        where_clause,
        ..
    } = generics;
    quote! {
        struct __Visitor #de_impl #where_clause {
            marker: ::core::marker::PhantomData<#struct_ident #ty>,
            lifetime: ::core::marker::PhantomData<&'de ()>,
        }
    }
}

fn visitor_expr() -> TokenStream2 {
    quote! {
        __Visitor {
            marker: ::core::marker::PhantomData,
            lifetime: ::core::marker::PhantomData,
        }
    }
}

/// Emit `fn __litmask_type_name() -> &'static str` for the container,
/// masking its resolved (post-`rename`) deserialize name.
fn type_name_fn(name: &(proc_macro2::Span, String)) -> TokenStream2 {
    let type_name = masked_static_name(name.0, &name.1);
    quote! {
        fn __litmask_type_name() -> &'static str {
            #type_name
        }
    }
}

/// Emit `fn #fn_ident() -> &'static [&'static str]` resolving a name
/// group (struct fields, enum variants, or one variant's fields) to
/// decrypted names, leaked once as the `&'static [&'static str]`
/// shape serde's `deserialize_struct`/`deserialize_enum`/
/// `struct_variant` and `unknown_field`/`unknown_variant` require.
fn names_list_fn(fn_ident: &syn::Ident, names: &[(proc_macro2::Span, String)]) -> TokenStream2 {
    let decrypts = names.iter().map(|(span, name)| mask_name(*span, name));
    quote! {
        fn #fn_ident() -> &'static [&'static str] {
            static __LITMASK_NAMES: ::std::sync::OnceLock<&'static [&'static str]> =
                ::std::sync::OnceLock::new();
            *__LITMASK_NAMES.get_or_init(|| {
                let __names: ::std::vec::Vec<&'static str> = ::std::vec![
                    #( ::std::boxed::Box::leak((#decrypts).into_boxed_str()) as &'static str ),*
                ];
                ::std::boxed::Box::leak(__names.into_boxed_slice())
            })
        }
    }
}

/// What an identifier visitor does with input that matches no name.
/// serde's two flavors: struct field keys fall through to `__ignore`
/// (unknown fields are skipped by default), enum variant tags are
/// hard errors (`unknown_variant`, or `invalid_value` for an
/// out-of-range index).
enum IdentifierKind {
    StructField,
    EnumVariant,
}

/// The `IdentifierKind`-specific pieces of the identifier visitor: the
/// optional trailing `__ignore` enum variant, the `expecting()` text,
/// and the three no-match fallthrough arms (`visit_u64`/`visit_str`/
/// `visit_bytes`).
struct IdentifierFallthrough {
    ignore_variant: Option<TokenStream2>,
    expecting: &'static str,
    u64_arm: TokenStream2,
    str_arm: TokenStream2,
    bytes_arm: TokenStream2,
}

/// Resolve the [`IdentifierKind`]-specific fallthrough behavior:
/// struct field keys skip to `__ignore` (or, under `deny_unknown`, are
/// a hard `unknown_field` error for string/byte keys); enum variant
/// tags are hard errors (`unknown_variant`, or `invalid_value` for an
/// out-of-range `visit_u64` index).
fn identifier_fallthrough(
    names_fn: &syn::Ident,
    count: usize,
    kind: &IdentifierKind,
    deny_unknown: bool,
) -> IdentifierFallthrough {
    match kind {
        IdentifierKind::StructField => {
            // `deny_unknown_fields` errors on unknown string/byte keys
            // (the keys self-describing formats use). A numeric
            // (`visit_u64`) out-of-range key still routes to `__ignore`,
            // matching serde for the self-describing path this targets.
            let (str_arm, bytes_arm) = if deny_unknown {
                (
                    quote! {
                        ::core::result::Result::Err(
                            ::litmask::__serde::de::Error::unknown_field(__value, #names_fn()),
                        )
                    },
                    quote! {
                        {
                            let __value = ::std::string::String::from_utf8_lossy(__value);
                            ::core::result::Result::Err(
                                ::litmask::__serde::de::Error::unknown_field(
                                    &__value,
                                    #names_fn(),
                                ),
                            )
                        }
                    },
                )
            } else {
                (
                    quote! { ::core::result::Result::Ok(__Field::__ignore) },
                    quote! { ::core::result::Result::Ok(__Field::__ignore) },
                )
            };
            IdentifierFallthrough {
                ignore_variant: Some(quote! { __ignore, }),
                expecting: "field identifier",
                u64_arm: quote! { ::core::result::Result::Ok(__Field::__ignore) },
                str_arm,
                bytes_arm,
            }
        }
        IdentifierKind::EnumVariant => {
            // The index-range text embeds only the variant count —
            // no schema vocabulary — so a compile-time literal
            // matching serde's wording exactly is safe here.
            let index_msg = format!("variant index 0 <= i < {count}");
            IdentifierFallthrough {
                ignore_variant: None,
                expecting: "variant identifier",
                u64_arm: quote! {
                    ::core::result::Result::Err(
                        ::litmask::__serde::de::Error::invalid_value(
                            ::litmask::__serde::de::Unexpected::Unsigned(__value),
                            &#index_msg,
                        ),
                    )
                },
                str_arm: quote! {
                    ::core::result::Result::Err(
                        ::litmask::__serde::de::Error::unknown_variant(__value, #names_fn()),
                    )
                },
                bytes_arm: quote! {
                    {
                        let __value = ::std::string::String::from_utf8_lossy(__value);
                        ::core::result::Result::Err(
                            ::litmask::__serde::de::Error::unknown_variant(
                                &__value,
                                #names_fn(),
                            ),
                        )
                    }
                },
            }
        }
    }
}

/// Extra `#[serde(alias)]` match arms: a leaked name function plus the
/// `(field index, alias index)` pairs mapping each alias back to its
/// field's `__Field` variant.
struct AliasMatch {
    names_fn: syn::Ident,
    entries: Vec<(usize, usize)>,
}

/// Build the `visit_str` / `visit_bytes` comparison arms for an
/// identifier visitor: one per primary name, plus one per
/// `#[serde(alias)]` mapping back to its field's variant.
fn identifier_match_arms(
    names_fn: &syn::Ident,
    variants: &[syn::Ident],
    aliases: Option<&AliasMatch>,
) -> (Vec<TokenStream2>, Vec<TokenStream2>) {
    let mut str_arms = Vec::new();
    let mut bytes_arms = Vec::new();
    for (i, variant) in variants.iter().enumerate() {
        str_arms.push(quote! {
            if __value == #names_fn()[#i] {
                return ::core::result::Result::Ok(__Field::#variant);
            }
        });
        bytes_arms.push(quote! {
            if __value == #names_fn()[#i].as_bytes() {
                return ::core::result::Result::Ok(__Field::#variant);
            }
        });
    }
    if let Some(alias) = aliases {
        let alias_fn = &alias.names_fn;
        for (field_index, alias_index) in &alias.entries {
            let variant = &variants[*field_index];
            str_arms.push(quote! {
                if __value == #alias_fn()[#alias_index] {
                    return ::core::result::Result::Ok(__Field::#variant);
                }
            });
            bytes_arms.push(quote! {
                if __value == #alias_fn()[#alias_index].as_bytes() {
                    return ::core::result::Result::Ok(__Field::#variant);
                }
            });
        }
    }
    (str_arms, bytes_arms)
}

/// Generate the `__Field` identifier enum, its visitor, and its
/// `Deserialize` impl — the machinery `MapAccess::next_key` /
/// `EnumAccess::variant` use to classify each incoming key or tag.
/// Mirrors serde's expansion with one difference: the
/// `visit_str`/`visit_bytes` arms compare against decrypted names at
/// runtime instead of literal match patterns. `aliases` adds extra
/// accepted names per field; `deny_unknown` makes unknown string keys a
/// hard error.
fn identifier_block(
    names_fn: &syn::Ident,
    count: usize,
    kind: &IdentifierKind,
    aliases: Option<&AliasMatch>,
    deny_unknown: bool,
) -> TokenStream2 {
    let variants: Vec<syn::Ident> = (0..count)
        .map(|i| quote::format_ident!("__field{i}"))
        .collect();
    let indices = 0..count as u64;
    let (str_arms, bytes_arms) = identifier_match_arms(names_fn, &variants, aliases);

    let IdentifierFallthrough {
        ignore_variant,
        expecting,
        u64_arm: u64_fallthrough,
        str_arm: str_fallthrough,
        bytes_arm: bytes_fallthrough,
    } = identifier_fallthrough(names_fn, count, kind, deny_unknown);

    quote! {
        #[allow(non_camel_case_types)]
        enum __Field {
            #(#variants,)*
            #ignore_variant
        }

        struct __FieldVisitor;

        #[automatically_derived]
        impl<'de> ::litmask::__serde::de::Visitor<'de> for __FieldVisitor {
            type Value = __Field;

            fn expecting(
                &self,
                __formatter: &mut ::core::fmt::Formatter,
            ) -> ::core::fmt::Result {
                ::core::fmt::Formatter::write_str(__formatter, #expecting)
            }

            fn visit_u64<__E>(
                self,
                __value: u64,
            ) -> ::core::result::Result<Self::Value, __E>
            where
                __E: ::litmask::__serde::de::Error,
            {
                match __value {
                    #(#indices => ::core::result::Result::Ok(__Field::#variants),)*
                    _ => #u64_fallthrough,
                }
            }

            fn visit_str<__E>(
                self,
                __value: &str,
            ) -> ::core::result::Result<Self::Value, __E>
            where
                __E: ::litmask::__serde::de::Error,
            {
                #(#str_arms)*
                #str_fallthrough
            }

            fn visit_bytes<__E>(
                self,
                __value: &[u8],
            ) -> ::core::result::Result<Self::Value, __E>
            where
                __E: ::litmask::__serde::de::Error,
            {
                #(#bytes_arms)*
                #bytes_fallthrough
            }
        }

        #[automatically_derived]
        impl<'de> ::litmask::__serde::Deserialize<'de> for __Field {
            #[inline]
            fn deserialize<__D>(
                __deserializer: __D,
            ) -> ::core::result::Result<Self, __D::Error>
            where
                __D: ::litmask::__serde::Deserializer<'de>,
            {
                ::litmask::__serde::Deserializer::deserialize_identifier(
                    __deserializer,
                    __FieldVisitor,
                )
            }
        }
    }
}

/// Configuration distinguishing the two named-fields contexts: a
/// top-level struct and one struct variant of an enum. Everything
/// else about their visitors (map/seq bodies, duplicate/missing
/// field handling) is identical.
struct NamedFieldsCx {
    /// `Type` or `Type::Variant` — the construction path.
    construct: TokenStream2,
    /// Generated fn resolving this context's field-name group.
    names_fn: syn::Ident,
    /// serde's expecting wording: `"struct"` or `"struct variant"`.
    shape: &'static str,
    /// Call yielding the decrypted variant name, for variants only.
    variant_name: Option<TokenStream2>,
    /// Visitor type name — distinct per scope so a struct-variant
    /// visitor never collides with the enum's own `__Visitor`.
    visitor: syn::Ident,
}

/// `Option<&'static str>` tokens for `ExpectedElements.variant`.
fn variant_option(variant_name: Option<&TokenStream2>) -> TokenStream2 {
    if let Some(call) = variant_name {
        quote! { ::core::option::Option::Some(#call) }
    } else {
        quote! { ::core::option::Option::None }
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

/// Visitor declaration + `Visitor` impl for a named-fields context
/// (top-level struct or struct variant): `visit_map` with
/// duplicate/missing-field handling and unknown-field skipping, plus
/// `visit_seq` for positional formats. The caller emits the matching
/// identifier block and dispatch call. `skip_deserializing` fields are
/// absent from the wire and filled with `Default::default()`.
fn named_fields_visitor(
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

    let expecting = expecting_body(shape, variant_name.as_ref());
    let visit_seq = named_visit_seq(infos, construct, shape, variant_name.as_ref());
    let visit_map = named_visit_map(infos, names_fn, construct);

    let generics = split_de_generics(input);
    let DeGenerics {
        de_impl,
        de_ty,
        ty,
        where_clause,
    } = &generics;

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
                let wrapper = de_with_wrapper(fty, path);
                quote! {
                    {
                        #wrapper
                        ::core::option::Option::map(
                            ::litmask::__serde::de::SeqAccess::next_element::<__DeserializeWith>(
                                &mut __seq,
                            )?,
                            |__w| __w.0,
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
            let wrapper = de_with_wrapper(fty, path);
            quote! {
                {
                    #wrapper
                    ::litmask::__serde::de::MapAccess::next_value::<__DeserializeWith>(&mut __map)?.0
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

fn named_struct_body(input: &DeriveInput, fields: &syn::FieldsNamed) -> syn::Result<TokenStream2> {
    let struct_ident = &input.ident;
    let container = serde_attrs::parse_container(MACRO_NAME, &input.attrs)?;
    let infos = named_field_infos(fields, container.rename_all.deserialize)?;
    let de_names = de_names_of(&infos);
    let names_fn = quote::format_ident!("__litmask_names");
    let aliases_fn = quote::format_ident!("__litmask_aliases");
    let type_name_fn = type_name_fn(&type_name_tuple(input, &container));
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

fn unit_struct_body(input: &DeriveInput) -> syn::Result<TokenStream2> {
    let struct_ident = &input.ident;
    let type_name_fn = type_name_fn(&container_de_name(input)?);
    let generics = split_de_generics(input);
    let visitor = visitor_decl(input, &generics);
    let visitor_expr = visitor_expr();
    let DeGenerics {
        de_impl,
        de_ty,
        ty,
        where_clause,
    } = &generics;
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
    })
}

/// Tuple-struct dispatch mirrors serde's: exactly one field is a
/// newtype (`deserialize_newtype_struct` + a `visit_newtype_struct`
/// method), any other arity — including zero — goes through
/// `deserialize_tuple_struct`. Both visitors share the `visit_seq`
/// path, which is what non-self-describing formats call.
fn tuple_struct_body(
    input: &DeriveInput,
    fields: &syn::FieldsUnnamed,
) -> syn::Result<TokenStream2> {
    let struct_ident = &input.ident;
    check_unnamed_field_attrs(fields)?;
    let type_name_fn = type_name_fn(&container_de_name(input)?);
    let field_tys: Vec<&syn::Type> = fields.unnamed.iter().map(|field| &field.ty).collect();
    let field_count = field_tys.len();
    let bindings: Vec<syn::Ident> = (0..field_count)
        .map(|i| quote::format_ident!("__field{i}"))
        .collect();

    let seq_lets = seq_field_lets(&bindings, &field_tys, "tuple struct", None, field_count);
    let seq_binding = if field_count == 0 {
        quote! { _ }
    } else {
        quote! { mut __seq }
    };

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

    let generics = split_de_generics(input);
    let visitor = visitor_decl(input, &generics);
    let DeGenerics {
        de_impl,
        de_ty,
        ty,
        where_clause,
    } = &generics;
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
fn enum_body(input: &DeriveInput, data: &syn::DataEnum) -> syn::Result<TokenStream2> {
    let enum_ident = &input.ident;
    let container = serde_attrs::parse_container(MACRO_NAME, &input.attrs)?;
    let de_names = variant_de_names(data, container.rename_all.deserialize)?;
    let names_fn = quote::format_ident!("__litmask_names");
    let type_name_fn = type_name_fn(&type_name_tuple(input, &container));
    let names_fn_decl = names_list_fn(&names_fn, &de_names);
    let variant_identifier = identifier_block(
        &names_fn,
        de_names.len(),
        &IdentifierKind::EnumVariant,
        None,
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
            .map(|(index, variant)| variant_arm(input, index, variant, &container))
            .collect::<syn::Result<Vec<_>>>()?;
        quote! {
            match ::litmask::__serde::de::EnumAccess::variant(__data)? {
                #(#arms)*
            }
        }
    };

    let generics = split_de_generics(input);
    let visitor = visitor_decl(input, &generics);
    let visitor_expr = visitor_expr();
    let DeGenerics {
        de_impl,
        de_ty,
        ty,
        where_clause,
    } = &generics;

    Ok(quote! {
        #type_name_fn
        #names_fn_decl
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
    index: usize,
    variant: &syn::Variant,
    container: &ContainerAttrs,
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
            check_unnamed_field_attrs(fields)?;
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
            vident,
            &field_variant,
            &variant_name_fn,
            &variant_name_call,
            fields,
        ),
        Fields::Named(fields) => struct_variant_arm(
            input,
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
    vident: &syn::Ident,
    field_variant: &syn::Ident,
    variant_name_fn: &TokenStream2,
    variant_name_call: &TokenStream2,
    fields: &syn::FieldsUnnamed,
) -> syn::Result<TokenStream2> {
    check_unnamed_field_attrs(fields)?;
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
    let seq_binding = if field_count == 0 {
        quote! { _ }
    } else {
        quote! { mut __seq }
    };
    let expecting = expecting_body("tuple variant", Some(variant_name_call));
    let generics = split_de_generics(input);
    let DeGenerics {
        de_impl,
        de_ty,
        ty,
        where_clause,
    } = &generics;
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
