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
    FailTag, compile_error, expand_derive, mask_ident, masked_name_expr, reject_serde_attrs,
    with_trait_bounds,
};

const MACRO_NAME: &str = "MaskDeserialize";

/// Implementation of the `#[proc_macro_derive] MaskDeserialize` entry
/// point. Re-exported at the crate root via a one-line wrapper.
pub(crate) fn expand(input: TokenStream) -> TokenStream {
    expand_derive(input, try_expand)
}

fn try_expand(input: &DeriveInput) -> syn::Result<TokenStream2> {
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
    match &input.data {
        Data::Struct(data) => {
            let field_attrs = data.fields.iter().flat_map(|field| field.attrs.iter());
            reject_serde_attrs(MACRO_NAME, input.attrs.iter().chain(field_attrs))?;
            match &data.fields {
                Fields::Named(fields) => Ok(named_struct_body(input, fields)),
                Fields::Unit => Ok(unit_struct_body(input)),
                Fields::Unnamed(fields) => Ok(tuple_struct_body(input, fields)),
            }
        }
        Data::Enum(data) => {
            let variant_attrs = data.variants.iter().flat_map(|variant| {
                variant
                    .attrs
                    .iter()
                    .chain(variant.fields.iter().flat_map(|field| field.attrs.iter()))
            });
            reject_serde_attrs(MACRO_NAME, input.attrs.iter().chain(variant_attrs))?;
            Ok(enum_body(input, data))
        }
        Data::Union(_) => Err(compile_error(
            input.ident.span(),
            MACRO_NAME,
            FailTag::Grammar,
            "supports structs and enums only",
        )),
    }
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
    let generics = with_trait_bounds(
        input.generics.clone(),
        &syn::parse_quote!(::litmask::__serde::Deserialize<'de>),
    );
    let mut de_generics = generics.clone();
    de_generics.params.insert(0, syn::parse_quote!('de));
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

/// Emit `fn __litmask_type_name() -> &'static str` for the container.
fn type_name_fn(container: &syn::Ident) -> TokenStream2 {
    let type_name = masked_name_expr(container);
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
fn names_list_fn(fn_ident: &syn::Ident, name_idents: &[&syn::Ident]) -> TokenStream2 {
    let decrypts = name_idents.iter().map(|ident| mask_ident(ident));
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

/// Generate the `__Field` identifier enum, its visitor, and its
/// `Deserialize` impl — the machinery `MapAccess::next_key` /
/// `EnumAccess::variant` use to classify each incoming key or tag.
/// Mirrors serde's expansion with one difference: the
/// `visit_str`/`visit_bytes` arms compare against decrypted names at
/// runtime instead of literal match patterns.
fn identifier_block(names_fn: &syn::Ident, count: usize, kind: &IdentifierKind) -> TokenStream2 {
    let variants: Vec<syn::Ident> = (0..count)
        .map(|i| quote::format_ident!("__field{i}"))
        .collect();
    let indices = 0..count as u64;
    let str_arms = variants.iter().enumerate().map(|(i, variant)| {
        quote! {
            if __value == #names_fn()[#i] {
                return ::core::result::Result::Ok(__Field::#variant);
            }
        }
    });
    let bytes_arms = variants.iter().enumerate().map(|(i, variant)| {
        quote! {
            if __value == #names_fn()[#i].as_bytes() {
                return ::core::result::Result::Ok(__Field::#variant);
            }
        }
    });

    let (ignore_variant, expecting, u64_fallthrough, str_fallthrough, bytes_fallthrough) =
        match kind {
            IdentifierKind::StructField => (
                Some(quote! { __ignore, }),
                "field identifier",
                quote! { ::core::result::Result::Ok(__Field::__ignore) },
                quote! { ::core::result::Result::Ok(__Field::__ignore) },
                quote! { ::core::result::Result::Ok(__Field::__ignore) },
            ),
            IdentifierKind::EnumVariant => {
                // The index-range text embeds only the variant count —
                // no schema vocabulary — so a compile-time literal
                // matching serde's wording exactly is safe here.
                let index_msg = format!("variant index 0 <= i < {count}");
                (
                    None,
                    "variant identifier",
                    quote! {
                        ::core::result::Result::Err(
                            ::litmask::__serde::de::Error::invalid_value(
                                ::litmask::__serde::de::Unexpected::Unsigned(__value),
                                &#index_msg,
                            ),
                        )
                    },
                    quote! {
                        ::core::result::Result::Err(
                            ::litmask::__serde::de::Error::unknown_variant(__value, #names_fn()),
                        )
                    },
                    quote! {
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
                )
            }
        };

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
    match variant_name {
        Some(call) => quote! { ::core::option::Option::Some(#call) },
        None => quote! { ::core::option::Option::None },
    }
}

/// `expecting()` body rendering `"<shape> <Name>"` (structs) or
/// `"<shape> <Name>::<Variant>"` (variants) from decrypted names.
fn expecting_body(shape: &str, variant_name: Option<&TokenStream2>) -> TokenStream2 {
    match variant_name {
        Some(call) => quote! {
            ::core::write!(
                __formatter,
                "{} {}::{}",
                #shape,
                __litmask_type_name(),
                #call,
            )
        },
        None => quote! {
            ::core::write!(__formatter, "{} {}", #shape, __litmask_type_name())
        },
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
/// identifier block and dispatch call.
fn named_fields_visitor(
    input: &DeriveInput,
    fields: &syn::FieldsNamed,
    cx: &NamedFieldsCx,
) -> TokenStream2 {
    let struct_ident = &input.ident;
    let field_idents: Vec<&syn::Ident> = fields
        .named
        .iter()
        .map(|field| field.ident.as_ref().expect("named field has an ident"))
        .collect();
    let field_tys: Vec<&syn::Type> = fields.named.iter().map(|field| &field.ty).collect();
    let field_count = field_idents.len();
    // Bindings are mangled, never the user's field idents: a field
    // named `__map` or `__seq` would otherwise shadow the generated
    // locals and break compilation.
    let bindings: Vec<syn::Ident> = (0..field_count)
        .map(|i| quote::format_ident!("__field{i}"))
        .collect();
    let field_variants = &bindings; // `__Field::__fieldN` reuses the same idents.

    let NamedFieldsCx {
        construct,
        names_fn,
        shape,
        variant_name,
        visitor,
    } = cx;

    let seq_lets = seq_field_lets(
        &bindings,
        &field_tys,
        shape,
        variant_name.as_ref(),
        field_count,
    );
    let expecting = expecting_body(shape, variant_name.as_ref());

    let map_lets = bindings.iter().enumerate().map(|(i, binding)| {
        let fty = field_tys[i];
        quote! {
            let mut #binding: ::core::option::Option<#fty> = ::core::option::Option::None;
        }
    });
    let map_arms = bindings.iter().enumerate().map(|(i, binding)| {
        let fty = field_tys[i];
        quote! {
            __Field::#binding => {
                if ::core::option::Option::is_some(&#binding) {
                    return ::core::result::Result::Err(
                        <__A::Error as ::litmask::__serde::de::Error>::duplicate_field(
                            #names_fn()[#i],
                        ),
                    );
                }
                #binding = ::core::option::Option::Some(
                    ::litmask::__serde::de::MapAccess::next_value::<#fty>(&mut __map)?,
                );
            }
        }
    });
    let map_extracts = bindings.iter().enumerate().map(|(i, binding)| {
        quote! {
            let #binding = match #binding {
                ::core::option::Option::Some(#binding) => #binding,
                ::core::option::Option::None => {
                    ::litmask::__serde_support::missing_field(#names_fn()[#i])?
                }
            };
        }
    });

    // A zero-field struct never touches its SeqAccess; binding it
    // `mut` would warn, binding it `_` mirrors serde's expansion.
    let seq_binding = if field_count == 0 {
        quote! { _ }
    } else {
        quote! { mut __seq }
    };

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

            #[inline]
            fn visit_seq<__A>(
                self,
                #seq_binding: __A,
            ) -> ::core::result::Result<Self::Value, __A::Error>
            where
                __A: ::litmask::__serde::de::SeqAccess<'de>,
            {
                #(#seq_lets)*
                ::core::result::Result::Ok(#construct {
                    #(#field_idents: #bindings),*
                })
            }

            #[inline]
            fn visit_map<__A>(
                self,
                mut __map: __A,
            ) -> ::core::result::Result<Self::Value, __A::Error>
            where
                __A: ::litmask::__serde::de::MapAccess<'de>,
            {
                #(#map_lets)*
                while let ::core::option::Option::Some(__key) =
                    ::litmask::__serde::de::MapAccess::next_key::<__Field>(&mut __map)?
                {
                    match __key {
                        #(#map_arms)*
                        _ => {
                            let _ = ::litmask::__serde::de::MapAccess::next_value::<
                                ::litmask::__serde::de::IgnoredAny,
                            >(&mut __map)?;
                        }
                    }
                }
                #(#map_extracts)*
                ::core::result::Result::Ok(#construct {
                    #(#field_idents: #field_variants),*
                })
            }
        }
    }
}

fn named_struct_body(input: &DeriveInput, fields: &syn::FieldsNamed) -> TokenStream2 {
    let struct_ident = &input.ident;
    let field_idents: Vec<&syn::Ident> = fields
        .named
        .iter()
        .map(|field| field.ident.as_ref().expect("named field has an ident"))
        .collect();
    let names_fn = quote::format_ident!("__litmask_names");
    let type_name_fn = type_name_fn(struct_ident);
    let names_fn_decl = names_list_fn(&names_fn, &field_idents);
    let field_identifier =
        identifier_block(&names_fn, field_idents.len(), &IdentifierKind::StructField);
    let visitor_ident = quote::format_ident!("__Visitor");
    let visitor = named_fields_visitor(
        input,
        fields,
        &NamedFieldsCx {
            construct: quote! { #struct_ident },
            names_fn,
            shape: "struct",
            variant_name: None,
            visitor: visitor_ident,
        },
    );
    let visitor_expr = visitor_expr();

    quote! {
        #type_name_fn
        #names_fn_decl
        #field_identifier
        #visitor

        ::litmask::__serde::Deserializer::deserialize_struct(
            __deserializer,
            __litmask_type_name(),
            __litmask_names(),
            #visitor_expr,
        )
    }
}

fn unit_struct_body(input: &DeriveInput) -> TokenStream2 {
    let struct_ident = &input.ident;
    let type_name_fn = type_name_fn(struct_ident);
    let generics = split_de_generics(input);
    let visitor = visitor_decl(input, &generics);
    let visitor_expr = visitor_expr();
    let DeGenerics {
        de_impl,
        de_ty,
        ty,
        where_clause,
    } = &generics;
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
fn tuple_struct_body(input: &DeriveInput, fields: &syn::FieldsUnnamed) -> TokenStream2 {
    let struct_ident = &input.ident;
    let type_name_fn = type_name_fn(struct_ident);
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
    }
}

/// Externally tagged enum (serde's no-attrs default): the
/// variant-identifier enum selects by decrypted name or by
/// declaration-order index (`visit_u64` — the non-self-describing
/// wire form), then each match arm calls the `VariantAccess` entry
/// point for its variant kind. Tuple and struct variants declare
/// their own visitor inside the arm's block, exactly as serde's
/// expansion scopes them.
fn enum_body(input: &DeriveInput, data: &syn::DataEnum) -> TokenStream2 {
    let enum_ident = &input.ident;
    let variant_idents: Vec<&syn::Ident> =
        data.variants.iter().map(|variant| &variant.ident).collect();
    let names_fn = quote::format_ident!("__litmask_names");
    let type_name_fn = type_name_fn(enum_ident);
    let names_fn_decl = names_list_fn(&names_fn, &variant_idents);
    let variant_identifier = identifier_block(
        &names_fn,
        variant_idents.len(),
        &IdentifierKind::EnumVariant,
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
            .map(|(index, variant)| variant_arm(input, index, variant));
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

    quote! {
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
    }
}

/// One `visit_enum` match arm per variant. The arm's block declares
/// everything the variant kind needs (an inner visitor for tuple and
/// struct variants, a field-identifier enum for struct variants) —
/// block scoping keeps each variant's generated items, including a
/// shadowed inner `__Field`, from colliding with the enum-level ones.
fn variant_arm(input: &DeriveInput, index: usize, variant: &syn::Variant) -> TokenStream2 {
    let enum_ident = &input.ident;
    let vident = &variant.ident;
    let field_variant = quote::format_ident!("__field{index}");
    let variant_name = masked_name_expr(vident);
    let variant_name_fn = quote! {
        fn __litmask_variant_name() -> &'static str {
            #variant_name
        }
    };
    let variant_name_call = quote! { __litmask_variant_name() };

    match &variant.fields {
        Fields::Unit => quote! {
            (__Field::#field_variant, __variant) => {
                ::litmask::__serde::de::VariantAccess::unit_variant(__variant)?;
                ::core::result::Result::Ok(#enum_ident::#vident)
            }
        },
        Fields::Unnamed(fields) if fields.unnamed.len() == 1 => {
            let fty = &fields.unnamed[0].ty;
            quote! {
                (__Field::#field_variant, __variant) => ::core::result::Result::map(
                    ::litmask::__serde::de::VariantAccess::newtype_variant::<#fty>(__variant),
                    #enum_ident::#vident,
                ),
            }
        }
        Fields::Unnamed(fields) => {
            let field_tys: Vec<&syn::Type> = fields.unnamed.iter().map(|field| &field.ty).collect();
            let field_count = field_tys.len();
            let bindings: Vec<syn::Ident> = (0..field_count)
                .map(|i| quote::format_ident!("__field{i}"))
                .collect();
            let seq_lets = seq_field_lets(
                &bindings,
                &field_tys,
                "tuple variant",
                Some(&variant_name_call),
                field_count,
            );
            let seq_binding = if field_count == 0 {
                quote! { _ }
            } else {
                quote! { mut __seq }
            };
            let expecting = expecting_body("tuple variant", Some(&variant_name_call));
            let generics = split_de_generics(input);
            let DeGenerics {
                de_impl,
                de_ty,
                ty,
                where_clause,
            } = &generics;
            quote! {
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
            }
        }
        Fields::Named(fields) => {
            let field_idents: Vec<&syn::Ident> = fields
                .named
                .iter()
                .map(|field| field.ident.as_ref().expect("named field has an ident"))
                .collect();
            let vfields_fn = quote::format_ident!("__litmask_vfields");
            let vfields_decl = names_list_fn(&vfields_fn, &field_idents);
            // The inner `__Field` shadows the enum-level variant
            // identifier inside this arm's block — intentional, and
            // exactly how serde scopes its per-variant expansion.
            let field_identifier = identifier_block(
                &vfields_fn,
                field_idents.len(),
                &IdentifierKind::StructField,
            );
            let visitor_ident = quote::format_ident!("__VariantVisitor");
            let visitor = named_fields_visitor(
                input,
                fields,
                &NamedFieldsCx {
                    construct: quote! { #enum_ident::#vident },
                    names_fn: vfields_fn.clone(),
                    shape: "struct variant",
                    variant_name: Some(variant_name_call),
                    visitor: visitor_ident,
                },
            );
            quote! {
                (__Field::#field_variant, __variant) => {
                    #variant_name_fn
                    #vfields_decl
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
            }
        }
    }
}
