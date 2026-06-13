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
//! formats deserialize structs positionally). Identifier matching
//! compares against decrypted names at runtime instead of literal
//! match arms; everything serde's expansion takes from
//! `serde::__private` (semver-exempt, so off-limits here) is
//! replicated against public API in `litmask::__serde_support`.
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

    // Bound every type param with `Deserialize<'de>`, mirroring the
    // plain serde derive's bound model: `Envelope<T>` deserializes
    // iff `T: Deserialize<'de>`.
    let generics = with_trait_bounds(
        input.generics.clone(),
        &syn::parse_quote!(::litmask::__serde::Deserialize<'de>),
    );
    // The impl introduces `'de` ahead of the type's own params:
    // `impl<'de, T> Deserialize<'de> for Envelope<T>`.
    let mut de_generics = generics.clone();
    de_generics.params.insert(0, syn::parse_quote!('de));
    let (de_impl_generics, _, _) = de_generics.split_for_impl();
    let (_, ty_generics, where_clause) = generics.split_for_impl();

    Ok(quote! {
        #[automatically_derived]
        impl #de_impl_generics ::litmask::__serde::Deserialize<'de>
            for #struct_ident #ty_generics #where_clause
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
        _ => Err(compile_error(
            input.ident.span(),
            MACRO_NAME,
            FailTag::Grammar,
            "supports structs only (prototype)",
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

/// Per-field `let` statements for a `visit_seq` body: each pulls the
/// next element or fails with the plain derive's `invalid_length`
/// message (`"<shape> <Name> with N element(s)"`, composed at runtime
/// from the decrypted name).
fn seq_field_lets<'a>(
    bindings: &'a [syn::Ident],
    field_tys: &'a [&'a syn::Type],
    shape: &'a str,
    field_count: usize,
) -> impl Iterator<Item = TokenStream2> + 'a {
    bindings.iter().enumerate().map(move |(i, binding)| {
        let fty = field_tys[i];
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
                                count: #field_count,
                            },
                        ),
                    );
                }
            };
        }
    })
}

fn unit_struct_body(input: &DeriveInput) -> TokenStream2 {
    let struct_ident = &input.ident;
    let type_name = masked_name_expr(struct_ident);
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
        fn __litmask_type_name() -> &'static str {
            #type_name
        }

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
    let type_name = masked_name_expr(struct_ident);
    let field_tys: Vec<&syn::Type> = fields.unnamed.iter().map(|field| &field.ty).collect();
    let field_count = field_tys.len();
    let bindings: Vec<syn::Ident> = (0..field_count)
        .map(|i| quote::format_ident!("__field{i}"))
        .collect();

    let seq_lets = seq_field_lets(&bindings, &field_tys, "tuple struct", field_count);
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
        fn __litmask_type_name() -> &'static str {
            #type_name
        }

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

/// Emit the two name-resolution fns shared by every generated
/// visitor: `__litmask_type_name()` (decrypted container name) and
/// `__litmask_names()` (decrypted field or variant names, leaked once
/// as a `&'static [&'static str]` — the shape serde's
/// `deserialize_struct`/`deserialize_enum` and
/// `unknown_field`/`unknown_variant` require).
fn name_fns(container: &syn::Ident, name_idents: &[&syn::Ident]) -> TokenStream2 {
    let type_name = masked_name_expr(container);
    let decrypts = name_idents.iter().map(|ident| mask_ident(ident));
    quote! {
        fn __litmask_type_name() -> &'static str {
            #type_name
        }
        fn __litmask_names() -> &'static [&'static str] {
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

/// Generate the `__Field` identifier enum, its visitor, and its
/// `Deserialize` impl — the machinery `MapAccess::next_key` uses to
/// classify each incoming key. Mirrors serde's expansion with one
/// difference: the `visit_str`/`visit_bytes` arms compare against
/// decrypted names at runtime instead of literal match patterns.
/// Unknown keys fall through to `__ignore` (default serde behavior:
/// unknown fields are skipped, not errors).
fn field_identifier_block(field_count: usize) -> TokenStream2 {
    let variants: Vec<syn::Ident> = (0..field_count)
        .map(|i| quote::format_ident!("__field{i}"))
        .collect();
    let indices = 0..field_count as u64;
    let str_arms = variants.iter().enumerate().map(|(i, variant)| {
        quote! {
            if __value == __litmask_names()[#i] {
                return ::core::result::Result::Ok(__Field::#variant);
            }
        }
    });
    let bytes_arms = variants.iter().enumerate().map(|(i, variant)| {
        quote! {
            if __value == __litmask_names()[#i].as_bytes() {
                return ::core::result::Result::Ok(__Field::#variant);
            }
        }
    });
    quote! {
        #[allow(non_camel_case_types)]
        enum __Field {
            #(#variants,)*
            __ignore,
        }

        struct __FieldVisitor;

        #[automatically_derived]
        impl<'de> ::litmask::__serde::de::Visitor<'de> for __FieldVisitor {
            type Value = __Field;

            fn expecting(
                &self,
                __formatter: &mut ::core::fmt::Formatter,
            ) -> ::core::fmt::Result {
                ::core::fmt::Formatter::write_str(__formatter, "field identifier")
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
                    _ => ::core::result::Result::Ok(__Field::__ignore),
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
                ::core::result::Result::Ok(__Field::__ignore)
            }

            fn visit_bytes<__E>(
                self,
                __value: &[u8],
            ) -> ::core::result::Result<Self::Value, __E>
            where
                __E: ::litmask::__serde::de::Error,
            {
                #(#bytes_arms)*
                ::core::result::Result::Ok(__Field::__ignore)
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

fn named_struct_body(input: &DeriveInput, fields: &syn::FieldsNamed) -> TokenStream2 {
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

    let name_fns = name_fns(struct_ident, &field_idents);
    let field_identifier = field_identifier_block(field_count);

    let seq_lets = seq_field_lets(&bindings, &field_tys, "struct", field_count);

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
                            __litmask_names()[#i],
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
                    ::litmask::__serde_support::missing_field(__litmask_names()[#i])?
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
    let visitor = visitor_decl(input, &generics);
    let visitor_expr = visitor_expr();
    let DeGenerics {
        de_impl,
        de_ty,
        ty,
        where_clause,
    } = &generics;

    quote! {
        #name_fns
        #field_identifier

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
                ::core::write!(__formatter, "struct {}", __litmask_type_name())
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
                ::core::result::Result::Ok(#struct_ident {
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
                ::core::result::Result::Ok(#struct_ident {
                    #(#field_idents: #field_variants),*
                })
            }
        }

        ::litmask::__serde::Deserializer::deserialize_struct(
            __deserializer,
            __litmask_type_name(),
            __litmask_names(),
            #visitor_expr,
        )
    }
}
