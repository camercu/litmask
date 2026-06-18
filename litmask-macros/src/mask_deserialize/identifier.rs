//! The `__Field` identifier machinery for the `MaskDeserialize`
//! expansion: the enum + visitor + `Deserialize` impl that
//! `MapAccess::next_key` / `EnumAccess::variant` use to classify each
//! incoming key or tag against runtime-decrypted names, plus the masked
//! name-list / type-name emitters those visitors call. Pure
//! tokens-in/tokens-out — no dependency on the body builders.

use proc_macro2::TokenStream as TokenStream2;
use quote::quote;
use syn::Ident;

use crate::common::{mask_name, masked_static_name};

/// Emit `fn __litmask_type_name() -> &'static str` for the container,
/// masking its resolved (post-`rename`) deserialize name.
pub(super) fn type_name_fn(name: &(proc_macro2::Span, String)) -> TokenStream2 {
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
pub(super) fn names_list_fn(
    fn_ident: &Ident,
    names: &[(proc_macro2::Span, String)],
) -> TokenStream2 {
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
pub(super) enum IdentifierKind {
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
    names_fn: &Ident,
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
pub(super) struct AliasMatch {
    pub(super) names_fn: Ident,
    pub(super) entries: Vec<(usize, usize)>,
}

/// Assemble the masked alias-name function plus the [`AliasMatch`] from a
/// sequence of `(target index, name span, aliases)` groups, where the
/// target index is the `__Field` variant each group's aliases resolve to
/// (a field's slot among the non-skipped fields, or a variant's
/// declaration-order index). Shared by the field- and variant-alias
/// builders; returns `(empty tokens, None)` when no aliases exist.
pub(super) fn build_alias_match<'a>(
    names_fn: &Ident,
    groups: impl IntoIterator<Item = (usize, proc_macro2::Span, &'a [String])>,
) -> (TokenStream2, Option<AliasMatch>) {
    let mut flat: Vec<(proc_macro2::Span, String)> = Vec::new();
    let mut entries: Vec<(usize, usize)> = Vec::new();
    for (target, span, aliases) in groups {
        for alias in aliases {
            entries.push((target, flat.len()));
            flat.push((span, alias.clone()));
        }
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

/// Build the `visit_str` / `visit_bytes` comparison arms for an
/// identifier visitor: one per primary name, plus one per
/// `#[serde(alias)]` mapping back to its field's variant.
fn identifier_match_arms(
    names_fn: &Ident,
    variants: &[Ident],
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
pub(super) fn identifier_block(
    names_fn: &Ident,
    count: usize,
    kind: &IdentifierKind,
    aliases: Option<&AliasMatch>,
    deny_unknown: bool,
) -> TokenStream2 {
    let variants: Vec<Ident> = (0..count)
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
