//! Codegen helpers shared by the masking derives (`MaskDebug`,
//! `MaskSerialize`, `MaskDeserialize`): the `#[proc_macro_derive]` entry
//! shim, where-clause bound application, and the `#[serde(transparent)]`
//! single-field extraction. These serve only the derives, so they live
//! apart from the universal `common` utilities every macro imports.

use proc_macro2::TokenStream;
#[cfg(feature = "serde")]
use quote::quote;

#[cfg(feature = "serde")]
use crate::common::{FailTag, compile_error};

/// Shared `#[proc_macro_derive]` entry shim: parse the input as
/// `DeriveInput`, run `try_expand`, lower errors via
/// `to_compile_error`. Single owner of the derive error-handling
/// idiom, so span or diagnostic changes land in every derive at once.
pub(crate) fn expand_derive(
    input: proc_macro::TokenStream,
    try_expand: impl FnOnce(&syn::DeriveInput) -> syn::Result<TokenStream>,
) -> proc_macro::TokenStream {
    let derive_input: syn::DeriveInput = match syn::parse(input) {
        Ok(parsed) => parsed,
        Err(e) => return e.to_compile_error().into(),
    };
    match try_expand(&derive_input) {
        Ok(tokens) => tokens.into(),
        Err(e) => e.to_compile_error().into(),
    }
}

/// Bound every type parameter with `bound`, mirroring the plain
/// derives' bound model: `struct Envelope<T>` gets the impl iff
/// `T: Bound`. Bounds land in the where-clause so the impl header
/// stays valid for params that already carry inline bounds.
pub(crate) fn with_trait_bounds(mut generics: syn::Generics, bound: &syn::Path) -> syn::Generics {
    let predicates: Vec<syn::WherePredicate> = generics
        .type_params()
        .map(|param| {
            let ident = &param.ident;
            syn::parse_quote!(#ident: #bound)
        })
        .collect();
    generics.make_where_clause().predicates.extend(predicates);
    generics
}

/// The single contained field of a `#[serde(transparent)]` struct: how
/// to access it on `self` (`#access` in `self.#access`), its type (for
/// the delegating deserialize), and its ident when the struct is named.
#[cfg(feature = "serde")]
pub(crate) struct TransparentField<'a> {
    pub(crate) access: TokenStream,
    pub(crate) ty: &'a syn::Type,
    pub(crate) named_ident: Option<&'a syn::Ident>,
}

/// Validate and extract the single field of a `#[serde(transparent)]`
/// struct. Errors loud if the input is not a struct with exactly one
/// field (the shape serde's `transparent` requires).
#[cfg(feature = "serde")]
pub(crate) fn transparent_field<'a>(
    input: &'a syn::DeriveInput,
    macro_name: &str,
) -> syn::Result<TransparentField<'a>> {
    let reject = || {
        compile_error(
            input.ident.span(),
            macro_name,
            FailTag::InvalidArg,
            "`#[serde(transparent)]` requires a struct with exactly one field",
        )
    };
    let syn::Data::Struct(data) = &input.data else {
        return Err(reject());
    };
    match &data.fields {
        syn::Fields::Named(fields) if fields.named.len() == 1 => {
            let field = &fields.named[0];
            let ident = field.ident.as_ref().expect("named field has an ident");
            Ok(TransparentField {
                access: quote! { #ident },
                ty: &field.ty,
                named_ident: Some(ident),
            })
        }
        syn::Fields::Unnamed(fields) if fields.unnamed.len() == 1 => Ok(TransparentField {
            access: quote! { 0 },
            ty: &fields.unnamed[0].ty,
            named_ident: None,
        }),
        _ => Err(reject()),
    }
}

/// Apply trait bounds to `generics`: with no `#[serde(bound = "...")]`
/// override, fall back to [`with_trait_bounds`] (the default per-param
/// `T: Bound`); with an override, add exactly the user's predicates and
/// skip the default — matching serde's `bound` semantics.
#[cfg(feature = "serde")]
pub(crate) fn apply_bounds(
    generics: syn::Generics,
    default_bound: &syn::Path,
    custom: Option<&[syn::WherePredicate]>,
) -> syn::Generics {
    match custom {
        Some(predicates) => {
            let mut generics = generics;
            generics
                .make_where_clause()
                .predicates
                .extend(predicates.iter().cloned());
            generics
        }
        None => with_trait_bounds(generics, default_bound),
    }
}
