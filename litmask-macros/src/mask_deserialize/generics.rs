//! Generic-parameter plumbing for the `MaskDeserialize` expansion: the
//! `'de`-threaded generics fragments every generated visitor needs, the
//! serde implicit-borrow lifetime analysis, and the `__Visitor` carrier
//! declaration. Self-contained — depends only on the parsed input and
//! the shared bound/attr helpers, never on the visitor or body builders.

use proc_macro2::TokenStream as TokenStream2;
use quote::quote;
use syn::{Data, DeriveInput};

use crate::derive_support::apply_bounds;
use crate::serde_attrs::ContainerAttrs;

/// The four generics fragments every generated visitor needs, with
/// the `'de` lifetime threaded ahead of the type's own params and
/// each type param bounded `Deserialize<'de>` (the plain derive's
/// bound model). Token streams rather than `syn` borrows so body
/// builders can own them without lifetime plumbing.
pub(super) struct DeGenerics {
    /// `<'de, T>` — impl-position generics including `'de`.
    pub(super) de_impl: TokenStream2,
    /// `<'de, T>` — type-position generics for `__Visitor`.
    pub(super) de_ty: TokenStream2,
    /// `<T>` — the input type's own type-position generics.
    pub(super) ty: TokenStream2,
    /// `where T: Deserialize<'de>` (empty when no type params).
    pub(super) where_clause: TokenStream2,
}

pub(super) fn split_de_generics(input: &DeriveInput, container: &ContainerAttrs) -> DeGenerics {
    // A `#[serde(bound)]` override replaces the default `T:
    // Deserialize<'de>` predicate; otherwise each type param is bounded
    // `Deserialize<'de>` (the plain derive's model). The container is
    // parsed once at the entry point and threaded in, so every generated
    // visitor reads the same bound without re-parsing.
    let generics = apply_bounds(
        input.generics.clone(),
        &syn::parse_quote!(::litmask::__serde::Deserialize<'de>),
        container.bound.deserialize.as_deref(),
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
pub(super) fn visitor_decl(input: &DeriveInput, generics: &DeGenerics) -> TokenStream2 {
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

pub(super) fn visitor_expr() -> TokenStream2 {
    quote! {
        __Visitor {
            marker: ::core::marker::PhantomData,
            lifetime: ::core::marker::PhantomData,
        }
    }
}
