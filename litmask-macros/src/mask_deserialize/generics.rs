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

#[cfg(test)]
mod tests {
    use super::*;
    use syn::parse_quote;

    fn ty(t: syn::Type) -> syn::Type {
        t
    }

    #[test]
    fn is_str_only_matches_the_bare_str_path() {
        assert!(is_str(&ty(parse_quote!(str))));
        // A single-segment `str` ident only — `String` and any qualified
        // path are not the borrow-eligible `str`.
        assert!(!is_str(&ty(parse_quote!(String))));
        assert!(!is_str(&ty(parse_quote!(std::primitive::str))));
    }

    #[test]
    fn is_slice_u8_matches_only_the_u8_slice() {
        assert!(is_slice_u8(&ty(parse_quote!([u8]))));
        assert!(!is_slice_u8(&ty(parse_quote!([u16]))));
        // A non-slice type must fall through the `_ => false` arm.
        assert!(!is_slice_u8(&ty(parse_quote!(str))));
    }

    #[test]
    fn option_inner_unwraps_single_segment_option_only() {
        // `Option<T>` (one segment, one type arg) yields `T`.
        let option_i32: syn::Type = parse_quote!(Option<i32>);
        let inner = option_inner(&option_i32).expect("Option<i32> unwraps");
        assert_eq!(quote!(#inner).to_string(), "i32");

        // Not an `Option` ident → no unwrap.
        assert!(option_inner(&ty(parse_quote!(Vec<i32>))).is_none());
        // Serde's rule is syntactic and un-qualified: a multi-segment
        // `std::option::Option<T>` is deliberately not recognised.
        assert!(option_inner(&ty(parse_quote!(std::option::Option<i32>))).is_none());
        // A bare `Option` with no angle-bracketed args is not `Option<T>`.
        assert!(option_inner(&ty(parse_quote!(Option))).is_none());
        // An inherent-qualified `<Foo>::Option<i32>` keeps a single
        // `Option<i32>` path segment but carries a qself, so it is not the
        // plain `Option<T>` serde borrows through — the `qself.is_some()`
        // guard (not the segment-count guard) is what must reject it.
        assert!(option_inner(&ty(parse_quote!(<Foo>::Option<i32>))).is_none());
    }

    #[test]
    fn implicitly_borrowed_reference_matches_serde_borrow_shapes() {
        // The `is_str || is_slice_u8` disjunction: `&str` borrows via the
        // str arm even though it is not a `&[u8]`.
        assert!(implicitly_borrowed_reference(&ty(parse_quote!(&str))).is_some());
        assert!(implicitly_borrowed_reference(&ty(parse_quote!(&[u8]))).is_some());
        // `Option`-wrapped, one level of recursion.
        assert!(implicitly_borrowed_reference(&ty(parse_quote!(Option<&str>))).is_some());
        // A reference to anything else does not implicitly borrow.
        assert!(implicitly_borrowed_reference(&ty(parse_quote!(&i32))).is_none());
        assert!(implicitly_borrowed_reference(&ty(parse_quote!(i32))).is_none());
    }

    #[test]
    fn borrowed_lifetimes_collects_only_borrowing_field_lifetimes() {
        let borrowing: DeriveInput = parse_quote! {
            struct S<'a> { name: &'a str, count: i32 }
        };
        let lifetimes = borrowed_lifetimes(&borrowing);
        assert_eq!(lifetimes.len(), 1, "only the &'a str field borrows");
        assert_eq!(lifetimes[0].to_string(), "'a");

        // No borrow-eligible field → no lifetimes.
        let owned: DeriveInput = parse_quote! {
            struct T<'a> { owned: String, marker: core::marker::PhantomData<&'a ()> }
        };
        assert!(borrowed_lifetimes(&owned).is_empty());
    }

    #[test]
    fn visitor_expr_and_decl_emit_the_visitor_carrier() {
        assert!(visitor_expr().to_string().contains("__Visitor"));

        let input: DeriveInput = parse_quote!(
            struct Foo {
                x: i32,
            }
        );
        let container = ContainerAttrs::default();
        let generics = split_de_generics(&input, &container);
        let decl = visitor_decl(&input, &generics).to_string();
        assert!(
            decl.contains("struct __Visitor"),
            "decl declares the carrier: {decl}"
        );
        assert!(
            decl.contains("PhantomData"),
            "decl pins the type + lifetime: {decl}"
        );
    }
}
