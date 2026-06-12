//! `#[derive(MaskDebug)]`: a `core::fmt::Debug` impl whose type and
//! field names are AEAD-masked at compile time.
//!
//! Plain `#[derive(Debug)]` embeds the type name and every field name
//! as cleartext `&'static str` data in `.rodata` via
//! `Formatter::debug_struct("Name")` / `.field("name", ...)`. This
//! derive routes each name through the same AEAD blob pipeline as
//! `mask!` and decrypts during formatting.
//!
//! Output contract: formatted output (`{:?}` and `{:#?}`) is
//! byte-identical to the plain derive. Unlike serde's
//! `serialize_struct`, the `Formatter` builder API takes `&str`, so
//! names are decrypted per `fmt` call and dropped afterwards — no
//! leak, no cache, no `std` dependency.

use proc_macro::TokenStream;
use proc_macro2::TokenStream as TokenStream2;
use quote::quote;
use syn::ext::IdentExt;
use syn::{Data, DeriveInput, Fields};

use crate::common::{FailTag, compile_error, mask_str};

const MACRO_NAME: &str = "MaskDebug";

/// Implementation of the `#[proc_macro_derive] MaskDebug` entry
/// point. Re-exported at the crate root via a one-line wrapper.
pub(crate) fn expand(input: TokenStream) -> TokenStream {
    let derive_input: DeriveInput = match syn::parse(input) {
        Ok(parsed) => parsed,
        Err(e) => return e.to_compile_error().into(),
    };
    match try_expand(&derive_input) {
        Ok(tokens) => tokens.into(),
        Err(e) => e.to_compile_error().into(),
    }
}

fn try_expand(input: &DeriveInput) -> syn::Result<TokenStream2> {
    let ident = &input.ident;
    let body = match &input.data {
        Data::Struct(data) => struct_body(ident, &data.fields),
        Data::Enum(data) => enum_body(data),
        Data::Union(_) => {
            return Err(compile_error(
                ident.span(),
                MACRO_NAME,
                FailTag::Grammar,
                "supports structs and enums only",
            ));
        }
    };

    let generics = with_debug_bounds(input.generics.clone());
    let (impl_generics, ty_generics, where_clause) = generics.split_for_impl();
    Ok(quote! {
        #[automatically_derived]
        impl #impl_generics ::core::fmt::Debug for #ident #ty_generics #where_clause {
            fn fmt(&self, __f: &mut ::core::fmt::Formatter<'_>) -> ::core::fmt::Result {
                #body
            }
        }
    })
}

/// Build the `fmt` body for a struct: field values are reached
/// through `self`.
fn struct_body(ident: &syn::Ident, fields: &Fields) -> TokenStream2 {
    let name = masked_name_expr(ident.unraw().to_string(), ident.span());
    let values: Vec<TokenStream2> = match fields {
        Fields::Named(named) => named
            .named
            .iter()
            .map(|field| {
                let ident = field.ident.as_ref().expect("named field has an ident");
                quote! { &self.#ident }
            })
            .collect(),
        Fields::Unnamed(unnamed) => (0..unnamed.unnamed.len())
            .map(|i| {
                let index = syn::Index::from(i);
                quote! { &self.#index }
            })
            .collect(),
        Fields::Unit => Vec::new(),
    };
    builder_body(&name, fields, &values)
}

/// Build the `fmt` body for an enum: one match arm per variant, each
/// formatting under the masked *variant* name — the plain derive
/// never prints the enum's own name.
fn enum_body(data: &syn::DataEnum) -> TokenStream2 {
    if data.variants.is_empty() {
        // An uninhabited enum has no arms; `match *self {}` is how the
        // plain derive proves exhaustiveness (`&Self` would not).
        return quote! { match *self {} };
    }
    let arms = data.variants.iter().map(|variant| {
        let vident = &variant.ident;
        let vname = masked_name_expr(vident.unraw().to_string(), vident.span());
        match &variant.fields {
            Fields::Named(named) => {
                let field_idents: Vec<&syn::Ident> = named
                    .named
                    .iter()
                    .map(|field| field.ident.as_ref().expect("named field has an ident"))
                    .collect();
                // Bindings are mangled, never the user's field idents:
                // a field named `__f` or `__builder` would otherwise
                // shadow the generated locals and break compilation.
                let bindings: Vec<syn::Ident> = (0..field_idents.len())
                    .map(|i| quote::format_ident!("__field{i}"))
                    .collect();
                let values: Vec<TokenStream2> = bindings.iter().map(|b| quote! { #b }).collect();
                let body = builder_body(&vname, &variant.fields, &values);
                quote! { Self::#vident { #(#field_idents: #bindings),* } => { #body } }
            }
            Fields::Unnamed(unnamed) => {
                let bindings: Vec<syn::Ident> = (0..unnamed.unnamed.len())
                    .map(|i| quote::format_ident!("__field{i}"))
                    .collect();
                let values: Vec<TokenStream2> = bindings.iter().map(|b| quote! { #b }).collect();
                let body = builder_body(&vname, &variant.fields, &values);
                quote! { Self::#vident(#(#bindings),*) => { #body } }
            }
            Fields::Unit => {
                let body = builder_body(&vname, &variant.fields, &[]);
                quote! { Self::#vident => { #body } }
            }
        }
    });
    quote! {
        match self {
            #(#arms)*
        }
    }
}

/// Emit the builder calls the plain derive expands to
/// (`debug_struct` / `debug_tuple` / `write_str`), with every name
/// routed through its masked expression — so `{:?}` and `{:#?}`
/// render identically to `#[derive(Debug)]`.
fn builder_body(name: &TokenStream2, fields: &Fields, values: &[TokenStream2]) -> TokenStream2 {
    match fields {
        Fields::Named(named) => {
            let field_calls = named.named.iter().zip(values).map(|(field, value)| {
                let ident = field.ident.as_ref().expect("named field has an ident");
                // `unraw` matches the plain derive: `r#type` renders
                // as `type`, without the raw-ident prefix.
                let field_name = masked_name_expr(ident.unraw().to_string(), ident.span());
                quote! { __builder.field(&#field_name, #value); }
            });
            quote! {
                let mut __builder = __f.debug_struct(&#name);
                #(#field_calls)*
                __builder.finish()
            }
        }
        Fields::Unnamed(_) => {
            let field_calls = values.iter().map(|value| {
                quote! { __builder.field(#value); }
            });
            quote! {
                let mut __builder = __f.debug_tuple(&#name);
                #(#field_calls)*
                __builder.finish()
            }
        }
        Fields::Unit => quote! { __f.write_str(&#name) },
    }
}

/// Bound every type parameter with `Debug`, mirroring the plain
/// derive's bound model: `struct Envelope<T>` is debuggable iff
/// `T: Debug`. Bounds land in the where-clause so the impl header
/// stays valid for params that already carry inline bounds.
fn with_debug_bounds(mut generics: syn::Generics) -> syn::Generics {
    let predicates: Vec<syn::WherePredicate> = generics
        .type_params()
        .map(|param| {
            let ident = &param.ident;
            syn::parse_quote!(#ident: ::core::fmt::Debug)
        })
        .collect();
    generics.make_where_clause().predicates.extend(predicates);
    generics
}

/// Emit an expression yielding the decrypted `name` as a `String`.
/// Decrypted fresh on every `fmt` call: the builder API borrows
/// `&str` only for the duration of the call, so nothing needs to be
/// cached or leaked.
fn masked_name_expr(name: String, span: proc_macro2::Span) -> TokenStream2 {
    mask_str(span, name.into_bytes())
}
