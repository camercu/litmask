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
use syn::{Data, DeriveInput, Fields};

use crate::common::{FailTag, compile_error, expand_derive, mask_ident, with_trait_bounds};

const MACRO_NAME: &str = "MaskDebug";

/// Implementation of the `#[proc_macro_derive] MaskDebug` entry
/// point. Re-exported at the crate root via a one-line wrapper.
pub(crate) fn expand(input: TokenStream) -> TokenStream {
    expand_derive(input, try_expand)
}

fn try_expand(input: &DeriveInput) -> syn::Result<TokenStream2> {
    let ident = &input.ident;
    let body = match &input.data {
        Data::Struct(data) => struct_body(ident, &data.fields, is_packed(input)),
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

    // Bound every type param with `Debug`, mirroring the plain
    // derive's bound model: `Envelope<T>` is debuggable iff `T: Debug`.
    let generics = with_trait_bounds(
        input.generics.clone(),
        &syn::parse_quote!(::core::fmt::Debug),
    );
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
/// through `self`. Packed fields are unaligned, so referencing them
/// is rejected (E0793); `&{ ... }` references an aligned copy instead,
/// matching the plain derive (which likewise requires `Copy` fields).
fn struct_body(ident: &syn::Ident, fields: &Fields, packed: bool) -> TokenStream2 {
    let name = mask_ident(ident);
    let shape = BuilderFields::collect(fields, |i, field| {
        let access = if let Some(field_ident) = &field.ident {
            quote! { self.#field_ident }
        } else {
            let index = syn::Index::from(i);
            quote! { self.#index }
        };
        if packed {
            quote! { &{ #access } }
        } else {
            quote! { &#access }
        }
    });
    builder_body(&name, &shape)
}

/// Whether any `#[repr(...)]` attribute carries `packed` /
/// `packed(N)`. Unparsable repr contents are someone else's error to
/// report — treat them as not packed.
fn is_packed(input: &DeriveInput) -> bool {
    let mut packed = false;
    for attr in input.attrs.iter().filter(|a| a.path().is_ident("repr")) {
        let _ = attr.parse_nested_meta(|meta| {
            if meta.path.is_ident("packed") {
                packed = true;
            }
            if meta.input.peek(syn::token::Paren) {
                let content;
                syn::parenthesized!(content in meta.input);
                let _: TokenStream2 = content.parse()?;
            }
            Ok(())
        });
    }
    packed
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
        let vname = mask_ident(vident);
        // Bindings are mangled, never the user's field idents: a
        // field named `__f` or `__builder` would otherwise shadow the
        // generated locals and break compilation.
        let bindings: Vec<syn::Ident> = (0..variant.fields.len())
            .map(|i| quote::format_ident!("__field{i}"))
            .collect();
        let shape = BuilderFields::collect(&variant.fields, |i, _| {
            let binding = &bindings[i];
            quote! { #binding }
        });
        let body = builder_body(&vname, &shape);
        let pattern = match &variant.fields {
            Fields::Named(named) => {
                let field_idents = named
                    .named
                    .iter()
                    .map(|field| field.ident.as_ref().expect("named field has an ident"));
                quote! { { #(#field_idents: #bindings),* } }
            }
            Fields::Unnamed(_) => quote! { ( #(#bindings),* ) },
            Fields::Unit => quote! {},
        };
        quote! { Self::#vident #pattern => { #body } }
    });
    quote! {
        match self {
            #(#arms)*
        }
    }
}

/// A variant or struct body's fields, each value expression
/// pre-paired with its masked field name. Pairing at construction
/// (rather than zipping parallel slices later) makes a name/value
/// desync unrepresentable — a future field filter (e.g. a `skip`
/// attribute) cannot silently drop trailing fields.
enum BuilderFields {
    Named(Vec<(TokenStream2, TokenStream2)>),
    Tuple(Vec<TokenStream2>),
    Unit,
}

impl BuilderFields {
    /// Walk `fields` once, rendering each field's value via
    /// `value_of` — the only per-caller difference between struct
    /// bodies (`self.x` access) and enum arms (match bindings).
    fn collect(fields: &Fields, value_of: impl Fn(usize, &syn::Field) -> TokenStream2) -> Self {
        match fields {
            Fields::Named(named) => Self::Named(
                named
                    .named
                    .iter()
                    .enumerate()
                    .map(|(i, field)| {
                        let ident = field.ident.as_ref().expect("named field has an ident");
                        (mask_ident(ident), value_of(i, field))
                    })
                    .collect(),
            ),
            Fields::Unnamed(unnamed) => Self::Tuple(
                unnamed
                    .unnamed
                    .iter()
                    .enumerate()
                    .map(|(i, field)| value_of(i, field))
                    .collect(),
            ),
            Fields::Unit => Self::Unit,
        }
    }
}

/// Emit the builder calls the plain derive expands to
/// (`debug_struct` / `debug_tuple` / `write_str`), with every name
/// routed through its masked expression — so `{:?}` and `{:#?}`
/// render identically to `#[derive(Debug)]`.
fn builder_body(name: &TokenStream2, fields: &BuilderFields) -> TokenStream2 {
    match fields {
        BuilderFields::Named(pairs) => {
            let field_calls = pairs.iter().map(|(field_name, value)| {
                quote! { __builder.field(&#field_name, #value); }
            });
            quote! {
                let mut __builder = __f.debug_struct(&#name);
                #(#field_calls)*
                __builder.finish()
            }
        }
        BuilderFields::Tuple(values) => {
            let field_calls = values.iter().map(|value| {
                quote! { __builder.field(#value); }
            });
            quote! {
                let mut __builder = __f.debug_tuple(&#name);
                #(#field_calls)*
                __builder.finish()
            }
        }
        BuilderFields::Unit => quote! { __f.write_str(&#name) },
    }
}
