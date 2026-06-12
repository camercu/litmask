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
        Data::Struct(data) if matches!(data.fields, Fields::Named(_)) => {
            fields_body(ident, &data.fields)
        }
        _ => {
            return Err(compile_error(
                ident.span(),
                MACRO_NAME,
                FailTag::Grammar,
                "supports structs with named fields only",
            ));
        }
    };

    let (impl_generics, ty_generics, where_clause) = input.generics.split_for_impl();
    Ok(quote! {
        #[automatically_derived]
        impl #impl_generics ::core::fmt::Debug for #ident #ty_generics #where_clause {
            fn fmt(&self, __f: &mut ::core::fmt::Formatter<'_>) -> ::core::fmt::Result {
                #body
            }
        }
    })
}

/// Build the `fmt` body for a struct's fields. The masked type name
/// goes through `debug_struct`, each field name through `.field` —
/// the same builders the plain derive expands to, so `{:?}` and
/// `{:#?}` render identically.
fn fields_body(ident: &syn::Ident, fields: &Fields) -> TokenStream2 {
    let name = masked_name_expr(ident.unraw().to_string(), ident.span());
    match fields {
        Fields::Named(named) => {
            let field_calls = named.named.iter().map(|field| {
                let ident = field.ident.as_ref().expect("named field has an ident");
                // `unraw` matches the plain derive: `r#type` renders
                // as `type`, without the raw-ident prefix.
                let name = masked_name_expr(ident.unraw().to_string(), ident.span());
                quote! { __builder.field(&#name, &self.#ident); }
            });
            quote! {
                let mut __builder = __f.debug_struct(&#name);
                #(#field_calls)*
                __builder.finish()
            }
        }
        Fields::Unnamed(_) | Fields::Unit => unreachable!("rejected by try_expand"),
    }
}

/// Emit an expression yielding the decrypted `name` as a `String`.
/// Decrypted fresh on every `fmt` call: the builder API borrows
/// `&str` only for the duration of the call, so nothing needs to be
/// cached or leaked.
fn masked_name_expr(name: String, span: proc_macro2::Span) -> TokenStream2 {
    mask_str(span, name.into_bytes())
}
