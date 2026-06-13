//! Parsing of the supported `#[serde(...)]` attribute subset for the
//! masking serde derives (`MaskSerialize` / `MaskDeserialize`,
//! `unstable-serde`).
//!
//! The masking derives must stay byte-identical to the plain serde
//! derives (§E.2.1/§E.2.6), so every honored attribute is parsed into a
//! typed model the codegen threads through; every attribute *not* yet
//! honored is rejected loud (`<macro>! invalid-arg`) rather than
//! silently ignored, which would change the wire format without warning.
//!
//! Supported so far: `rename` (and the `rename(serialize = ...,
//! deserialize = ...)` split form) on the container, variants, and
//! fields. Every other key is reject-loud and listed for a later slice.

use syn::ext::IdentExt;
use syn::meta::ParseNestedMeta;
use syn::spanned::Spanned;
use syn::{Attribute, Ident, LitStr};

use crate::common::{FailTag, compile_error};

/// A `rename`, possibly split into distinct serialize / deserialize
/// names. `rename = "x"` sets both; `rename(serialize = "s")` sets only
/// the serialize side (the deserialize side falls back to the ident).
#[derive(Default, Debug)]
pub(crate) struct Rename {
    pub(crate) serialize: Option<String>,
    pub(crate) deserialize: Option<String>,
}

impl Rename {
    fn both(name: String) -> Self {
        Self {
            serialize: Some(name.clone()),
            deserialize: Some(name),
        }
    }
}

/// Container-level (`struct` / `enum`) serde attributes.
#[derive(Default, Debug)]
pub(crate) struct ContainerAttrs {
    pub(crate) rename: Rename,
}

/// Field-level serde attributes.
#[derive(Default, Debug)]
pub(crate) struct FieldAttrs {
    pub(crate) rename: Rename,
}

/// Enum-variant-level serde attributes.
#[derive(Default, Debug)]
pub(crate) struct VariantAttrs {
    pub(crate) rename: Rename,
}

/// Resolve the serialize-side name for `ident` under `rename`.
fn serialize_name(rename: &Rename, ident: &Ident) -> String {
    rename
        .serialize
        .clone()
        .unwrap_or_else(|| ident.unraw().to_string())
}

/// Resolve the deserialize-side name for `ident` under `rename`.
fn deserialize_name(rename: &Rename, ident: &Ident) -> String {
    rename
        .deserialize
        .clone()
        .unwrap_or_else(|| ident.unraw().to_string())
}

impl ContainerAttrs {
    pub(crate) fn serialize_name(&self, ident: &Ident) -> String {
        serialize_name(&self.rename, ident)
    }
    pub(crate) fn deserialize_name(&self, ident: &Ident) -> String {
        deserialize_name(&self.rename, ident)
    }
}

impl FieldAttrs {
    pub(crate) fn serialize_name(&self, ident: &Ident) -> String {
        serialize_name(&self.rename, ident)
    }
    pub(crate) fn deserialize_name(&self, ident: &Ident) -> String {
        deserialize_name(&self.rename, ident)
    }
}

impl VariantAttrs {
    pub(crate) fn serialize_name(&self, ident: &Ident) -> String {
        serialize_name(&self.rename, ident)
    }
    pub(crate) fn deserialize_name(&self, ident: &Ident) -> String {
        deserialize_name(&self.rename, ident)
    }
}

/// Parse the container's `#[serde(...)]` attributes.
pub(crate) fn parse_container(
    macro_name: &str,
    attrs: &[Attribute],
) -> syn::Result<ContainerAttrs> {
    let mut out = ContainerAttrs::default();
    parse_serde(attrs, |meta| {
        if meta.path.is_ident("rename") {
            out.rename = parse_rename(&meta)?;
            Ok(())
        } else {
            Err(unsupported(macro_name, &meta))
        }
    })?;
    Ok(out)
}

/// Parse a field's `#[serde(...)]` attributes.
pub(crate) fn parse_field(macro_name: &str, attrs: &[Attribute]) -> syn::Result<FieldAttrs> {
    let mut out = FieldAttrs::default();
    parse_serde(attrs, |meta| {
        if meta.path.is_ident("rename") {
            out.rename = parse_rename(&meta)?;
            Ok(())
        } else {
            Err(unsupported(macro_name, &meta))
        }
    })?;
    Ok(out)
}

/// Parse an enum variant's `#[serde(...)]` attributes.
pub(crate) fn parse_variant(macro_name: &str, attrs: &[Attribute]) -> syn::Result<VariantAttrs> {
    let mut out = VariantAttrs::default();
    parse_serde(attrs, |meta| {
        if meta.path.is_ident("rename") {
            out.rename = parse_rename(&meta)?;
            Ok(())
        } else {
            Err(unsupported(macro_name, &meta))
        }
    })?;
    Ok(out)
}

/// Run `f` over every nested meta item of every `#[serde(...)]`
/// attribute in `attrs`.
fn parse_serde<F>(attrs: &[Attribute], mut f: F) -> syn::Result<()>
where
    F: FnMut(ParseNestedMeta) -> syn::Result<()>,
{
    for attr in attrs {
        if attr.path().is_ident("serde") {
            attr.parse_nested_meta(&mut f)?;
        }
    }
    Ok(())
}

/// Parse `rename = "x"` or `rename(serialize = "s", deserialize = "d")`.
fn parse_rename(meta: &ParseNestedMeta) -> syn::Result<Rename> {
    if meta.input.peek(syn::Token![=]) {
        let lit: LitStr = meta.value()?.parse()?;
        return Ok(Rename::both(lit.value()));
    }
    let mut rename = Rename::default();
    meta.parse_nested_meta(|inner| {
        if inner.path.is_ident("serialize") {
            rename.serialize = Some(inner.value()?.parse::<LitStr>()?.value());
        } else if inner.path.is_ident("deserialize") {
            rename.deserialize = Some(inner.value()?.parse::<LitStr>()?.value());
        } else {
            return Err(inner.error("expected `serialize` or `deserialize`"));
        }
        Ok(())
    })?;
    Ok(rename)
}

/// Reject-loud error for a `#[serde(...)]` key not yet honored by the
/// masking derives: silently ignoring it would diverge from the plain
/// derive's wire format (§E.2.1/§E.2.6).
fn unsupported(macro_name: &str, meta: &ParseNestedMeta) -> syn::Error {
    let key = meta
        .path
        .get_ident()
        .map_or_else(|| "?".to_string(), ToString::to_string);
    compile_error(
        meta.path.span(),
        macro_name,
        FailTag::InvalidArg,
        &format!(
            "`#[serde({key})]` is not yet supported; keep a plain derive \
             (or `#[unmasked_derive]` under `#[mask_all]`)"
        ),
    )
}

#[cfg(test)]
mod tests {
    use super::*;
    use quote::quote;

    fn field(src: &proc_macro2::TokenStream) -> syn::Field {
        let di: syn::DeriveInput =
            syn::parse2(quote! { struct S { #src } }).expect("fixture parses");
        let syn::Data::Struct(data) = di.data else {
            unreachable!()
        };
        data.fields.into_iter().next().expect("one field")
    }

    #[test]
    fn rename_simple_sets_both_sides() {
        let f = field(&quote! { #[serde(rename = "url")] endpoint: String });
        let attrs = parse_field("MaskSerialize", &f.attrs).expect("parses");
        let ident = f.ident.as_ref().unwrap();
        assert_eq!(attrs.serialize_name(ident), "url");
        assert_eq!(attrs.deserialize_name(ident), "url");
    }

    #[test]
    fn rename_split_sets_each_side() {
        let f = field(
            &quote! { #[serde(rename(serialize = "ser", deserialize = "de"))] endpoint: String },
        );
        let attrs = parse_field("MaskSerialize", &f.attrs).expect("parses");
        let ident = f.ident.as_ref().unwrap();
        assert_eq!(attrs.serialize_name(ident), "ser");
        assert_eq!(attrs.deserialize_name(ident), "de");
    }

    #[test]
    fn no_rename_falls_back_to_ident() {
        let f = field(&quote! { endpoint: String });
        let attrs = parse_field("MaskSerialize", &f.attrs).expect("parses");
        let ident = f.ident.as_ref().unwrap();
        assert_eq!(attrs.serialize_name(ident), "endpoint");
        assert_eq!(attrs.deserialize_name(ident), "endpoint");
    }

    #[test]
    fn unsupported_key_is_reject_loud() {
        let f = field(&quote! { #[serde(flatten)] inner: String });
        let err = parse_field("MaskSerialize", &f.attrs).expect_err("must reject");
        let msg = err.to_string();
        assert!(msg.contains("MaskSerialize! invalid-arg"), "got: {msg}");
        assert!(msg.contains("`#[serde(flatten)]`"), "got: {msg}");
    }
}
