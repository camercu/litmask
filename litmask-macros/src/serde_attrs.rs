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
//! Supported so far: `rename` and `rename_all` (each with the
//! `(serialize = ..., deserialize = ...)` split form) on the container,
//! variants, and fields as serde allows, plus `skip` /
//! `skip_serializing` / `skip_deserializing` / `skip_serializing_if` on
//! named fields. Every other key is reject-loud and listed for a later
//! slice.

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

/// serde's `rename_all` case conventions. The transforms are ported to
/// match serde byte-for-byte — the wire-identity contract (§E.2.1/
/// §E.2.6) depends on it, and the case-matrix twin test pins parity
/// against the real serde derive.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum RenameRule {
    Lower,
    Upper,
    Pascal,
    Camel,
    Snake,
    ScreamingSnake,
    Kebab,
    ScreamingKebab,
}

impl RenameRule {
    fn parse(name: &str) -> Option<Self> {
        Some(match name {
            "lowercase" => Self::Lower,
            "UPPERCASE" => Self::Upper,
            "PascalCase" => Self::Pascal,
            "camelCase" => Self::Camel,
            "snake_case" => Self::Snake,
            "SCREAMING_SNAKE_CASE" => Self::ScreamingSnake,
            "kebab-case" => Self::Kebab,
            "SCREAMING-KEBAB-CASE" => Self::ScreamingKebab,
            _ => return None,
        })
    }

    /// Apply to a field name (serde assumes a `snake_case` source).
    fn apply_to_field(self, field: &str) -> String {
        match self {
            Self::Lower | Self::Snake => field.to_owned(),
            Self::Upper | Self::ScreamingSnake => field.to_ascii_uppercase(),
            Self::Pascal => {
                let mut pascal = String::new();
                let mut capitalize = true;
                for ch in field.chars() {
                    if ch == '_' {
                        capitalize = true;
                    } else if capitalize {
                        pascal.push(ch.to_ascii_uppercase());
                        capitalize = false;
                    } else {
                        pascal.push(ch);
                    }
                }
                pascal
            }
            Self::Camel => {
                let pascal = Self::Pascal.apply_to_field(field);
                pascal[..1].to_ascii_lowercase() + &pascal[1..]
            }
            Self::Kebab => field.replace('_', "-"),
            Self::ScreamingKebab => Self::ScreamingSnake.apply_to_field(field).replace('_', "-"),
        }
    }

    /// Apply to a variant name (serde assumes a `PascalCase` source).
    fn apply_to_variant(self, variant: &str) -> String {
        match self {
            Self::Pascal => variant.to_owned(),
            Self::Lower => variant.to_ascii_lowercase(),
            Self::Upper => variant.to_ascii_uppercase(),
            Self::Camel => variant[..1].to_ascii_lowercase() + &variant[1..],
            Self::Snake => {
                let mut snake = String::new();
                for (i, ch) in variant.char_indices() {
                    if i > 0 && ch.is_uppercase() {
                        snake.push('_');
                    }
                    snake.push(ch.to_ascii_lowercase());
                }
                snake
            }
            Self::ScreamingSnake => Self::Snake.apply_to_variant(variant).to_ascii_uppercase(),
            Self::Kebab => Self::Snake.apply_to_variant(variant).replace('_', "-"),
            Self::ScreamingKebab => Self::ScreamingSnake
                .apply_to_variant(variant)
                .replace('_', "-"),
        }
    }
}

/// A `rename_all`, possibly split into distinct serialize / deserialize
/// rules. Applies to a container's children (struct fields, enum
/// variants) or a variant's own fields.
#[derive(Default, Debug)]
pub(crate) struct RenameAll {
    pub(crate) serialize: Option<RenameRule>,
    pub(crate) deserialize: Option<RenameRule>,
}

/// Container-level (`struct` / `enum`) serde attributes.
#[derive(Default, Debug)]
pub(crate) struct ContainerAttrs {
    pub(crate) rename: Rename,
    pub(crate) rename_all: RenameAll,
}

/// Field-level serde attributes.
#[derive(Default)]
pub(crate) struct FieldAttrs {
    pub(crate) rename: Rename,
    /// `#[serde(skip_serializing)]` (or `skip`): omit from the
    /// serialized output and from the serialize field count.
    pub(crate) skip_serializing: bool,
    /// `#[serde(skip_deserializing)]` (or `skip`): never read from the
    /// input; the field is filled with `Default::default()` instead.
    pub(crate) skip_deserializing: bool,
    /// `#[serde(skip_serializing_if = "path")]`: a predicate called with
    /// `&field` at serialize time; when it returns `true` the field is
    /// omitted and the struct length shrinks by one.
    pub(crate) skip_serializing_if: Option<syn::Path>,
}

impl FieldAttrs {
    /// True when a `skip` flag or `skip_serializing_if` is set — used to
    /// reject-loud on shapes the masking derives don't yet support skip
    /// on (tuple fields), where silently honoring it would shift element
    /// indices and diverge from serde.
    pub(crate) fn skips_a_tuple_field(&self) -> bool {
        self.skip_serializing || self.skip_deserializing || self.skip_serializing_if.is_some()
    }
}

/// Enum-variant-level serde attributes.
#[derive(Default, Debug)]
pub(crate) struct VariantAttrs {
    pub(crate) rename: Rename,
    pub(crate) rename_all: RenameAll,
}

impl ContainerAttrs {
    /// The container's own type name (only `rename` applies — a
    /// container's `rename_all` governs its children, not itself).
    pub(crate) fn serialize_name(&self, ident: &Ident) -> String {
        self.rename
            .serialize
            .clone()
            .unwrap_or_else(|| ident.unraw().to_string())
    }
    pub(crate) fn deserialize_name(&self, ident: &Ident) -> String {
        self.rename
            .deserialize
            .clone()
            .unwrap_or_else(|| ident.unraw().to_string())
    }
}

impl FieldAttrs {
    /// Resolve a field's serialize-side name: an explicit field
    /// `rename` wins; otherwise the parent `rename_all` rule (if any)
    /// is applied to the ident, mirroring serde's precedence.
    pub(crate) fn serialize_name(&self, ident: &Ident, parent: Option<RenameRule>) -> String {
        resolve_field_name(self.rename.serialize.as_deref(), ident, parent)
    }
    pub(crate) fn deserialize_name(&self, ident: &Ident, parent: Option<RenameRule>) -> String {
        resolve_field_name(self.rename.deserialize.as_deref(), ident, parent)
    }
}

impl VariantAttrs {
    /// Resolve a variant's serialize-side name: an explicit variant
    /// `rename` wins; otherwise the container's `rename_all` rule (if
    /// any) is applied to the variant ident.
    pub(crate) fn serialize_name(&self, ident: &Ident, parent: Option<RenameRule>) -> String {
        resolve_variant_name(self.rename.serialize.as_deref(), ident, parent)
    }
    pub(crate) fn deserialize_name(&self, ident: &Ident, parent: Option<RenameRule>) -> String {
        resolve_variant_name(self.rename.deserialize.as_deref(), ident, parent)
    }
}

fn resolve_field_name(rename: Option<&str>, ident: &Ident, parent: Option<RenameRule>) -> String {
    if let Some(name) = rename {
        return name.to_owned();
    }
    let base = ident.unraw().to_string();
    match parent {
        Some(rule) => rule.apply_to_field(&base),
        None => base,
    }
}

fn resolve_variant_name(rename: Option<&str>, ident: &Ident, parent: Option<RenameRule>) -> String {
    if let Some(name) = rename {
        return name.to_owned();
    }
    let base = ident.unraw().to_string();
    match parent {
        Some(rule) => rule.apply_to_variant(&base),
        None => base,
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
        } else if meta.path.is_ident("rename_all") {
            out.rename_all = parse_rename_all(macro_name, &meta)?;
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
        } else if meta.path.is_ident("skip") {
            out.skip_serializing = true;
            out.skip_deserializing = true;
            Ok(())
        } else if meta.path.is_ident("skip_serializing") {
            out.skip_serializing = true;
            Ok(())
        } else if meta.path.is_ident("skip_deserializing") {
            out.skip_deserializing = true;
            Ok(())
        } else if meta.path.is_ident("skip_serializing_if") {
            let lit: LitStr = meta.value()?.parse()?;
            out.skip_serializing_if = Some(lit.parse()?);
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
        } else if meta.path.is_ident("rename_all") {
            out.rename_all = parse_rename_all(macro_name, &meta)?;
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

/// Parse `rename_all = "case"` or `rename_all(serialize = "...",
/// deserialize = "...")`.
fn parse_rename_all(macro_name: &str, meta: &ParseNestedMeta) -> syn::Result<RenameAll> {
    if meta.input.peek(syn::Token![=]) {
        let lit: LitStr = meta.value()?.parse()?;
        let rule = rule_from_lit(macro_name, &lit)?;
        return Ok(RenameAll {
            serialize: Some(rule),
            deserialize: Some(rule),
        });
    }
    let mut rename_all = RenameAll::default();
    meta.parse_nested_meta(|inner| {
        if inner.path.is_ident("serialize") {
            let lit: LitStr = inner.value()?.parse()?;
            rename_all.serialize = Some(rule_from_lit(macro_name, &lit)?);
        } else if inner.path.is_ident("deserialize") {
            let lit: LitStr = inner.value()?.parse()?;
            rename_all.deserialize = Some(rule_from_lit(macro_name, &lit)?);
        } else {
            return Err(inner.error("expected `serialize` or `deserialize`"));
        }
        Ok(())
    })?;
    Ok(rename_all)
}

/// Map a `rename_all` rule literal to a [`RenameRule`], or reject-loud
/// with the unknown-rule diagnostic (matching serde's accepted set).
fn rule_from_lit(macro_name: &str, lit: &LitStr) -> syn::Result<RenameRule> {
    RenameRule::parse(&lit.value()).ok_or_else(|| {
        compile_error(
            lit.span(),
            macro_name,
            FailTag::InvalidArg,
            &format!("unknown `rename_all` rule `{}`", lit.value()),
        )
    })
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
        assert_eq!(attrs.serialize_name(ident, None), "url");
        assert_eq!(attrs.deserialize_name(ident, None), "url");
    }

    #[test]
    fn rename_split_sets_each_side() {
        let f = field(
            &quote! { #[serde(rename(serialize = "ser", deserialize = "de"))] endpoint: String },
        );
        let attrs = parse_field("MaskSerialize", &f.attrs).expect("parses");
        let ident = f.ident.as_ref().unwrap();
        assert_eq!(attrs.serialize_name(ident, None), "ser");
        assert_eq!(attrs.deserialize_name(ident, None), "de");
    }

    #[test]
    fn no_rename_falls_back_to_ident() {
        let f = field(&quote! { endpoint: String });
        let attrs = parse_field("MaskSerialize", &f.attrs).expect("parses");
        let ident = f.ident.as_ref().unwrap();
        assert_eq!(attrs.serialize_name(ident, None), "endpoint");
        assert_eq!(attrs.deserialize_name(ident, None), "endpoint");
    }

    #[test]
    fn unsupported_key_is_reject_loud() {
        let f = field(&quote! { #[serde(flatten)] inner: String });
        let err = match parse_field("MaskSerialize", &f.attrs) {
            Ok(_) => panic!("expected flatten to be reject-loud"),
            Err(err) => err,
        };
        let msg = err.to_string();
        assert!(msg.contains("MaskSerialize! invalid-arg"), "got: {msg}");
        assert!(msg.contains("`#[serde(flatten)]`"), "got: {msg}");
    }

    #[test]
    fn rename_rule_field_conventions_match_serde() {
        // Source field is `snake_case` (serde's assumption). Expected
        // values mirror serde's `RenameRule::apply_to_field`.
        let cases = [
            ("lowercase", "two_words"),
            ("UPPERCASE", "TWO_WORDS"),
            ("PascalCase", "TwoWords"),
            ("camelCase", "twoWords"),
            ("snake_case", "two_words"),
            ("SCREAMING_SNAKE_CASE", "TWO_WORDS"),
            ("kebab-case", "two-words"),
            ("SCREAMING-KEBAB-CASE", "TWO-WORDS"),
        ];
        for (rule, expected) in cases {
            let rule = RenameRule::parse(rule).expect("known rule");
            assert_eq!(rule.apply_to_field("two_words"), expected);
        }
    }

    #[test]
    fn rename_rule_variant_conventions_match_serde() {
        // Source variant is `PascalCase`. Expected values mirror
        // serde's `RenameRule::apply_to_variant`.
        let cases = [
            ("lowercase", "twowords"),
            ("UPPERCASE", "TWOWORDS"),
            ("PascalCase", "TwoWords"),
            ("camelCase", "twoWords"),
            ("snake_case", "two_words"),
            ("SCREAMING_SNAKE_CASE", "TWO_WORDS"),
            ("kebab-case", "two-words"),
            ("SCREAMING-KEBAB-CASE", "TWO-WORDS"),
        ];
        for (rule, expected) in cases {
            let rule = RenameRule::parse(rule).expect("known rule");
            assert_eq!(rule.apply_to_variant("TwoWords"), expected);
        }
    }

    #[test]
    fn unknown_rename_all_rule_is_reject_loud() {
        let di: syn::DeriveInput = syn::parse2(quote! {
            #[serde(rename_all = "bogus")]
            struct S { x: u8 }
        })
        .expect("parses");
        let err = parse_container("MaskSerialize", &di.attrs).expect_err("must reject");
        assert!(
            err.to_string()
                .contains("unknown `rename_all` rule `bogus`"),
            "got: {err}",
        );
    }

    #[test]
    fn skip_sets_both_directions() {
        let f = field(&quote! { #[serde(skip)] internal: u8 });
        let attrs = parse_field("MaskSerialize", &f.attrs).expect("parses");
        assert!(attrs.skip_serializing);
        assert!(attrs.skip_deserializing);
        assert!(attrs.skips_a_tuple_field());
    }

    #[test]
    fn skip_serializing_and_deserializing_are_independent() {
        let ser = field(&quote! { #[serde(skip_serializing)] a: u8 });
        let ser = parse_field("MaskSerialize", &ser.attrs).expect("parses");
        assert!(ser.skip_serializing && !ser.skip_deserializing);

        let de = field(&quote! { #[serde(skip_deserializing)] a: u8 });
        let de = parse_field("MaskSerialize", &de.attrs).expect("parses");
        assert!(de.skip_deserializing && !de.skip_serializing);
    }

    #[test]
    fn skip_serializing_if_parses_a_path() {
        let f = field(&quote! { #[serde(skip_serializing_if = "Option::is_none")] a: Option<u8> });
        let attrs = parse_field("MaskSerialize", &f.attrs).expect("parses");
        let path = attrs.skip_serializing_if.expect("path present");
        assert_eq!(
            quote!(#path).to_string(),
            quote!(Option::is_none).to_string()
        );
    }

    #[test]
    fn field_rename_overrides_parent_rename_all() {
        let f = field(&quote! { #[serde(rename = "kept")] two_words: u8 });
        let attrs = parse_field("MaskSerialize", &f.attrs).expect("parses");
        let ident = f.ident.as_ref().unwrap();
        // Explicit field rename wins over the parent rule.
        assert_eq!(
            attrs.serialize_name(ident, Some(RenameRule::Pascal)),
            "kept",
        );
    }
}
