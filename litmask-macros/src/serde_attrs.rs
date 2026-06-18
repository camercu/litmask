//! Parsing of the supported `#[serde(...)]` attribute subset for the
//! masking serde derives (`MaskSerialize` / `MaskDeserialize`,
//! `serde`).
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
//! `skip_serializing` / `skip_deserializing` / `skip_serializing_if` /
//! `default` (and `default = "path"`) / `alias` / `with` /
//! `serialize_with` / `deserialize_with` on named fields, and
//! `deny_unknown_fields` / `bound` / `transparent` on the container.
//! Every other key is reject-loud and listed for a later slice.

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

/// A `#[serde(bound = "...")]` override of the generated where-clause
/// predicates, possibly split per direction. `None` keeps the derive's
/// default per-type-param bound; `Some(preds)` replaces it entirely.
#[derive(Default)]
pub(crate) struct BoundOverride {
    pub(crate) serialize: Option<Vec<syn::WherePredicate>>,
    pub(crate) deserialize: Option<Vec<syn::WherePredicate>>,
}

/// The enum representation a container requests. `External` (serde's
/// default) is the only form the masking derives currently emit; the
/// other three are parsed into this model but reject-loud at codegen
/// (`reject_unsupported_tagging`) until their `Content`-buffering
/// machinery lands (SPEC §E.2.5 deferred).
#[derive(Default, Debug, PartialEq)]
pub(crate) enum Tagging {
    #[default]
    External,
    Internal {
        tag: String,
    },
    Adjacent {
        tag: String,
        content: String,
    },
    Untagged,
}

/// Container-level (`struct` / `enum`) serde attributes.
#[derive(Default)]
pub(crate) struct ContainerAttrs {
    pub(crate) rename: Rename,
    pub(crate) rename_all: RenameAll,
    /// `#[serde(deny_unknown_fields)]`: an unknown field key is a hard
    /// error (`unknown_field`) instead of being skipped.
    pub(crate) deny_unknown_fields: bool,
    /// `#[serde(bound = "...")]` where-clause override.
    pub(crate) bound: BoundOverride,
    /// `#[serde(transparent)]`: (de)serialize as the single contained
    /// field, with no struct wrapper on the wire.
    pub(crate) transparent: bool,
    /// Enum representation from `tag`/`content`/`untagged`. Parsed here
    /// but not yet emitted — see [`Tagging`] and
    /// [`ContainerAttrs::reject_unsupported_tagging`].
    pub(crate) tagging: Tagging,
    /// The first tagging key seen (`(span, name)`), so the deferred-reject
    /// error underlines that key (matching the pre-spike `unsupported`
    /// span) and names what the user actually wrote — e.g. `content` for
    /// the invalid `content`-without-`tag` form, not a phantom `tag`.
    tagging_key: Option<(proc_macro2::Span, String)>,
}

impl ContainerAttrs {
    /// Reject-loud on a non-default enum representation until its codegen
    /// lands. Mirrors [`unsupported`]'s message/tag so the deferred forms
    /// stay indistinguishable from any other not-yet-supported key.
    pub(crate) fn reject_unsupported_tagging(&self, macro_name: &str) -> syn::Result<()> {
        if self.tagging == Tagging::External {
            return Ok(());
        }
        let (span, key) = self
            .tagging_key
            .clone()
            .unwrap_or_else(|| (proc_macro2::Span::call_site(), String::from("tag")));
        Err(compile_error(
            span,
            macro_name,
            FailTag::InvalidArg,
            &format!(
                "`#[serde({key})]` is not yet supported; keep a plain derive \
                 (or `#[unmasked_derive]` under `#[mask_all]`)"
            ),
        ))
    }
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
    /// `#[serde(default)]` / `#[serde(default = "path")]`: how a missing
    /// (or `skip_deserializing`) field is filled instead of erroring.
    pub(crate) default: Option<DefaultSource>,
    /// `#[serde(alias = "name")]` (repeatable): extra literal names the
    /// field also accepts on deserialize. Not affected by `rename_all`.
    pub(crate) aliases: Vec<String>,
    /// `#[serde(serialize_with = "path")]` (or `with`): serialize the
    /// field by calling `path(&field, serializer)`.
    pub(crate) serialize_with: Option<syn::Path>,
    /// `#[serde(deserialize_with = "path")]` (or `with`): deserialize the
    /// field by calling `path(deserializer)`.
    pub(crate) deserialize_with: Option<syn::Path>,
}

/// Where a defaulted field's value comes from when absent from the
/// input: the `Default` trait (`#[serde(default)]`) or a named function
/// (`#[serde(default = "path")]`).
pub(crate) enum DefaultSource {
    DefaultTrait,
    Path(syn::Path),
}

impl FieldAttrs {
    /// True when any supported `#[serde(...)]` key is set on the field.
    /// Tuple (positional) fields don't yet get attribute support, so an
    /// attribute there is reject-loud rather than silently honored —
    /// otherwise `serialize_with` / `default` / `skip` and friends would
    /// be dropped (changing the wire format) without warning.
    pub(crate) fn is_set(&self) -> bool {
        self.rename.serialize.is_some()
            || self.rename.deserialize.is_some()
            || self.skip_serializing
            || self.skip_deserializing
            || self.skip_serializing_if.is_some()
            || self.default.is_some()
            || !self.aliases.is_empty()
            || self.serialize_with.is_some()
            || self.deserialize_with.is_some()
    }
}

/// Enum-variant-level serde attributes.
#[derive(Default, Debug)]
pub(crate) struct VariantAttrs {
    pub(crate) rename: Rename,
    pub(crate) rename_all: RenameAll,
    /// `#[serde(alias = "name")]` (repeatable): extra names this variant
    /// also accepts on deserialize. Deserialize-only — serialize emits
    /// the primary (renamed) name. Not affected by `rename_all`.
    pub(crate) aliases: Vec<String>,
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
    let mut tag: Option<String> = None;
    let mut content: Option<String> = None;
    let mut untagged = false;
    parse_serde(attrs, |meta| {
        if meta.path.is_ident("rename") {
            out.rename = parse_rename(&meta)?;
            Ok(())
        } else if meta.path.is_ident("rename_all") {
            out.rename_all = parse_rename_all(macro_name, &meta)?;
            Ok(())
        } else if meta.path.is_ident("deny_unknown_fields") {
            out.deny_unknown_fields = true;
            Ok(())
        } else if meta.path.is_ident("bound") {
            out.bound = parse_bound(&meta)?;
            Ok(())
        } else if meta.path.is_ident("transparent") {
            out.transparent = true;
            Ok(())
        } else if meta.path.is_ident("tag") {
            out.tagging_key
                .get_or_insert_with(|| (meta.path.span(), "tag".to_string()));
            tag = Some(meta.value()?.parse::<LitStr>()?.value());
            Ok(())
        } else if meta.path.is_ident("content") {
            out.tagging_key
                .get_or_insert_with(|| (meta.path.span(), "content".to_string()));
            content = Some(meta.value()?.parse::<LitStr>()?.value());
            Ok(())
        } else if meta.path.is_ident("untagged") {
            out.tagging_key
                .get_or_insert_with(|| (meta.path.span(), "untagged".to_string()));
            untagged = true;
            Ok(())
        } else {
            Err(unsupported(macro_name, &meta))
        }
    })?;
    out.tagging = resolve_tagging(tag, content, untagged);
    Ok(out)
}

/// Fold the raw `tag`/`content`/`untagged` keys into a [`Tagging`].
/// `content` without `tag` is invalid in serde; it is modeled as an
/// (empty-tag) `Adjacent` so codegen still reject-louds rather than
/// silently treating it as `External`.
fn resolve_tagging(tag: Option<String>, content: Option<String>, untagged: bool) -> Tagging {
    if untagged {
        Tagging::Untagged
    } else if let Some(tag) = tag {
        match content {
            Some(content) => Tagging::Adjacent { tag, content },
            None => Tagging::Internal { tag },
        }
    } else if let Some(content) = content {
        Tagging::Adjacent {
            tag: String::new(),
            content,
        }
    } else {
        Tagging::External
    }
}

/// Parse `bound = "preds"` or `bound(serialize = "...", deserialize =
/// "...")` into where-clause predicate lists.
fn parse_bound(meta: &ParseNestedMeta) -> syn::Result<BoundOverride> {
    let (serialize, deserialize) = parse_split(meta, parse_predicates)?;
    Ok(BoundOverride {
        serialize,
        deserialize,
    })
}

/// Parse a `bound` string literal as a comma-separated list of
/// where-clause predicates (`"T: Foo, U: Bar"`).
fn parse_predicates(lit: &LitStr) -> syn::Result<Vec<syn::WherePredicate>> {
    let parsed = lit.parse_with(
        syn::punctuated::Punctuated::<syn::WherePredicate, syn::Token![,]>::parse_terminated,
    )?;
    Ok(parsed.into_iter().collect())
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
        } else if meta.path.is_ident("default") {
            out.default = Some(if meta.input.peek(syn::Token![=]) {
                let lit: LitStr = meta.value()?.parse()?;
                DefaultSource::Path(lit.parse()?)
            } else {
                DefaultSource::DefaultTrait
            });
            Ok(())
        } else if meta.path.is_ident("alias") {
            let lit: LitStr = meta.value()?.parse()?;
            out.aliases.push(lit.value());
            Ok(())
        } else if meta.path.is_ident("with") {
            let module: syn::Path = meta.value()?.parse::<LitStr>()?.parse()?;
            out.serialize_with = Some(syn::parse_quote!(#module::serialize));
            out.deserialize_with = Some(syn::parse_quote!(#module::deserialize));
            Ok(())
        } else if meta.path.is_ident("serialize_with") {
            out.serialize_with = Some(meta.value()?.parse::<LitStr>()?.parse()?);
            Ok(())
        } else if meta.path.is_ident("deserialize_with") {
            out.deserialize_with = Some(meta.value()?.parse::<LitStr>()?.parse()?);
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
        } else if meta.path.is_ident("alias") {
            let lit: LitStr = meta.value()?.parse()?;
            out.aliases.push(lit.value());
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

/// Parse the shared serde split grammar: `= "value"` (sets both
/// directions) or `(serialize = "...", deserialize = "...")`.
/// `parse_one` maps each string literal to the typed value.
fn parse_split<T: Clone>(
    meta: &ParseNestedMeta,
    parse_one: impl Fn(&LitStr) -> syn::Result<T>,
) -> syn::Result<(Option<T>, Option<T>)> {
    if meta.input.peek(syn::Token![=]) {
        let value = parse_one(&meta.value()?.parse::<LitStr>()?)?;
        return Ok((Some(value.clone()), Some(value)));
    }
    let mut serialize = None;
    let mut deserialize = None;
    meta.parse_nested_meta(|inner| {
        if inner.path.is_ident("serialize") {
            serialize = Some(parse_one(&inner.value()?.parse::<LitStr>()?)?);
        } else if inner.path.is_ident("deserialize") {
            deserialize = Some(parse_one(&inner.value()?.parse::<LitStr>()?)?);
        } else {
            return Err(inner.error("expected `serialize` or `deserialize`"));
        }
        Ok(())
    })?;
    Ok((serialize, deserialize))
}

/// Parse `rename = "x"` or `rename(serialize = "s", deserialize = "d")`.
fn parse_rename(meta: &ParseNestedMeta) -> syn::Result<Rename> {
    let (serialize, deserialize) = parse_split(meta, |lit| Ok(lit.value()))?;
    Ok(Rename {
        serialize,
        deserialize,
    })
}

/// Parse `rename_all = "case"` or `rename_all(serialize = "...",
/// deserialize = "...")`.
fn parse_rename_all(macro_name: &str, meta: &ParseNestedMeta) -> syn::Result<RenameAll> {
    let (serialize, deserialize) = parse_split(meta, |lit| rule_from_lit(macro_name, lit))?;
    Ok(RenameAll {
        serialize,
        deserialize,
    })
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

/// Reject-loud any `#[serde(...)]` on unnamed (tuple) fields. The
/// masking derives don't apply field attributes positionally yet, so
/// honoring one silently (e.g. `serialize_with`, `skip`, `default`)
/// would diverge from serde's wire format without warning.
pub(crate) fn reject_tuple_field_attrs(
    macro_name: &str,
    fields: &syn::FieldsUnnamed,
) -> syn::Result<()> {
    for field in &fields.unnamed {
        if parse_field(macro_name, &field.attrs)?.is_set() {
            return Err(compile_error(
                field.span(),
                macro_name,
                FailTag::InvalidArg,
                "`#[serde(...)]` on a tuple field is not yet supported",
            ));
        }
    }
    Ok(())
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
        let err = match parse_container("MaskSerialize", &di.attrs) {
            Ok(_) => panic!("expected unknown rule to be reject-loud"),
            Err(err) => err,
        };
        assert!(
            err.to_string()
                .contains("unknown `rename_all` rule `bogus`"),
            "got: {err}",
        );
    }

    #[test]
    fn is_set_detects_any_supported_key() {
        // Drives the tuple-field reject: a positional field carrying any
        // supported attr must be caught (it would otherwise be silently
        // dropped). A bare field is not flagged.
        for src in [
            quote! { #[serde(serialize_with = "p")] x: u8 },
            quote! { #[serde(default)] x: u8 },
            quote! { #[serde(skip)] x: u8 },
            quote! { #[serde(rename = "y")] x: u8 },
            quote! { #[serde(alias = "y")] x: u8 },
        ] {
            let f = field(&src);
            assert!(
                parse_field("MaskSerialize", &f.attrs)
                    .expect("parses")
                    .is_set(),
                "expected is_set for {src}",
            );
        }
        let bare = field(&quote! { x: u8 });
        assert!(
            !parse_field("MaskSerialize", &bare.attrs)
                .expect("parses")
                .is_set()
        );
    }

    #[test]
    fn skip_sets_both_directions() {
        let f = field(&quote! { #[serde(skip)] internal: u8 });
        let attrs = parse_field("MaskSerialize", &f.attrs).expect("parses");
        assert!(attrs.skip_serializing);
        assert!(attrs.skip_deserializing);
        assert!(attrs.is_set());
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
    fn default_parses_trait_and_path_forms() {
        let bare = field(&quote! { #[serde(default)] a: u8 });
        let bare = parse_field("MaskDeserialize", &bare.attrs).expect("parses");
        assert!(matches!(bare.default, Some(DefaultSource::DefaultTrait)));

        let path = field(&quote! { #[serde(default = "make_default")] a: u8 });
        let path = parse_field("MaskDeserialize", &path.attrs).expect("parses");
        match path.default {
            Some(DefaultSource::Path(p)) => {
                assert_eq!(quote!(#p).to_string(), quote!(make_default).to_string());
            }
            _ => panic!("expected a default path"),
        }
    }

    #[test]
    fn aliases_accumulate() {
        let f = field(&quote! { #[serde(alias = "id", alias = "key")] primary: u8 });
        let attrs = parse_field("MaskDeserialize", &f.attrs).expect("parses");
        assert_eq!(attrs.aliases, vec!["id".to_string(), "key".to_string()]);
    }

    #[test]
    fn bound_parses_split_predicates() {
        let di: syn::DeriveInput = syn::parse2(quote! {
            #[serde(bound(serialize = "T: Clone", deserialize = "T: Default"))]
            struct S<T> { x: T }
        })
        .expect("parses");
        let attrs = parse_container("MaskSerialize", &di.attrs).expect("parses");
        let ser = attrs.bound.serialize.expect("serialize preds");
        let de = attrs.bound.deserialize.expect("deserialize preds");
        assert_eq!(ser.len(), 1);
        assert_eq!(de.len(), 1);
        assert_eq!(quote!(#(#ser)*).to_string(), quote!(T: Clone).to_string());
    }

    #[test]
    fn with_expands_to_serialize_and_deserialize_paths() {
        let f = field(&quote! { #[serde(with = "my_mod")] x: u8 });
        let attrs = parse_field("MaskSerialize", &f.attrs).expect("parses");
        let ser = attrs.serialize_with.expect("serialize_with");
        let de = attrs.deserialize_with.expect("deserialize_with");
        assert_eq!(
            quote!(#ser).to_string(),
            quote!(my_mod::serialize).to_string()
        );
        assert_eq!(
            quote!(#de).to_string(),
            quote!(my_mod::deserialize).to_string()
        );
    }

    #[test]
    fn deny_unknown_fields_parses_on_container() {
        let di: syn::DeriveInput = syn::parse2(quote! {
            #[serde(deny_unknown_fields)]
            struct S { x: u8 }
        })
        .expect("parses");
        let attrs = parse_container("MaskDeserialize", &di.attrs).expect("parses");
        assert!(attrs.deny_unknown_fields);
    }

    fn container(src: &proc_macro2::TokenStream) -> ContainerAttrs {
        let di: syn::DeriveInput =
            syn::parse2(quote! { #src enum E { V } }).expect("fixture parses");
        parse_container("MaskDeserialize", &di.attrs).expect("container parses")
    }

    #[test]
    fn tagging_models_each_representation() {
        // `tag`/`content`/`untagged` now parse into the Tagging model
        // (spike 2a) even though codegen still reject-louds them.
        assert_eq!(container(&quote! {}).tagging, Tagging::External);
        assert_eq!(
            container(&quote! { #[serde(tag = "t")] }).tagging,
            Tagging::Internal { tag: "t".into() },
        );
        assert_eq!(
            container(&quote! { #[serde(tag = "t", content = "c")] }).tagging,
            Tagging::Adjacent {
                tag: "t".into(),
                content: "c".into(),
            },
        );
        assert_eq!(
            container(&quote! { #[serde(untagged)] }).tagging,
            Tagging::Untagged,
        );
    }

    #[test]
    fn unsupported_tagging_is_reject_loud_at_codegen() {
        // The parser accepts the representation; the codegen guard is what
        // keeps it reject-loud until the Content machinery lands.
        let attrs = container(&quote! { #[serde(tag = "t")] });
        let err = attrs
            .reject_unsupported_tagging("MaskDeserialize")
            .expect_err("non-external tagging must reject");
        assert!(err.to_string().contains("invalid-arg"), "got: {err}");
        // External stays fine.
        assert!(
            container(&quote! {})
                .reject_unsupported_tagging("MaskDeserialize")
                .is_ok()
        );
    }

    #[test]
    fn content_without_tag_reject_names_content_not_tag() {
        // `content` without `tag` is invalid in serde and modeled as an
        // empty-tag Adjacent so it still reject-louds; the diagnostic must
        // name the key the user actually wrote (`content`), not `tag`.
        let attrs = container(&quote! { #[serde(content = "c")] });
        let err = attrs
            .reject_unsupported_tagging("MaskDeserialize")
            .expect_err("content-only must reject");
        assert!(err.to_string().contains("content"), "got: {err}");
        assert!(
            !err.to_string().contains("tag"),
            "should not name a phantom `tag`: {err}",
        );
    }

    #[test]
    fn variant_aliases_accumulate() {
        let di: syn::DeriveInput = syn::parse2(quote! {
            enum E {
                #[serde(alias = "v", alias = "w")]
                V,
            }
        })
        .expect("parses");
        let syn::Data::Enum(data) = di.data else {
            unreachable!()
        };
        let variant = &data.variants[0];
        let attrs = parse_variant("MaskDeserialize", &variant.attrs).expect("variant alias parses");
        assert_eq!(attrs.aliases, vec!["v".to_string(), "w".to_string()]);
    }

    #[test]
    fn out_of_scope_container_keys_are_reject_loud() {
        // `into`/`from`/`try_from` delegate (de)serialization to a shadow
        // type whose own derive owns the names, so masking can never reach
        // them — they are permanently out of scope (§E.2.5), not deferred.
        // This pins that commitment so a future parser change can't quietly
        // start honoring them.
        for key in ["into", "from", "try_from"] {
            let ident = syn::Ident::new(key, proc_macro2::Span::call_site());
            let di: syn::DeriveInput = syn::parse2(quote! {
                #[serde(#ident = "Other")]
                struct S { x: u8 }
            })
            .expect("parses");
            let err = match parse_container("MaskDeserialize", &di.attrs) {
                Ok(_) => panic!("expected `{key}` to be reject-loud"),
                Err(err) => err,
            };
            assert!(err.to_string().contains("invalid-arg"), "got: {err}");
        }
    }

    #[test]
    fn out_of_scope_getter_field_key_is_reject_loud() {
        // `getter` is a remote-derive field attr; same shadow-type
        // reasoning as the container keys above.
        let f = field(&quote! { #[serde(getter = "get_x")] x: u8 });
        let err = match parse_field("MaskSerialize", &f.attrs) {
            Ok(_) => panic!("expected `getter` to be reject-loud"),
            Err(err) => err,
        };
        assert!(err.to_string().contains("invalid-arg"), "got: {err}");
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
