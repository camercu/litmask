//! `#[mask_all]` derive-swapping: rewrite a type's plain
//! `#[derive(Serialize)]` / `#[derive(Deserialize)]` / `#[derive(Debug)]`
//! to litmask's masking counterparts so the container / field / variant
//! *names* never re-enter `.rodata` as cleartext — the leak the
//! literal-rewrite pass alone cannot reach (a plain derive embeds every
//! name as a `&'static str`).
//!
//! `Debug` swaps unconditionally (`MaskDebug` is ungated); `Serialize` /
//! `Deserialize` swap only when litmask is built with `serde`,
//! because their masking derives live behind that feature.
//!
//! A type carrying the [`OPT_OUT`] marker attribute is left untouched and
//! the marker stripped, so a user can keep a plain derive on a chosen
//! type (e.g. one using a not-yet-supported `#[serde(...)]` attribute).

use syn::punctuated::Punctuated;
use syn::{Attribute, Path, Token};

/// Marker attribute that opts a single item out of derive-swapping.
/// `#[mask_all]` strips it before emit; outside a `#[mask_all]` module
/// the `unmasked_derive` attribute macro expands it to an identity
/// no-op. Matched on the last path segment so both `#[unmasked_derive]`
/// and `#[litmask::unmasked_derive]` are recognized.
const OPT_OUT: &str = "unmasked_derive";

/// Map a derive's last path segment to its litmask masking
/// counterpart, or `None` when the derive is not one litmask masks.
/// `serde_enabled` gates the serde pair: the masking derives only
/// exist when litmask is compiled with `serde`, so swapping
/// to them otherwise would reference an absent symbol.
fn masked_counterpart(last_segment: &str, serde_enabled: bool) -> Option<Path> {
    let target = match last_segment {
        "Debug" => "MaskDebug",
        "Serialize" if serde_enabled => "MaskSerialize",
        "Deserialize" if serde_enabled => "MaskDeserialize",
        _ => return None,
    };
    Some(syn::parse_str(&format!("::litmask::{target}")).expect("static masking path parses"))
}

/// Swap a struct/enum item's derives unless it opts out: strip an
/// `#[unmasked_derive]` marker and, when absent, rewrite the recognized
/// plain derives to their masking counterparts.
pub(super) fn swap_item_derives(attrs: &mut Vec<Attribute>, serde_enabled: bool) {
    if !take_opt_out(attrs) {
        rewrite_derives(attrs, serde_enabled);
    }
}

/// Rewrite every `#[derive(...)]` in `attrs` in place, swapping each
/// recognized plain derive for its litmask masking counterpart while
/// preserving declaration order and every other derive. Last-segment
/// matching mirrors `classify_macro`, so `serde::Serialize` and
/// `serde_derive::Serialize` are recognized too. `cfg_attr`-wrapped
/// derives are not reached and remain plain (documented limitation).
pub(super) fn rewrite_derives(attrs: &mut [Attribute], serde_enabled: bool) {
    for attr in attrs.iter_mut() {
        if !attr.path().is_ident("derive") {
            continue;
        }
        let Ok(paths) = attr.parse_args_with(Punctuated::<Path, Token![,]>::parse_terminated)
        else {
            continue;
        };
        let mut changed = false;
        let rewritten: Vec<Path> = paths
            .into_iter()
            .map(|path| {
                let swapped = path
                    .segments
                    .last()
                    .and_then(|seg| masked_counterpart(&seg.ident.to_string(), serde_enabled));
                match swapped {
                    Some(repl) => {
                        changed = true;
                        repl
                    }
                    None => path,
                }
            })
            .collect();
        if changed {
            *attr = syn::parse_quote!(#[derive(#(#rewritten),*)]);
        }
    }
}

/// True when `attr` is the [`OPT_OUT`] marker (a bare path attribute
/// whose last segment is `unmasked_derive`).
fn is_opt_out(attr: &Attribute) -> bool {
    matches!(attr.meta, syn::Meta::Path(_))
        && attr
            .path()
            .segments
            .last()
            .is_some_and(|seg| seg.ident == OPT_OUT)
}

/// Strip the [`OPT_OUT`] marker if present, returning whether the item
/// opted out — the caller then skips derive-swapping for that item.
pub(super) fn take_opt_out(attrs: &mut Vec<Attribute>) -> bool {
    let before = attrs.len();
    attrs.retain(|attr| !is_opt_out(attr));
    attrs.len() != before
}

#[cfg(test)]
mod tests {
    use super::*;
    use quote::{ToTokens, quote};

    fn parse(src: proc_macro2::TokenStream) -> syn::DeriveInput {
        syn::parse2(src).expect("fixture parses as a derive input")
    }

    /// Render the paths inside the (single) `#[derive(...)]` attribute
    /// as normalized strings for assertion.
    fn derive_paths(item: &syn::DeriveInput) -> Vec<String> {
        let attr = item
            .attrs
            .iter()
            .find(|a| a.path().is_ident("derive"))
            .expect("fixture has a derive attribute");
        attr.parse_args_with(Punctuated::<Path, Token![,]>::parse_terminated)
            .expect("derive args parse")
            .iter()
            .map(|p| p.to_token_stream().to_string().replace(' ', ""))
            .collect()
    }

    #[test]
    fn debug_swaps_unconditionally() {
        let mut di = parse(quote! { #[derive(Debug)] struct S; });
        rewrite_derives(&mut di.attrs, false);
        assert_eq!(derive_paths(&di), vec!["::litmask::MaskDebug"]);
    }

    #[test]
    fn serde_pair_swaps_when_enabled() {
        let mut di = parse(quote! { #[derive(serde::Serialize, serde::Deserialize)] struct S; });
        rewrite_derives(&mut di.attrs, true);
        assert_eq!(
            derive_paths(&di),
            vec!["::litmask::MaskSerialize", "::litmask::MaskDeserialize"],
        );
    }

    #[test]
    fn serde_pair_left_plain_when_disabled() {
        let mut di = parse(quote! { #[derive(Serialize, Deserialize)] struct S; });
        rewrite_derives(&mut di.attrs, false);
        assert_eq!(derive_paths(&di), vec!["Serialize", "Deserialize"]);
    }

    #[test]
    fn other_derives_preserved_in_order() {
        let mut di = parse(quote! { #[derive(Clone, Serialize, Debug, PartialEq)] struct S; });
        rewrite_derives(&mut di.attrs, true);
        assert_eq!(
            derive_paths(&di),
            vec![
                "Clone",
                "::litmask::MaskSerialize",
                "::litmask::MaskDebug",
                "PartialEq",
            ],
        );
    }

    #[test]
    fn opt_out_marker_taken_and_stripped() {
        let mut di = parse(quote! {
            #[unmasked_derive]
            #[derive(Debug)]
            struct S;
        });
        assert!(take_opt_out(&mut di.attrs));
        assert!(!di.attrs.iter().any(is_opt_out));
        // `take_opt_out` only removes the marker; the derive is left
        // for the caller to (deliberately) skip.
        assert_eq!(derive_paths(&di), vec!["Debug"]);
    }

    #[test]
    fn opt_out_qualified_path_recognized() {
        let mut di = parse(quote! {
            #[litmask::unmasked_derive]
            #[derive(Debug)]
            struct S;
        });
        assert!(take_opt_out(&mut di.attrs));
    }

    #[test]
    fn take_opt_out_false_when_absent() {
        let mut di = parse(quote! { #[derive(Debug)] struct S; });
        assert!(!take_opt_out(&mut di.attrs));
    }
}
