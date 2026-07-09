//! Skip-tracking types for `#[mask_all]`.
//!
//! Each literal the walker passes over without rewriting is recorded
//! as a [`SkipRecord`] with a [`SkipReason`] tag. After the walk
//! completes, [`diagnostic_items`] translates the records into
//! ghost-deprecation warnings (or `compile_error!` under strict mode).

use proc_macro2::TokenStream as TokenStream2;
use quote::{format_ident, quote};

use crate::common::{canonicalize_file_path, manifest_dir};

/// Reason tag for one skipped literal. The full diagnostic note
/// (per spec §2.3.1.4 amendment 2026-05-10) is
/// `litmask: skipped literal at <file>:<line>: <reason>` — see
/// [`SkipRecord::note`]. This enum carries the reason only; the
/// file/line travels alongside it in a [`SkipRecord`].
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub(super) enum SkipReason {
    PatternPosition,
    ConstInitializer,
    StaticInitializer,
    /// String-shaped literal argument to a macro the walker doesn't
    /// recognize (neither in the skip list nor in any of the rewrite
    /// families). The literal is left alone and a warning fires per
    /// occurrence.
    UnrecognizedMacro,
    /// One of the `format!` / output / write / panic /
    /// `assert*!`-with-message macros was invoked with a non-`LitStr`
    /// template (e.g., `format!(concat!(...), ...)`). The walker
    /// cannot mask the template bytes, so the macro is left
    /// unchanged and a warning fires per occurrence (§2.3.2.2–
    /// §2.3.2.4).
    NonLiteralTemplate,
}

impl SkipReason {
    fn tag(self) -> &'static str {
        match self {
            Self::PatternPosition => "pattern_position",
            Self::ConstInitializer => "const_initializer",
            Self::StaticInitializer => "static_initializer",
            Self::UnrecognizedMacro => "unrecognized_macro",
            Self::NonLiteralTemplate => "non_literal_template",
        }
    }
}

/// One skipped literal: reason + the literal's own span. The
/// diagnostic note is normatively
/// `litmask: skipped literal at <file>:<line>: <reason>` per
/// §2.3.1.4 amendment 2026-05-10; the file/line in the note
/// identifies the *literal*, not the auto-generated
/// `#[deprecated]` const or `compile_error!()` item that carries it.
///
/// The span is stored raw and resolved to file/line only in
/// [`note`](Self::note), at render time. Recording a skip is therefore
/// pure — it never touches `proc_macro::Span`, which panics outside a
/// real proc-macro invocation — so the walker's skip logic is unit
/// testable via [`reason`](Self::reason). File/line resolution is the
/// proc-macro-coupled shell, deferred to the one place that always runs
/// inside a proc-macro expansion.
#[derive(Clone, Copy)]
pub(super) struct SkipRecord {
    reason: SkipReason,
    span: proc_macro2::Span,
}

impl SkipRecord {
    /// Record a skip for the literal at `span`. Pure: the span is kept
    /// as-is and only resolved to file/line in [`note`](Self::note).
    pub(super) fn from_span(reason: SkipReason, span: proc_macro2::Span) -> Self {
        Self { reason, span }
    }

    /// The skip's reason tag — the walker's classification of why this
    /// literal was left unmasked. Test-only: production reads the reason
    /// through [`note`](Self::note).
    #[cfg(test)]
    pub(super) fn reason(&self) -> SkipReason {
        self.reason
    }

    /// Render the diagnostic note. Resolves the literal's span to a
    /// `file:line` here (not at record time): the path is canonicalized
    /// against `CARGO_MANIFEST_DIR` (via the cached [`manifest_dir`]) so
    /// absolute build-host paths don't leak into the diagnostic text.
    fn note(&self) -> String {
        let pm_span = self.span.unwrap();
        let file = canonicalize_file_path(pm_span.file(), manifest_dir());
        format!(
            "litmask: skipped literal at {file}:{line}: {tag}",
            line = pm_span.line(),
            tag = self.reason.tag(),
        )
    }
}

/// Translate collected skip records into module-level diagnostic
/// items. In the default (non-strict) mode, emit a hidden
/// `__litmask_skips` submodule of `#[deprecated]` consts whose
/// `deprecated` lint surfaces each skip as a warning. In strict
/// mode (§2.3.3.1), each skip becomes a `compile_error!` item
/// instead — the build fails with one error per unmasked
/// literal, forcing the user to either mask it or wrap it in
/// `unmasked!()` (§2.3.3.2).
pub(super) fn diagnostic_items(skipped: &[SkipRecord], strict: bool) -> Vec<syn::Item> {
    if skipped.is_empty() {
        return Vec::new();
    }
    if strict {
        return skipped
            .iter()
            .map(|record| {
                let note = record.note();
                syn::parse_quote! {
                    ::core::compile_error!(#note);
                }
            })
            .collect();
    }
    let mut const_items: Vec<TokenStream2> = Vec::with_capacity(skipped.len());
    let mut anchor_refs: Vec<TokenStream2> = Vec::with_capacity(skipped.len());
    for (i, record) in skipped.iter().enumerate() {
        let ident = format_ident!("_LITMASK_SKIP_{i}");
        let note = record.note();
        // `dead_code` allow is load-bearing: the const has no use
        // outside the sibling anchor fn. Without it, every skip
        // would emit a competing `unused constant` warning.
        const_items.push(quote! {
            #[deprecated(note = #note)]
            #[allow(dead_code)]
            const #ident: () = ();
        });
        anchor_refs.push(quote! { let _ = #ident; });
    }
    let module: syn::Item = syn::parse_quote! {
        #[doc(hidden)]
        #[allow(non_snake_case, dead_code)]
        mod __litmask_skips {
            #(#const_items)*
            fn __anchor() {
                #(#anchor_refs)*
            }
        }
    };
    vec![module]
}
