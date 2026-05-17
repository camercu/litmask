//! `#[mask_all]` proc-macro attribute: walks the AST of an attributed
//! module and rewrites bare string / byte string / C string literal
//! expressions to `mask!(literal)` calls.
//!
//! Task 12 / spec §2.3.1.1–§2.3.1.6 + §2.3.2.1 + §2.3.2.6.
//! Strict mode (§2.3.3) and the full macro substitution table for
//! `format!` / `println!` / `panic!` / `include_str!` / `concat!`
//! / user-defined macros (§2.3.2.2-§2.3.2.5, §2.3.2.7) land in
//! Tasks 13–14.
//!
//! The walker uses syn's `VisitMut` and tracks a small context bitset
//! that controls whether a literal at the current cursor position is
//! eligible for rewriting:
//!
//! - Inside a pattern (match arm, `if let`, `while let`): skip.
//! - Inside a `const` / `static` initializer: skip.
//! - Inside an attribute argument: skip (the attribute walker never
//!   sees those expressions, so this is implicit).
//! - Inside a recognized macro invocation:
//!   - `mask!`, `maskfmt!`, `unmasked!`: already-explicit; skip.
//!   - `dbg!`, `stringify!`, `assert_eq!`, `assert_ne!` (no-message
//!     form): per §2.3.2.6 skip.
//!   - Other macros: walked normally; future Tasks 13 wrap them.

use proc_macro::TokenStream;
use proc_macro2::TokenStream as TokenStream2;
use quote::{format_ident, quote};
use syn::visit_mut::{self, VisitMut};
use syn::{Expr, ExprLit, ItemConst, ItemMod, ItemStatic, Lit, Pat, parse_macro_input};

/// Implementation of the `#[proc_macro_attribute] mask_all` entry
/// point. The attribute applies only to module items (§2.3.1.1);
/// other targets produce a `syn::Error` at expansion time.
pub(crate) fn expand(_attr: TokenStream, item: TokenStream) -> TokenStream {
    let mut module = parse_macro_input!(item as ItemMod);
    let mut walker = MaskAllWalker::default();
    walker.visit_item_mod_mut(&mut module);

    // Per spec §2.3.1.4 + amendment 2026-05-10: emit one
    // ghost-deprecation pair per skipped literal so rustc's
    // `deprecated` lint surfaces each skip in cargo's warning
    // output. Splice the anchor items into the module body.
    if let Some((_, items)) = module.content.as_mut() {
        items.extend(walker.warning_items());
    }

    quote! { #module }.into()
}

/// Reason tag for one skipped literal. Lives in the
/// `#[deprecated(note = "...")]` text so the user can grep cargo's
/// warning stream for the skip kind.
#[derive(Clone, Copy)]
enum SkipReason {
    PatternPosition,
    ConstInitializer,
    StaticInitializer,
}

impl SkipReason {
    fn tag(self) -> &'static str {
        match self {
            Self::PatternPosition => "pattern_position",
            Self::ConstInitializer => "const_initializer",
            Self::StaticInitializer => "static_initializer",
        }
    }
}

/// AST walker that rewrites eligible literal expressions to
/// `mask!(literal)`. Each `in_*_depth` counter is bumped on entry
/// to a skip context and decremented on exit. Counters rather than
/// booleans handle nested cases (e.g., `dbg!(mask!(...))` — outer
/// `dbg!` already suppresses, inner `mask!` independently suppresses)
/// without re-entering rewrite mode in the middle.
// Field names share the `_depth` suffix by intent: each is a
// stack-depth counter for the same nesting model. Clippy's
// `struct_field_names` heuristic flags this as a "same postfix"
// smell; the suffix is load-bearing here for naming consistency.
#[allow(clippy::struct_field_names)]
#[derive(Default)]
struct MaskAllWalker {
    /// Depth inside `mask!`/`maskfmt!`/`unmasked!`/`weak_mask!`/`dbg!`/
    /// `stringify!`/`assert_eq!`/`assert_ne!`.
    skip_macro_depth: usize,
    /// Depth inside a `const` initializer expression. `mask!()`
    /// returns a runtime `String`, so substituting it into a const
    /// context would fail to compile with a non-const-fn error.
    const_depth: usize,
    /// Depth inside a `static` initializer expression. Tracked
    /// separately from const so the emitted warning can name the
    /// right reason tag.
    static_depth: usize,
    /// Depth inside a `Pat` (match arm pattern, `if let`,
    /// `while let`, `let` LHS pattern). Pattern syntax does not
    /// accept arbitrary macro invocations.
    pattern_depth: usize,
    /// Skip reasons collected for each literal the walker passed
    /// over without rewriting. Translated to ghost-deprecation
    /// items in `warning_items()` after the walk completes.
    skipped: Vec<SkipReason>,
}

impl MaskAllWalker {
    /// Current skip reason for warning emission. Caller is
    /// responsible for only invoking this when at least one skip
    /// context is active; the priority order (pattern → const →
    /// static) is arbitrary but stable.
    fn current_skip_reason(&self) -> Option<SkipReason> {
        if self.pattern_depth > 0 {
            Some(SkipReason::PatternPosition)
        } else if self.const_depth > 0 {
            Some(SkipReason::ConstInitializer)
        } else if self.static_depth > 0 {
            Some(SkipReason::StaticInitializer)
        } else {
            None
        }
    }

    /// Build the ghost-deprecation pairs per amendment 2026-05-10:
    /// one `#[deprecated]` const per skip plus a synthetic anchor
    /// fn that holds a `let _ = SKIP_N;` reference for each. Rustc's
    /// `deprecated` lint fires once per anchor reference, surfacing
    /// each skip as a "warning: use of deprecated constant" line in
    /// cargo output.
    fn warning_items(&self) -> Vec<syn::Item> {
        if self.skipped.is_empty() {
            return Vec::new();
        }
        let mut items: Vec<syn::Item> = Vec::with_capacity(self.skipped.len() + 1);
        let mut anchor_refs: Vec<TokenStream2> = Vec::with_capacity(self.skipped.len());
        for (i, reason) in self.skipped.iter().enumerate() {
            let ident = format_ident!("_LITMASK_SKIP_{i}");
            let note = format!("litmask: skipped literal: {}", reason.tag());
            let const_item: syn::Item = syn::parse_quote! {
                #[deprecated(note = #note)]
                #[allow(non_upper_case_globals, dead_code)]
                const #ident: () = ();
            };
            items.push(const_item);
            anchor_refs.push(quote! { let _ = #ident; });
        }
        let anchor_fn: syn::Item = syn::parse_quote! {
            #[doc(hidden)]
            #[allow(dead_code, non_snake_case)]
            fn __litmask_skip_anchors() {
                #(#anchor_refs)*
            }
        };
        items.push(anchor_fn);
        items
    }
}

impl VisitMut for MaskAllWalker {
    fn visit_expr_mut(&mut self, expr: &mut Expr) {
        // Recurse first so inner expressions are processed bottom-up.
        // This means a literal nested inside e.g. a function call has
        // its rewrite happen before the outer expression sees it,
        // which is the desired order for replacement semantics.
        visit_mut::visit_expr_mut(self, expr);

        if !is_string_shaped_literal(expr) {
            return;
        }
        if let Some(reason) = self.current_skip_reason() {
            // Literal in a context where rewriting would be invalid
            // — but it's still a string-shaped literal worth flagging
            // (§2.3.1.4). Record the reason; ghost-deprecation
            // emission happens after the walk completes.
            self.skipped.push(reason);
            return;
        }
        if self.skip_macro_depth > 0 {
            // Inside an explicit mask/maskfmt/unmasked/dbg/etc. —
            // intentional skip per spec rationale, no warning.
            return;
        }
        if let Some(rewritten) = maybe_rewrite_literal(expr) {
            *expr = rewritten;
        }
    }

    fn visit_expr_macro_mut(&mut self, mac: &mut syn::ExprMacro) {
        let was_skip = is_skip_macro(&mac.mac);
        if was_skip {
            self.skip_macro_depth += 1;
        }
        visit_mut::visit_expr_macro_mut(self, mac);
        if was_skip {
            self.skip_macro_depth -= 1;
        }
    }

    fn visit_item_const_mut(&mut self, item: &mut ItemConst) {
        self.const_depth += 1;
        visit_mut::visit_item_const_mut(self, item);
        self.const_depth -= 1;
    }

    fn visit_item_static_mut(&mut self, item: &mut ItemStatic) {
        self.static_depth += 1;
        visit_mut::visit_item_static_mut(self, item);
        self.static_depth -= 1;
    }

    fn visit_pat_mut(&mut self, pat: &mut Pat) {
        // Record pattern literals separately from expression
        // literals: in syn 2, `Pat::Lit` carries a `Lit` directly
        // (not wrapped in `Expr::Lit`), so `visit_expr_mut` never
        // sees these. Walk before recording so nested patterns
        // (e.g., `Some("...")`) reach this arm at every depth.
        self.pattern_depth += 1;
        visit_mut::visit_pat_mut(self, pat);
        self.pattern_depth -= 1;
        if let Pat::Lit(pat_lit) = pat {
            if matches!(pat_lit.lit, Lit::Str(_) | Lit::ByteStr(_) | Lit::CStr(_)) {
                self.skipped.push(SkipReason::PatternPosition);
            }
        }
    }
}

/// True if `expr` is a bare string / byte string / C string literal
/// expression — the three kinds §2.3.2.1 targets. Used both to gate
/// rewrite emission AND to recognize when a skipped literal should
/// fire the §2.3.1.4 warning (non-string literals like numerics or
/// chars never trigger a warning even when in a skip context).
fn is_string_shaped_literal(expr: &Expr) -> bool {
    let Expr::Lit(ExprLit { lit, .. }) = expr else {
        return false;
    };
    matches!(lit, Lit::Str(_) | Lit::ByteStr(_) | Lit::CStr(_))
}

/// Return `Some(mask!(literal))` if `expr` is a bare string / byte
/// string / C string literal expression; otherwise `None`. Numeric,
/// boolean, char, and other literal kinds are left alone — only the
/// three string-shaped literal kinds are masked per §2.3.2.1.
fn maybe_rewrite_literal(expr: &Expr) -> Option<Expr> {
    let Expr::Lit(ExprLit { lit, .. }) = expr else {
        return None;
    };
    let tokens: TokenStream2 = match lit {
        Lit::Str(s) => quote! { ::litmask::mask!(#s) },
        Lit::ByteStr(s) => quote! { ::litmask::mask!(#s) },
        Lit::CStr(s) => quote! { ::litmask::mask!(#s) },
        _ => return None,
    };
    Some(syn::parse2(tokens).expect("emitted mask!(literal) parses as Expr"))
}

/// Recognize the small set of macros whose literal arguments must NOT
/// be rewritten per §2.3.1.3 + §2.3.2.6. Detection is by single-ident
/// path-segment match — qualified paths (`std::dbg!`, `core::dbg!`)
/// are not currently recognized; that nuance lands in Task 13 along
/// with the full substitution table.
fn is_skip_macro(mac: &syn::Macro) -> bool {
    let Some(ident) = mac.path.get_ident() else {
        return false;
    };
    matches!(
        ident.to_string().as_str(),
        "mask"
            | "maskfmt"
            | "unmasked"
            | "weak_mask"
            | "dbg"
            | "stringify"
            | "assert_eq"
            | "assert_ne"
    )
}
