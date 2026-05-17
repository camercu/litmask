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
use syn::spanned::Spanned;
use syn::visit_mut::{self, VisitMut};
use syn::{Expr, ExprLit, Item, ItemConst, ItemStatic, Lit, Pat, Stmt, parse_macro_input};

/// Implementation of the `#[proc_macro_attribute] mask_all` entry
/// point. The attribute applies only to module items (§2.3.1.1);
/// other targets produce a typed compile error naming the constraint
/// (rather than the opaque "expected `mod`" syn parse error that
/// `parse_macro_input!(item as ItemMod)` alone would produce).
pub(crate) fn expand(_attr: TokenStream, item: TokenStream) -> TokenStream {
    let parsed = parse_macro_input!(item as Item);
    let Item::Mod(mut module) = parsed else {
        return syn::Error::new(
            parsed.span(),
            "#[mask_all] applies only to module items (e.g. `#[mask_all] mod foo { ... }`)",
        )
        .to_compile_error()
        .into();
    };
    let mut walker = MaskAllWalker::default();
    walker.visit_item_mod_mut(&mut module);

    // Per spec §2.3.1.4 + amendment 2026-05-10: emit one
    // ghost-deprecation pair per skipped literal so rustc's
    // `deprecated` lint surfaces each skip in cargo's warning
    // output. Splice the anchor items into the module body.
    //
    // `module.content` is `None` for the `mod foo;` file-module
    // form — the actual items live in another file we never see.
    // Pass that form through unchanged; users wanting `#[mask_all]`
    // semantics there can apply the attribute inside the target
    // file's root module instead.
    if let Some((_, items)) = module.content.as_mut() {
        items.extend(walker.warning_items());
    }

    quote! { #module }.into()
}

/// Reason tag for one skipped literal. Lives in the
/// `#[deprecated(note = "...")]` text so the user can grep cargo's
/// warning stream for the skip kind. The note string is fully
/// preformatted per variant so emission doesn't allocate.
#[derive(Clone, Copy)]
enum SkipReason {
    PatternPosition,
    ConstInitializer,
    StaticInitializer,
}

impl SkipReason {
    fn note(self) -> &'static str {
        match self {
            Self::PatternPosition => "litmask: skipped literal: pattern_position",
            Self::ConstInitializer => "litmask: skipped literal: const_initializer",
            Self::StaticInitializer => "litmask: skipped literal: static_initializer",
        }
    }
}

/// AST walker that rewrites eligible literal expressions to
/// `mask!(literal)`. Each `*_depth` field is bumped on entry to a
/// skip context and decremented on exit. Counters rather than
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
    /// Current skip reason for warning emission. Returns `None` when
    /// no skip-context is active. The priority order (pattern →
    /// const → static) is most-local-context-first: when a pattern
    /// literal appears inside a `const` initializer, the pattern
    /// position is the proximate cause and gives the more useful
    /// warning. The three counters can in principle overlap; only
    /// one reason ever lands in the warning text.
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
            let note = reason.note();
            // `dead_code` is load-bearing: the const has no public
            // callers besides the anchor fn below (which itself has
            // `#[allow(dead_code)]`). Without it, every skip would
            // emit a competing `unused constant` warning.
            let const_item: syn::Item = syn::parse_quote! {
                #[deprecated(note = #note)]
                #[allow(dead_code)]
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

        // §2.3.2.2 + §2.3.2.3 + §2.3.2.5: macro-family rewrites.
        // Each helper recognizes one family by macro path;
        // literal-template checking happens inside. Order doesn't
        // matter — the helpers' path matches are disjoint.
        if self.skip_macro_depth == 0 && self.current_skip_reason().is_none() {
            if let Some(wrapped) = maybe_wrap_include_or_concat(expr) {
                *expr = wrapped;
                return;
            }
            if let Some(rewritten) = maybe_rewrite_format(expr) {
                *expr = rewritten;
                return;
            }
            if let Some(rewritten) = maybe_rewrite_output_macro(expr) {
                *expr = rewritten;
                return;
            }
        }

        let Some(rewritten) = maybe_rewrite_string_literal(expr) else {
            return;
        };
        if let Some(reason) = self.current_skip_reason() {
            // Literal in a context where rewriting would be invalid
            // (§2.3.1.3). Record the reason; ghost-deprecation
            // emission happens after the walk completes.
            self.skipped.push(reason);
        } else if self.skip_macro_depth == 0 {
            // Outside every skip context — rewrite. Skip-macro
            // depth produces no warning by design: those macro
            // invocations are intentional opt-outs.
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

    fn visit_stmt_mut(&mut self, stmt: &mut Stmt) {
        // Recurse first so the rewrite operates on already-walked
        // children if any.
        visit_mut::visit_stmt_mut(self, stmt);

        // Statement-position macro invocations (`println!(...);`,
        // `format!(...);` used as a statement, etc.) parse as
        // `Stmt::Macro`, NOT `Stmt::Expr(Expr::Macro)`. `visit_expr_mut`
        // never sees them. Promote known macro families to a block
        // expression here.
        let Stmt::Macro(stmt_mac) = stmt else { return };
        if self.skip_macro_depth > 0 || self.current_skip_reason().is_some() {
            return;
        }
        // Synthesize an Expr::Macro from the Stmt::Macro and run it
        // through the same rewrite pipeline used by visit_expr_mut.
        let synthetic_expr = Expr::Macro(syn::ExprMacro {
            attrs: stmt_mac.attrs.clone(),
            mac: stmt_mac.mac.clone(),
        });
        let rewritten = maybe_wrap_include_or_concat(&synthetic_expr)
            .or_else(|| maybe_rewrite_format(&synthetic_expr))
            .or_else(|| maybe_rewrite_output_macro(&synthetic_expr));
        if let Some(rewritten) = rewritten {
            *stmt = Stmt::Expr(rewritten, stmt_mac.semi_token);
        }
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

/// Return `Some({ let __s = maskfmt!(...); println!("{}", __s) })`
/// if `expr` is an output-macro invocation (`println!` / `eprintln!`
/// / `print!` / `eprint!`) whose template is a string literal, per
/// §2.3.2.3. The rewrite preserves the original macro's return type
/// and side effects (stdout/stderr writes, line termination); only
/// the format-string materialization moves into `maskfmt!`. The
/// `__s` binding uses `Span::mixed_site()` hygiene so a caller with
/// their own `__s` in scope doesn't collide.
///
/// `write!` / `writeln!` are intentionally NOT recognized here:
/// they take the writer as their first argument, so the literal
/// template appears in the second position. They land in a follow-up
/// commit alongside the panic family that also has variant
/// argument shapes.
fn maybe_rewrite_output_macro(expr: &Expr) -> Option<Expr> {
    const OUTPUT_MACROS: &[&str] = &["println", "eprintln", "print", "eprint"];
    let Expr::Macro(em) = expr else {
        return None;
    };
    let ident = em.mac.path.get_ident()?;
    if !OUTPUT_MACROS.iter().any(|name| ident == name) {
        return None;
    }
    if !macro_starts_with_str_lit(&em.mac) {
        return None;
    }
    let tokens = &em.mac.tokens;
    let s = syn::Ident::new("__s", proc_macro2::Span::mixed_site());
    Some(syn::parse_quote! {{
        let #s = ::litmask::maskfmt!(#tokens);
        #ident!("{}", #s)
    }})
}

/// Return `Some(maskfmt!(...))` if `expr` is a `format!(literal, ...)`
/// macro invocation, per §2.3.2.2. The literal-template check uses
/// syn to peek the first token as a `LitStr`; only `format!`
/// invocations whose first argument is a string literal are
/// rewritten — non-literal-template forms are left alone here and
/// will fall through to the §2.3.2.7 user-defined-macro warning
/// path in a later phase.
fn maybe_rewrite_format(expr: &Expr) -> Option<Expr> {
    let Expr::Macro(em) = expr else {
        return None;
    };
    let ident = em.mac.path.get_ident()?;
    if ident != "format" {
        return None;
    }
    if !macro_starts_with_str_lit(&em.mac) {
        return None;
    }
    let tokens = &em.mac.tokens;
    Some(syn::parse_quote! { ::litmask::maskfmt!(#tokens) })
}

/// True if `mac`'s body parses as `LitStr [, ...]` — i.e., the first
/// argument is a string literal. Used by §2.3.2.2 and §2.3.2.3 /
/// §2.3.2.4 (when those phases land) to distinguish literal-template
/// from non-literal-template macro invocations.
fn macro_starts_with_str_lit(mac: &syn::Macro) -> bool {
    use syn::parse::Parser as _;
    let parser = |input: syn::parse::ParseStream| -> syn::Result<()> {
        input.parse::<syn::LitStr>()?;
        Ok(())
    };
    parser.parse2(mac.tokens.clone()).is_ok()
}

/// Return `Some(mask!(<expr>))` if `expr` is an `include_str!(...)`
/// or `concat!(...)` macro invocation, per §2.3.2.5. The wrap
/// produces the literal source form `mask!(include_str!(...))` /
/// `mask!(concat!(...))`, which `mask!`'s extended grammar
/// (§2.1.1.14) accepts and resolves at proc-macro time. Returns
/// `None` for any other expression — including macro invocations
/// whose paths don't match.
fn maybe_wrap_include_or_concat(expr: &Expr) -> Option<Expr> {
    let Expr::Macro(em) = expr else {
        return None;
    };
    let ident = em.mac.path.get_ident()?;
    if !(ident == "include_str" || ident == "concat") {
        return None;
    }
    Some(syn::parse_quote! { ::litmask::mask!(#em) })
}

/// Return `Some(mask!(literal))` if `expr` is a bare string / byte
/// string / C string literal expression; otherwise `None`. The three
/// string-shaped literal kinds §2.3.2.1 targets are the only ones
/// considered — numeric, boolean, char, and other `Lit` variants
/// are out of scope and produce no rewrite and no warning.
///
/// The returned `Expr` is the rewritten form. The caller decides
/// whether to install it (free literal, not in any skip context) or
/// just record a skip (literal in a pattern / const / static).
fn maybe_rewrite_string_literal(expr: &Expr) -> Option<Expr> {
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
///
/// Comparison uses `proc_macro2::Ident == &str` directly so the
/// hot path (every macro invocation in the user's module) doesn't
/// pay a per-call `Ident::to_string` allocation.
fn is_skip_macro(mac: &syn::Macro) -> bool {
    const SKIP_LIST: &[&str] = &[
        "mask",
        "maskfmt",
        "unmasked",
        "weak_mask",
        "dbg",
        "stringify",
        "assert_eq",
        "assert_ne",
    ];
    let Some(ident) = mac.path.get_ident() else {
        return false;
    };
    SKIP_LIST.iter().any(|name| ident == name)
}
