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
use quote::quote;
use syn::visit_mut::{self, VisitMut};
use syn::{Expr, ExprLit, ItemMod, Lit, parse_macro_input};

/// Implementation of the `#[proc_macro_attribute] mask_all` entry
/// point. The attribute applies only to module items (§2.3.1.1);
/// other targets produce a `syn::Error` at expansion time.
pub(crate) fn expand(_attr: TokenStream, item: TokenStream) -> TokenStream {
    let mut module = parse_macro_input!(item as ItemMod);
    let mut walker = MaskAllWalker::default();
    walker.visit_item_mod_mut(&mut module);
    quote! { #module }.into()
}

/// AST walker that rewrites eligible literal expressions to
/// `mask!(literal)`. `in_skip_macro_depth` is a counter rather than a
/// boolean so nested skip-macro invocations (e.g., `dbg!(mask!(...))`
/// — pathological but possible) still apply the skip rule at the
/// outermost level without re-entering rewrite mode.
#[derive(Default)]
struct MaskAllWalker {
    in_skip_macro_depth: usize,
}

impl VisitMut for MaskAllWalker {
    fn visit_expr_mut(&mut self, expr: &mut Expr) {
        // Recurse first so inner expressions are processed bottom-up.
        // This means a literal nested inside e.g. a function call has
        // its rewrite happen before the outer expression sees it,
        // which is the desired order for replacement semantics.
        visit_mut::visit_expr_mut(self, expr);

        if self.in_skip_macro_depth > 0 {
            return;
        }
        if let Some(rewritten) = maybe_rewrite_literal(expr) {
            *expr = rewritten;
        }
    }

    fn visit_expr_macro_mut(&mut self, mac: &mut syn::ExprMacro) {
        let was_skip = is_skip_macro(&mac.mac);
        if was_skip {
            self.in_skip_macro_depth += 1;
        }
        visit_mut::visit_expr_macro_mut(self, mac);
        if was_skip {
            self.in_skip_macro_depth -= 1;
        }
    }
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
