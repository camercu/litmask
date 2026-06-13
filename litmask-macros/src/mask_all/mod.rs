//! `#[mask_all]` proc-macro attribute: walks the AST of an attributed
//! module and rewrites string-shaped literals into the appropriate
//! `mask!` / `mask_format!` form so that the plaintext never lands in the
//! compiled binary.
//!
//! The walker tracks a small context bitset that gates rewriting:
//!
//! - Inside a pattern (match arm, `if let`, `while let`): skip.
//! - Inside a `const` / `static` initializer: skip — `mask!()`
//!   returns a runtime `String` and cannot be evaluated at compile
//!   time.
//! - Inside attribute arguments: skip implicitly — `VisitMut` walks
//!   attribute meta items as token streams, not expressions, so they
//!   never reach the rewrite path.
//! - Inside `mask!` / `mask_format!` / `unmasked!` / `weak_mask!`: skip;
//!   the user has already made an explicit choice.
//! - Inside `dbg!` / `stringify!` / `assert_eq!` / `assert_ne!` (no
//!   custom message form): skip; the literal is used for diagnostic
//!   text rather than embedded plaintext.
//!
//! Every skip that prevents a literal from being masked emits a
//! ghost-deprecation warning so the user can grep cargo's output for
//! unintentional plaintext exposure.

use proc_macro::TokenStream;
use proc_macro2::TokenStream as TokenStream2;
use quote::{format_ident, quote};
use syn::spanned::Spanned;
use syn::visit_mut::{self, VisitMut};
use syn::{Expr, ExprLit, Item, ItemConst, ItemStatic, Lit, Pat, Stmt, parse_macro_input};

use crate::common::{FailTag, compile_error};

mod classify;
mod derives;
mod skip;

use classify::{MacroFamily, classify_macro};
use skip::{SkipReason, SkipRecord};

const MACRO_NAME: &str = "mask_all";

/// Implementation of the `#[proc_macro_attribute] mask_all` entry
/// point. The attribute applies only to module items; other targets
/// produce a typed compile error naming the constraint.
///
/// Attribute argument grammar: `#[mask_all]` (empty) or
/// `#[mask_all(strict)]`. Strict mode (§2.3.3.1) upgrades the
/// ghost-deprecation skip warnings to hard `compile_error!` items so
/// every unmasked literal forces an explicit `unmasked!()` opt-out.
pub(crate) fn expand(attr: TokenStream, item: TokenStream) -> TokenStream {
    let strict = match parse_attr_strict(attr.into()) {
        Ok(s) => s,
        Err(err) => return err.to_compile_error().into(),
    };
    let parsed = parse_macro_input!(item as Item);
    let Item::Mod(mut module) = parsed else {
        return compile_error(
            parsed.span(),
            MACRO_NAME,
            FailTag::InvalidArg,
            "applies only to module items (e.g. `#[mask_all] mod foo { ... }`)",
        )
        .to_compile_error()
        .into();
    };
    process_module(&mut module, strict);
    quote! { #module }.into()
}

/// Parse the attribute argument list. Accepts an empty arg list or
/// the bare `strict` keyword; any other token shape yields a typed
/// compile error so the user sees a specific diagnostic instead of
/// silent acceptance of an unknown flag.
fn parse_attr_strict(attr: TokenStream2) -> syn::Result<bool> {
    use syn::parse::Parser as _;
    let parser = |input: syn::parse::ParseStream| -> syn::Result<bool> {
        if input.is_empty() {
            return Ok(false);
        }
        let ident: syn::Ident = input.parse()?;
        if ident == "strict" && input.is_empty() {
            return Ok(true);
        }
        Err(syn::Error::new(
            ident.span(),
            "mask_all: invalid_arg: only `strict` is supported \
             (e.g. `#[mask_all(strict)]`)",
        ))
    };
    parser.parse2(attr)
}

/// Walk and rewrite one module's items with a fresh `MaskAllWalker`,
/// then emit that module's diagnostic items (deprecation anchors or
/// `compile_error!` calls under strict) into its own item list.
/// Recurses explicitly into nested `mod` items so each module gets
/// its own walker and its own skip anchor namespace — pooling all
/// skips at the outer mod would shift diagnostic paths up one level
/// for every nested literal. The strict flag propagates unchanged
/// into nested modules: an outer `#[mask_all(strict)]` applies to
/// every literal in every descendant module of the attributed mod.
///
/// `mod foo;` file-module forms have `content == None`; the items
/// live in a separate file the proc-macro never sees, so the module
/// passes through untouched.
fn process_module(m: &mut syn::ItemMod, strict: bool) {
    let Some((_, items)) = m.content.as_mut() else {
        return;
    };
    let mut walker = MaskAllWalker {
        strict,
        ..MaskAllWalker::default()
    };
    for item in items.iter_mut() {
        if let Item::Mod(child) = item {
            process_module(child, strict);
        } else {
            walker.visit_item_mut(item);
        }
    }
    items.extend(skip::diagnostic_items(&walker.skipped, walker.strict));
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
    /// Depth inside a `SkipExplicit` (`mask!` / `mask_format!` /
    /// `unmasked!` / `weak_mask!`) or `SkipDiagnostic` (`dbg!` /
    /// `stringify!` / bare `assert*!` family / `compile_error!` /
    /// `cfg!` / `file!` / `line!` / `column!` / `module_path!`)
    /// macro. Children inside these are not rewritten.
    skip_macro_depth: usize,
    /// Depth inside a `const` initializer expression.
    const_depth: usize,
    /// Depth inside a `static` initializer expression.
    static_depth: usize,
    /// Depth inside a `Pat` (match arm pattern, `if let`,
    /// `while let`, `let` LHS pattern).
    pattern_depth: usize,
    /// `#[mask_all(strict)]` (§2.3.3.1): every skip becomes a hard
    /// `compile_error!` instead of a ghost-deprecation warning.
    strict: bool,
    /// Skip reasons collected for each literal the walker passed
    /// over without rewriting. Translated to ghost-deprecation
    /// items (or `compile_error!` items under `strict`) in
    /// [`skip::diagnostic_items`] after the walk completes.
    skipped: Vec<SkipRecord>,
}

impl MaskAllWalker {
    /// True when the walker is in a position where emitting a
    /// `SkipReason` warning is meaningful: outside skip-list macros
    /// and outside any pattern / const / static context that would
    /// have its own dedicated reason.
    fn in_warnable_context(&self) -> bool {
        self.skip_macro_depth == 0 && self.current_skip_reason().is_none()
    }

    /// Current skip reason for warning emission. Returns `None` when
    /// no skip-context is active. The priority order (pattern →
    /// const → static) is most-local-context-first: when a pattern
    /// literal appears inside a `const` initializer, the pattern
    /// position is the proximate cause and gives the more useful
    /// warning.
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

    /// Single dispatch for macro-family rewrites. Returns the
    /// rewritten `Expr` if any family applies; otherwise `None`.
    /// Side effect: appends a `SkipReason::UnrecognizedMacro` to
    /// `self.skipped` for each string-literal argument of a
    /// user-defined macro.
    fn try_rewrite_macro(&mut self, expr: &Expr) -> Option<Expr> {
        let Expr::Macro(em) = expr else { return None };
        match classify_macro(&em.mac) {
            MacroFamily::RewriteToMasked { masked_name } => {
                Some(rewrite_to_masked(em, masked_name))
            }
            MacroFamily::Format => self.rewrite_or_warn(em, 0, RewriteShape::Replace),
            MacroFamily::Output | MacroFamily::Panic => {
                self.rewrite_or_warn(em, 0, RewriteShape::Wrap)
            }
            MacroFamily::Write => self.rewrite_or_warn(em, 1, RewriteShape::Wrap),
            MacroFamily::AssertWithMessage { head_arity } => {
                self.rewrite_or_warn(em, head_arity, RewriteShape::Wrap)
            }
            MacroFamily::UserDefined => {
                for lit_span in string_literal_spans(&em.mac.tokens) {
                    self.skipped.push(SkipRecord::from_span(
                        SkipReason::UnrecognizedMacro,
                        lit_span,
                    ));
                }
                None
            }
            MacroFamily::SkipExplicit | MacroFamily::SkipDiagnostic => None,
        }
    }

    /// Rewrite a "head, template, args..." macro, or record a skip.
    /// Classifies the body in a single pass via [`classify_template`]:
    /// - `Literal`: emit the `mask_format!`-based rewrite.
    /// - `NonLiteral`: the template arg exists but is not a `LitStr`
    ///   (e.g., `format!(concat!(...), ...)`); record a
    ///   `NonLiteralTemplate` skip so the macro warns in non-strict
    ///   mode and hard-errors under `#[mask_all(strict)]`
    ///   (§2.3.2.2–§2.3.2.4, §2.3.3.1).
    /// - `Absent`: empty body, too few args, or a malformed body —
    ///   nothing the walker could have masked, left untouched with no
    ///   warning so rustc surfaces any genuine error from the
    ///   original invocation.
    fn rewrite_or_warn(
        &mut self,
        em: &syn::ExprMacro,
        head_arity: usize,
        shape: RewriteShape,
    ) -> Option<Expr> {
        match classify_template(&em.mac.tokens, head_arity) {
            TemplateParse::Literal(head_and_rest) => Some(build_rewrite(em, head_and_rest, shape)),
            TemplateParse::NonLiteral => {
                self.skipped.push(SkipRecord::from_span(
                    SkipReason::NonLiteralTemplate,
                    em.mac.path.span(),
                ));
                None
            }
            TemplateParse::Absent => None,
        }
    }
}

/// Build the rewritten expression for a macro whose template parsed as
/// a `LitStr`. `shape` controls the outer form:
/// - `RewriteShape::Replace`: the entire invocation becomes a single
///   `mask_format!(...)` call (used for `format!`).
/// - `RewriteShape::Wrap`: the invocation becomes a block that binds
///   the masked string and calls the original macro with the head
///   positions followed by `"{}", __s` (used for output / write /
///   panic / assert).
fn build_rewrite(em: &syn::ExprMacro, head_and_rest: HeadAndTemplate, shape: RewriteShape) -> Expr {
    let HeadAndTemplate {
        head_tokens,
        template_and_args,
    } = head_and_rest;
    let macro_name = &em
        .mac
        .path
        .segments
        .last()
        .expect("classified path has a last segment")
        .ident;
    let s = mixed_site_s();
    match shape {
        RewriteShape::Replace => syn::parse_quote! {
            ::litmask::mask_format!(#template_and_args)
        },
        RewriteShape::Wrap => {
            let head_prefix = if head_tokens.is_empty() {
                quote! {}
            } else {
                quote! { #head_tokens, }
            };
            syn::parse_quote! {{
                let #s = ::litmask::mask_format!(#template_and_args);
                #macro_name!(#head_prefix "{}", #s)
            }}
        }
    }
}

#[derive(Clone, Copy)]
enum RewriteShape {
    /// Replace the entire invocation with a `mask_format!(...)` call.
    Replace,
    /// Wrap as `{ let __s = mask_format!(...); <macro>(<head>, "{}", __s) }`.
    Wrap,
}

struct HeadAndTemplate {
    /// Token stream for the head args (everything before the
    /// template). Empty for macros where the template is the first
    /// argument (`format!`, `println!`, `panic!`).
    head_tokens: TokenStream2,
    /// Token stream for the template + format args. The template is
    /// the first token here and is guaranteed to parse as a
    /// `LitStr`; what follows are the format args.
    template_and_args: TokenStream2,
}

/// Outcome of classifying a "head, template, args..." macro body. The
/// three variants are mutually exclusive and cover every shape
/// `rewrite_or_warn` must distinguish.
enum TemplateParse {
    /// The arg at index `head_arity` is a `LitStr`. Carries the head
    /// tokens and template-and-args tail, ready for [`build_rewrite`].
    Literal(HeadAndTemplate),
    /// A template arg is present at the expected position but is not a
    /// string literal (e.g. `format!(concat!(...), ...)` or
    /// `assert!(cond, my_err)`). Warned per §2.3.2.2–§2.3.2.4.
    NonLiteral,
    /// Empty body (`panic!()`), too few args, or a malformed body. No
    /// literal the walker could have masked; left untouched with no
    /// warning so rustc surfaces any genuine error from the original
    /// invocation.
    Absent,
}

/// Classify a macro body as `head_args[..head_arity], template, rest`
/// in a single parse pass. Walking the body once answers the three
/// questions `rewrite_or_warn` needs — rewritable literal template,
/// warnable non-literal template, or nothing maskable — without
/// re-parsing the same token stream twice.
fn classify_template(tokens: &TokenStream2, head_arity: usize) -> TemplateParse {
    use syn::parse::Parser as _;
    let parser = move |input: syn::parse::ParseStream| -> syn::Result<TemplateParse> {
        let mut head_pieces: Vec<TokenStream2> = Vec::with_capacity(head_arity);
        for _ in 0..head_arity {
            let head_expr: syn::Expr = input.parse()?;
            input.parse::<syn::Token![,]>()?;
            head_pieces.push(quote! { #head_expr });
        }
        // No template arg at all (e.g. `panic!()`): nothing to mask.
        if input.is_empty() {
            return Ok(TemplateParse::Absent);
        }
        // Peek the template position: a non-`LitStr` here is the
        // warnable case, not a parse error. Drain the rest so the
        // outer `parse2` sees a fully-consumed stream (an early
        // return with tokens left would surface as a parse error
        // and misclassify as `Absent`).
        if input.fork().parse::<syn::LitStr>().is_err() {
            let _rest: TokenStream2 = input.parse()?;
            return Ok(TemplateParse::NonLiteral);
        }
        let template_and_args: TokenStream2 = input.parse()?;
        let head_tokens = if head_pieces.is_empty() {
            TokenStream2::new()
        } else {
            quote! { #(#head_pieces),* }
        };
        Ok(TemplateParse::Literal(HeadAndTemplate {
            head_tokens,
            template_and_args,
        }))
    };
    // A parse error means too few head args or a malformed body:
    // benign, leave it untouched (rustc reports any real error).
    parser
        .parse2(tokens.clone())
        .unwrap_or(TemplateParse::Absent)
}

fn mixed_site_s() -> syn::Ident {
    syn::Ident::new("__s", proc_macro2::Span::mixed_site())
}

impl VisitMut for MaskAllWalker {
    fn visit_item_mut(&mut self, item: &mut Item) {
        // Swap a type's plain `#[derive(Serialize/Deserialize/Debug)]`
        // for litmask's masking derives so the container / field /
        // variant names don't re-enter `.rodata` as cleartext — the
        // leak the literal-rewrite pass cannot reach. A type carrying
        // the `#[unmasked_derive]` opt-out keeps its plain derives;
        // the marker is stripped either way. Serde swapping is gated
        // on `unstable-serde` because the masking serde derives only
        // exist under that feature. Recursion (literal masking) still
        // descends into the item afterward, opt-out or not.
        let serde_enabled = cfg!(feature = "unstable-serde");
        match item {
            Item::Struct(s) => {
                if !derives::take_opt_out(&mut s.attrs) {
                    derives::rewrite_derives(&mut s.attrs, serde_enabled);
                }
            }
            Item::Enum(e) => {
                if !derives::take_opt_out(&mut e.attrs) {
                    derives::rewrite_derives(&mut e.attrs, serde_enabled);
                }
            }
            _ => {}
        }
        visit_mut::visit_item_mut(self, item);
    }

    fn visit_expr_mut(&mut self, expr: &mut Expr) {
        // Recurse first so inner expressions are processed bottom-up.
        visit_mut::visit_expr_mut(self, expr);

        if self.in_warnable_context() {
            if let Some(rewritten) = self.try_rewrite_macro(expr) {
                *expr = rewritten;
                return;
            }
        }

        let Some(rewritten) = maybe_rewrite_string_literal(expr) else {
            return;
        };
        if let Some(reason) = self.current_skip_reason() {
            self.skipped
                .push(SkipRecord::from_span(reason, expr.span()));
        } else if self.skip_macro_depth == 0 {
            *expr = rewritten;
        }
    }

    fn visit_expr_macro_mut(&mut self, mac: &mut syn::ExprMacro) {
        let family = classify_macro(&mac.mac);
        let bump = matches!(
            family,
            MacroFamily::SkipExplicit | MacroFamily::SkipDiagnostic
        );
        if bump {
            self.skip_macro_depth += 1;
        }
        visit_mut::visit_expr_macro_mut(self, mac);
        if bump {
            self.skip_macro_depth -= 1;
        }
    }

    fn visit_item_mod_mut(&mut self, m: &mut syn::ItemMod) {
        // Inline `mod inner { ... }` items (e.g. nested inside a
        // function body or a block) get their own sub-walker so the
        // inner mod's skip anchors land in `inner::__litmask_skips`
        // rather than pooling at the outer mod's namespace. Do not
        // recurse via `visit_mut::visit_item_mod_mut(self, m)` — that
        // would re-pool everything into `self.skipped`. Strict mode
        // propagates: an outer `#[mask_all(strict)]` constrains every
        // descendant module the same way.
        process_module(m, self.strict);
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
        // `format!(...);` as a statement, etc.) parse as `Stmt::Macro`,
        // NOT `Stmt::Expr(Expr::Macro)`. `visit_expr_mut` never sees
        // them. Promote known macro families to a block expression
        // here.
        let Stmt::Macro(stmt_mac) = stmt else { return };
        if !self.in_warnable_context() {
            return;
        }
        // Synthesize an Expr::Macro from the Stmt::Macro and run it
        // through the same rewrite pipeline used by visit_expr_mut.
        // The original statement's semicolon token (or absence
        // thereof) is preserved on the rewritten Stmt::Expr so the
        // expression-statement vs trailing-expression distinction is
        // honored.
        let synthetic_expr = Expr::Macro(syn::ExprMacro {
            attrs: stmt_mac.attrs.clone(),
            mac: stmt_mac.mac.clone(),
        });
        if let Some(rewritten) = self.try_rewrite_macro(&synthetic_expr) {
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
        if let Pat::Lit(pat_lit) = pat
            && matches!(pat_lit.lit, Lit::Str(_) | Lit::ByteStr(_) | Lit::CStr(_))
        {
            self.skipped.push(SkipRecord::from_span(
                SkipReason::PatternPosition,
                pat_lit.lit.span(),
            ));
        }
    }
}

/// Replace the macro path of `em` with `::litmask::<masked_name>`,
/// preserving its argument tokens. Used by the `RewriteToMasked`
/// family to swap stdlib compile-time macros (`include_str!`,
/// `concat!`, `env!`, etc.) for their dedicated litmask
/// counterparts.
fn rewrite_to_masked(em: &syn::ExprMacro, masked_name: &str) -> Expr {
    let masked_ident = format_ident!("{masked_name}");
    let path: syn::Path = syn::parse_quote! { ::litmask::#masked_ident };
    Expr::Macro(syn::ExprMacro {
        attrs: em.attrs.clone(),
        mac: syn::Macro {
            path,
            bang_token: em.mac.bang_token,
            delimiter: em.mac.delimiter.clone(),
            tokens: em.mac.tokens.clone(),
        },
    })
}

/// Return `Some(mask!(literal))` if `expr` is a bare string / byte
/// string / C string literal expression; otherwise `None`. Numeric,
/// boolean, char, and other literal kinds are out of scope and
/// produce neither a rewrite nor a warning.
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

/// Collect the spans of every string-shaped literal token-tree in
/// `tokens`, recursing into groups (parens / brackets / braces).
/// Used to emit one `UnrecognizedMacro` skip per string literal
/// argument to a user-defined macro, each carrying the literal's
/// own source location.
///
/// Each `TokenTree::Literal` is routed through `syn::parse2::<Lit>`
/// so raw forms (`r"..."`, `br"..."`, `cr"..."`) classify uniformly
/// with their quoted counterparts. The literal's own span is
/// preserved through the parse so the resulting [`SkipRecord`]
/// points at the literal, not at the macro path.
fn string_literal_spans(tokens: &TokenStream2) -> Vec<proc_macro2::Span> {
    let mut out = Vec::new();
    collect_string_literal_spans(tokens, &mut out);
    out
}

fn collect_string_literal_spans(tokens: &TokenStream2, out: &mut Vec<proc_macro2::Span>) {
    for tt in tokens.clone() {
        match tt {
            proc_macro2::TokenTree::Literal(lit) => {
                let span = lit.span();
                let ts = TokenStream2::from(proc_macro2::TokenTree::Literal(lit));
                if let Ok(parsed) = syn::parse2::<Lit>(ts)
                    && matches!(parsed, Lit::Str(_) | Lit::ByteStr(_) | Lit::CStr(_))
                {
                    out.push(span);
                }
            }
            proc_macro2::TokenTree::Group(g) => {
                collect_string_literal_spans(&g.stream(), out);
            }
            _ => {}
        }
    }
}
