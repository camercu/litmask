//! `#[mask_all]` proc-macro attribute: walks the AST of an attributed
//! module and rewrites string-shaped literals into the appropriate
//! `mask!` / `maskfmt!` form so that the plaintext never lands in the
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
//! - Inside `mask!` / `maskfmt!` / `unmasked!` / `weak_mask!`: skip;
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

/// Implementation of the `#[proc_macro_attribute] mask_all` entry
/// point. The attribute applies only to module items; other targets
/// produce a typed compile error naming the constraint.
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
    process_module(&mut module);
    quote! { #module }.into()
}

/// Walk and rewrite one module's items with a fresh `MaskAllWalker`,
/// then emit that module's `__litmask_skips` submodule (if any skips
/// fired) into its own item list. Recurses explicitly into nested
/// `mod` items so each module gets its own walker and its own skip
/// anchor namespace — pooling all skips at the outer mod would
/// shift diagnostic paths up one level for every nested literal.
///
/// `mod foo;` file-module forms have `content == None`; the items
/// live in a separate file the proc-macro never sees, so the module
/// passes through untouched.
fn process_module(m: &mut syn::ItemMod) {
    let Some((_, items)) = m.content.as_mut() else {
        return;
    };
    let mut walker = MaskAllWalker::default();
    for item in items.iter_mut() {
        if let Item::Mod(child) = item {
            process_module(child);
        } else {
            walker.visit_item_mut(item);
        }
    }
    items.extend(walker.warning_items());
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
    /// String-shaped literal argument to a macro the walker doesn't
    /// recognize (neither in the skip list nor in any of the rewrite
    /// families). The literal is left alone and a warning fires per
    /// occurrence.
    UnrecognizedMacro,
}

impl SkipReason {
    fn note(self) -> &'static str {
        match self {
            Self::PatternPosition => "litmask: skipped literal: pattern_position",
            Self::ConstInitializer => "litmask: skipped literal: const_initializer",
            Self::StaticInitializer => "litmask: skipped literal: static_initializer",
            Self::UnrecognizedMacro => "litmask: skipped literal: unrecognized_macro",
        }
    }
}

/// Recognized macro families. Returned by [`classify_macro`] for each
/// macro invocation encountered during the walk. The classification
/// depends on the macro's path (last segment, so qualified paths like
/// `std::format!` are recognized) and, for the assert family, on the
/// argument count (the no-message form takes a different path from
/// the custom-message form).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum MacroFamily {
    /// `mask!`, `maskfmt!`, `unmasked!`, `weak_mask!` — explicit user
    /// choice; never rewritten, never warned.
    SkipExplicit,
    /// `dbg!`, `stringify!`, `compile_error!`, `cfg!`, `file!`,
    /// `line!`, `column!`, `module_path!`; the no-message form of
    /// `assert!` / `assert_eq!` / `assert_ne!`; and **all** forms of
    /// the `debug_assert!` family (`debug_assert!`,
    /// `debug_assert_eq!`, `debug_assert_ne!`, with or without a
    /// message). Left alone with no warning. Release builds strip
    /// `debug_assert!` bodies via `cfg!(debug_assertions)`, so
    /// masking their messages would add a `.rodata` blob and a
    /// runtime decrypt that's never observed in shipping binaries.
    SkipDiagnostic,
    /// `format!` — rewritten to `maskfmt!`.
    Format,
    /// `println!`, `eprintln!`, `print!`, `eprint!` — wrapped via
    /// `maskfmt!` and re-emitted with a `"{}"` placeholder for the
    /// formatted result.
    Output,
    /// `write!`, `writeln!` — like [`Output`] but the writer occupies
    /// the first argument; the template starts at argument index 1.
    Write,
    /// `panic!`, `todo!`, `unimplemented!`, `unreachable!` — wrapped
    /// via `maskfmt!`, preserving the unwinding behavior.
    Panic,
    /// `assert!` with a custom-message argument, or `assert_eq!` /
    /// `assert_ne!` with the equivalent custom-message form. The
    /// condition (and values, for the equality variants) stay
    /// positional; the message is masked. `head_arity` is 1 for
    /// `assert!` (just the condition) and 2 for the equality
    /// asserts (both operands). The `debug_assert!` family does
    /// **not** route here — see `SkipDiagnostic`.
    AssertWithMessage { head_arity: usize },
    /// `include_str!` or `concat!` — the entire invocation is wrapped
    /// in `mask!()`. The wrapped invocation is resolved at proc-macro
    /// expansion time by `mask!`'s grammar and the resulting bytes
    /// are masked exactly like a bare literal.
    IncludeConcat,
    /// Anything not recognized above. Literal arguments fall through
    /// unmasked and the walker emits a warning per literal so the
    /// user is alerted.
    UserDefined,
}

/// Classify a macro invocation by its path. Qualified paths
/// (`std::format!`, `core::dbg!`, `::std::panic!`) are recognized by
/// matching the last path segment, so the stdlib paths interoperate
/// the same as their unqualified forms.
fn classify_macro(mac: &syn::Macro) -> MacroFamily {
    let Some(name) = macro_last_segment(mac) else {
        return MacroFamily::UserDefined;
    };
    match name.as_str() {
        "mask" | "maskfmt" | "unmasked" | "weak_mask" => MacroFamily::SkipExplicit,
        // `debug_assert!` / `_eq!` / `_ne!` expand to
        // `if cfg!(debug_assertions) { assert!(...) }`; release
        // builds dead-code-eliminate the body, so masking the
        // message would generate a `.rodata` blob and a runtime
        // decrypt that's discarded — pure cost for no release-
        // binary benefit. Treat the whole debug-assert family as
        // diagnostic-only regardless of the message form.
        "dbg" | "stringify" | "compile_error" | "cfg" | "file" | "line" | "column"
        | "module_path" | "debug_assert" | "debug_assert_eq" | "debug_assert_ne" => {
            MacroFamily::SkipDiagnostic
        }
        "assert" => {
            // assert!(cond) — no message; assert!(cond, msg, ...) — with.
            if count_top_level_args(&mac.tokens) >= 2 {
                MacroFamily::AssertWithMessage { head_arity: 1 }
            } else {
                MacroFamily::SkipDiagnostic
            }
        }
        "assert_eq" | "assert_ne" => {
            // assert_eq!(a, b) — no message; assert_eq!(a, b, msg, ...) — with.
            if count_top_level_args(&mac.tokens) >= 3 {
                MacroFamily::AssertWithMessage { head_arity: 2 }
            } else {
                MacroFamily::SkipDiagnostic
            }
        }
        "format" => MacroFamily::Format,
        "println" | "eprintln" | "print" | "eprint" => MacroFamily::Output,
        "write" | "writeln" => MacroFamily::Write,
        "panic" | "todo" | "unimplemented" | "unreachable" => MacroFamily::Panic,
        "include_str" | "concat" => MacroFamily::IncludeConcat,
        _ => MacroFamily::UserDefined,
    }
}

fn macro_last_segment(mac: &syn::Macro) -> Option<String> {
    Some(mac.path.segments.last()?.ident.to_string())
}

/// Count top-level comma-separated arguments in a macro body.
/// Commas inside parenthesized or bracketed sub-expressions are
/// not counted as separators because `Punctuated::<Expr, _>::parse_terminated`
/// honors expression nesting. Returns 0 if the body is empty or
/// fails to parse as a comma-separated argument list.
fn count_top_level_args(tokens: &TokenStream2) -> usize {
    use syn::parse::Parser as _;
    let parser = |input: syn::parse::ParseStream| -> syn::Result<usize> {
        let punct: syn::punctuated::Punctuated<syn::Expr, syn::Token![,]> =
            syn::punctuated::Punctuated::parse_terminated(input)?;
        Ok(punct.len())
    };
    parser.parse2(tokens.clone()).unwrap_or(0)
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
    /// Depth inside a `SkipExplicit` (`mask!` / `maskfmt!` /
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
    /// Skip reasons collected for each literal the walker passed
    /// over without rewriting. Translated to ghost-deprecation
    /// items in `warning_items()` after the walk completes.
    skipped: Vec<SkipReason>,
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

    /// Build a hidden submodule housing one `#[deprecated]` const per
    /// skip plus a synthetic anchor fn that references each. Rustc's
    /// `deprecated` lint fires once per reference, surfacing each
    /// skip as a "use of deprecated constant" line in cargo output.
    /// The submodule (`__litmask_skips`) scopes the consts so they
    /// don't pollute the user-visible identifier namespace of the
    /// attributed module.
    fn warning_items(&self) -> Vec<syn::Item> {
        if self.skipped.is_empty() {
            return Vec::new();
        }
        let mut const_items: Vec<TokenStream2> = Vec::with_capacity(self.skipped.len());
        let mut anchor_refs: Vec<TokenStream2> = Vec::with_capacity(self.skipped.len());
        for (i, reason) in self.skipped.iter().enumerate() {
            let ident = format_ident!("_LITMASK_SKIP_{i}");
            let note = reason.note();
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

    /// Single dispatch for macro-family rewrites. Returns the
    /// rewritten `Expr` if any family applies; otherwise `None`.
    /// Side effect: appends a `SkipReason::UnrecognizedMacro` to
    /// `self.skipped` for each string-literal argument of a
    /// user-defined macro.
    fn try_rewrite_macro(&mut self, expr: &Expr) -> Option<Expr> {
        let Expr::Macro(em) = expr else { return None };
        match classify_macro(&em.mac) {
            MacroFamily::IncludeConcat => Some(wrap_include_or_concat(em)),
            MacroFamily::Format => Self::rewrite_template(em, 0, RewriteShape::Replace),
            MacroFamily::Output | MacroFamily::Panic => {
                Self::rewrite_template(em, 0, RewriteShape::Wrap)
            }
            MacroFamily::Write => Self::rewrite_template(em, 1, RewriteShape::Wrap),
            MacroFamily::AssertWithMessage { head_arity } => {
                Self::rewrite_template(em, head_arity, RewriteShape::Wrap)
            }
            MacroFamily::UserDefined => {
                for _ in 0..count_string_literal_tokens(&em.mac.tokens) {
                    self.skipped.push(SkipReason::UnrecognizedMacro);
                }
                None
            }
            MacroFamily::SkipExplicit | MacroFamily::SkipDiagnostic => None,
        }
    }

    /// Generic rewriter for "head, template, args..." macros:
    /// - parses the body as `(head_exprs[..head_arity], template,
    ///   rest)`,
    /// - if the template parses as a `LitStr`, emits a `maskfmt!`-
    ///   based rewrite,
    /// - otherwise returns `None` silently — an empty body
    ///   (`panic!()`), a non-literal template (`format!(my_tmpl,
    ///   ...)`), or a non-literal message (`assert!(cond, my_err)`)
    ///   all reach this path and none contain a literal the walker
    ///   could have masked. Genuine syntax errors inside the macro
    ///   body still surface to the user via rustc's expansion of the
    ///   original unaltered macro.
    ///
    /// `shape` controls the outer form:
    /// - `RewriteShape::Replace`: the entire invocation becomes a
    ///   single `maskfmt!(...)` call (used for `format!`).
    /// - `RewriteShape::Wrap`: the invocation becomes a block that
    ///   binds the masked string and calls the original macro with
    ///   the head positions followed by `"{}", __s` (used for
    ///   output / write / panic / assert).
    fn rewrite_template(
        em: &syn::ExprMacro,
        head_arity: usize,
        shape: RewriteShape,
    ) -> Option<Expr> {
        let head_and_rest = parse_head_and_template(&em.mac.tokens, head_arity)?;
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
        let rewritten: Expr = match shape {
            RewriteShape::Replace => syn::parse_quote! {
                ::litmask::maskfmt!(#template_and_args)
            },
            RewriteShape::Wrap => {
                let head_prefix = if head_tokens.is_empty() {
                    quote! {}
                } else {
                    quote! { #head_tokens, }
                };
                syn::parse_quote! {{
                    let #s = ::litmask::maskfmt!(#template_and_args);
                    #macro_name!(#head_prefix "{}", #s)
                }}
            }
        };
        Some(rewritten)
    }
}

#[derive(Clone, Copy)]
enum RewriteShape {
    /// Replace the entire invocation with a `maskfmt!(...)` call.
    Replace,
    /// Wrap as `{ let __s = maskfmt!(...); <macro>(<head>, "{}", __s) }`.
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

/// Parse a macro body as `head_args[..head_arity], template, rest`.
/// Returns `None` if the body has fewer than `head_arity + 1` args,
/// or if the argument at index `head_arity` is not a string literal.
fn parse_head_and_template(tokens: &TokenStream2, head_arity: usize) -> Option<HeadAndTemplate> {
    use syn::parse::Parser as _;
    let parser = move |input: syn::parse::ParseStream| -> syn::Result<HeadAndTemplate> {
        let mut head_pieces: Vec<TokenStream2> = Vec::with_capacity(head_arity);
        for _ in 0..head_arity {
            let head_expr: syn::Expr = input.parse()?;
            input.parse::<syn::Token![,]>()?;
            head_pieces.push(quote! { #head_expr });
        }
        // Peek to ensure the next token actually IS a string literal
        // — non-literal templates fall through to `NonLiteralTemplate`
        // skip emission instead of attempting a rewrite.
        let _template: syn::LitStr = input.fork().parse()?;
        let template_and_args: TokenStream2 = input.parse()?;
        let head_tokens = if head_pieces.is_empty() {
            TokenStream2::new()
        } else {
            quote! { #(#head_pieces),* }
        };
        Ok(HeadAndTemplate {
            head_tokens,
            template_and_args,
        })
    };
    parser.parse2(tokens.clone()).ok()
}

fn mixed_site_s() -> syn::Ident {
    syn::Ident::new("__s", proc_macro2::Span::mixed_site())
}

impl VisitMut for MaskAllWalker {
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
            self.skipped.push(reason);
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
        // would re-pool everything into `self.skipped`.
        process_module(m);
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
            self.skipped.push(SkipReason::PatternPosition);
        }
    }
}

/// Wrap `include_str!(...)` or `concat!(...)` in `mask!()`. Produces
/// the literal source form `mask!(include_str!(...))` /
/// `mask!(concat!(...))`, which `mask!`'s grammar accepts and
/// resolves at proc-macro expansion time.
fn wrap_include_or_concat(em: &syn::ExprMacro) -> Expr {
    syn::parse_quote! { ::litmask::mask!(#em) }
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

/// Count string-shaped literal token-trees in `tokens`, recursing
/// into groups (parens / brackets / braces). Used to emit one
/// `UnrecognizedMacro` warning per string literal argument to a
/// user-defined macro. The recursion is intentional: a literal
/// nested inside an inner expression of a user-defined macro is
/// still data the walker cannot mask and still warrants a warning.
///
/// Each `TokenTree::Literal` is routed through `syn::parse2::<Lit>`
/// so raw forms (`r"..."`, `br"..."`, `cr"..."`) classify uniformly
/// with their quoted counterparts.
fn count_string_literal_tokens(tokens: &TokenStream2) -> usize {
    let mut count = 0;
    for tt in tokens.clone() {
        match tt {
            proc_macro2::TokenTree::Literal(lit) => {
                let ts = TokenStream2::from(proc_macro2::TokenTree::Literal(lit));
                if let Ok(parsed) = syn::parse2::<Lit>(ts)
                    && matches!(parsed, Lit::Str(_) | Lit::ByteStr(_) | Lit::CStr(_))
                {
                    count += 1;
                }
            }
            proc_macro2::TokenTree::Group(g) => {
                count += count_string_literal_tokens(&g.stream());
            }
            _ => {}
        }
    }
    count
}
