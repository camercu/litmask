//! The rewrite mechanics for `#[mask_all]`: pure token transforms that
//! turn a recognized macro invocation or a bare literal into its masked
//! form. These carry no walker state — the [`super::MaskAllWalker`]
//! decides *when* to rewrite (context, skip tracking); this module
//! decides *how*.

use proc_macro2::TokenStream as TokenStream2;
use quote::{format_ident, quote};
use syn::{Expr, ExprLit, Lit};

/// Build the rewritten expression for a macro whose template parsed as
/// a `LitStr`. `shape` controls the outer form:
/// - `RewriteShape::Replace`: the entire invocation becomes a single
///   `mask_format!(...)` call (used for `format!`).
/// - `RewriteShape::Wrap`: the invocation becomes a block that binds
///   the masked string and calls the original macro with the head
///   positions followed by `"{}", __s` (used for output / write /
///   panic / assert).
pub(super) fn build_rewrite(
    em: &syn::ExprMacro,
    head_and_rest: HeadAndTemplate,
    shape: RewriteShape,
) -> Expr {
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
pub(super) enum RewriteShape {
    /// Replace the entire invocation with a `mask_format!(...)` call.
    Replace,
    /// Wrap as `{ let __s = mask_format!(...); <macro>(<head>, "{}", __s) }`.
    Wrap,
}

pub(super) struct HeadAndTemplate {
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
pub(super) enum TemplateParse {
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
pub(super) fn classify_template(tokens: &TokenStream2, head_arity: usize) -> TemplateParse {
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

/// Replace the macro path of `em` with `::litmask::<masked_name>`,
/// preserving its argument tokens. Used by the `RewriteToMasked`
/// family to swap stdlib compile-time macros (`include_str!`,
/// `concat!`, `env!`, etc.) for their dedicated litmask
/// counterparts.
pub(super) fn rewrite_to_masked(em: &syn::ExprMacro, masked_name: &str) -> Expr {
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
pub(super) fn maybe_rewrite_string_literal(expr: &Expr) -> Option<Expr> {
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
/// preserved through the parse so the resulting [`super::SkipRecord`]
/// points at the literal, not at the macro path.
pub(super) fn string_literal_spans(tokens: &TokenStream2) -> Vec<proc_macro2::Span> {
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
