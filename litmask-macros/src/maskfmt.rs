//! `maskfmt!` proc-macro: format-string template whose literal fragments
//! are individually masked via [`crate::mask::expand`] and spliced with
//! the formatted arguments at runtime.
//!
//! Template parsing happens here at proc-macro time; only the
//! per-placeholder format specs (e.g. `{:.2}`, `{:?}`) appear in the
//! compiled binary — the template text never does. Placeholder names
//! (named arguments and implicit captures) are rewritten to positional
//! references against an internal binding table, so the names never
//! survive into the compiled output (§2.2.2.2).

use proc_macro::TokenStream;
use proc_macro2::TokenStream as TokenStream2;
use quote::quote;
use syn::parse::{Parse, ParseStream};
use syn::punctuated::Punctuated;
use syn::spanned::Spanned;
use syn::{Expr, LitStr, Token, parse_macro_input};

/// §1.9.6 mandates this exact substring when `maskfmt!`'s template
/// argument is not a string literal.
const MASKFMT_NON_LITERAL_MSG: &str = "maskfmt! requires a string literal template at the call site; use `mask!` to decrypt a runtime string";

/// Implementation of the `#[proc_macro] maskfmt` entry point.
///
/// Supports positional placeholders (`{}`, `{N}`), named arguments
/// (`maskfmt!("{x}", x = e)`), implicit captures (`{var}` where `var`
/// is a local in scope), and dynamic width/precision (`{:>w$}`,
/// `{:.p$}`) per spec §2.2.2.
///
/// # Compile errors
///
/// - Non-literal template → §1.9.6 substring "maskfmt! requires a
///   string literal template at the call site".
/// - Positional argument after a named argument → typed error.
/// - Out-of-range positional index → typed error.
/// - Unused positional argument → typed error (mirrors `format!`).
///
/// # Panics
///
/// Inherits [`crate::mask::expand`]'s expansion-time panic policy
/// (missing `OUT_DIR`, unreadable build artifact, AEAD failure).
pub(crate) fn expand(input: TokenStream) -> TokenStream {
    let parsed = parse_macro_input!(input as MaskfmtInput);
    match maskfmt_expand(&parsed) {
        Ok(ts) => ts.into(),
        Err(e) => e.to_compile_error().into(),
    }
}

/// Parsed `maskfmt!(...)` input — the literal template plus the
/// raw argument list, which may mix positional exprs and `name = expr`
/// named-argument forms.
struct MaskfmtInput {
    template: LitStr,
    args: Punctuated<Expr, Token![,]>,
}

impl Parse for MaskfmtInput {
    fn parse(input: ParseStream) -> syn::Result<Self> {
        if !input.peek(LitStr) {
            return Err(syn::Error::new(input.span(), MASKFMT_NON_LITERAL_MSG));
        }
        let template: LitStr = input.parse()?;
        let args = if input.is_empty() {
            Punctuated::new()
        } else {
            let _: Token![,] = input.parse()?;
            Punctuated::parse_terminated(input)?
        };
        Ok(MaskfmtInput { template, args })
    }
}

/// `(ident, value-expression)` pair for one named argument.
type NamedArg = (syn::Ident, Expr);

/// Split the args list into positional + named. Two `format!`-style
/// invariants are enforced as `syn::Error`s, both with the user's
/// span so the diagnostic lands on the offending source:
///
/// - Positional args must precede named args (mirrors `format!`).
/// - Each name appears at most once across the named-args list.
///   Without this check, a duplicate silently shadows the earlier
///   binding in the internal layout and surfaces as a stray
///   `unused variable: maskfmt_arg_N` later — a diagnostic that
///   points at proc-macro-generated identifiers and confuses the
///   caller.
fn split_args(args: &Punctuated<Expr, Token![,]>) -> syn::Result<(Vec<Expr>, Vec<NamedArg>)> {
    let mut positional: Vec<Expr> = Vec::new();
    let mut named: Vec<NamedArg> = Vec::new();
    for expr in args {
        if let Some((name, value)) = as_named_arg(expr) {
            if let Some((prev, _)) = named.iter().find(|(n, _)| n == &name) {
                return Err(syn::Error::new(
                    name.span(),
                    format!(
                        "duplicate named argument `{prev}` in maskfmt! (each name may appear at most once)",
                    ),
                ));
            }
            named.push((name, value));
        } else {
            if !named.is_empty() {
                return Err(syn::Error::new(
                    expr.span(),
                    "positional arguments must precede named arguments in maskfmt!",
                ));
            }
            positional.push(expr.clone());
        }
    }
    Ok((positional, named))
}

/// If `expr` is `<ident> = <value>` with a simple single-segment
/// path on the left, return the `(name, value)` pair (cloning both
/// halves so the caller owns them). Otherwise return `None` — the
/// expression is a positional argument.
fn as_named_arg(expr: &Expr) -> Option<NamedArg> {
    let Expr::Assign(assign) = expr else {
        return None;
    };
    let Expr::Path(path) = &*assign.left else {
        return None;
    };
    if path.qself.is_some() || path.path.segments.len() != 1 {
        return None;
    }
    let seg = &path.path.segments[0];
    if !seg.arguments.is_none() {
        return None;
    }
    Some((seg.ident.clone(), (*assign.right).clone()))
}

/// A placeholder reference — either a positional index (from `{}`,
/// `{N}`, or `<N>$`; bare `{}` resolves to the next auto-positional
/// index during parsing) or an identifier from `{name}` / `<name>$`.
#[derive(Clone, Debug)]
enum TemplateRef {
    Positional(usize),
    Named(String),
}

/// One placeholder parsed from the template. `value` is the main
/// argument being formatted; `spec_refs` are the dynamic width /
/// precision references found inside the spec text (e.g. `w` in
/// `{:>w$}`). `spec_raw` is the spec text as written, with
/// `<token>$` patterns left in their source form; resolution
/// rewrites them to positional indices when building the per-
/// placeholder format template.
#[derive(Debug)]
struct ParsedPlaceholder {
    value: TemplateRef,
    spec_refs: Vec<TemplateRef>,
    spec_raw: String,
}

fn maskfmt_expand(parsed: &MaskfmtInput) -> syn::Result<TokenStream2> {
    let template_span = parsed.template.span();
    let template_value = parsed.template.value();
    let (fragments, placeholders) =
        parse_maskfmt_template(&template_value).map_err(|m| syn::Error::new(template_span, m))?;

    let (positional, named) = split_args(&parsed.args)?;
    let positional_count = positional.len();

    // Resolve every TemplateRef in every placeholder to a binding
    // index in the internal layout described on `Bindings`. Implicit
    // captures are discovered here in first-reference order.
    let mut bindings = Bindings::new(positional_count, &named);
    let resolved = resolve_placeholders(&placeholders, &mut bindings, template_span)?;
    check_unused_positionals(&resolved, positional_count, template_span)?;

    // `mixed_site` hygiene on the LHS keeps each `maskfmt_arg_<i>`
    // binding isolated from the caller's namespace — required because
    // implicit captures emit the user's bare identifier on the RHS
    // (e.g. `let maskfmt_arg_3 = &var;`) and call_site resolution there
    // would otherwise risk capturing our own LHS name.
    let arg_idents: Vec<syn::Ident> = (0..bindings.total())
        .map(|i| syn::Ident::new(&format!("maskfmt_arg_{i}"), proc_macro2::Span::mixed_site()))
        .collect();
    let arg_bindings: Vec<TokenStream2> = bindings
        .binding_exprs(&positional, &named)
        .iter()
        .zip(arg_idents.iter())
        .map(|(expr, name)| quote! { let #name = #expr; })
        .collect();

    // Hygienic output binding name — call_site idents in the user's
    // scope cannot collide with it. Built once and reused at the
    // declaration site, every fragment/placeholder write, and the
    // tail expression.
    let out_ident = syn::Ident::new("maskfmt_out", proc_macro2::Span::mixed_site());

    // Each placeholder's `format_args!` template + ref list is
    // identical between the runtime write and the compile-time
    // type-check; compute once, share between both builders.
    let emissions: Vec<(String, Vec<usize>)> =
        resolved.iter().map(build_placeholder_emission).collect();

    let writes = build_writes(&fragments, &resolved, &emissions, &arg_idents, &out_ident);
    let arg_checks = build_arg_checks(&emissions, &arg_idents);

    Ok(quote! {
        {
            #(#arg_bindings)*
            #(#arg_checks)*
            let mut #out_ident = ::std::string::String::new();
            #(#writes)*
            #out_ident
        }
    })
}

/// Walk parsed placeholders + resolve every `TemplateRef` against
/// the binding table. Implicit captures are discovered here in
/// first-reference order via `Bindings::resolve`.
fn resolve_placeholders(
    placeholders: &[ParsedPlaceholder],
    bindings: &mut Bindings,
    template_span: proc_macro2::Span,
) -> syn::Result<Vec<ResolvedPlaceholder>> {
    let mut resolved: Vec<ResolvedPlaceholder> = Vec::with_capacity(placeholders.len());
    for ph in placeholders {
        let value_idx = bindings.resolve(&ph.value, template_span)?;
        let mut spec_idxs: Vec<usize> = Vec::with_capacity(ph.spec_refs.len());
        for sr in &ph.spec_refs {
            spec_idxs.push(bindings.resolve(sr, template_span)?);
        }
        resolved.push(ResolvedPlaceholder {
            value_idx,
            spec_idxs,
            spec_raw: ph.spec_raw.clone(),
        });
    }
    Ok(resolved)
}

/// §2.2.3.2: mirror `format!`'s "positional argument never used"
/// hard error. Implicit captures and named args don't get this
/// check — format! doesn't either.
fn check_unused_positionals(
    resolved: &[ResolvedPlaceholder],
    positional_count: usize,
    template_span: proc_macro2::Span,
) -> syn::Result<()> {
    let mut used = vec![false; positional_count];
    for r in resolved {
        for idx in std::iter::once(r.value_idx).chain(r.spec_idxs.iter().copied()) {
            if idx < positional_count {
                used[idx] = true;
            }
        }
    }
    for (i, &was_used) in used.iter().enumerate() {
        if !was_used {
            return Err(syn::Error::new(
                template_span,
                format!(
                    "positional argument {i} is never used (give it a placeholder or remove it from the maskfmt! call)",
                ),
            ));
        }
    }
    Ok(())
}

/// Interleave fragment + placeholder writes. Each fragment is masked
/// individually via `mask!()` (§2.2.2.1); each placeholder lands as
/// its own `format_args!` over only the bindings it references,
/// with the spec text rewritten so any `<token>$` resolves to a
/// LOCAL positional index — placeholder names never reach
/// `format_args!`'s argument list either.
fn build_writes(
    fragments: &[String],
    resolved: &[ResolvedPlaceholder],
    emissions: &[(String, Vec<usize>)],
    arg_idents: &[syn::Ident],
    out_ident: &syn::Ident,
) -> Vec<TokenStream2> {
    let mut writes: Vec<TokenStream2> = Vec::new();
    for (i, fragment) in fragments.iter().enumerate() {
        if !fragment.is_empty() {
            writes.push(quote! {
                ::std::fmt::Write::write_str(
                    &mut #out_ident,
                    &::litmask::mask!(#fragment),
                ).unwrap();
            });
        }
        if resolved.get(i).is_some() {
            let args = placeholder_format_args(&emissions[i], arg_idents);
            writes.push(quote! {
                ::std::fmt::Write::write_fmt(&mut #out_ident, #args).unwrap();
            });
        }
    }
    writes
}

/// Per-placeholder compile-time type-check, separate from the
/// runtime write. Catches spec/type incompatibility early without
/// leaking the surrounding template text — each `format_args!`
/// here carries only one placeholder's spec plus its bindings.
fn build_arg_checks(
    emissions: &[(String, Vec<usize>)],
    arg_idents: &[syn::Ident],
) -> Vec<TokenStream2> {
    emissions
        .iter()
        .map(|emission| {
            let args = placeholder_format_args(emission, arg_idents);
            quote! { let _ = #args; }
        })
        .collect()
}

/// Render a single placeholder's `format_args!(template, refs...)`
/// call. Shared by the runtime write path and the compile-time
/// type-check path; both wrap the same call in different shells.
fn placeholder_format_args(
    emission: &(String, Vec<usize>),
    arg_idents: &[syn::Ident],
) -> TokenStream2 {
    let (template, refs) = emission;
    let refs_tokens: Vec<&syn::Ident> = refs.iter().map(|&idx| &arg_idents[idx]).collect();
    quote! { ::core::format_args!(#template #(, #refs_tokens)*) }
}

/// Internal binding layout: positional args first (indices `0..P`),
/// then named args in declaration order (`P..P+N`), then implicit
/// captures in first-reference order (`P+N..P+N+I`). Resolution maps
/// every `TemplateRef` to a single index in this space.
struct Bindings {
    positional_count: usize,
    named_idx: std::collections::BTreeMap<String, usize>, // ident → P + i
    implicit: Vec<syn::Ident>,                            // first-ref order
    implicit_idx: std::collections::BTreeMap<String, usize>,
    base_for_implicit: usize, // = P + N
}

impl Bindings {
    fn new(positional_count: usize, named: &[NamedArg]) -> Self {
        let mut named_idx = std::collections::BTreeMap::new();
        for (i, (ident, _)) in named.iter().enumerate() {
            named_idx.insert(ident.to_string(), positional_count + i);
        }
        Self {
            positional_count,
            base_for_implicit: positional_count + named.len(),
            named_idx,
            implicit: Vec::new(),
            implicit_idx: std::collections::BTreeMap::new(),
        }
    }

    fn total(&self) -> usize {
        self.base_for_implicit + self.implicit.len()
    }

    fn resolve(&mut self, r: &TemplateRef, span: proc_macro2::Span) -> syn::Result<usize> {
        match r {
            TemplateRef::Positional(k) => {
                if *k >= self.positional_count {
                    return Err(syn::Error::new(
                        span,
                        format!(
                            "positional argument {k} not provided to maskfmt! (only {} given)",
                            self.positional_count,
                        ),
                    ));
                }
                Ok(*k)
            }
            TemplateRef::Named(name) => {
                if let Some(&idx) = self.named_idx.get(name) {
                    return Ok(idx);
                }
                if let Some(&idx) = self.implicit_idx.get(name) {
                    return Ok(idx);
                }
                // Implicit capture: register the ident with call-site
                // resolution so it picks up the caller's local of the
                // same name, mirroring `format!("{var}")`'s behavior.
                let ident = syn::Ident::new(name, proc_macro2::Span::call_site());
                let idx = self.base_for_implicit + self.implicit.len();
                self.implicit_idx.insert(name.clone(), idx);
                self.implicit.push(ident);
                Ok(idx)
            }
        }
    }

    /// Return the per-binding initializer expressions in layout
    /// order: positional exprs verbatim, named arg RHS exprs in
    /// declaration order, then bare-ident exprs for each implicit
    /// capture (which resolve at the call site).
    fn binding_exprs(&self, positional: &[Expr], named: &[NamedArg]) -> Vec<TokenStream2> {
        let mut out: Vec<TokenStream2> = Vec::with_capacity(self.total());
        for e in positional {
            out.push(quote! { #e });
        }
        for (_, e) in named {
            out.push(quote! { #e });
        }
        // Implicit-capture bindings reference the caller's local by
        // name. Take a borrow rather than moving: matches `format!`'s
        // borrow semantics for `{var}` (locals stay usable after the
        // call) and works for both Copy and non-Copy types.
        for ident in &self.implicit {
            out.push(quote! { &#ident });
        }
        out
    }
}

/// A placeholder after binding resolution. The spec text still
/// contains source-form refs (`<token>$`); rewriting to local indices
/// happens in `build_placeholder_emission`.
#[derive(Debug)]
struct ResolvedPlaceholder {
    value_idx: usize,
    spec_idxs: Vec<usize>,
    spec_raw: String,
}

/// Produce the per-placeholder `format_args!` template + the list of
/// binding indices it references (in local-positional order). The
/// template embeds local positional indices (`{0}`, `{1:>2$}`, etc.)
/// so the runtime `format_args!` resolves references against the
/// passed-in argument list rather than against names.
fn build_placeholder_emission(ph: &ResolvedPlaceholder) -> (String, Vec<usize>) {
    // Local-positional layout: the value is always local index 0;
    // spec refs follow in declaration order, deduplicated by binding
    // index so a placeholder like `{:>w$.w$}` only passes `w` once
    // to `format_args!`.
    let mut refs: Vec<usize> = Vec::with_capacity(1 + ph.spec_idxs.len());
    refs.push(ph.value_idx);
    let mut binding_to_local: std::collections::BTreeMap<usize, usize> =
        std::collections::BTreeMap::new();
    binding_to_local.insert(ph.value_idx, 0);
    for &b in &ph.spec_idxs {
        binding_to_local.entry(b).or_insert_with(|| {
            let local = refs.len();
            refs.push(b);
            local
        });
    }

    // Precompute the per-$-token local index in source order so the
    // rewriter walks the spec linearly — one $-token consumes one
    // entry of `local_idx_in_source_order`. This avoids re-scanning
    // the spec for each token, which would be O(K^2).
    let local_idx_in_source_order: Vec<usize> =
        ph.spec_idxs.iter().map(|b| binding_to_local[b]).collect();
    let spec_rewritten = rewrite_spec_refs(&ph.spec_raw, &local_idx_in_source_order);

    let template = if spec_rewritten.is_empty() {
        "{0}".to_string()
    } else {
        format!("{{0:{spec_rewritten}}}")
    };
    (template, refs)
}

/// Chars permitted in a placeholder name or numeric index — both
/// positions accept the same alphabet, so a single predicate covers
/// the start char and the continuation chars uniformly.
fn is_token_char(c: char) -> bool {
    c.is_ascii_digit() || c == '_' || c.is_alphabetic()
}

/// Walk `spec`, replacing the i-th `<token>$` substring with
/// `<resolved[i]>$`. Non-`$`-suffixed token runs and all other
/// characters pass through verbatim.
///
/// Precondition: `resolved.len()` equals the count of source-order
/// `<token>$` substrings in `spec`. The parser builds both lists in
/// lockstep (`ParsedPlaceholder::spec_refs`), so this is invariant
/// by construction; a mismatch trips the `unreachable!()` below.
fn rewrite_spec_refs(spec: &str, resolved: &[usize]) -> String {
    use std::fmt::Write as _;
    let chars: Vec<char> = spec.chars().collect();
    let mut out = String::with_capacity(spec.len());
    let mut i = 0;
    let mut next_resolved = 0;
    while i < chars.len() {
        if is_token_char(chars[i]) {
            let start = i;
            while i < chars.len() && is_token_char(chars[i]) {
                i += 1;
            }
            if i < chars.len() && chars[i] == '$' {
                let idx = *resolved.get(next_resolved).unwrap_or_else(|| {
                    unreachable!("rewrite_spec_refs: resolved list shorter than $-tokens in spec")
                });
                next_resolved += 1;
                let _ = write!(out, "{idx}$");
                i += 1;
                continue;
            }
            out.extend(&chars[start..i]);
            continue;
        }
        out.push(chars[i]);
        i += 1;
    }
    out
}

/// Walk the user's template once, emitting alternating literal
/// fragments and parsed placeholders. The result invariant is
/// `fragments.len() == placeholders.len() + 1`.
fn parse_maskfmt_template(s: &str) -> Result<(Vec<String>, Vec<ParsedPlaceholder>), String> {
    let mut fragments = vec![String::new()];
    let mut placeholders: Vec<ParsedPlaceholder> = Vec::new();
    let mut next_auto = 0_usize;
    let mut chars = s.chars().peekable();

    while let Some(ch) = chars.next() {
        match ch {
            '{' => {
                if chars.peek() == Some(&'{') {
                    chars.next();
                    fragments.last_mut().unwrap().push('{');
                    continue;
                }
                let placeholder = parse_placeholder_body(&mut chars, &mut next_auto)?;
                placeholders.push(placeholder);
                fragments.push(String::new());
            }
            '}' => {
                if chars.peek() == Some(&'}') {
                    chars.next();
                    fragments.last_mut().unwrap().push('}');
                } else {
                    return Err(
                        "unmatched `}` in maskfmt! template; use `}}` to print a literal `}`"
                            .to_string(),
                    );
                }
            }
            c => fragments.last_mut().unwrap().push(c),
        }
    }

    Ok((fragments, placeholders))
}

/// Parse the inside of a single `{...}` placeholder. The opening
/// `{` has already been consumed; this consumes through the closing
/// `}` and returns the parsed placeholder.
fn parse_placeholder_body(
    chars: &mut std::iter::Peekable<std::str::Chars<'_>>,
    next_auto: &mut usize,
) -> Result<ParsedPlaceholder, String> {
    let header = consume_placeholder_header(chars)?;
    let value = resolve_value_ref(&header, next_auto)?;
    let (spec_raw, spec_refs) = consume_placeholder_spec(chars)?;
    Ok(ParsedPlaceholder {
        value,
        spec_refs,
        spec_raw,
    })
}

/// Consume the placeholder's header — the chars between `{` and
/// either `:` or `}`. Empty header means bare `{}`; all-digit means
/// explicit positional; identifier means named / implicit-capture.
fn consume_placeholder_header(
    chars: &mut std::iter::Peekable<std::str::Chars<'_>>,
) -> Result<String, String> {
    let mut header = String::new();
    while let Some(&c) = chars.peek() {
        if c == ':' || c == '}' {
            break;
        }
        if !is_token_char(c) {
            return Err(format!(
                "unexpected `{c}` inside `{{...}}` placeholder in maskfmt! template",
            ));
        }
        header.push(c);
        chars.next();
    }
    Ok(header)
}

fn resolve_value_ref(header: &str, next_auto: &mut usize) -> Result<TemplateRef, String> {
    if header.is_empty() {
        let i = *next_auto;
        *next_auto = next_auto.checked_add(1).ok_or_else(|| {
            "too many auto-positional placeholders in maskfmt! template".to_string()
        })?;
        Ok(TemplateRef::Positional(i))
    } else if header.chars().all(|c| c.is_ascii_digit()) {
        let i = header
            .parse::<usize>()
            .map_err(|_| "invalid positional index in maskfmt! template".to_string())?;
        Ok(TemplateRef::Positional(i))
    } else {
        Ok(TemplateRef::Named(header.to_string()))
    }
}

/// Consume the placeholder's spec — everything between an optional
/// `:` and the closing `}`. Collects `<token>$` patterns as
/// `TemplateRef`s in source order; the spec text itself is preserved
/// verbatim for later rewriting in `build_placeholder_emission`.
fn consume_placeholder_spec(
    chars: &mut std::iter::Peekable<std::str::Chars<'_>>,
) -> Result<(String, Vec<TemplateRef>), String> {
    // Caller has already consumed the header. The next char tells us
    // whether a spec follows (`:`) or the placeholder closes here
    // (`}`); anything else means an unterminated `{...}`.
    match chars.next() {
        Some(':') => {}
        Some('}') => return Ok((String::new(), Vec::new())),
        _ => return Err("unclosed `{...}` placeholder in maskfmt! template".to_string()),
    }

    let mut spec_raw = String::new();
    let mut spec_refs: Vec<TemplateRef> = Vec::new();
    let mut token = String::new();
    loop {
        let Some(c) = chars.next() else {
            return Err("unclosed `{...}` placeholder in maskfmt! template".to_string());
        };
        match c {
            '}' => break,
            '{' => {
                return Err(
                    "nested `{` inside maskfmt! placeholder spec; use `<name>$` for dynamic width / precision"
                        .to_string(),
                );
            }
            _ => {
                spec_raw.push(c);
                if is_token_char(c) {
                    token.push(c);
                } else if c == '$' && !token.is_empty() {
                    spec_refs.push(make_template_ref(&token));
                    token.clear();
                } else {
                    token.clear();
                }
            }
        }
    }
    Ok((spec_raw, spec_refs))
}

fn make_template_ref(token: &str) -> TemplateRef {
    if token.chars().all(|c| c.is_ascii_digit()) {
        TemplateRef::Positional(token.parse::<usize>().expect("all-digits parses as usize"))
    } else {
        TemplateRef::Named(token.to_string())
    }
}
