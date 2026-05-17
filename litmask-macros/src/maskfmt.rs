//! `maskfmt!` proc-macro: format-string template whose literal fragments
//! are individually masked via [`crate::mask::expand`] and spliced with
//! the formatted positional arguments at runtime.
//!
//! Template parsing happens here at proc-macro time; only the
//! per-placeholder format specs (e.g. `{:.2}`, `{:?}`) appear in the
//! compiled binary — the template text never does.

use proc_macro::TokenStream;
use proc_macro2::TokenStream as TokenStream2;
use quote::quote;
use syn::parse::{Parse, ParseStream};
use syn::punctuated::Punctuated;
use syn::{Expr, LitStr, Token, parse_macro_input};

/// §1.9.6 mandates this exact substring when `maskfmt!`'s template
/// argument is not a string literal.
const MASKFMT_NON_LITERAL_MSG: &str = "maskfmt! requires a string literal template at the call site; use `mask!` to decrypt a runtime string";

/// Implementation of the `#[proc_macro] maskfmt` entry point.
///
/// Task 10 supports positional placeholders only. Named arguments
/// (`{name}`) and implicit captures (`{var}`) land in Task 11; the
/// parser rejects them with a typed error today.
///
/// # Compile errors
///
/// - Non-literal template → §1.9.6 substring "maskfmt! requires a
///   string literal template at the call site".
/// - Named / implicit-capture placeholder → deferred-feature error.
/// - Positional index out of range → typed error.
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

struct MaskfmtPlaceholder {
    /// Positional index into the user's argument list.
    index: usize,
    /// Format spec after the colon, e.g. `"?"`, `">10"`, `".2"`.
    /// Empty when the placeholder was bare `{}` / `{N}`.
    spec: String,
}

fn maskfmt_expand(parsed: &MaskfmtInput) -> syn::Result<TokenStream2> {
    let template_span = parsed.template.span();
    let template_value = parsed.template.value();
    let (fragments, placeholders) =
        parse_maskfmt_template(&template_value).map_err(|m| syn::Error::new(template_span, m))?;

    let arg_count = parsed.args.len();
    for ph in &placeholders {
        if ph.index >= arg_count {
            return Err(syn::Error::new(
                template_span,
                format!(
                    "positional argument {} not provided to maskfmt! (only {} given)",
                    ph.index, arg_count
                ),
            ));
        }
    }
    // §2.2.3.2 mirrors `format!`'s arg-count check, which is a hard
    // rustc error (not a lint). Detect unused positional args at
    // proc-macro time so the failure mode matches `format!()` —
    // relying on `unused_variables` would only fire under
    // `-D warnings`, leaving stock builds permissive.
    let used: Vec<usize> = placeholders.iter().map(|ph| ph.index).collect();
    for i in 0..arg_count {
        if !used.contains(&i) {
            return Err(syn::Error::new(
                template_span,
                format!(
                    "positional argument {i} is never used (give it a placeholder or remove it from the maskfmt! call)",
                ),
            ));
        }
    }

    // Bind each user-supplied expression to a stable local exactly
    // once, matching format!()'s single-evaluation guarantee (§2.2.3.1).
    //
    // Two non-obvious choices in the binding name:
    // 1. `Span::mixed_site()` hygiene isolates the name from the
    //    caller's identifier namespace. A user writing
    //    `maskfmt!("{}", maskfmt_arg_0)` (with their own
    //    `maskfmt_arg_0` in scope) sees their identifier resolve at
    //    the call site, not our internal binding.
    // 2. No leading underscore. Rust suppresses `unused_variables`
    //    on `_`-prefixed names, which would silently accept extra
    //    arguments — but §2.2.3.2 requires `format!`'s arg-count
    //    check. A binding the placeholders never reference now
    //    fires `unused_variables`, which CI's `-D warnings` upgrades
    //    to a compile error.
    let arg_idents: Vec<syn::Ident> = (0..arg_count)
        .map(|i| syn::Ident::new(&format!("maskfmt_arg_{i}"), proc_macro2::Span::mixed_site()))
        .collect();
    let arg_bindings = arg_idents
        .iter()
        .zip(parsed.args.iter())
        .map(|(name, expr)| {
            quote! { let #name = #expr; }
        });

    // Canonical `{:spec}` (or `{}`) template per placeholder. Computed
    // once and reused for both the compile-time type check and the
    // runtime write — same spec, same canonical form.
    let placeholder_templates: Vec<String> = placeholders
        .iter()
        .map(|ph| placeholder_spec_to_format_template(&ph.spec))
        .collect();

    // Per-placeholder compile-time type validation, separate from the
    // runtime write. Catches spec/type incompatibility early without
    // leaking the surrounding template text — each `format_args!`
    // carries only the per-placeholder spec.
    let arg_checks = placeholders
        .iter()
        .zip(&placeholder_templates)
        .map(|(ph, check_template)| {
            let arg = &arg_idents[ph.index];
            quote! { let _ = ::core::format_args!(#check_template, #arg); }
        });

    // Hygienic output identifier — `mixed_site` isolates the binding
    // from caller scope, parallel to the `maskfmt_arg_N` hygiene.
    let out_ident = syn::Ident::new("maskfmt_out", proc_macro2::Span::mixed_site());

    // Interleave fragment + placeholder writes. Skip empty fragments
    // so we don't pay for a mask!() round-trip on a zero-byte literal.
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
        if let Some(ph) = placeholders.get(i) {
            let arg = &arg_idents[ph.index];
            let write_template = &placeholder_templates[i];
            writes.push(quote! {
                ::std::fmt::Write::write_fmt(
                    &mut #out_ident,
                    ::core::format_args!(#write_template, #arg),
                ).unwrap();
            });
        }
    }

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

/// Reassemble a placeholder's spec into the canonical `{:spec}` shape
/// that `format_args!()` accepts. Empty spec collapses to `"{}"`
/// rather than `"{:}"` for clarity in emitted code.
fn placeholder_spec_to_format_template(spec: &str) -> String {
    if spec.is_empty() {
        "{}".to_string()
    } else {
        format!("{{:{spec}}}")
    }
}

/// Walk the user's template once, emitting alternating literal
/// fragments and parsed placeholders. The result invariant is
/// `fragments.len() == placeholders.len() + 1`.
fn parse_maskfmt_template(s: &str) -> Result<(Vec<String>, Vec<MaskfmtPlaceholder>), String> {
    let mut fragments = vec![String::new()];
    let mut placeholders: Vec<MaskfmtPlaceholder> = Vec::new();
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
                // Parse optional positional index.
                let mut index_str = String::new();
                while let Some(&c) = chars.peek() {
                    if c.is_ascii_digit() {
                        index_str.push(c);
                        chars.next();
                    } else {
                        break;
                    }
                }
                // Reject named arguments and implicit captures for
                // Task 10's positional-only scope. Identifier-leading
                // chars in placeholder position are the signal.
                if let Some(&c) = chars.peek()
                    && (c.is_alphabetic() || c == '_')
                {
                    return Err(
                        "named arguments and implicit captures are not yet supported by maskfmt!"
                            .to_string(),
                    );
                }
                let index = if index_str.is_empty() {
                    let i = next_auto;
                    next_auto = next_auto.checked_add(1).ok_or_else(|| {
                        "too many auto-positional placeholders in maskfmt! template".to_string()
                    })?;
                    i
                } else {
                    index_str
                        .parse::<usize>()
                        .map_err(|_| "invalid positional index in maskfmt! template".to_string())?
                };
                let mut spec = String::new();
                match chars.next() {
                    Some(':') => loop {
                        match chars.next() {
                            Some('}') => break,
                            // Dynamic width / precision (`{:>{w}}`,
                            // `{:.prec$}`) is deferred to Task 11 per
                            // §2.2.2.6. Surfacing the deferred-feature
                            // message at parse time gives a clearer
                            // diagnostic than the natural "unmatched
                            // `}`" that would otherwise fire on the
                            // trailing brace.
                            Some('{') => {
                                return Err(
                                    "dynamic width and precision are not yet supported by maskfmt!"
                                        .to_string(),
                                );
                            }
                            Some(c) => spec.push(c),
                            None => {
                                return Err(
                                    "unclosed `{...}` placeholder in maskfmt! template".to_string()
                                );
                            }
                        }
                    },
                    Some('}') => {}
                    _ => {
                        return Err("unclosed `{...}` placeholder in maskfmt! template".to_string());
                    }
                }
                placeholders.push(MaskfmtPlaceholder { index, spec });
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
