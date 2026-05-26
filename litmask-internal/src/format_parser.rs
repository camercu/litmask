//! Format-template parser shared by `litmask-macros` (proc-macro
//! expansion) and fuzzing harnesses.
//!
//! Extracts alternating literal fragments and parsed placeholders from
//! a `format!`-style template string. The result invariant is
//! `fragments.len() == placeholders.len() + 1`.

use alloc::string::{String, ToString};
use alloc::vec;
use alloc::vec::Vec;

/// A placeholder reference — either a positional index (from `{}`,
/// `{N}`, or `<N>$`; bare `{}` resolves to the next auto-positional
/// index during parsing) or an identifier from `{name}` / `<name>$`.
#[derive(Clone, Debug)]
pub enum TemplateRef {
    /// Positional index (e.g. `{}` auto-resolved or `{0}` explicit).
    Positional(usize),
    /// Named identifier (e.g. `{name}` or `<name>$` in a spec).
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
pub struct ParsedPlaceholder {
    /// The main argument reference for this placeholder.
    pub value: TemplateRef,
    /// Dynamic width / precision references (`<token>$` in the spec).
    pub spec_refs: Vec<TemplateRef>,
    /// Raw format spec text between `:` and `}`.
    pub spec_raw: String,
}

/// Walk the user's template once, emitting alternating literal
/// fragments and parsed placeholders. The result invariant is
/// `fragments.len() == placeholders.len() + 1`.
///
/// # Errors
///
/// Returns a descriptive `String` on malformed templates (unmatched
/// braces, invalid placeholder characters, etc.).
#[allow(clippy::missing_panics_doc)]
pub fn parse_mask_format_template(
    s: &str,
) -> Result<(Vec<String>, Vec<ParsedPlaceholder>), String> {
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
                        "unmatched `}` in mask_format! template; use `}}` to print a literal `}`"
                            .to_string(),
                    );
                }
            }
            c => fragments.last_mut().unwrap().push(c),
        }
    }

    debug_assert_eq!(fragments.len(), placeholders.len() + 1);
    Ok((fragments, placeholders))
}

fn parse_placeholder_body(
    chars: &mut core::iter::Peekable<core::str::Chars<'_>>,
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

fn consume_placeholder_header(
    chars: &mut core::iter::Peekable<core::str::Chars<'_>>,
) -> Result<String, String> {
    let mut header = String::new();
    while let Some(&c) = chars.peek() {
        if c == ':' || c == '}' {
            break;
        }
        if !is_token_char(c) {
            return Err(alloc::format!(
                "unexpected `{c}` inside `{{...}}` placeholder in mask_format! template",
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
            "too many auto-positional placeholders in mask_format! template".to_string()
        })?;
        Ok(TemplateRef::Positional(i))
    } else if header.chars().all(|c| c.is_ascii_digit()) {
        let i = header
            .parse::<usize>()
            .map_err(|_| "invalid positional index in mask_format! template".to_string())?;
        Ok(TemplateRef::Positional(i))
    } else {
        Ok(TemplateRef::Named(header.to_string()))
    }
}

fn consume_placeholder_spec(
    chars: &mut core::iter::Peekable<core::str::Chars<'_>>,
) -> Result<(String, Vec<TemplateRef>), String> {
    match chars.next() {
        Some(':') => {}
        Some('}') => return Ok((String::new(), Vec::new())),
        _ => return Err("unclosed `{...}` placeholder in mask_format! template".to_string()),
    }

    let mut spec_raw = String::new();
    let mut spec_refs: Vec<TemplateRef> = Vec::new();
    let mut token = String::new();
    loop {
        let Some(c) = chars.next() else {
            return Err("unclosed `{...}` placeholder in mask_format! template".to_string());
        };
        match c {
            '}' => break,
            '{' => {
                return Err(
                    "nested `{` inside mask_format! placeholder spec; use `<name>$` for dynamic width / precision"
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

/// Whether `c` is valid inside a placeholder name or numeric index.
#[must_use]
pub fn is_token_char(c: char) -> bool {
    c.is_ascii_digit() || c == '_' || c.is_alphabetic()
}
