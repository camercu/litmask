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
                    spec_refs.push(make_template_ref(&token)?);
                    token.clear();
                } else {
                    token.clear();
                }
            }
        }
    }
    Ok((spec_raw, spec_refs))
}

fn make_template_ref(token: &str) -> Result<TemplateRef, String> {
    if token.chars().all(|c| c.is_ascii_digit()) {
        let i = token.parse::<usize>().map_err(|_| {
            alloc::format!("positional index `{token}` overflows usize in mask_format! spec")
        })?;
        Ok(TemplateRef::Positional(i))
    } else {
        Ok(TemplateRef::Named(token.to_string()))
    }
}

/// Whether `c` is valid inside a placeholder name or numeric index.
#[must_use]
pub fn is_token_char(c: char) -> bool {
    c.is_ascii_digit() || c == '_' || c.is_alphabetic()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn overflowing_positional_in_spec_returns_error() {
        let input = "{:>6666666666666666666666$}";
        let err = parse_mask_format_template(input).unwrap_err();
        assert!(
            err.contains("overflows"),
            "expected overflow error, got: {err}"
        );
    }

    #[test]
    fn valid_positional_in_spec_succeeds() {
        let (frags, phs) = parse_mask_format_template("{:>0$}").unwrap();
        assert_eq!(frags.len(), 2);
        assert_eq!(phs[0].spec_refs.len(), 1);
    }

    #[test]
    fn fuzz_crash_input_returns_error_not_panic() {
        let input =
            "{:>6666666666666666666666${:\x00\x15 :\x00%A$666666666666${:\x00\x15 :\x00%A$}\np}\n";
        let _ = parse_mask_format_template(input);
    }

    // ── invariant: fragments.len() == placeholders.len() + 1 ────

    fn assert_invariant(frags: &[String], phs: &[ParsedPlaceholder]) {
        assert_eq!(
            frags.len(),
            phs.len() + 1,
            "invariant violated: frags={}, phs={}",
            frags.len(),
            phs.len(),
        );
    }

    // ── empty / static templates ────────────────────────────────

    #[test]
    fn empty_template() {
        let (frags, phs) = parse_mask_format_template("").unwrap();
        assert_invariant(&frags, &phs);
        assert_eq!(frags, &[""]);
        assert!(phs.is_empty());
    }

    #[test]
    fn static_text_only() {
        let (frags, phs) = parse_mask_format_template("hello world").unwrap();
        assert_invariant(&frags, &phs);
        assert_eq!(frags, &["hello world"]);
        assert!(phs.is_empty());
    }

    // ── escaped braces ──────────────────────────────────────────

    #[test]
    fn escaped_open_brace() {
        let (frags, phs) = parse_mask_format_template("a{{b").unwrap();
        assert_invariant(&frags, &phs);
        assert_eq!(frags, &["a{b"]);
        assert!(phs.is_empty());
    }

    #[test]
    fn escaped_close_brace() {
        let (frags, phs) = parse_mask_format_template("a}}b").unwrap();
        assert_invariant(&frags, &phs);
        assert_eq!(frags, &["a}b"]);
        assert!(phs.is_empty());
    }

    #[test]
    fn escaped_braces_adjacent_to_placeholder() {
        let (frags, phs) = parse_mask_format_template("{{{}}}").unwrap();
        assert_invariant(&frags, &phs);
        assert_eq!(frags, &["{", "}"]);
        assert_eq!(phs.len(), 1);
        assert!(matches!(phs[0].value, TemplateRef::Positional(0)));
    }

    // ── auto-positional ─────────────────────────────────────────

    #[test]
    fn single_auto_positional() {
        let (frags, phs) = parse_mask_format_template("x={}").unwrap();
        assert_invariant(&frags, &phs);
        assert_eq!(frags, &["x=", ""]);
        assert!(matches!(phs[0].value, TemplateRef::Positional(0)));
    }

    #[test]
    fn multiple_auto_positional() {
        let (frags, phs) = parse_mask_format_template("{} {} {}").unwrap();
        assert_invariant(&frags, &phs);
        assert_eq!(frags, &["", " ", " ", ""]);
        assert!(matches!(phs[0].value, TemplateRef::Positional(0)));
        assert!(matches!(phs[1].value, TemplateRef::Positional(1)));
        assert!(matches!(phs[2].value, TemplateRef::Positional(2)));
    }

    // ── explicit positional ─────────────────────────────────────

    #[test]
    fn explicit_positional_indices() {
        let (frags, phs) = parse_mask_format_template("{1} {0} {1}").unwrap();
        assert_invariant(&frags, &phs);
        assert_eq!(phs.len(), 3);
        assert!(matches!(phs[0].value, TemplateRef::Positional(1)));
        assert!(matches!(phs[1].value, TemplateRef::Positional(0)));
        assert!(matches!(phs[2].value, TemplateRef::Positional(1)));
    }

    // ── named placeholders ──────────────────────────────────────

    #[test]
    fn named_placeholder() {
        let (frags, phs) = parse_mask_format_template("{name}").unwrap();
        assert_invariant(&frags, &phs);
        assert_eq!(phs.len(), 1);
        match &phs[0].value {
            TemplateRef::Named(n) => assert_eq!(n, "name"),
            TemplateRef::Positional(_) => panic!("expected Named, got Positional"),
        }
    }

    #[test]
    fn named_with_underscores_and_digits() {
        let (frags, phs) = parse_mask_format_template("{my_var_2}").unwrap();
        assert_invariant(&frags, &phs);
        match &phs[0].value {
            TemplateRef::Named(n) => assert_eq!(n, "my_var_2"),
            TemplateRef::Positional(_) => panic!("expected Named, got Positional"),
        }
    }

    // ── format specs ────────────────────────────────────────────

    #[test]
    fn debug_spec() {
        let (_, phs) = parse_mask_format_template("{:?}").unwrap();
        assert_eq!(phs[0].spec_raw, "?");
    }

    #[test]
    fn alternate_debug_spec() {
        let (_, phs) = parse_mask_format_template("{:#?}").unwrap();
        assert_eq!(phs[0].spec_raw, "#?");
    }

    #[test]
    fn right_align_with_width_no_false_refs() {
        let (_, phs) = parse_mask_format_template("{:>10}").unwrap();
        assert_eq!(phs[0].spec_raw, ">10");
        assert!(phs[0].spec_refs.is_empty());
    }

    // ── dynamic width / precision ───────────────────────────────

    #[test]
    fn dynamic_width_named() {
        let (_, phs) = parse_mask_format_template("{:>w$}").unwrap();
        assert_eq!(phs[0].spec_raw, ">w$");
        assert_eq!(phs[0].spec_refs.len(), 1);
        match &phs[0].spec_refs[0] {
            TemplateRef::Named(n) => assert_eq!(n, "w"),
            TemplateRef::Positional(_) => panic!("expected Named, got Positional"),
        }
    }

    // ── mixed named + positional ────────────────────────────────

    #[test]
    fn mixed_named_and_positional() {
        let (frags, phs) = parse_mask_format_template("{x} {} {y}").unwrap();
        assert_invariant(&frags, &phs);
        assert_eq!(phs.len(), 3);
        match &phs[0].value {
            TemplateRef::Named(n) => assert_eq!(n, "x"),
            TemplateRef::Positional(_) => panic!("expected Named, got Positional"),
        }
        assert!(matches!(phs[1].value, TemplateRef::Positional(0)));
        match &phs[2].value {
            TemplateRef::Named(n) => assert_eq!(n, "y"),
            TemplateRef::Positional(_) => panic!("expected Named, got Positional"),
        }
    }

    // ── error cases ─────────────────────────────────────────────

    #[test]
    fn unmatched_close_brace() {
        let err = parse_mask_format_template("a}b").unwrap_err();
        assert!(err.contains("unmatched"), "got: {err}");
    }

    #[test]
    fn unclosed_placeholder() {
        let err = parse_mask_format_template("{").unwrap_err();
        assert!(err.contains("unclosed"), "got: {err}");
    }

    #[test]
    fn unclosed_placeholder_with_spec() {
        let err = parse_mask_format_template("{:>10").unwrap_err();
        assert!(err.contains("unclosed"), "got: {err}");
    }

    #[test]
    fn nested_brace_in_spec_rejected() {
        let err = parse_mask_format_template("{:{}}").unwrap_err();
        assert!(err.contains("nested"), "got: {err}");
    }

    #[test]
    fn invalid_placeholder_char() {
        let err = parse_mask_format_template("{a+b}").unwrap_err();
        assert!(err.contains("unexpected"), "got: {err}");
    }
}
