//! Format-template parser shared by `litmask-macros` (proc-macro
//! expansion) and fuzzing harnesses.
//!
//! Extracts alternating literal fragments and parsed placeholders from
//! a `format!`-style template string. The result invariant is
//! `fragments.len() == placeholders.len() + 1`.

use alloc::string::{String, ToString};
use alloc::vec;
use alloc::vec::Vec;
use core::fmt;

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

/// Errors from [`parse_mask_format_template`].
#[derive(Debug, Clone, PartialEq, Eq)]
#[non_exhaustive]
pub enum TemplateParseError {
    /// Bare `}` without a matching `{`.
    UnmatchedCloseBrace,
    /// `{` without a closing `}`.
    UnclosedPlaceholder,
    /// `{` inside a format spec (e.g. `{:{}}`) — use `<name>$` instead.
    NestedBrace,
    /// Non-token character inside `{...}`.
    InvalidChar(char),
    /// More auto-positional `{}` placeholders than `usize` can index.
    TooManyAutoPositional,
    /// Positional index could not be parsed as `usize`.
    InvalidPositionalIndex,
    /// `<token>$` index in a spec overflows `usize`.
    OverflowingIndex(String),
}

impl fmt::Display for TemplateParseError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::UnmatchedCloseBrace => f.write_str(
                "unmatched `}` in mask_format! template; use `}}` to print a literal `}`",
            ),
            Self::UnclosedPlaceholder => {
                f.write_str("unclosed `{...}` placeholder in mask_format! template")
            }
            Self::NestedBrace => f.write_str(
                "nested `{` inside mask_format! placeholder spec; \
                 use `<name>$` for dynamic width / precision",
            ),
            Self::InvalidChar(c) => write!(
                f,
                "unexpected `{c}` inside `{{...}}` placeholder in mask_format! template",
            ),
            Self::TooManyAutoPositional => {
                f.write_str("too many auto-positional placeholders in mask_format! template")
            }
            Self::InvalidPositionalIndex => {
                f.write_str("invalid positional index in mask_format! template")
            }
            Self::OverflowingIndex(token) => write!(
                f,
                "positional index `{token}` overflows usize in mask_format! spec",
            ),
        }
    }
}

/// Walk the user's template once, emitting alternating literal
/// fragments and parsed placeholders. The result invariant is
/// `fragments.len() == placeholders.len() + 1`.
///
/// # Errors
///
/// Returns [`TemplateParseError`] on malformed templates (unmatched
/// braces, invalid placeholder characters, etc.).
// The `fragments.last_mut().unwrap()` calls below are infallible:
// `fragments` is seeded with one element and only ever grows (push,
// never pop), so `last_mut()` is always `Some`. The lint flags that
// unwrap as a panic path; allow it rather than document a `# Panics`
// section that would falsely claim a reachable panic.
#[allow(clippy::missing_panics_doc)]
pub fn parse_mask_format_template(
    s: &str,
) -> Result<(Vec<String>, Vec<ParsedPlaceholder>), TemplateParseError> {
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
                    return Err(TemplateParseError::UnmatchedCloseBrace);
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
) -> Result<ParsedPlaceholder, TemplateParseError> {
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
) -> Result<String, TemplateParseError> {
    let mut header = String::new();
    while let Some(&c) = chars.peek() {
        if c == ':' || c == '}' {
            break;
        }
        if !is_token_char(c) {
            return Err(TemplateParseError::InvalidChar(c));
        }
        header.push(c);
        chars.next();
    }
    Ok(header)
}

fn resolve_value_ref(
    header: &str,
    next_auto: &mut usize,
) -> Result<TemplateRef, TemplateParseError> {
    if header.is_empty() {
        let i = *next_auto;
        *next_auto = next_auto
            .checked_add(1)
            .ok_or(TemplateParseError::TooManyAutoPositional)?;
        return Ok(TemplateRef::Positional(i));
    }
    classify_token(header, || TemplateParseError::InvalidPositionalIndex)
}

/// Classify a non-empty token as a positional index (all-digit) or a
/// named reference. `on_overflow` supplies the error when an all-digit
/// token does not fit `usize`; the two call sites report different
/// variants for the same overflow.
fn classify_token(
    token: &str,
    on_overflow: impl FnOnce() -> TemplateParseError,
) -> Result<TemplateRef, TemplateParseError> {
    if token.chars().all(|c| c.is_ascii_digit()) {
        token
            .parse::<usize>()
            .map(TemplateRef::Positional)
            .map_err(|_| on_overflow())
    } else {
        Ok(TemplateRef::Named(token.to_string()))
    }
}

fn consume_placeholder_spec(
    chars: &mut core::iter::Peekable<core::str::Chars<'_>>,
) -> Result<(String, Vec<TemplateRef>), TemplateParseError> {
    match chars.next() {
        Some(':') => {}
        Some('}') => return Ok((String::new(), Vec::new())),
        _ => return Err(TemplateParseError::UnclosedPlaceholder),
    }

    let mut spec_raw = String::new();
    let mut spec_refs: Vec<TemplateRef> = Vec::new();
    let mut token = String::new();
    loop {
        let Some(c) = chars.next() else {
            return Err(TemplateParseError::UnclosedPlaceholder);
        };
        match c {
            '}' => break,
            '{' => return Err(TemplateParseError::NestedBrace),
            _ => {
                spec_raw.push(c);
                if is_token_char(c) {
                    token.push(c);
                } else if c == '$' && !token.is_empty() {
                    spec_refs.push(classify_token(&token, || {
                        TemplateParseError::OverflowingIndex(token.clone())
                    })?);
                    token.clear();
                } else {
                    token.clear();
                }
            }
        }
    }
    Ok((spec_raw, spec_refs))
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
    fn template_parse_error_display_is_stable() {
        assert_eq!(
            alloc::format!("{}", TemplateParseError::UnclosedPlaceholder),
            "unclosed `{...}` placeholder in mask_format! template"
        );
        assert_eq!(
            alloc::format!("{}", TemplateParseError::InvalidPositionalIndex),
            "invalid positional index in mask_format! template"
        );
        assert_eq!(
            alloc::format!("{}", TemplateParseError::InvalidChar('%')),
            "unexpected `%` inside `{...}` placeholder in mask_format! template"
        );
    }

    /// A big all-digit run inside a spec is a width reference only when it
    /// is `$`-terminated. Without the `$` it is ordinary format-spec text,
    /// so it must parse cleanly instead of being classified as a token
    /// (and rejected as an overflowing index). Complements
    /// `overflowing_positional_in_spec_returns_error`, which covers the
    /// `$` case — together they pin the `$`-terminator requirement.
    #[test]
    fn big_digit_run_without_dollar_is_not_a_width_ref() {
        assert!(parse_mask_format_template("{:6666666666666666666666>}").is_ok());
    }

    #[test]
    fn overflowing_positional_in_spec_returns_error() {
        let input = "{:>6666666666666666666666$}";
        assert!(matches!(
            parse_mask_format_template(input),
            Err(TemplateParseError::OverflowingIndex(_)),
        ));
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
        assert_eq!(
            parse_mask_format_template("a}b").unwrap_err(),
            TemplateParseError::UnmatchedCloseBrace,
        );
    }

    #[test]
    fn unclosed_placeholder() {
        assert_eq!(
            parse_mask_format_template("{").unwrap_err(),
            TemplateParseError::UnclosedPlaceholder,
        );
    }

    #[test]
    fn unclosed_placeholder_with_spec() {
        assert_eq!(
            parse_mask_format_template("{:>10").unwrap_err(),
            TemplateParseError::UnclosedPlaceholder,
        );
    }

    #[test]
    fn nested_brace_in_spec_rejected() {
        assert_eq!(
            parse_mask_format_template("{:{}}").unwrap_err(),
            TemplateParseError::NestedBrace,
        );
    }

    #[test]
    fn invalid_placeholder_char() {
        assert_eq!(
            parse_mask_format_template("{a+b}").unwrap_err(),
            TemplateParseError::InvalidChar('+'),
        );
    }
}
