//! The §1.9.6 compile-error surface: the closed `FailTag` set, the single
//! `compile_error` emission path, and the env-var diagnostic mapping.

/// Closed set of failure tags from spec §1.9.6. Every litmask compile
/// error carries the invoking macro name plus one of these tags, so the
/// rejection reason is identifiable by `<macro>! <tag>` rather than by
/// prose wording; the `tests/compile/*.stderr` snapshots pin the format.
#[derive(Clone, Copy)]
pub(crate) enum FailTag {
    NonLiteral,
    MissingArg,
    ReadFailure,
    Unset,
    UnicodeFailure,
    InvalidArg,
    ArgsNotAllowed,
    DuplicateName,
    PositionalAfterNamed,
    PositionalUnused,
    NamedUnused,
    PositionalOutOfRange,
    InvalidPlaceholder,
    TemplateSyntax,
    TierMismatch,
    Grammar,
}

impl FailTag {
    fn slug(self) -> &'static str {
        match self {
            Self::NonLiteral => "non-literal",
            Self::MissingArg => "missing-arg",
            Self::ReadFailure => "read-failure",
            Self::Unset => "unset",
            Self::UnicodeFailure => "unicode-failure",
            Self::InvalidArg => "invalid-arg",
            Self::ArgsNotAllowed => "args-not-allowed",
            Self::DuplicateName => "duplicate-name",
            Self::PositionalAfterNamed => "positional-after-named",
            Self::PositionalUnused => "positional-unused",
            Self::NamedUnused => "named-unused",
            Self::PositionalOutOfRange => "positional-out-of-range",
            Self::InvalidPlaceholder => "invalid-placeholder",
            Self::TemplateSyntax => "template-syntax",
            Self::TierMismatch => "tier-mismatch",
            Self::Grammar => "grammar",
        }
    }
}

/// Construct a `syn::Error` matching the §1.9.6 format
/// `<macro_name>! <tag>: <detail>` (detail omitted when empty).
/// The single emission path keeps every litmask compile error
/// consistent without forcing callers to remember the exact wire
/// shape.
pub(crate) fn compile_error(
    span: proc_macro2::Span,
    macro_name: &str,
    tag: FailTag,
    detail: &str,
) -> syn::Error {
    let msg = if detail.is_empty() {
        format!("{macro_name}! {}", tag.slug())
    } else {
        format!("{macro_name}! {}: {detail}", tag.slug())
    };
    syn::Error::new(span, msg)
}

/// Map a `std::env::var` failure to its §1.9.6 `(tag, detail)` pair.
/// Single source of truth for the env-var diagnostic wording shared by
/// `mask_env!`, `mask_option_env!`, and `mask_concat!`'s nested `env!`.
/// `prefix` distinguishes a direct macro ("") from a nested form
/// ("nested env!: ").
pub(crate) fn env_failure(err: &std::env::VarError, name: &str, prefix: &str) -> (FailTag, String) {
    match err {
        std::env::VarError::NotPresent => (
            FailTag::Unset,
            format!("{prefix}environment variable `{name}` is not set"),
        ),
        std::env::VarError::NotUnicode(_) => (
            FailTag::UnicodeFailure,
            format!(
                "{prefix}environment variable `{name}` is set but its value is not valid UTF-8"
            ),
        ),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    // `env_failure` is the pure decision function behind the env
    // macros' diagnostics: given a `VarError`, it picks the §1.9.6 tag
    // and message. Testing it here (rather than driving the macros with
    // a mutated process environment) mirrors the `parse_env_value`
    // precedent in `litmask/src/provider/env.rs` — the workspace
    // `forbid(unsafe_code)` lint rules out the `env::set_var` approach
    // a macro-level test would need. The tag classification is the
    // externally-visible behavior #3 changed: `NotUnicode` is now an
    // error category, not a silent `None`.
    #[test]
    fn env_failure_not_present_classifies_as_unset() {
        let (tag, detail) = env_failure(&std::env::VarError::NotPresent, "FOO", "");
        assert!(matches!(tag, FailTag::Unset));
        assert_eq!(detail, "environment variable `FOO` is not set");
    }

    #[test]
    fn env_failure_not_unicode_classifies_as_unicode_failure() {
        let err = std::env::VarError::NotUnicode(std::ffi::OsString::from("x"));
        let (tag, detail) = env_failure(&err, "FOO", "");
        assert!(matches!(tag, FailTag::UnicodeFailure));
        assert_eq!(
            detail,
            "environment variable `FOO` is set but its value is not valid UTF-8"
        );
    }

    #[test]
    fn env_failure_prefix_is_prepended() {
        let (_, detail) = env_failure(&std::env::VarError::NotPresent, "BAR", "nested env!: ");
        assert_eq!(detail, "nested env!: environment variable `BAR` is not set");
    }
}
