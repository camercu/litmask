//! Error types surfaced by initialization.

use core::fmt;

/// Boxed error inside [`KeyError::Provider`]. `Send + Sync` so callers
/// can propagate provider failures across threads (logging the error
/// in a different task than the one that constructed it); `'static`
/// so the box is owning (no borrowed inner). The bound is reified
/// here so the same alias is shared between the type signature and
/// every constructor / matcher.
pub(crate) type ProviderError = alloc::boxed::Box<dyn core::error::Error + Send + Sync + 'static>;

/// Errors surfaced by [`crate::init!`] / [`crate::init_with!`].
///
/// # Examples
///
/// ```
/// use litmask::InitError;
///
/// let err = InitError::Decryption;
/// assert_eq!(err.sysexit_code(), 65);
/// ```
#[non_exhaustive]
#[derive(Debug)]
pub enum InitError {
    /// The [`crate::KeyProvider`] failed to retrieve `unlock_key`.
    KeyProvider(KeyError),
    /// AEAD authentication failed during embedded `mask_key` wrapper
    /// decryption — indistinguishable from the cryptographic
    /// standpoint between a wrong `unlock_key` and a tampered wrapper.
    Decryption,
    /// The wrapper's authenticated format-version byte does not match
    /// a version this build supports. Surfaced after a successful AEAD
    /// tag check so a tampered version byte cannot be silently
    /// swallowed as [`Self::Decryption`].
    UnsupportedFormat,
}

impl InitError {
    /// Sysexits.h-compatible exit code.
    ///
    /// | Variant | Code | Name |
    /// |---|---|---|
    /// | `KeyProvider(NotFound)` | 78 | `EX_CONFIG` |
    /// | `KeyProvider(Permission)` | 77 | `EX_NOPERM` |
    /// | `KeyProvider(InvalidFormat)` | 65 | `EX_DATAERR` |
    /// | `KeyProvider(Provider(_))` | 69 | `EX_UNAVAILABLE` |
    /// | `Decryption` | 65 | `EX_DATAERR` |
    /// | `UnsupportedFormat` | 70 | `EX_SOFTWARE` |
    ///
    /// # Examples
    ///
    /// ```
    /// use litmask::{InitError, KeyError};
    ///
    /// let err = InitError::KeyProvider(KeyError::NotFound);
    /// assert_eq!(err.sysexit_code(), 78);
    /// ```
    #[must_use]
    // `match_same_arms` would collapse `InvalidFormat` and
    // `Decryption` into a single arm because both map to 65. Keeping
    // the arms separate lets a future change adjust one without
    // disturbing the other.
    #[allow(clippy::match_same_arms)]
    pub fn sysexit_code(&self) -> i32 {
        match self {
            Self::KeyProvider(KeyError::NotFound) => 78,
            Self::KeyProvider(KeyError::Permission) => 77,
            Self::KeyProvider(KeyError::InvalidFormat) => 65,
            Self::KeyProvider(KeyError::Provider(_)) => 69,
            Self::Decryption => 65,
            Self::UnsupportedFormat => 70,
        }
    }
}

impl fmt::Display for InitError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::KeyProvider(e) => write!(f, "key_provider:{e}"),
            Self::Decryption => f.write_str("decryption_failed"),
            Self::UnsupportedFormat => f.write_str("unsupported_format"),
        }
    }
}

impl core::error::Error for InitError {
    fn source(&self) -> Option<&(dyn core::error::Error + 'static)> {
        match self {
            Self::KeyProvider(e) => Some(e),
            Self::Decryption | Self::UnsupportedFormat => None,
        }
    }
}

/// Errors surfaced by [`crate::KeyProvider::unlock_key`].
///
/// # Examples
///
/// ```
/// use litmask::KeyError;
///
/// let err = KeyError::NotFound;
/// assert_eq!(format!("{err}"), "not_found");
/// ```
#[non_exhaustive]
#[derive(Debug)]
pub enum KeyError {
    /// The unlock-key source is unavailable (env var unset, file
    /// missing, etc.).
    NotFound,
    /// The unlock-key source exists but is not readable by the
    /// current process (file mode disallows read access, ACL denial,
    /// etc.).
    Permission,
    /// The unlock-key bytes are malformed (wrong length, bad
    /// encoding).
    InvalidFormat,
    /// The provider's upstream dependency failed (e.g. `machine-uid`
    /// could not read a stable machine identifier on this host).
    /// Carries the upstream error inside a
    /// `Box<dyn core::error::Error + Send + Sync + 'static>` so the
    /// cause survives propagation across thread / async boundaries.
    Provider(ProviderError),
}

impl fmt::Display for KeyError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::NotFound => f.write_str("not_found"),
            Self::Permission => f.write_str("permission"),
            Self::InvalidFormat => f.write_str("invalid_format"),
            // Display delegates to the inner cause so operators see
            // upstream context (machine-uid's reason for failure)
            // rather than just a generic tag. The `Display` impl on
            // `InitError::KeyProvider(KeyError::Provider(_))` still
            // surfaces the canonical `key_provider:provider:<inner>`
            // chain.
            Self::Provider(inner) => write!(f, "provider:{inner}"),
        }
    }
}

impl core::error::Error for KeyError {
    fn source(&self) -> Option<&(dyn core::error::Error + 'static)> {
        match self {
            Self::Provider(inner) => Some(inner.as_ref()),
            Self::NotFound | Self::Permission | Self::InvalidFormat => None,
        }
    }
}

impl From<KeyError> for InitError {
    fn from(e: KeyError) -> Self {
        Self::KeyProvider(e)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use alloc::format;
    use rstest::rstest;

    #[rstest]
    #[case::not_found(KeyError::NotFound, "not_found")]
    #[case::invalid_format(KeyError::InvalidFormat, "invalid_format")]
    fn key_error_display_tag(#[case] err: KeyError, #[case] expected: &str) {
        assert_eq!(format!("{err}"), expected);
    }

    #[rstest]
    #[case::key_not_found(InitError::KeyProvider(KeyError::NotFound), "key_provider:not_found")]
    #[case::key_invalid_format(
        InitError::KeyProvider(KeyError::InvalidFormat),
        "key_provider:invalid_format"
    )]
    #[case::key_permission(
        InitError::KeyProvider(KeyError::Permission),
        "key_provider:permission"
    )]
    #[case::decryption(InitError::Decryption, "decryption_failed")]
    #[case::unsupported_format(InitError::UnsupportedFormat, "unsupported_format")]
    fn init_error_display_tag(#[case] err: InitError, #[case] expected: &str) {
        assert_eq!(format!("{err}"), expected);
    }

    #[test]
    fn from_key_error_for_init_error() {
        let init: InitError = KeyError::NotFound.into();
        match init {
            InitError::KeyProvider(KeyError::NotFound) => {}
            _ => panic!("unexpected variant"),
        }
    }

    #[test]
    fn init_error_chains_source() {
        use core::error::Error;
        let err = InitError::KeyProvider(KeyError::NotFound);
        let src = err.source().expect("InitError::KeyProvider has a source");
        assert_eq!(format!("{src}"), "not_found");
    }

    #[test]
    fn display_tags_contain_no_english_explanation_substrings() {
        let cases = [
            InitError::KeyProvider(KeyError::NotFound),
            InitError::KeyProvider(KeyError::Permission),
            InitError::KeyProvider(KeyError::InvalidFormat),
            InitError::Decryption,
            InitError::UnsupportedFormat,
        ];
        for err in &cases {
            let rendered = format!("{err}");
            for english in ["the ", " was ", " is ", " key ", " was not ", "failed to "] {
                assert!(
                    !rendered.contains(english),
                    "Display for {err:?} contains English fragment {english:?}: {rendered}",
                );
            }
        }
    }

    #[test]
    fn decryption_variant_has_no_inner_source() {
        use core::error::Error;
        assert!(InitError::Decryption.source().is_none());
    }

    // ── sysexit_code mapping (§1.9.7) ─────────────────────────

    #[rstest]
    #[case::key_not_found(InitError::KeyProvider(KeyError::NotFound), 78)]
    #[case::key_permission(InitError::KeyProvider(KeyError::Permission), 77)]
    #[case::key_invalid_format(InitError::KeyProvider(KeyError::InvalidFormat), 65)]
    #[case::decryption(InitError::Decryption, 65)]
    #[case::unsupported_format(InitError::UnsupportedFormat, 70)]
    fn init_error_sysexit_code(#[case] err: InitError, #[case] expected: i32) {
        assert_eq!(err.sysexit_code(), expected);
    }

    #[test]
    fn sysexit_code_key_provider_boxed_inner_is_ex_unavailable_69() {
        let inner: alloc::boxed::Box<dyn core::error::Error + Send + Sync + 'static> =
            alloc::boxed::Box::new(core::fmt::Error);
        assert_eq!(
            InitError::KeyProvider(KeyError::Provider(inner)).sysexit_code(),
            69,
        );
    }
}
