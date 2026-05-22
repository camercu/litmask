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
#[non_exhaustive]
#[derive(Debug)]
pub enum InitError {
    /// The [`crate::KeyProvider`] failed to retrieve `unlock_key`.
    KeyProvider(KeyError),
    /// AEAD authentication failed during embedded `mask_key` wrapper
    /// decryption — indistinguishable from the cryptographic
    /// standpoint between a wrong `unlock_key` and a tampered wrapper.
    Decryption,
    /// The wrapper's format-version byte does not match a version
    /// this build supports. Detected before AEAD decryption so a
    /// tampered version byte cannot be silently swallowed as
    /// [`Self::Decryption`] (§2.7.1, §1.12.2).
    UnsupportedFormat,
    /// The wrapper's cipher-id byte does not match the cipher this
    /// build was compiled with. Detected before AEAD decryption so
    /// a mismatched cipher byte produces a typed diagnostic instead
    /// of a generic auth-failure (§2.7.1, §1.12.2).
    UnsupportedCipher,
}

impl InitError {
    /// Sysexits.h-compatible exit code (§1.9.7). Mapping:
    ///
    /// | Variant | Code | Name |
    /// |---|---|---|
    /// | `KeyProvider(NotFound)` | 78 | `EX_CONFIG` |
    /// | `KeyProvider(Permission)` | 77 | `EX_NOPERM` |
    /// | `KeyProvider(InvalidFormat)` | 65 | `EX_DATAERR` |
    /// | `KeyProvider(Provider(_))` | 69 | `EX_UNAVAILABLE` |
    /// | `Decryption` | 65 | `EX_DATAERR` |
    /// | `UnsupportedFormat` | 70 | `EX_SOFTWARE` |
    /// | `UnsupportedCipher` | 70 | `EX_SOFTWARE` |
    ///
    /// Numeric constants are inline literals — no `sysexits` crate
    /// dependency. The mapping mirrors the §1.9.7 table verbatim;
    /// new variants MUST extend this match in lockstep.
    #[must_use]
    // `match_same_arms` would collapse `InvalidFormat` and
    // `Decryption` into a single arm because both map to 65. They
    // are independent ACs in §1.9.7 — keeping the arms separate
    // lets a future spec change adjust one without disturbing the
    // other, and the source layout still mirrors the §1.9.7 table.
    #[allow(clippy::match_same_arms)]
    pub fn sysexit_code(&self) -> i32 {
        match self {
            Self::KeyProvider(KeyError::NotFound) => 78,
            Self::KeyProvider(KeyError::Permission) => 77,
            Self::KeyProvider(KeyError::InvalidFormat) => 65,
            Self::KeyProvider(KeyError::Provider(_)) => 69,
            Self::Decryption => 65,
            Self::UnsupportedFormat | Self::UnsupportedCipher => 70,
        }
    }
}

impl fmt::Display for InitError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::KeyProvider(e) => write!(f, "key_provider:{e}"),
            Self::Decryption => f.write_str("decryption_failed"),
            Self::UnsupportedFormat => f.write_str("unsupported_format"),
            Self::UnsupportedCipher => f.write_str("unsupported_cipher"),
        }
    }
}

impl core::error::Error for InitError {
    fn source(&self) -> Option<&(dyn core::error::Error + 'static)> {
        match self {
            Self::KeyProvider(e) => Some(e),
            Self::Decryption | Self::UnsupportedFormat | Self::UnsupportedCipher => None,
        }
    }
}

/// Errors surfaced by [`crate::KeyProvider::unlock_key`].
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

    #[test]
    fn key_error_display_tags() {
        assert_eq!(format!("{}", KeyError::NotFound), "not_found");
        assert_eq!(format!("{}", KeyError::InvalidFormat), "invalid_format");
    }

    #[test]
    fn init_error_display_tags() {
        assert_eq!(
            format!("{}", InitError::KeyProvider(KeyError::NotFound)),
            "key_provider:not_found",
        );
        assert_eq!(
            format!("{}", InitError::KeyProvider(KeyError::InvalidFormat)),
            "key_provider:invalid_format",
        );
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
    fn decryption_variant_display_tag_is_decryption_failed() {
        // Display contributes to operator-facing error logs; the tag
        // must be short and free of litmask-specific vocabulary to
        // satisfy the minimal-plaintext aim of the error surface.
        // §1.9.3 normatively pins the tag at `"decryption_failed"`.
        assert_eq!(format!("{}", InitError::Decryption), "decryption_failed");
    }

    #[test]
    fn key_provider_permission_display_tag() {
        assert_eq!(
            format!("{}", InitError::KeyProvider(KeyError::Permission)),
            "key_provider:permission",
        );
    }

    #[test]
    fn unsupported_format_display_tag() {
        assert_eq!(
            format!("{}", InitError::UnsupportedFormat),
            "unsupported_format",
        );
    }

    #[test]
    fn unsupported_cipher_display_tag() {
        assert_eq!(
            format!("{}", InitError::UnsupportedCipher),
            "unsupported_cipher",
        );
    }

    #[test]
    fn display_tags_contain_no_english_explanation_substrings() {
        // The minimal-plaintext goal of the error surface rules out
        // English phrases that would identify failure semantics in
        // a leaked log line. Pin the absence of canonical English
        // terms across every variant.
        let cases = [
            InitError::KeyProvider(KeyError::NotFound),
            InitError::KeyProvider(KeyError::Permission),
            InitError::KeyProvider(KeyError::InvalidFormat),
            InitError::Decryption,
            InitError::UnsupportedFormat,
            InitError::UnsupportedCipher,
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
        // `Decryption` is a terminal cause — AEAD failure has no
        // typed inner; chained errors would either leak structure or
        // require carrying a non-Send error around.
        use core::error::Error;
        assert!(InitError::Decryption.source().is_none());
    }

    // ── sysexit_code mapping (§1.9.7) ─────────────────────────

    #[test]
    fn sysexit_code_key_provider_not_found_is_ex_config_78() {
        assert_eq!(
            InitError::KeyProvider(KeyError::NotFound).sysexit_code(),
            78,
        );
    }

    #[test]
    fn sysexit_code_key_provider_permission_is_ex_noperm_77() {
        assert_eq!(
            InitError::KeyProvider(KeyError::Permission).sysexit_code(),
            77,
        );
    }

    #[test]
    fn sysexit_code_key_provider_invalid_format_is_ex_dataerr_65() {
        assert_eq!(
            InitError::KeyProvider(KeyError::InvalidFormat).sysexit_code(),
            65,
        );
    }

    #[test]
    fn sysexit_code_key_provider_provider_inner_is_ex_unavailable_69() {
        // Boxed provider error → EX_UNAVAILABLE. The inner type
        // could carry rich detail; the exit code stays the same
        // regardless of the inner so the caller's exit-code matcher
        // does not have to inspect Box<dyn Error>.
        let inner: alloc::boxed::Box<dyn core::error::Error + Send + Sync + 'static> =
            alloc::boxed::Box::new(core::fmt::Error);
        assert_eq!(
            InitError::KeyProvider(KeyError::Provider(inner)).sysexit_code(),
            69,
        );
    }

    #[test]
    fn sysexit_code_decryption_is_ex_dataerr_65() {
        assert_eq!(InitError::Decryption.sysexit_code(), 65);
    }

    #[test]
    fn sysexit_code_unsupported_format_is_ex_software_70() {
        assert_eq!(InitError::UnsupportedFormat.sysexit_code(), 70);
    }

    #[test]
    fn sysexit_code_unsupported_cipher_is_ex_software_70() {
        assert_eq!(InitError::UnsupportedCipher.sysexit_code(), 70);
    }
}
