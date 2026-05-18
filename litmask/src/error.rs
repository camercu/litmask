//! Error types surfaced by initialization.

use core::fmt;

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
}

impl fmt::Display for InitError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::KeyProvider(e) => write!(f, "key_provider:{e}"),
            Self::Decryption => f.write_str("decryption"),
        }
    }
}

impl core::error::Error for InitError {
    fn source(&self) -> Option<&(dyn core::error::Error + 'static)> {
        match self {
            Self::KeyProvider(e) => Some(e),
            Self::Decryption => None,
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
    /// The unlock-key bytes are malformed (wrong length, bad
    /// encoding).
    InvalidFormat,
}

impl fmt::Display for KeyError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let tag = match self {
            Self::NotFound => "not_found",
            Self::InvalidFormat => "invalid_format",
        };
        f.write_str(tag)
    }
}

impl core::error::Error for KeyError {}

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
    fn decryption_variant_display_tag_is_terse_and_non_identifying() {
        // Display contributes to operator-facing error logs; the tag
        // must be short and free of litmask-specific vocabulary to
        // satisfy the minimal-plaintext aim of the error surface.
        assert_eq!(format!("{}", InitError::Decryption), "decryption");
    }

    #[test]
    fn decryption_variant_has_no_inner_source() {
        // `Decryption` is a terminal cause — AEAD failure has no
        // typed inner; chained errors would either leak structure or
        // require carrying a non-Send error around.
        use core::error::Error;
        assert!(InitError::Decryption.source().is_none());
    }
}
