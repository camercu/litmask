//! Error types surfaced by initialization.
//!
//! `Display` impls emit short ASCII `category:variant` tags only;
//! Task 22 will tighten them per §1.9.3. `Decryption` variant lands in
//! Task 8 along with the tampering panic policy (§1.9.5).

use core::fmt;

/// Errors surfaced by [`crate::init!`] / [`crate::init_with!`].
#[non_exhaustive]
#[derive(Debug)]
pub enum InitError {
    /// The [`crate::KeyProvider`] failed to retrieve `unlock_key`.
    KeyProvider(KeyError),
}

impl fmt::Display for InitError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::KeyProvider(e) => write!(f, "key_provider:{e}"),
        }
    }
}

impl core::error::Error for InitError {
    fn source(&self) -> Option<&(dyn core::error::Error + 'static)> {
        match self {
            Self::KeyProvider(e) => Some(e),
        }
    }
}

/// Errors surfaced by [`crate::KeyProvider::unlock_key`].
#[non_exhaustive]
#[derive(Debug)]
pub enum KeyError {
    /// The key source is unavailable (env var unset, file missing, etc.).
    NotFound,
    /// The key data is malformed (wrong length, bad encoding).
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
        // The source must Display as the inner KeyError tag.
        assert_eq!(format!("{src}"), "not_found");
    }
}
