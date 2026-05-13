//! [`KeyProvider`] trait + built-in [`EnvVarProvider`].
//!
//! The trait is intentionally minimal — no `deployment_hint()` or
//! similar method that would embed English-language plaintext in user
//! binaries.

use crate::error::KeyError;
use crate::key::UnlockKey;
#[cfg(feature = "std")]
use zeroize::Zeroizing;

/// A source of `unlock_key` for the layered key strategy.
///
/// The `&self` receiver permits stateful providers (cached lookups,
/// network clients). Implementations must be `Send + Sync` so providers
/// can be passed to [`crate::init_with!`] in multithreaded contexts.
pub trait KeyProvider: Send + Sync {
    /// Retrieve the `unlock_key` used to decrypt the embedded
    /// `mask_key` wrapper.
    ///
    /// # Errors
    ///
    /// Returns [`KeyError`] when the underlying source is unavailable
    /// or returns malformed data.
    fn unlock_key(&self) -> Result<UnlockKey, KeyError>;
}

// Object-safety check enforced at compile time.
const _: fn() = || {
    fn _assert_object_safe(_: &dyn KeyProvider) {}
};

/// Reads `unlock_key` from a configurable environment variable.
///
/// Only available when the `std` feature is enabled (the default).
#[cfg(feature = "std")]
pub struct EnvVarProvider {
    name: &'static str,
}

#[cfg(feature = "std")]
impl EnvVarProvider {
    /// Construct a provider reading the named environment variable.
    #[must_use]
    pub const fn new(name: &'static str) -> Self {
        Self { name }
    }

    /// The environment variable this provider reads. Useful for
    /// error messages and operational tooling that wants to print the
    /// expected variable name.
    #[must_use]
    pub const fn var_name(&self) -> &'static str {
        self.name
    }
}

#[cfg(feature = "std")]
impl Default for EnvVarProvider {
    /// Reads from `LITMASK_UNLOCK_KEY`. The variable name itself is
    /// obfuscated against the per-build wrapper bytes via the public
    /// [`crate::weak_mask!`] macro, so the literal does not appear in
    /// `.rodata` of user binaries.
    fn default() -> Self {
        Self::new(crate::weak_mask!("LITMASK_UNLOCK_KEY"))
    }
}

#[cfg(feature = "std")]
impl KeyProvider for EnvVarProvider {
    fn unlock_key(&self) -> Result<UnlockKey, KeyError> {
        parse_env_value(read_env_value(self.name))
    }
}

/// Read the named environment variable and wrap its value so the
/// underlying heap buffer wipes on drop. The variable holds the
/// base64url-encoded unlock key in plaintext form; without the
/// [`Zeroizing`] wrapper the buffer would linger after parsing.
#[cfg(feature = "std")]
fn read_env_value(name: &str) -> Option<Zeroizing<alloc::string::String>> {
    std::env::var(name).ok().map(Zeroizing::new)
}

/// Pure parser for an environment-variable value: maps the optional
/// owned string to the canonical [`KeyError`] surface. `None`
/// represents "env var unset" and produces [`KeyError::NotFound`];
/// `Some(value)` is delegated to [`UnlockKey::from_base64url`].
///
/// Takes ownership of a [`Zeroizing<String>`] so the plaintext base64
/// buffer is wiped when this function returns, regardless of which
/// branch executed.
///
/// Extracted as a free fn so tests cover the error-mapping paths
/// without mutating process-wide environment state (the workspace lint
/// `forbid(unsafe_code)` blocks the `unsafe { std::env::set_var(...) }`
/// pattern that env-mutation tests would otherwise require).
#[cfg(feature = "std")]
fn parse_env_value(value: Option<Zeroizing<alloc::string::String>>) -> Result<UnlockKey, KeyError> {
    match value {
        None => Err(KeyError::NotFound),
        Some(s) => UnlockKey::from_base64url(s.as_str()),
    }
}

#[cfg(all(test, feature = "std"))]
mod tests {
    use super::*;
    use alloc::string::{String, ToString};
    use zeroize::Zeroizing;

    const VALID_BASE64URL_32B: &str = "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA";

    fn z(s: &str) -> Zeroizing<String> {
        Zeroizing::new(s.to_string())
    }

    #[test]
    fn default_reads_litmask_unlock_key() {
        let p = EnvVarProvider::default();
        assert_eq!(p.var_name(), "LITMASK_UNLOCK_KEY");
    }

    #[test]
    fn read_env_value_returns_zeroizing_string_so_buffer_wipes_on_drop() {
        // Type-asserts the env-read boundary returns a wiped-on-drop
        // wrapper rather than a plain String.
        let _: Option<Zeroizing<String>> = read_env_value("LITMASK_DEFINITELY_NOT_SET_XYZ_42");
    }

    #[test]
    fn parse_env_value_unset_yields_not_found() {
        assert!(matches!(parse_env_value(None), Err(KeyError::NotFound)));
    }

    #[test]
    fn parse_env_value_bad_base64_yields_invalid_format() {
        let err = parse_env_value(Some(z("not valid base64!"))).unwrap_err();
        assert!(matches!(err, KeyError::InvalidFormat));
    }

    #[test]
    fn parse_env_value_wrong_length_yields_invalid_format() {
        // 32-char base64url decodes to 24 bytes, not 32.
        let err = parse_env_value(Some(z("AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"))).unwrap_err();
        assert!(matches!(err, KeyError::InvalidFormat));
    }

    #[test]
    fn parse_env_value_padded_yields_invalid_format() {
        let err =
            parse_env_value(Some(z("AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA="))).unwrap_err();
        assert!(matches!(err, KeyError::InvalidFormat));
    }

    #[test]
    fn parse_env_value_valid_32_byte_key_succeeds() {
        let key = parse_env_value(Some(z(VALID_BASE64URL_32B))).expect("valid 32-byte key");
        assert_eq!(key.as_bytes(), &[0u8; crate::internal::KEY_LEN]);
    }

    #[test]
    fn key_provider_is_object_safe() {
        let _: alloc::boxed::Box<dyn KeyProvider> =
            alloc::boxed::Box::new(EnvVarProvider::default());
    }
}
