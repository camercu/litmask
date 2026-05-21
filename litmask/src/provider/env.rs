//! [`EnvVarProvider`] — reads `unlock_key` from a configurable
//! environment variable. The default reads `LITMASK_UNLOCK_KEY`.

use zeroize::Zeroizing;

use crate::error::KeyError;
use crate::key::UnlockKey;
use crate::provider::KeyProvider;

/// Reads `unlock_key` from a configurable environment variable.
pub struct EnvVarProvider {
    name: &'static str,
}

impl EnvVarProvider {
    /// Construct a provider reading the named environment variable.
    #[must_use]
    pub const fn new(name: &'static str) -> Self {
        Self { name }
    }

    /// Expose the configured variable name so error messages and
    /// operational tooling can surface it without hardcoding.
    #[must_use]
    pub const fn var_name(&self) -> &'static str {
        self.name
    }
}

impl Default for EnvVarProvider {
    /// Reads from `LITMASK_UNLOCK_KEY`. The variable name itself is
    /// obfuscated against the per-build wrapper bytes via the public
    /// [`crate::weak_mask!`] macro, so the literal does not appear in
    /// `.rodata` of user binaries.
    fn default() -> Self {
        Self::new(crate::weak_mask!("LITMASK_UNLOCK_KEY"))
    }
}

impl KeyProvider for EnvVarProvider {
    fn unlock_key(&self) -> Result<UnlockKey, KeyError> {
        parse_env_value(read_env_value(self.name))
    }
}

/// Read the named environment variable and wrap its value so the
/// underlying heap buffer wipes on drop. The variable holds the
/// base64url-encoded unlock key in plaintext form; without the
/// [`Zeroizing`] wrapper the buffer would linger after parsing.
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
fn parse_env_value(value: Option<Zeroizing<alloc::string::String>>) -> Result<UnlockKey, KeyError> {
    match value {
        None => Err(KeyError::NotFound),
        Some(s) => UnlockKey::from_base64url(s.as_str()),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use alloc::string::{String, ToString};

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
}
