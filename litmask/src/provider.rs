//! [`KeyProvider`] trait + built-in [`EnvVarProvider`].
//!
//! The trait is intentionally minimal — no `deployment_hint()` or
//! similar method that would embed English-language plaintext in user
//! binaries.

use crate::error::KeyError;
use crate::key::UnlockKey;

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
    /// Reads from `LITMASK_UNLOCK_KEY`.
    fn default() -> Self {
        Self::new(default_env_var_name())
    }
}

/// Decode the default environment variable name from an XOR-masked
/// byte array at first call. The literal `"LITMASK_UNLOCK_KEY"` is
/// never present contiguously in `.rodata`; only the masked bytes
/// are, and they fall outside the printable-ASCII range so `strings(1)`
/// does not surface them. Decoded once and leaked into a `'static`
/// string via [`std::sync::OnceLock`].
///
/// The compromise this works around is that std-emitted panic
/// source-location strings remain visible in `.rodata` on stable Rust;
/// see the litmask spec amendment dated 2026-05-11 (B).
#[cfg(feature = "std")]
fn default_env_var_name() -> &'static str {
    /// XOR mask applied to each byte of the encoded env-var name. Any
    /// non-zero byte that pushes encoded bytes outside the
    /// 0x20–0x7E printable-ASCII window suffices; 0xAA keeps every
    /// resulting byte at 0xE0+ so `strings(1)` does not include them.
    const MASK: u8 = 0xAA;
    /// XOR-masked bytes for `"LITMASK_UNLOCK_KEY"`. Verified by the
    /// test `default_provider_uses_litmask_unlock_key`.
    const MASKED: [u8; 18] = [
        0xE6, 0xE3, 0xFE, 0xE7, 0xEB, 0xF9, 0xE1, 0xF5, 0xFF, 0xE4, 0xE6, 0xE5, 0xE9, 0xE1, 0xF5,
        0xE1, 0xEF, 0xF3,
    ];
    static NAME: std::sync::OnceLock<std::string::String> = std::sync::OnceLock::new();
    NAME.get_or_init(|| {
        // `core::hint::black_box` prevents LLVM from constant-folding
        // the XOR loop into a precomputed string literal in .rodata.
        // Without it, the optimizer materializes the first 16 bytes of
        // the decoded name (SIMD-chunk size) as a literal, defeating
        // the obfuscation.
        let mask = core::hint::black_box(MASK);
        let bytes: alloc::vec::Vec<u8> = MASKED.iter().map(|b| b ^ mask).collect();
        std::string::String::from_utf8(bytes).expect("decoded env-var name is valid UTF-8")
    })
    .as_str()
}

#[cfg(feature = "std")]
impl KeyProvider for EnvVarProvider {
    fn unlock_key(&self) -> Result<UnlockKey, KeyError> {
        parse_env_value(std::env::var(self.name).as_deref().ok())
    }
}

/// Pure parser for an environment-variable value: maps `Option<&str>`
/// to the canonical [`KeyError`] surface. `None` represents
/// "env var unset" and produces [`KeyError::NotFound`]; `Some(value)`
/// is delegated to [`UnlockKey::from_base64url`].
///
/// Extracted as a free fn so tests cover the error-mapping paths
/// without mutating process-wide environment state (the workspace lint
/// `forbid(unsafe_code)` blocks the `unsafe { std::env::set_var(...) }`
/// pattern that env-mutation tests would otherwise require).
#[cfg(feature = "std")]
fn parse_env_value(value: Option<&str>) -> Result<UnlockKey, KeyError> {
    match value {
        None => Err(KeyError::NotFound),
        Some(s) => UnlockKey::from_base64url(s),
    }
}

#[cfg(all(test, feature = "std"))]
mod tests {
    use super::*;

    const VALID_BASE64URL_32B: &str = "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA";

    #[test]
    fn default_reads_litmask_unlock_key() {
        let p = EnvVarProvider::default();
        assert_eq!(p.var_name(), "LITMASK_UNLOCK_KEY");
    }

    #[test]
    fn default_env_var_name_decodes_to_expected_string() {
        // Sanity: the XOR-encoded byte table really decodes to the
        // documented env-var name.
        assert_eq!(default_env_var_name(), "LITMASK_UNLOCK_KEY");
    }

    #[test]
    fn parse_env_value_unset_yields_not_found() {
        assert!(matches!(parse_env_value(None), Err(KeyError::NotFound)));
    }

    #[test]
    fn parse_env_value_bad_base64_yields_invalid_format() {
        let err = parse_env_value(Some("not valid base64!")).unwrap_err();
        assert!(matches!(err, KeyError::InvalidFormat));
    }

    #[test]
    fn parse_env_value_wrong_length_yields_invalid_format() {
        // 32-char base64url decodes to 24 bytes, not 32.
        let err = parse_env_value(Some("AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA")).unwrap_err();
        assert!(matches!(err, KeyError::InvalidFormat));
    }

    #[test]
    fn parse_env_value_padded_yields_invalid_format() {
        let err =
            parse_env_value(Some("AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=")).unwrap_err();
        assert!(matches!(err, KeyError::InvalidFormat));
    }

    #[test]
    fn parse_env_value_valid_32_byte_key_succeeds() {
        let key = parse_env_value(Some(VALID_BASE64URL_32B)).expect("valid 32-byte key");
        assert_eq!(key.0, [0u8; crate::format::KEY_LEN]);
    }

    #[test]
    fn key_provider_is_object_safe() {
        let _: alloc::boxed::Box<dyn KeyProvider> =
            alloc::boxed::Box::new(EnvVarProvider::default());
    }
}
