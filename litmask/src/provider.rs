//! [`KeyProvider`] trait + built-in [`EnvVarProvider`].
//!
//! `FileProvider`, `HardwareIdProvider`, and `StaticProvider` arrive in
//! later tasks (15–17). The trait is intentionally minimal (§1.6.1) —
//! no `deployment_hint()` or similar method that would embed
//! English-language plaintext in user binaries (§2.5.1.5).

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

// Object-safety assertion — keep at module scope so it runs at compile
// time. `&dyn KeyProvider` and `Box<dyn KeyProvider>` must both work
// (spec §2.5.1.2).
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

    /// Convenience accessor for the env-var name this provider reads.
    #[must_use]
    pub const fn var_name(&self) -> &'static str {
        self.name
    }
}

#[cfg(feature = "std")]
impl Default for EnvVarProvider {
    /// Reads from `LITMASK_UNLOCK_KEY`.
    fn default() -> Self {
        Self::new("LITMASK_UNLOCK_KEY")
    }
}

#[cfg(feature = "std")]
impl KeyProvider for EnvVarProvider {
    fn unlock_key(&self) -> Result<UnlockKey, KeyError> {
        match std::env::var(self.name) {
            Ok(value) => UnlockKey::from_base64url(&value),
            Err(std::env::VarError::NotPresent) => Err(KeyError::NotFound),
            Err(std::env::VarError::NotUnicode(_)) => Err(KeyError::InvalidFormat),
        }
    }
}
