//! [`KeyProvider`] trait + built-in providers.
//!
//! The trait is intentionally minimal — no `deployment_hint()` or
//! similar method that would embed English-language plaintext in user
//! binaries. Each built-in provider lives in its own submodule so the
//! per-provider tests, error wrappers, and pure helpers stay
//! colocated with the provider they describe:
//!
//! - [`env`] / [`EnvVarProvider`] — `LITMASK_UNLOCK_KEY` environment var
//! - [`file`] / [`FileProvider`] — filesystem path, base64url or raw
//! - [`hw_id`] / [`HardwareIdProvider`] — machine-id + BLAKE3 (opt-in)
//! - [`static_key`] / [`StaticProvider`] — fixed key, tests-only

use crate::error::KeyError;
use crate::key::UnlockKey;

#[cfg(feature = "std")]
pub(crate) mod env;
#[cfg(feature = "std")]
pub(crate) mod file;
#[cfg(feature = "hw-id")]
pub(crate) mod hw_id;
pub(crate) mod static_key;

#[cfg(feature = "std")]
pub use env::EnvVarProvider;
#[cfg(feature = "std")]
pub use file::{FileProvider, KeyEncoding};
#[cfg(feature = "hw-id")]
pub use hw_id::HardwareIdProvider;
pub use static_key::StaticProvider;

/// A source of `unlock_key` for the layered key strategy.
///
/// The `&self` receiver permits stateful providers (cached lookups,
/// network clients). Implementations must be `Send + Sync` so providers
/// can be passed to [`crate::init_with!`] in multithreaded contexts.
///
/// # Examples
///
/// ```
/// use litmask::{KeyProvider, UnlockKey, KeyError, KEY_LEN};
///
/// struct FixedProvider;
///
/// impl KeyProvider for FixedProvider {
///     fn unlock_key(&self) -> Result<UnlockKey, KeyError> {
///         UnlockKey::from_base64url(
///             "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"
///         )
///     }
/// }
/// ```
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

#[cfg(test)]
mod tests {
    use super::*;
    use crate::internal::KEY_LEN;

    /// Pinned via `StaticProvider` because it's the one built-in
    /// available in every build configuration (no-std, no-features),
    /// so this assertion holds even when the std-only providers are
    /// compiled out. A regression that broke object safety would
    /// otherwise hide under `#[cfg(feature = "std")]`.
    #[test]
    fn key_provider_is_object_safe() {
        let _: alloc::boxed::Box<dyn KeyProvider> =
            alloc::boxed::Box::new(StaticProvider::new(UnlockKey::from_raw([0u8; KEY_LEN])));
    }

    #[cfg(feature = "std")]
    #[test]
    fn key_provider_is_object_safe_for_env_provider() {
        // Companion to the no-std assertion above: under the std
        // feature, the env-var provider must also satisfy object
        // safety. A regression that drifted only the std-only impls
        // (e.g. an added associated type) would hide from the
        // no-std-friendly test.
        let _: alloc::boxed::Box<dyn KeyProvider> =
            alloc::boxed::Box::new(EnvVarProvider::default());
    }
}
