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
//! - [`static_provider`] / [`StaticProvider`] — fixed key, tests-only

use crate::error::KeyError;
use crate::key::UnlockKey;

#[cfg(feature = "std")]
pub(crate) mod env;
#[cfg(feature = "std")]
pub(crate) mod file;
#[cfg(feature = "hw-id")]
pub(crate) mod hw_id;
pub(crate) mod static_provider;

#[cfg(feature = "std")]
pub use env::EnvVarProvider;
#[cfg(feature = "std")]
pub use file::{FileProvider, KeyEncoding};
#[cfg(feature = "hw-id")]
pub use hw_id::HardwareIdProvider;
pub use static_provider::StaticProvider;

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

#[cfg(all(test, feature = "std"))]
mod tests {
    use super::*;

    #[test]
    fn key_provider_is_object_safe() {
        let _: alloc::boxed::Box<dyn KeyProvider> =
            alloc::boxed::Box::new(EnvVarProvider::default());
    }
}
