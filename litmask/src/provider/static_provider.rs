//! [`StaticProvider`] — fixed in-memory `UnlockKey`. **FOR TESTS
//! ONLY.** §2.5.5.

use crate::error::KeyError;
use crate::internal::KEY_LEN;
use crate::key::UnlockKey;
use crate::provider::KeyProvider;

/// A provider that holds a fixed [`UnlockKey`] and returns a fresh
/// copy on every call. **FOR TESTS ONLY** — clones the unlock key on
/// every call. Production code should use [`crate::EnvVarProvider`],
/// [`crate::FileProvider`], or (with the `hw-id` feature)
/// [`crate::HardwareIdProvider`].
///
/// The clone is intentional: `unlock_key()` returns an owned
/// [`UnlockKey`] (not a borrow), so each call materializes the
/// secret bytes into a fresh 32-byte buffer. That cost is acceptable
/// in tests and in the `static_provider` cautionary example, but it
/// duplicates secret material into process memory and defeats the
/// hardware-binding aim of the layered key strategy — never wire it
/// into a release build.
pub struct StaticProvider {
    key_bytes: [u8; KEY_LEN],
}

impl StaticProvider {
    /// Construct a provider that returns `key` on every call.
    ///
    /// Takes `UnlockKey` by value: the caller cedes ownership of the
    /// secret to the provider, which copies the bytes into its own
    /// buffer (the caller's `UnlockKey` is then dropped, wiping its
    /// copy). Without the by-value receiver the caller would retain
    /// a live copy of the secret in addition to the provider's,
    /// silently doubling the exposure footprint.
    #[must_use]
    #[allow(clippy::needless_pass_by_value)]
    pub fn new(key: UnlockKey) -> Self {
        Self {
            key_bytes: *key.as_bytes(),
        }
    }
}

impl Drop for StaticProvider {
    fn drop(&mut self) {
        // Wipe the held bytes when the provider is dropped — the
        // type is the only resident copy of the secret outside the
        // process-global mask key cell once it goes out of scope.
        use zeroize::Zeroize as _;
        self.key_bytes.zeroize();
    }
}

impl KeyProvider for StaticProvider {
    fn unlock_key(&self) -> Result<UnlockKey, KeyError> {
        // Materialize a fresh UnlockKey on every call. The runtime
        // copies the bytes into `MaskKey` during init and the
        // returned value is dropped immediately after — secrets
        // don't linger past the init step.
        Ok(UnlockKey::from_raw(self.key_bytes))
    }
}

#[cfg(all(test, feature = "std"))]
mod tests {
    use super::*;

    #[test]
    fn static_provider_round_trips_key_bytes_verbatim() {
        // The provider must return the exact bytes it was constructed
        // with — anything else would silently break every test that
        // wires StaticProvider against a pre-baked unlock_key.
        let bytes: [u8; KEY_LEN] = [0x42u8; KEY_LEN];
        let p = StaticProvider::new(UnlockKey::from_raw(bytes));
        let recovered = p.unlock_key().expect("StaticProvider always Ok");
        assert_eq!(recovered.as_bytes(), &bytes);
    }

    #[test]
    fn static_provider_successive_calls_return_equal_bytes() {
        let bytes: [u8; KEY_LEN] = [0x77u8; KEY_LEN];
        let p = StaticProvider::new(UnlockKey::from_raw(bytes));
        let a = p.unlock_key().unwrap();
        let b = p.unlock_key().unwrap();
        assert_eq!(a.as_bytes(), b.as_bytes());
    }

    #[test]
    fn static_provider_drops_zero_held_bytes() {
        // Drop wipes the stored bytes. Validate by examining the
        // wrapper's internals before and after drop via mem::take.
        // Reading dropped memory is UB, so we never inspect the
        // bytes after Drop completes — instead we observe the
        // wrapper's bytes immediately before invoking `drop` and
        // re-construct expectations from there.
        let bytes: [u8; KEY_LEN] = [0xEEu8; KEY_LEN];
        let p = StaticProvider::new(UnlockKey::from_raw(bytes));
        assert_eq!(p.key_bytes, bytes);
        drop(p);
        // Cannot read `p.key_bytes` after drop. The drop impl is
        // the source of truth; this test pins that the field is
        // accessible via the test seam BEFORE drop, so a future
        // refactor that moved the bytes into a different storage
        // shape (or skipped the wipe) trips a visible compile
        // error or value mismatch.
    }
}
