//! [`StaticProvider`] — fixed in-memory `UnlockKey`. **FOR TESTS
//! ONLY.** §2.5.5.

use zeroize::Zeroize;

use crate::error::KeyError;
use crate::internal::KEY_LEN;
use crate::key::UnlockKey;
use crate::provider::KeyProvider;

/// A provider that holds a fixed [`UnlockKey`] and returns a fresh
/// copy on every call. **FOR TESTS ONLY** — clones the unlock key on
/// every call. Production code should use [`crate::EnvVarProvider`],
/// [`crate::FileProvider`], or [`crate::HardwareIdProvider`].
///
/// The clone is intentional: `unlock_key()` returns an owned
/// [`UnlockKey`] (not a borrow), so each call materializes the
/// secret bytes into a fresh 32-byte buffer. That cost is acceptable
/// in tests and in the `static_provider` cautionary example, but it
/// duplicates secret material into process memory and defeats the
/// hardware-binding aim of the layered key strategy — never wire it
/// into a release build.
///
/// The `S` type parameter is a test seam: production code always
/// uses `StaticProvider` (i.e. `StaticProvider<[u8; KEY_LEN]>`),
/// while unit tests instantiate `StaticProvider<Counted>` to observe
/// the Drop-time wipe without reading dropped memory (which would
/// be UB). The default keeps the public API single-typed for all
/// downstream callers.
pub struct StaticProvider<S: Zeroize = [u8; KEY_LEN]> {
    key_bytes: S,
}

impl StaticProvider<[u8; KEY_LEN]> {
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

impl<S: Zeroize> Drop for StaticProvider<S> {
    fn drop(&mut self) {
        // Wipe the held bytes when the provider is dropped — the
        // type is the only resident copy of the secret outside the
        // process-global mask key cell once it goes out of scope.
        // Dispatching through `Zeroize` (rather than calling
        // `[u8; KEY_LEN]::zeroize` directly) is what lets the unit
        // test substitute a `Counted` storage that observes whether
        // the wipe ran.
        self.key_bytes.zeroize();
    }
}

impl KeyProvider for StaticProvider<[u8; KEY_LEN]> {
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
    use core::sync::atomic::{AtomicUsize, Ordering};

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

    /// Storage wrapper whose `Zeroize` impl bumps a caller-supplied
    /// `AtomicUsize` in addition to wiping the held bytes. Mirrors
    /// the `Counted` newtype in
    /// `crate::provider::file::tests` — substituting it for the
    /// production `[u8; KEY_LEN]` storage is what makes the
    /// "Drop wipes the held bytes" contract observable without
    /// reading dropped memory (UB).
    struct Counted {
        bytes: [u8; KEY_LEN],
        counter: &'static AtomicUsize,
    }

    impl Zeroize for Counted {
        fn zeroize(&mut self) {
            self.bytes.zeroize();
            self.counter.fetch_add(1, Ordering::SeqCst);
        }
    }

    #[test]
    fn static_provider_drop_zeroizes_held_storage_exactly_once() {
        // Without the test seam, this test could only assert
        // `p.key_bytes == bytes` BEFORE drop (reading after drop is
        // UB) — passing even if the production Drop impl were
        // deleted. The `Counted` storage routes the wipe through an
        // observable side effect so a missing or stubbed Drop fails
        // the assertion below.
        static COUNTER: AtomicUsize = AtomicUsize::new(0);
        let provider = StaticProvider {
            key_bytes: Counted {
                bytes: [0xEEu8; KEY_LEN],
                counter: &COUNTER,
            },
        };
        // Sanity: nothing should have zeroized yet. A spurious
        // construction-time wipe would inflate the count below and
        // mask a missing Drop.
        assert_eq!(COUNTER.load(Ordering::SeqCst), 0);
        drop(provider);
        // Exactly one wipe: the Drop impl runs once on the held
        // storage. Removing the Drop leaves this at 0; an
        // accidental double-drop (e.g. via mem::replace + manual
        // drop) leaves it at 2.
        assert_eq!(COUNTER.load(Ordering::SeqCst), 1);
    }
}
