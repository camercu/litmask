//! [`EmbeddedProvider`] — the keyless Embedded-tier `unlock_key`
//! source, plus a `#[cfg(test)]`-only verbatim-key [`TestProvider`].

use crate::error::KeyError;
use crate::internal::{NONCE_LEN, WRAPPER_LEN, derive_embedded_unlock_key, parse_wrapper};
use crate::key::UnlockKey;
use crate::provider::KeyProvider;

/// The internal keyless [`KeyProvider`] backing the Embedded seal tier.
///
/// `pub(crate)`: it is the mechanism behind the keyless floor, not a type
/// consumers construct. The Embedded tier self-initializes on the first
/// `mask!()` (there is no `init!` form that takes it), and the wrapper
/// bytes it needs are internal — so it has no consumer-facing use.
///
/// Stores no secret. It captures the wrapper's **cleartext** nonce at
/// construction and recomputes the Embedded-tier `unlock_key` from that
/// nonce on every call — the same derivation `litmask-build` runs at
/// seal time. The nonce ships in the binary in the clear, so the Embedded
/// tier buys `strings(1)` resistance, not secrecy. Higher tiers source a
/// real secret from a runtime channel.
#[derive(Debug)]
pub(crate) struct EmbeddedProvider {
    // Non-secret: the wrapper nonce is public and ships in cleartext,
    // so no zeroize-on-drop is warranted.
    nonce: [u8; NONCE_LEN],
}

impl EmbeddedProvider {
    /// Capture the wrapper's cleartext nonce so [`unlock_key`] can
    /// recompute the Embedded-tier key on demand.
    ///
    /// [`unlock_key`]: KeyProvider::unlock_key
    #[must_use]
    pub(crate) fn new(wrapper: &[u8; WRAPPER_LEN]) -> Self {
        Self {
            nonce: *parse_wrapper(wrapper).nonce,
        }
    }
}

impl KeyProvider for EmbeddedProvider {
    fn unlock_key(&self) -> Result<UnlockKey, KeyError> {
        // `weak_mask!()` keeps the BLAKE3 context literal out of
        // `strings(1)` output — this provider is on the default path,
        // so an un-masked context would fingerprint every binary as
        // litmask-built. The literal MUST match
        // `litmask_internal::EMBEDDED_UNLOCK_DERIVATION_CONTEXT`
        // byte-for-byte (which `litmask-build` uses at seal time) or
        // build ↔ runtime derivations diverge; pinned by the
        // `weak_mask_literal_matches_const` test below.
        Ok(UnlockKey::from_raw(derive_embedded_unlock_key(
            crate::weak_mask!("litmask-embedded-v1"),
            &self.nonce,
        )))
    }
}

/// Verbatim-key provider for in-crate unit tests only. Holds a fixed
/// [`UnlockKey`] and returns a fresh copy on every call. Gated behind
/// `#[cfg(test)]`, so it never reaches the public API or a release
/// build — a fixed-key provider is the opposite of the keyless
/// Embedded floor and must not be shippable.
#[cfg(test)]
pub(crate) struct TestProvider {
    key: UnlockKey,
}

#[cfg(test)]
impl TestProvider {
    pub(crate) fn new(key: UnlockKey) -> Self {
        Self { key }
    }
}

#[cfg(test)]
impl KeyProvider for TestProvider {
    fn unlock_key(&self) -> Result<UnlockKey, KeyError> {
        Ok(UnlockKey::from_raw(*self.key.as_bytes()))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::internal::{
        CURRENT_CIPHER, EMBEDDED_UNLOCK_DERIVATION_CONTEXT, FormatVersion, KEY_LEN,
        WRAPPER_BODY_LEN, WRAPPER_PLAINTEXT_LEN, aead_encrypt, assemble_wrapper, decrypt_wrapper,
    };

    /// Seal a wrapper exactly as `litmask-build` does for the Embedded
    /// tier: `unlock_key` derived from the chosen nonce, then
    /// `version || mask_key` sealed under it.
    fn seal_embedded_wrapper(nonce: [u8; NONCE_LEN], mask_key: [u8; KEY_LEN]) -> [u8; WRAPPER_LEN] {
        let unlock_key = derive_embedded_unlock_key(EMBEDDED_UNLOCK_DERIVATION_CONTEXT, &nonce);
        let mut plaintext = [0u8; WRAPPER_PLAINTEXT_LEN];
        plaintext[0] = FormatVersion::CURRENT.to_byte();
        plaintext[1..].copy_from_slice(&mask_key);
        let body = aead_encrypt(CURRENT_CIPHER, &unlock_key, &nonce, &plaintext)
            .expect("aead_encrypt under derived unlock_key");
        let body: &[u8; WRAPPER_BODY_LEN] = body.as_slice().try_into().expect("body length");
        assemble_wrapper(&nonce, body)
    }

    #[test]
    fn new_captures_the_wrapper_nonce() {
        let nonce = [0x5au8; NONCE_LEN];
        let wrapper = seal_embedded_wrapper(nonce, [0u8; KEY_LEN]);
        let provider = EmbeddedProvider::new(&wrapper);
        assert_eq!(provider.nonce, nonce);
    }

    #[test]
    fn unlock_key_equals_nonce_derivation() {
        let nonce = [0x21u8; NONCE_LEN];
        let wrapper = seal_embedded_wrapper(nonce, [0u8; KEY_LEN]);
        let provider = EmbeddedProvider::new(&wrapper);
        let recovered = provider.unlock_key().expect("EmbeddedProvider always Ok");
        assert_eq!(
            recovered.as_bytes(),
            &derive_embedded_unlock_key(EMBEDDED_UNLOCK_DERIVATION_CONTEXT, &nonce)
        );
    }

    /// Pin the literal-vs-const drift: `EmbeddedProvider::unlock_key`
    /// inlines `weak_mask!("litmask-embedded-v1")` so the BLAKE3 context
    /// bytes are obfuscated in user binaries, while `litmask-build`
    /// seals the wrapper using `EMBEDDED_UNLOCK_DERIVATION_CONTEXT`
    /// directly. The two MUST decode to the same string or every build
    /// fails to unlock at runtime.
    #[test]
    fn weak_mask_literal_matches_const() {
        assert_eq!(
            crate::weak_mask!("litmask-embedded-v1"),
            EMBEDDED_UNLOCK_DERIVATION_CONTEXT
        );
    }

    #[test]
    fn derived_key_round_trips_a_build_emitted_wrapper() {
        let nonce = [0x09u8; NONCE_LEN];
        let mask_key = [0x11u8; KEY_LEN];
        let wrapper = seal_embedded_wrapper(nonce, mask_key);
        let provider = EmbeddedProvider::new(&wrapper);
        let unlock_key = provider.unlock_key().unwrap();
        let recovered = decrypt_wrapper(unlock_key.as_bytes(), &wrapper).expect("round-trip");
        assert_eq!(recovered, mask_key);
    }

    #[test]
    fn test_provider_round_trips_key_bytes_verbatim() {
        let bytes: [u8; KEY_LEN] = [0x42u8; KEY_LEN];
        let p = TestProvider::new(UnlockKey::from_raw(bytes));
        let recovered = p.unlock_key().expect("TestProvider always Ok");
        assert_eq!(recovered.as_bytes(), &bytes);
    }

    #[test]
    fn test_provider_successive_calls_return_equal_bytes() {
        let bytes: [u8; KEY_LEN] = [0x77u8; KEY_LEN];
        let p = TestProvider::new(UnlockKey::from_raw(bytes));
        let a = p.unlock_key().unwrap();
        let b = p.unlock_key().unwrap();
        assert_eq!(a.as_bytes(), b.as_bytes());
    }
}
