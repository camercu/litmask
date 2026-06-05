//! Symmetric-key newtypes.
//!
//! [`UnlockKey`] is the public-facing unlock key supplied by a
//! [`crate::KeyProvider`]. [`MaskKey`] is the runtime-only decrypted
//! mask key held in a process-global once-cell. Both zero their
//! contents on drop.

use zeroize::{Zeroize, ZeroizeOnDrop, Zeroizing};

use crate::error::KeyError;
use crate::internal::{KEY_LEN, base64url};

/// The runtime-supplied key that decrypts the embedded `mask_key`
/// wrapper.
///
/// `Clone` is intentionally not implemented; duplicating a
/// zero-on-drop secret should be opt-in and obvious at the call site.
///
/// Equality comparison is constant-time (branchless XOR-chunk
/// accumulation) to prevent timing side-channels.
///
/// # Examples
///
/// ```
/// use litmask::UnlockKey;
///
/// // 32 bytes of zeros encoded as base64url (43 chars, no padding).
/// let key = UnlockKey::from_base64url(
///     "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"
/// ).expect("valid key");
/// assert_eq!(format!("{key:?}"), "UnlockKey([REDACTED])");
/// ```
#[derive(Zeroize, ZeroizeOnDrop)]
pub struct UnlockKey([u8; KEY_LEN]);

// KEY_LEN (32) divides evenly into 4 × u64 chunks.
const _: () = assert!(KEY_LEN % 8 == 0);

impl PartialEq for UnlockKey {
    fn eq(&self, other: &Self) -> bool {
        // XOR each 8-byte chunk, saturating-add the results. Any
        // differing byte produces a non-zero chunk that can never
        // wrap back to zero through saturating addition.
        self.0
            .chunks_exact(8)
            .zip(other.0.chunks_exact(8))
            .fold(0u64, |acc, (a, b)| {
                let a = u64::from_ne_bytes(a.try_into().unwrap());
                let b = u64::from_ne_bytes(b.try_into().unwrap());
                acc.saturating_add(a ^ b)
            })
            == 0
    }
}

impl Eq for UnlockKey {}

impl UnlockKey {
    /// Decode a base64url-encoded 32-byte key. Padded inputs and any
    /// length other than 32 are rejected with
    /// [`KeyError::InvalidFormat`].
    ///
    /// # Errors
    ///
    /// Returns [`KeyError::InvalidFormat`] for malformed encoding or
    /// wrong length.
    pub fn from_base64url(input: &str) -> Result<Self, KeyError> {
        // Plaintext key bytes MUST NOT linger on the heap after the
        // fixed-size array is populated.
        let decoded =
            Zeroizing::new(base64url::decode(input).map_err(|_| KeyError::InvalidFormat)?);
        let bytes: [u8; KEY_LEN] = decoded
            .as_slice()
            .try_into()
            .map_err(|_| KeyError::InvalidFormat)?;
        Ok(Self(bytes))
    }

    /// Construct an `UnlockKey` from raw 32-byte material. Used by
    /// providers that source the key bytes directly (rather than via
    /// base64url-encoded text), e.g. `EmbeddedProvider` (nonce-derived),
    /// `FileProvider` under `KeyEncoding::Raw`, and `MachineIdProvider`.
    /// Stays crate-private so the encoded/typed entry point
    /// (`from_base64url`) remains the canonical user-facing API and a
    /// caller cannot accidentally bypass the length check by handing
    /// in arbitrary bytes — the type system pins the array length.
    pub(crate) fn from_raw(bytes: [u8; KEY_LEN]) -> Self {
        Self(bytes)
    }

    /// Normalize arbitrary-length external material into the 32-byte
    /// `unlock_key` via `KDF("litmask-unlock-v1", material)` — the
    /// single derivation §2.2 mandates for every external factor
    /// (env, file, custom provider). The seal side (`litmask-build`)
    /// chains the identical KDF, so build and runtime agree.
    ///
    /// `weak_mask!()` keeps the BLAKE3 context literal out of
    /// `strings(1)` in user binaries; it MUST decode to
    /// `litmask_internal::EXTERNAL_UNLOCK_DERIVATION_CONTEXT` (pinned by
    /// the `derive_weak_mask_literal_matches_const` test).
    #[must_use]
    pub fn derive(material: &[u8]) -> Self {
        Self(crate::internal::derive_external_unlock_key(
            crate::weak_mask!("litmask-unlock-v1"),
            material,
        ))
    }

    pub(crate) fn as_bytes(&self) -> &[u8; KEY_LEN] {
        &self.0
    }
}

impl core::fmt::Debug for UnlockKey {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        // Never print key material, even in Debug output.
        f.write_str("UnlockKey([REDACTED])")
    }
}

/// The decrypted mask key. Held in a process-global once-cell for
/// the program's lifetime; never re-decrypted. Crate-internal only.
#[derive(Zeroize, ZeroizeOnDrop)]
#[doc(hidden)]
pub struct MaskKey([u8; KEY_LEN]);

impl MaskKey {
    pub(crate) fn new(bytes: [u8; KEY_LEN]) -> Self {
        Self(bytes)
    }

    pub(crate) fn as_bytes(&self) -> &[u8; KEY_LEN] {
        &self.0
    }
}

impl core::fmt::Debug for MaskKey {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.write_str("MaskKey([REDACTED])")
    }
}

/// Canonical 32-byte test key (all zeros) encoded as 43-char
/// base64url, no padding. Shared crate-wide so the key/env/file unit
/// tests assert against one fixture instead of three drifting copies.
#[cfg(test)]
pub(crate) const VALID_BASE64URL_32B: &str = "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA";

#[cfg(test)]
mod tests {
    use super::*;
    use alloc::format;

    #[test]
    fn from_base64url_accepts_valid_32_byte_key() {
        let key = UnlockKey::from_base64url(VALID_BASE64URL_32B).expect("valid 32-byte key");
        assert_eq!(key.0, [0u8; KEY_LEN]);
    }

    #[test]
    fn derive_matches_external_unlock_kdf() {
        use crate::internal::{EXTERNAL_UNLOCK_DERIVATION_CONTEXT, derive_external_unlock_key};
        let material = b"operator-supplied secret of arbitrary length";
        let key = UnlockKey::derive(material);
        assert_eq!(
            key.as_bytes(),
            &derive_external_unlock_key(EXTERNAL_UNLOCK_DERIVATION_CONTEXT, material)
        );
    }

    #[test]
    fn derive_accepts_arbitrary_length_material() {
        // Any-length material is the point of the external tier — no
        // 32-byte/base64url constraint, the KDF normalizes it.
        let short = UnlockKey::derive(b"x");
        let long = UnlockKey::derive(&[0x5au8; 1024]);
        assert_ne!(short, long);
    }

    /// Pin the literal-vs-const drift: `UnlockKey::derive` inlines
    /// `weak_mask!("litmask-unlock-v1")` so the BLAKE3 context bytes are
    /// obfuscated in user binaries, while `litmask-build` seals the
    /// external wrapper using `EXTERNAL_UNLOCK_DERIVATION_CONTEXT`
    /// directly. The two MUST decode to the same string or every
    /// external build fails to unlock at runtime.
    #[test]
    fn derive_weak_mask_literal_matches_const() {
        assert_eq!(
            crate::weak_mask!("litmask-unlock-v1"),
            crate::internal::EXTERNAL_UNLOCK_DERIVATION_CONTEXT
        );
    }

    #[rstest::rstest]
    #[case::padded("AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=")]
    #[case::too_short("AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA")]
    #[case::too_long(&"A".repeat(64))]
    #[case::non_url_safe_chars("++++/////+++++++++/////++++++++++/////++++++")]
    fn from_base64url_rejects_invalid_input(#[case] input: &str) {
        assert!(matches!(
            UnlockKey::from_base64url(input),
            Err(KeyError::InvalidFormat),
        ));
    }

    #[test]
    fn equal_keys_are_equal() {
        let a = UnlockKey([0x42u8; KEY_LEN]);
        let b = UnlockKey([0x42u8; KEY_LEN]);
        assert_eq!(a, b);
    }

    #[test]
    fn different_keys_are_not_equal() {
        let a = UnlockKey([0x42u8; KEY_LEN]);
        let b = UnlockKey([0x43u8; KEY_LEN]);
        assert_ne!(a, b);
    }

    #[test]
    fn single_bit_difference_detected() {
        let a = UnlockKey([0x00u8; KEY_LEN]);
        let mut bytes = [0x00u8; KEY_LEN];
        bytes[KEY_LEN - 1] = 0x01;
        let b = UnlockKey(bytes);
        assert_ne!(a, b);
    }

    #[test]
    fn debug_does_not_print_key_material() {
        let bytes = [0xCAu8; KEY_LEN];
        let key = UnlockKey(bytes);
        let dbg = format!("{key:?}");
        assert!(dbg.contains("REDACTED"));
        assert!(!dbg.contains("ca"));
        assert!(!dbg.contains("CA"));
    }

    #[test]
    fn debug_mask_key_does_not_print_key_material() {
        let bytes = [0xCAu8; KEY_LEN];
        let key = MaskKey(bytes);
        let dbg = format!("{key:?}");
        assert!(dbg.contains("REDACTED"));
        assert!(!dbg.contains("ca"));
    }

    use proptest::strategy::Strategy as _;

    proptest::proptest! {
        // Any 32-byte key encoded via the shared codec must round-trip
        // through the public parser unchanged. Catches future drift
        // between base64url::encode and from_base64url's accepted
        // alphabet / length policy.
        #[test]
        fn proptest_from_base64url_round_trips_random_keys(
            bytes in proptest::array::uniform32(proptest::num::u8::ANY),
        ) {
            let encoded = crate::internal::base64url::encode(&bytes);
            let key = UnlockKey::from_base64url(&encoded).expect("32-byte key must parse");
            proptest::prop_assert_eq!(key.as_bytes(), &bytes);
        }

        // Inputs whose decoded length is anything other than KEY_LEN
        // must surface as InvalidFormat. Generating via the codec
        // guarantees the candidate input is valid base64url, so the
        // failure mode under test is specifically the length check,
        // not the alphabet check.
        #[test]
        fn proptest_partial_eq_matches_iff_bytes_equal(
            a in proptest::array::uniform32(proptest::num::u8::ANY),
            b in proptest::array::uniform32(proptest::num::u8::ANY),
        ) {
            let ka = UnlockKey(a);
            let kb = UnlockKey(b);
            proptest::prop_assert_eq!(ka == kb, a == b);
        }

        #[test]
        fn proptest_from_base64url_rejects_wrong_length(
            bytes in proptest::collection::vec(proptest::num::u8::ANY, 0..=64)
                .prop_filter("must not be exactly KEY_LEN", |v| v.len() != KEY_LEN),
        ) {
            let encoded = crate::internal::base64url::encode(&bytes);
            proptest::prop_assert!(matches!(
                UnlockKey::from_base64url(&encoded),
                Err(KeyError::InvalidFormat),
            ));
        }
    }
}
